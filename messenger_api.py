from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable

import aiosqlite
from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field


SESSION_TTL = 60 * 60 * 24 * 30
DM_MESSAGES_PER_MINUTE = 30
CHANNEL_POSTS_PER_MINUTE = 20
LOGIN_REQUESTS_PER_IP_PER_HOUR = 100
MAX_MESSAGE_LENGTH = 4000
PHONE_RE = re.compile(r"^\+1[0-9]{10}$")
GIFT_SERIAL_RE = re.compile(r"^WG-[A-F0-9]{12}$")


async def init_messenger_storage(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(database_path) as db:
        await db.executescript(
            """
            CREATE TABLE IF NOT EXISTS api_sessions (
                token_hash TEXT PRIMARY KEY,
                telegram_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_api_sessions_user
                ON api_sessions(telegram_id, expires_at);
            CREATE TABLE IF NOT EXISTS api_login_request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL,
                ip TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_api_login_phone_time
                ON api_login_request_log(phone, created_at);
            CREATE INDEX IF NOT EXISTS idx_api_login_ip_time
                ON api_login_request_log(ip, created_at);
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_telegram_id INTEGER NOT NULL,
                recipient_telegram_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_api_messages_pair
                ON messages(sender_telegram_id, recipient_telegram_id, id);
            CREATE INDEX IF NOT EXISTS idx_api_messages_sender_time
                ON messages(sender_telegram_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_api_messages_recipient_time
                ON messages(recipient_telegram_id, created_at);
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                owner_telegram_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS channel_admins (
                channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                telegram_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(channel_id, telegram_id)
            );
            CREATE TABLE IF NOT EXISTS channel_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                author_telegram_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_api_channel_messages
                ON channel_messages(channel_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_api_channel_author_time
                ON channel_messages(author_telegram_id, created_at);
            CREATE TABLE IF NOT EXISTS api_idempotency_records (
                telegram_id INTEGER NOT NULL,
                scope TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(telegram_id, scope, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS idx_api_idempotency_created
                ON api_idempotency_records(created_at);
            """
        )
        # Older Telegram admin grants used WG- plus 8 hex digits. Expand them
        # once so the Android client can validate every existing gift serial.
        cur = await db.execute(
            "SELECT id,serial_number FROM user_gifts WHERE serial_number LIKE 'WG-%' AND LENGTH(serial_number)=11"
        )
        legacy_gifts = await cur.fetchall()
        for gift_id, old_serial in legacy_gifts:
            new_serial = str(old_serial) + secrets.token_hex(2).upper()
            await db.execute(
                "UPDATE user_gifts SET serial_number=? WHERE id=?",
                (new_serial, gift_id),
            )
            await db.execute(
                "UPDATE gift_transactions SET serial_number=? WHERE serial_number=?",
                (new_serial, old_serial),
            )
        await db.commit()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _public_account(row: Any, include_phone: bool = False) -> dict[str, Any]:
    result = {
        "id": int(row["telegram_id"]),
        "username": str(row["username"] or ""),
        "display_name": str(row["display_name"] or ""),
    }
    if include_phone:
        result["phone"] = row["virtual_number"]
    result["stars"] = int(row["stars"])
    result["grams"] = int(row["grams"])
    return result


def _message_body(value: str) -> str:
    body = str(value).strip()
    if not body or len(body) > MAX_MESSAGE_LENGTH:
        raise HTTPException(status_code=400, detail="Текст сообщения должен содержать 1–4000 символов")
    return body


def build_messenger_router(
    database_path: Path | Callable[[], Path],
    auth_store: Any,
    bot_provider: Callable[[], Any],
    account_is_banned: Callable[[int], Any],
) -> APIRouter:
    router = APIRouter()
    db_path = database_path if callable(database_path) else lambda: database_path

    async def current_user(authorization: str | None) -> dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Требуется вход")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=401, detail="Требуется вход")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT a.* FROM api_sessions s
                   JOIN accounts a ON a.telegram_id=s.telegram_id
                   WHERE s.token_hash=? AND s.expires_at>?""",
                (_token_hash(token), now),
            )
            row = await cur.fetchone()
            if row is None:
                await db.execute("DELETE FROM api_sessions WHERE token_hash=?", (_token_hash(token),))
                await db.commit()
                raise HTTPException(status_code=401, detail="Сессия истекла или недействительна")
            user = dict(row)
        if user["is_banned"]:
            raise HTTPException(status_code=403, detail="Аккаунт заблокирован")
        return user

    def idempotency_descriptor(path: str, body: dict[str, Any], key: str | None):
        value = (key or "").strip()
        if not value:
            return None
        if len(value) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", value):
            raise HTTPException(status_code=400, detail="Некорректный Idempotency-Key")
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256((path + "\\n" + canonical).encode("utf-8")).hexdigest()
        return value, digest

    async def idempotency_lookup(
        db: Any, telegram_id: int, scope: str, descriptor: Any, now: int
    ) -> dict[str, Any] | None:
        if descriptor is None:
            return None
        key, request_hash = descriptor
        cur = await db.execute(
            """SELECT request_hash,response_json FROM api_idempotency_records
               WHERE telegram_id=? AND scope=? AND idempotency_key=? AND created_at>=?""",
            (telegram_id, scope, key, now - 7 * 86400),
        )
        prior = await cur.fetchone()
        if prior is None:
            return None
        if not hmac.compare_digest(str(prior[0]), request_hash):
            raise HTTPException(status_code=409, detail="Idempotency-Key уже использован для другого запроса")
        try:
            return json.loads(prior[1])
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=500, detail="Не удалось восстановить предыдущий результат") from exc

    async def idempotency_store(
        db: Any, telegram_id: int, scope: str, descriptor: Any,
        response: dict[str, Any], now: int
    ) -> None:
        if descriptor is None:
            return
        key, request_hash = descriptor
        await db.execute("DELETE FROM api_idempotency_records WHERE created_at<?", (now - 7 * 86400,))
        await db.execute(
            """INSERT INTO api_idempotency_records
               (telegram_id,scope,idempotency_key,request_hash,response_json,created_at)
               VALUES(?,?,?,?,?,?)""",
            (telegram_id, scope, key, request_hash,
             json.dumps(response, ensure_ascii=False, separators=(",", ":")), now),
        )

    async def channel_row(channel_id: int) -> dict[str, Any]:
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ch.id,ch.username,ch.title,ch.owner_telegram_id,
                          owner.username AS owner_username
                   FROM channels ch LEFT JOIN accounts owner
                     ON owner.telegram_id=ch.owner_telegram_id
                   WHERE ch.id=?""",
                (channel_id,),
            )
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Канал не найден")
        return dict(row)

    async def can_manage_channel(channel_id: int, telegram_id: int) -> bool:
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                """SELECT 1 FROM channels WHERE id=? AND owner_telegram_id=?
                   UNION SELECT 1 FROM channel_admins WHERE channel_id=? AND telegram_id=? LIMIT 1""",
                (channel_id, telegram_id, channel_id, telegram_id),
            )
            return await cur.fetchone() is not None

    @router.get("/api/config")
    async def api_config() -> dict[str, Any]:
        return {
            "brand": "WaysGram",
            "api_version": 1,
            "auth": "authwaysgram_bot",
            "authbot_delivery_ready": bool(bot_provider()),
            "sms_delivery_ready": False,
            "test_otp_enabled": False,
            "currencies": ["stars", "grams"],
            "gift_model": "internal_collectible",
            "messaging_limits": {
                "direct_messages_per_minute": DM_MESSAGES_PER_MINUTE,
                "channel_posts_per_minute": CHANNEL_POSTS_PER_MINUTE,
                "message_characters": MAX_MESSAGE_LENGTH,
            },
            "features": [
                "profiles", "direct_messages", "incremental_messages",
                "channels", "incremental_channel_posts", "idempotent_writes",
                "session_refresh", "gifts", "gift_inventory", "gift_transfer",
                "stars", "grams",
            ],
        }

    @router.post("/api/auth/request-code")
    async def request_login_code(payload: dict[str, Any], request: Request) -> dict[str, str]:
        phone = str(payload.get("phone", payload.get("number", ""))).strip()
        if not PHONE_RE.fullmatch(phone):
            raise HTTPException(status_code=400, detail="Номер должен иметь формат +1 и 10 цифр")
        owner = await auth_store.resolve_number(phone)
        if not owner:
            raise HTTPException(status_code=404, detail="Номер не закреплён за аккаунтом")
        if not owner.get("verified"):
            raise HTTPException(status_code=403, detail="Сначала пройдите проверку в AuthWaysGram_bot")
        telegram_id = int(owner["telegram_id"])
        if await account_is_banned(telegram_id):
            raise HTTPException(status_code=403, detail="Аккаунт заблокирован")
        bot = bot_provider()
        if bot is None:
            raise HTTPException(status_code=503, detail="Telegram-бот ещё не запущен")

        now = int(time.time())
        ip = request.client.host if request.client else "unknown"
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            await db.execute("DELETE FROM api_login_request_log WHERE created_at<?", (now - 7 * 86400,))
            cur = await db.execute(
                "SELECT COUNT(*) FROM api_login_request_log WHERE phone=? AND created_at>?",
                (phone, now - 3600),
            )
            phone_count = int((await cur.fetchone())[0])
            cur = await db.execute(
                "SELECT COUNT(*) FROM api_login_request_log WHERE ip=? AND created_at>?",
                (ip, now - 3600),
            )
            ip_count = int((await cur.fetchone())[0])
            if phone_count >= 5 or ip_count >= LOGIN_REQUESTS_PER_IP_PER_HOUR:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен часовой лимит запросов кода")
            await db.commit()

        code = f"{secrets.randbelow(1_000_000):06d}"
        if not await auth_store.save_code(phone, code, 300):
            raise HTTPException(status_code=429, detail="Повторный запрос кода доступен через 30 секунд")
        async with aiosqlite.connect(db_path()) as db:
            await db.execute(
                "INSERT INTO api_login_request_log(phone,ip,created_at) VALUES(?,?,?)",
                (phone, ip, now),
            )
            await db.commit()
        try:
            language = str(owner.get("language") or "en")
            text = (
                "Код WaysGram готов. Нажмите «Получить код» в меню бота."
                if language == "ru"
                else "Your WaysGram code is ready. Tap “Get code” in the bot menu."
            )
            await bot.send_message(chat_id=int(owner["chat_id"]), text=text)
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Не удалось отправить уведомление через Telegram-бота") from exc
        return {
            "status": "sent",
            "brand": "WaysGram",
            "delivery": "AuthWaysGram_bot",
            "message": "Код подготовлен. Откройте AuthWaysGram_bot и нажмите «Получить код».",
        }

    @router.post("/api/auth/verify-code")
    async def verify_login_code(payload: dict[str, Any]) -> dict[str, Any]:
        phone = str(payload.get("phone", payload.get("number", ""))).strip()
        code = str(payload.get("code", "")).strip()
        if not PHONE_RE.fullmatch(phone) or not re.fullmatch(r"[0-9]{6}", code):
            raise HTTPException(status_code=400, detail="Проверьте виртуальный номер и шестизначный код")
        owner = await auth_store.resolve_number(phone)
        if not owner or not owner.get("verified"):
            raise HTTPException(status_code=401, detail="Номер не подтверждён")
        telegram_id = int(owner["telegram_id"])
        if await account_is_banned(telegram_id):
            raise HTTPException(status_code=403, detail="Аккаунт заблокирован")
        if not await auth_store.verify_code(phone, code):
            raise HTTPException(status_code=401, detail="Неверный, истёкший или уже использованный код")

        now = int(time.time())
        token = secrets.token_urlsafe(36)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                """INSERT OR IGNORE INTO accounts
                   (telegram_id,virtual_number,created_at,updated_at)
                   VALUES(?,?,?,?)""",
                (telegram_id, phone, now, now),
            )
            await db.execute(
                "UPDATE accounts SET virtual_number=?,updated_at=? WHERE telegram_id=?",
                (phone, now, telegram_id),
            )
            await db.execute(
                "INSERT INTO api_sessions(token_hash,telegram_id,expires_at,created_at) VALUES(?,?,?,?)",
                (_token_hash(token), telegram_id, now + SESSION_TTL, now),
            )
            cur = await db.execute("SELECT * FROM accounts WHERE telegram_id=?", (telegram_id,))
            account = await cur.fetchone()
            await db.commit()
        return {
            "token": token,
            "expires_at": now + SESSION_TTL,
            "user": _public_account(account, include_phone=True),
        }

    @router.post("/api/auth/refresh")
    async def refresh_session(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        token = authorization[7:].strip()
        expires_at = int(time.time()) + SESSION_TTL
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "UPDATE api_sessions SET expires_at=? WHERE token_hash=? AND expires_at>?",
                (expires_at, _token_hash(token), int(time.time())),
            )
            if cur.rowcount != 1:
                raise HTTPException(status_code=401, detail="Сессия истекла или недействительна")
            await db.commit()
        return {
            "status": "refreshed",
            "expires_at": expires_at,
            "user": _public_account(user, include_phone=True),
        }

    @router.post("/api/auth/logout")
    async def logout_session(authorization: str | None = Header(default=None)) -> dict[str, str]:
        if authorization and authorization.startswith("Bearer "):
            token = authorization[7:].strip()
            if token:
                async with aiosqlite.connect(db_path()) as db:
                    await db.execute("DELETE FROM api_sessions WHERE token_hash=?", (_token_hash(token),))
                    await db.commit()
        return {"status": "logged_out"}

    @router.get("/api/me")
    async def get_me(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        return _public_account(await current_user(authorization), include_phone=True)

    @router.patch("/api/me")
    async def update_me(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        if not payload or not ({"username", "display_name"} & payload.keys()):
            raise HTTPException(status_code=400, detail="Нет полей для изменения")
        username = user["username"]
        display_name = user["display_name"]
        if "display_name" in payload:
            display_name = payload["display_name"]
            if not isinstance(display_name, str) or len(display_name.strip()) > 60:
                raise HTTPException(status_code=400, detail="Имя профиля должно содержать не более 60 символов")
            display_name = display_name.strip()
        if "username" in payload:
            username = payload["username"]
            if not isinstance(username, str):
                raise HTTPException(status_code=400, detail="Некорректный username")
            username = username.strip().lstrip("@").lower()
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", username):
                raise HTTPException(status_code=400, detail="Username: 1–32 символа, латиница, цифры и _, первый символ — буква")
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            if "username" in payload:
                cur = await db.execute(
                    "SELECT 1 FROM accounts WHERE username=? COLLATE NOCASE AND telegram_id<>?",
                    (username, int(user["telegram_id"])),
                )
                if await cur.fetchone():
                    raise HTTPException(status_code=409, detail="Username уже занят")
            await db.execute(
                "UPDATE accounts SET username=?,display_name=?,updated_at=? WHERE telegram_id=?",
                (username, display_name, int(time.time()), int(user["telegram_id"])),
            )
            await db.commit()
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM accounts WHERE telegram_id=?", (int(user["telegram_id"]),))
            row = await cur.fetchone()
        return _public_account(row, include_phone=True)

    @router.get("/api/me/wallet")
    async def get_wallet(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        return {
            "user_id": int(user["telegram_id"]),
            "stars": int(user["stars"]),
            "grams": int(user["grams"]),
            "currencies": {"stars": int(user["stars"]), "grams": int(user["grams"])},
        }

    @router.get("/api/me/wallet/transactions")
    async def wallet_transactions(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,asset,amount,balance_after,reason,admin_id,created_at
                   FROM economy_transactions WHERE telegram_id=? ORDER BY id DESC LIMIT 100""",
                (int(user["telegram_id"]),),
            )
            rows = await cur.fetchall()
        return {"transactions": [dict(row) for row in rows]}

    @router.get("/api/me/gifts")
    async def my_gifts(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,serial_number,gift_id,gift_name,acquired_at
                   FROM user_gifts WHERE owner_telegram_id=? ORDER BY id DESC""",
                (int(user["telegram_id"]),),
            )
            rows = await cur.fetchall()
        return {"gifts": [dict(row) for row in rows]}

    @router.get("/api/me/gifts/transactions")
    async def my_gift_transactions(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT gt.id,gt.event_type,gt.serial_number,gt.gift_name,
                          gt.from_telegram_id,sender.username AS from_username,
                          gt.to_telegram_id,recipient.username AS to_username,gt.created_at
                   FROM gift_transactions gt
                   LEFT JOIN accounts sender ON sender.telegram_id=gt.from_telegram_id
                   JOIN accounts recipient ON recipient.telegram_id=gt.to_telegram_id
                   WHERE gt.from_telegram_id=? OR gt.to_telegram_id=?
                   ORDER BY gt.id DESC LIMIT 100""",
                (uid, uid),
            )
            rows = await cur.fetchall()
        return {"transactions": [dict(row) for row in rows]}

    @router.get("/api/users")
    async def search_users(
        q: str = Query(default="", max_length=64),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        q = q.strip().lstrip("@")
        if not q:
            return {"users": []}
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            if q.isdigit():
                cur = await db.execute(
                    """SELECT telegram_id AS id,username,display_name FROM accounts
                       WHERE telegram_id=? LIMIT 30""",
                    (int(q),),
                )
            else:
                cur = await db.execute(
                    """SELECT telegram_id AS id,username,display_name FROM accounts
                       WHERE username LIKE ? OR display_name LIKE ?
                       ORDER BY telegram_id DESC LIMIT 30""",
                    (f"%{q}%", f"%{q}%"),
                )
            rows = await cur.fetchall()
        return {"users": [dict(row) for row in rows]}

    @router.get("/api/users/{user_id}")
    async def get_user_profile(
        user_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT telegram_id AS id,username,display_name,created_at
                   FROM accounts WHERE telegram_id=?""",
                (user_id,),
            )
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        return dict(row)

    @router.get("/api/gifts")
    async def gift_catalog(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,name,price_grams AS price,supply FROM gift_catalog
                   WHERE supply>0 ORDER BY id DESC"""
            )
            rows = await cur.fetchall()
        return {"currency": "grams", "gifts": [dict(row) for row in rows]}

    @router.post("/api/gifts/{gift_id}/purchase", status_code=201)
    async def purchase_gift(
        gift_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if gift_id <= 0:
            raise HTTPException(status_code=400, detail="Некорректный ID подарка")
        key = (idempotency_key or "").strip()
        if key and (len(key) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", key)):
            raise HTTPException(status_code=400, detail="Некорректный Idempotency-Key")
        canonical = json.dumps({"gift_id": gift_id, "payload": payload}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        request_hash = hashlib.sha256(("/api/gifts/purchase\n" + canonical).encode("utf-8")).hexdigest()
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            if key:
                cur = await db.execute(
                    """SELECT request_hash,response_json FROM api_idempotency_records
                       WHERE telegram_id=? AND scope='gift_purchase' AND idempotency_key=? AND created_at>=?""",
                    (uid, key, now - 7 * 86400),
                )
                prior = await cur.fetchone()
                if prior:
                    await db.rollback()
                    if not hmac.compare_digest(str(prior["request_hash"]), request_hash):
                        raise HTTPException(status_code=409, detail="Idempotency-Key уже использован для другого запроса")
                    return json.loads(prior["response_json"])
            cur = await db.execute(
                "SELECT id,name,price_grams,supply FROM gift_catalog WHERE id=?",
                (gift_id,),
            )
            gift = await cur.fetchone()
            if not gift:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Подарок не найден")
            if int(gift["supply"]) <= 0:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Подарок закончился")
            cur = await db.execute(
                "SELECT grams,is_banned FROM accounts WHERE telegram_id=?",
                (uid,),
            )
            account = await cur.fetchone()
            price = int(gift["price_grams"])
            if not account or account["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Аккаунт недоступен")
            if int(account["grams"]) < price:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Gram")
            cur = await db.execute(
                "UPDATE accounts SET grams=grams-?,updated_at=? WHERE telegram_id=? AND grams>=?",
                (price, now, uid, price),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Gram")
            cur = await db.execute(
                "UPDATE gift_catalog SET supply=supply-1 WHERE id=? AND supply>0",
                (gift_id,),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Подарок закончился")
            serial = "WG-" + secrets.token_hex(6).upper()
            cur = await db.execute(
                """INSERT INTO user_gifts
                   (serial_number,gift_id,gift_name,owner_telegram_id,acquired_at)
                   VALUES(?,?,?,?,?)""",
                (serial, gift_id, str(gift["name"]), uid, now),
            )
            gift_instance_id = int(cur.lastrowid)
            balance = int(account["grams"]) - price
            if price:
                await db.execute(
                    """INSERT INTO economy_transactions
                       (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                       VALUES(?,'grams',?,?,?,NULL,?)""",
                    (uid, -price, balance, f"gift_purchase:{gift_id}", now),
                )
            await db.execute(
                """INSERT INTO gift_transactions
                   (event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                   VALUES('purchase',?,?,NULL,?,?)""",
                (serial, str(gift["name"]), uid, now),
            )
            result = {
                "status": "purchased",
                "gift": {
                    "id": gift_instance_id,
                    "serial_number": serial,
                    "gift_id": gift_id,
                    "name": str(gift["name"]),
                    "acquired_at": now,
                },
                "grams_spent": price,
                "grams_balance": balance,
            }
            if key:
                await db.execute(
                    """DELETE FROM api_idempotency_records WHERE created_at<?""",
                    (now - 7 * 86400,),
                )
                await db.execute(
                    """INSERT INTO api_idempotency_records
                       (telegram_id,scope,idempotency_key,request_hash,response_json,created_at)
                       VALUES(?,'gift_purchase',?,?,?,?)""",
                    (uid, key, request_hash, json.dumps(result, ensure_ascii=False, separators=(",", ":")), now),
                )
            await db.commit()
        return result

    @router.post("/api/gifts/transfer")
    async def transfer_gift(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        serial = str(payload.get("serial_number", "")).strip().upper()
        recipient_key = str(payload.get("recipient", payload.get("recipient_id", ""))).strip().lstrip("@")
        if not GIFT_SERIAL_RE.fullmatch(serial) or not recipient_key or len(recipient_key) > 64:
            raise HTTPException(status_code=400, detail="Проверьте серийный номер и получателя")
        now = int(time.time())
        descriptor = idempotency_descriptor("/api/gifts/transfer", payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, "/api/gifts/transfer", descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            if recipient_key.isdigit():
                cur = await db.execute(
                    "SELECT telegram_id,username,is_banned FROM accounts WHERE telegram_id=?",
                    (int(recipient_key),),
                )
            else:
                cur = await db.execute(
                    "SELECT telegram_id,username,is_banned FROM accounts WHERE username=? COLLATE NOCASE",
                    (recipient_key,),
                )
            recipient = await cur.fetchone()
            if not recipient:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Получатель не найден")
            target_id = int(recipient["telegram_id"])
            if recipient["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Получатель заблокирован")
            if target_id == uid:
                await db.rollback()
                raise HTTPException(status_code=400, detail="Нельзя передать подарок самому себе")
            cur = await db.execute(
                """SELECT id,gift_name FROM user_gifts
                   WHERE serial_number=? AND owner_telegram_id=?""",
                (serial, uid),
            )
            gift = await cur.fetchone()
            if not gift:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Подарок не найден в вашем инвентаре")
            cur = await db.execute(
                "UPDATE user_gifts SET owner_telegram_id=? WHERE id=? AND owner_telegram_id=?",
                (target_id, int(gift["id"]), uid),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Владение подарком уже изменилось")
            await db.execute(
                """INSERT INTO gift_transactions
                   (event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                   VALUES('transfer',?,?,?,?,?)""",
                (serial, str(gift["gift_name"]), uid, target_id, now),
            )
            result = {
                "status": "transferred",
                "serial_number": serial,
                "gift_name": str(gift["gift_name"]),
                "from_user_id": uid,
                "to_user_id": target_id,
                "to_username": str(recipient["username"] or ""),
            }
            await idempotency_store(db, uid, "/api/gifts/transfer", descriptor, result, now)
            await db.commit()
        return result

    @router.get("/api/channels")
    async def list_channels(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ch.id,ch.username,ch.title,ch.owner_telegram_id,
                          owner.username AS owner_username
                   FROM channels ch LEFT JOIN accounts owner
                     ON owner.telegram_id=ch.owner_telegram_id
                   ORDER BY ch.id DESC"""
            )
            rows = await cur.fetchall()
        return {"channels": [dict(row) for row in rows]}

    @router.post("/api/channels", status_code=201)
    async def create_channel(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        title = payload.get("title")
        username = str(payload.get("username", "")).strip().lstrip("@").lower()
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 80:
            raise HTTPException(status_code=400, detail="Название канала должно содержать 1–80 символов")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", username):
            raise HTTPException(status_code=400, detail="Username канала: латиница, цифры и _, первый символ — буква")
        now = int(time.time())
        try:
            async with aiosqlite.connect(db_path()) as db:
                cur = await db.execute(
                    "INSERT INTO channels(username,title,owner_telegram_id,created_at) VALUES(?,?,?,?)",
                    (username, title.strip(), int(user["telegram_id"]), now),
                )
                channel_id = int(cur.lastrowid)
                await db.commit()
        except aiosqlite.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username канала уже занят") from exc
        return {"id": channel_id, "username": username, "title": title.strip(), "owner_telegram_id": int(user["telegram_id"])}

    @router.get("/api/channels/{channel_id}")
    async def get_channel(
        channel_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        return await channel_row(channel_id)

    @router.get("/api/channels/{channel_id}/messages")
    async def list_channel_messages(
        channel_id: int,
        after_id: int = Query(default=0, ge=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        await channel_row(channel_id)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            if after_id:
                cur = await db.execute(
                    """SELECT id,channel_id,author_telegram_id AS author_id,body,created_at
                       FROM channel_messages WHERE channel_id=? AND id>?
                       ORDER BY id ASC LIMIT 100""",
                    (channel_id, after_id),
                )
            else:
                cur = await db.execute(
                    """SELECT id,channel_id,author_telegram_id AS author_id,body,created_at
                       FROM channel_messages WHERE channel_id=?
                       ORDER BY id DESC LIMIT 100""",
                    (channel_id,),
                )
            rows = await cur.fetchall()
        items = [dict(row) for row in rows]
        if not after_id:
            items.reverse()
        return {"messages": items}

    @router.post("/api/channels/{channel_id}/messages", status_code=201)
    async def create_channel_message(
        channel_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        body = _message_body(payload.get("body", ""))
        if not await can_manage_channel(channel_id, uid):
            raise HTTPException(status_code=403, detail="Публиковать в канале может только владелец или администратор")
        now = int(time.time())
        scope = f"/api/channels/{channel_id}/messages"
        descriptor = idempotency_descriptor(scope, payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, scope, descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            cur = await db.execute(
                "SELECT COUNT(*) FROM channel_messages WHERE author_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= CHANNEL_POSTS_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит публикаций")
            cur = await db.execute(
                """INSERT INTO channel_messages(channel_id,author_telegram_id,body,created_at)
                   VALUES(?,?,?,?)""",
                (channel_id, uid, body, now),
            )
            message_id = int(cur.lastrowid)
            result = {"id": message_id, "status": "published", "channel_id": channel_id, "author_id": uid, "body": body, "created_at": now}
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()
        return result

    @router.post("/api/channels/{channel_id}/admins", status_code=201)
    async def add_channel_admin(
        channel_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if int((await channel_row(channel_id))["owner_telegram_id"]) != uid:
            raise HTTPException(status_code=403, detail="Только владелец может назначать администраторов")
        try:
            target_id = int(payload.get("telegram_id", 0))
        except (TypeError, ValueError):
            target_id = 0
        if target_id <= 0:
            raise HTTPException(status_code=400, detail="Некорректный Telegram ID")
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (target_id,))
            if not await cur.fetchone():
                raise HTTPException(status_code=404, detail="Пользователь не найден")
            await db.execute(
                "INSERT OR IGNORE INTO channel_admins(channel_id,telegram_id,created_at) VALUES(?,?,?)",
                (channel_id, target_id, int(time.time())),
            )
            await db.commit()
        return {"channel_id": channel_id, "telegram_id": target_id, "admin": True}

    @router.delete("/api/channels/{channel_id}/admins/{telegram_id}")
    async def remove_channel_admin(
        channel_id: int,
        telegram_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        channel = await channel_row(channel_id)
        if int(channel["owner_telegram_id"]) != int(user["telegram_id"]):
            raise HTTPException(status_code=403, detail="Только владелец может удалять администраторов")
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "DELETE FROM channel_admins WHERE channel_id=? AND telegram_id=?",
                (channel_id, telegram_id),
            )
            await db.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Администратор канала не найден")
        return {"deleted": True, "channel_id": channel_id, "telegram_id": telegram_id}

    @router.delete("/api/channels/{channel_id}")
    async def delete_channel(
        channel_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, bool]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT 1 FROM channels WHERE id=? AND owner_telegram_id=?",
                (channel_id, int(user["telegram_id"])),
            )
            if not await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=404, detail="Канал не найден или вы не являетесь владельцем")
            await db.execute("DELETE FROM channel_messages WHERE channel_id=?", (channel_id,))
            await db.execute("DELETE FROM channel_admins WHERE channel_id=?", (channel_id,))
            await db.execute(
                "DELETE FROM channels WHERE id=? AND owner_telegram_id=?",
                (channel_id, int(user["telegram_id"])),
            )
            await db.commit()
        return {"deleted": True}

    @router.get("/api/messages")
    async def list_messages(
        peer: int = Query(alias="with", gt=0),
        after_id: int = Query(default=0, ge=0),
        before_id: int = Query(default=0, ge=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if after_id and before_id:
            raise HTTPException(status_code=400, detail="Используйте только один курсор: after_id или before_id")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (peer,))
            if not await cur.fetchone():
                raise HTTPException(status_code=404, detail="Собеседник не найден")
            base = """
                SELECT id,sender_telegram_id AS sender_id,
                       recipient_telegram_id AS recipient_id,body,created_at
                FROM messages WHERE
                (sender_telegram_id=? AND recipient_telegram_id=?) OR
                (sender_telegram_id=? AND recipient_telegram_id=?)
            """
            params: tuple[Any, ...] = (uid, peer, peer, uid)
            if after_id:
                cur = await db.execute(
                    base + " AND id>? ORDER BY id ASC LIMIT 100",
                    params + (after_id,),
                )
            elif before_id:
                cur = await db.execute(
                    base + " AND id<? ORDER BY id DESC LIMIT 100",
                    params + (before_id,),
                )
            else:
                cur = await db.execute(
                    base + " ORDER BY id DESC LIMIT 100",
                    params,
                )
            rows = await cur.fetchall()
        items = [dict(row) for row in rows]
        if not after_id:
            items.reverse()
        return {
            "messages": items,
            "count": len(items),
            "next_before_id": items[0]["id"] if items else 0,
            "next_after_id": items[-1]["id"] if items else 0,
        }

    @router.post("/api/messages", status_code=201)
    async def send_message(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            recipient_id = int(payload.get("recipient_id", payload.get("to", 0)))
        except (TypeError, ValueError):
            recipient_id = 0
        if recipient_id <= 0 or recipient_id == uid:
            raise HTTPException(status_code=400, detail="Укажите корректного получателя")
        body = _message_body(payload.get("body", ""))
        now = int(time.time())
        descriptor = idempotency_descriptor("/api/messages", payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, "/api/messages", descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            cur = await db.execute(
                "SELECT is_banned FROM accounts WHERE telegram_id=?",
                (recipient_id,),
            )
            recipient = await cur.fetchone()
            if not recipient:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Получатель не найден")
            if recipient[0]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Получатель заблокирован")
            cur = await db.execute(
                "SELECT COUNT(*) FROM messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит отправки сообщений")
            cur = await db.execute(
                """INSERT INTO messages(sender_telegram_id,recipient_telegram_id,body,created_at)
                   VALUES(?,?,?,?)""",
                (uid, recipient_id, body, now),
            )
            message_id = int(cur.lastrowid)
            result = {
                "id": message_id,
                "status": "sent",
                "sender_id": uid,
                "recipient_id": recipient_id,
                "body": body,
                "created_at": now,
            }
            await idempotency_store(db, uid, "/api/messages", descriptor, result, now)
            await db.commit()
        return result

    @router.get("/api/conversations")
    async def list_conversations(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """WITH recent AS (
                    SELECT CASE WHEN sender_telegram_id=? THEN recipient_telegram_id
                                ELSE sender_telegram_id END AS peer_id,
                           MAX(id) AS last_message_id
                    FROM messages
                    WHERE sender_telegram_id=? OR recipient_telegram_id=?
                    GROUP BY peer_id
                )
                SELECT peer.telegram_id AS id,peer.username,peer.display_name,
                       message.body AS last_message,message.created_at,
                       message.id AS last_message_id,
                       message.sender_telegram_id AS last_sender_id
                FROM recent
                JOIN accounts AS peer ON peer.telegram_id=recent.peer_id
                JOIN messages AS message ON message.id=recent.last_message_id
                ORDER BY message.id DESC LIMIT 100""",
                (uid, uid, uid),
            )
            rows = await cur.fetchall()
        return {"conversations": [dict(row) for row in rows]}

    return router
