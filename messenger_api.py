from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import hmac
import json
import re
import secrets
import time
from io import BytesIO
from urllib.parse import quote
from pathlib import Path
from typing import Any, Callable

import aiosqlite
import httpx
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field


SESSION_TTL = 60 * 60 * 24 * 30
DM_MESSAGES_PER_MINUTE = 30
CHANNEL_POSTS_PER_MINUTE = 20
LOGIN_REQUESTS_PER_IP_PER_HOUR = 100
MAX_MESSAGE_LENGTH = 4000
MAX_IMAGE_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
MAX_USER_MEDIA_BYTES = 100 * 1024 * 1024
MAX_USER_IMAGE_UPLOADS_PER_HOUR = 30
PHONE_RE = re.compile(r"^\+1[0-9]{10}$")
GIFT_SERIAL_RE = re.compile(r"^WG-[A-F0-9]{12}$")


def _normalize_uploaded_image(raw: bytes) -> tuple[bytes, str, str]:
    """Decode, validate and re-encode a static raster image without metadata."""
    try:
        with Image.open(BytesIO(raw)) as source:
            image_format = str(source.format or "").upper()
            if image_format not in {"JPEG", "PNG", "WEBP"}:
                raise ValueError("Поддерживаются только JPEG, PNG и WebP")
            width, height = source.size
            if width <= 0 or height <= 0 or width > 8192 or height > 8192:
                raise ValueError("Размер изображения не поддерживается")
            if width * height > MAX_IMAGE_PIXELS:
                raise ValueError("Изображение слишком большое по разрешению")
            if getattr(source, "is_animated", False) or getattr(source, "n_frames", 1) != 1:
                raise ValueError("Анимированные изображения пока не поддерживаются")
            source.verify()

        with Image.open(BytesIO(raw)) as source:
            source.load()
            image = ImageOps.exif_transpose(source)
            has_alpha = "A" in image.getbands() or "transparency" in image.info
            output = BytesIO()
            if image_format == "JPEG":
                image.convert("RGB").save(output, format="JPEG", quality=88, optimize=True)
                mime_type, extension = "image/jpeg", ".jpg"
            elif image_format == "PNG":
                image.convert("RGBA" if has_alpha else "RGB").save(
                    output, format="PNG", optimize=True
                )
                mime_type, extension = "image/png", ".png"
            else:
                image.convert("RGBA" if has_alpha else "RGB").save(
                    output, format="WEBP", quality=88, method=4
                )
                mime_type, extension = "image/webp", ".webp"
            normalized = output.getvalue()
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Файл не является корректным изображением") from exc
    if not normalized or len(normalized) > MAX_IMAGE_UPLOAD_BYTES:
        raise ValueError("После обработки изображение превышает лимит 10 МБ")
    return normalized, mime_type, extension


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
            CREATE TABLE IF NOT EXISTS media_assets (
                id TEXT PRIMARY KEY,
                owner_telegram_id INTEGER NOT NULL,
                storage_name TEXT NOT NULL UNIQUE,
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_media_assets_owner_time
                ON media_assets(owner_telegram_id,created_at);
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
            CREATE TABLE IF NOT EXISTS telegram_gift_catalog (
                gift_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                sticker_file_id TEXT NOT NULL,
                sticker_file_unique_id TEXT NOT NULL DEFAULT '',
                sticker_type TEXT NOT NULL DEFAULT 'regular',
                sticker_emoji TEXT NOT NULL DEFAULT '',
                sticker_set_name TEXT NOT NULL DEFAULT '',
                sticker_width INTEGER,
                sticker_height INTEGER,
                sticker_is_animated INTEGER NOT NULL DEFAULT 0,
                sticker_is_video INTEGER NOT NULL DEFAULT 0,
                sticker_mime_type TEXT NOT NULL DEFAULT '',
                star_count INTEGER NOT NULL DEFAULT 0 CHECK(star_count >= 0),
                upgrade_star_count INTEGER,
                is_premium INTEGER NOT NULL DEFAULT 0,
                has_colors INTEGER NOT NULL DEFAULT 0,
                total_count INTEGER,
                remaining_count INTEGER,
                personal_total_count INTEGER,
                personal_remaining_count INTEGER,
                unique_gift_variant_count INTEGER,
                background_json TEXT,
                publisher_chat_json TEXT,
                source_payload TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                is_available INTEGER NOT NULL DEFAULT 1,
                synced_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_telegram_gifts_available
                ON telegram_gift_catalog(is_available,position);
            CREATE TABLE IF NOT EXISTS telegram_gift_sync_state (
                id INTEGER PRIMARY KEY CHECK(id=1),
                last_synced_at INTEGER NOT NULL,
                gift_count INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'telegram_bot_api'
            );
            CREATE TABLE IF NOT EXISTS telegram_mtproto_gift_catalog (
                gift_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                sticker_emoji TEXT NOT NULL DEFAULT '',
                sticker_set_name TEXT NOT NULL DEFAULT '',
                sticker_width INTEGER,
                sticker_height INTEGER,
                sticker_is_animated INTEGER NOT NULL DEFAULT 0,
                sticker_is_video INTEGER NOT NULL DEFAULT 0,
                sticker_mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                sticker_document_id INTEGER,
                sticker_dc_id INTEGER,
                sticker_size INTEGER,
                stars INTEGER NOT NULL DEFAULT 0 CHECK(stars >= 0),
                limited INTEGER NOT NULL DEFAULT 0,
                sold_out INTEGER NOT NULL DEFAULT 0,
                birthday INTEGER NOT NULL DEFAULT 0,
                require_premium INTEGER NOT NULL DEFAULT 0,
                limited_per_user INTEGER NOT NULL DEFAULT 0,
                peer_color_available INTEGER NOT NULL DEFAULT 0,
                auction INTEGER NOT NULL DEFAULT 0,
                availability_remains INTEGER,
                availability_total INTEGER,
                availability_resale INTEGER,
                convert_stars INTEGER,
                first_sale_date INTEGER,
                last_sale_date INTEGER,
                upgrade_stars INTEGER,
                resell_min_stars INTEGER,
                released_by_json TEXT,
                per_user_total INTEGER,
                per_user_remains INTEGER,
                locked_until_date INTEGER,
                auction_slug TEXT NOT NULL DEFAULT '',
                gifts_per_round INTEGER,
                auction_start_date INTEGER,
                upgrade_variants INTEGER,
                background_json TEXT,
                source_payload TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                is_available INTEGER NOT NULL DEFAULT 1,
                synced_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_telegram_mtproto_gifts_available
                ON telegram_mtproto_gift_catalog(is_available,position);
            CREATE TABLE IF NOT EXISTS chat_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT COLLATE NOCASE UNIQUE,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                owner_telegram_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL,
                telegram_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member'
                    CHECK(role IN ('owner','admin','member')),
                joined_at INTEGER NOT NULL,
                PRIMARY KEY(group_id,telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_group_members_user
                ON group_members(telegram_id,group_id);
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                sender_telegram_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_group_messages_group
                ON group_messages(group_id,id DESC);
            CREATE INDEX IF NOT EXISTS idx_group_messages_sender_time
                ON group_messages(sender_telegram_id,created_at);
            CREATE TABLE IF NOT EXISTS bots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_telegram_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                about TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bots_owner
                ON bots(owner_telegram_id,is_active);
            CREATE TABLE IF NOT EXISTS bot_commands (
                bot_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(bot_id,command)
            );
            CREATE TABLE IF NOT EXISTS bot_chats (
                bot_id INTEGER NOT NULL,
                user_telegram_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_activity INTEGER NOT NULL,
                PRIMARY KEY(bot_id,user_telegram_id)
            );
            CREATE TABLE IF NOT EXISTS bot_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id INTEGER NOT NULL,
                user_telegram_id INTEGER NOT NULL,
                sender_type TEXT NOT NULL CHECK(sender_type IN ('user','bot')),
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bot_messages_chat
                ON bot_messages(bot_id,user_telegram_id,id);
            CREATE INDEX IF NOT EXISTS idx_bot_messages_updates
                ON bot_messages(bot_id,sender_type,id);
            """
        )
        for table_name in ("messages", "group_messages", "channel_messages"):
            cur = await db.execute(f"PRAGMA table_info({table_name})")
            columns = {str(row[1]) for row in await cur.fetchall()}
            if "media_id" not in columns:
                await db.execute(f"ALTER TABLE {table_name} ADD COLUMN media_id TEXT")
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


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _json_text(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


async def fetch_telegram_gifts(bot: Any) -> list[dict[str, Any]]:
    """Fetch the current catalog that the configured AuthBot may send."""
    token = str(getattr(bot, "token", "") or "").strip()
    if not token:
        raise RuntimeError("Telegram bot token is unavailable")
    url = f"https://api.telegram.org/bot{token}/getAvailableGifts"
    async with httpx.AsyncClient(timeout=httpx.Timeout(25.0)) as client:
        response = await client.post(url)
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict) or not payload.get("ok"):
        raise RuntimeError("Telegram getAvailableGifts returned an unsuccessful response")
    result = payload.get("result")
    gifts = result.get("gifts") if isinstance(result, dict) else None
    if not isinstance(gifts, list):
        raise RuntimeError("Telegram getAvailableGifts returned an invalid catalog")
    return [gift for gift in gifts if isinstance(gift, dict)]


async def store_telegram_gifts(
    database_path: Path,
    gifts: list[dict[str, Any]],
    synced_at: int | None = None,
) -> dict[str, Any]:
    """Persist a Telegram Bot API gift snapshot without changing WaysGram gifts."""
    now = int(synced_at or time.time())
    normalized: list[tuple[Any, ...]] = []
    for position, gift in enumerate(gifts):
        gift_id = str(gift.get("id") or "").strip()
        sticker = gift.get("sticker")
        if not gift_id or not isinstance(sticker, dict):
            continue
        sticker_file_id = str(sticker.get("file_id") or "").strip()
        if not sticker_file_id:
            continue
        emoji = str(sticker.get("emoji") or "")
        title = str(gift.get("title") or emoji or f"Telegram gift {gift_id}")
        normalized.append((
            gift_id,
            title[:160],
            sticker_file_id,
            str(sticker.get("file_unique_id") or ""),
            str(sticker.get("type") or "regular"),
            emoji[:32],
            str(sticker.get("set_name") or ""),
            _optional_int(sticker.get("width")),
            _optional_int(sticker.get("height")),
            int(bool(sticker.get("is_animated"))),
            int(bool(sticker.get("is_video"))),
            str(sticker.get("mime_type") or ""),
            max(0, _optional_int(gift.get("star_count")) or 0),
            _optional_int(gift.get("upgrade_star_count")),
            int(bool(gift.get("is_premium"))),
            int(bool(gift.get("has_colors"))),
            _optional_int(gift.get("total_count")),
            _optional_int(gift.get("remaining_count")),
            _optional_int(gift.get("personal_total_count")),
            _optional_int(gift.get("personal_remaining_count")),
            _optional_int(gift.get("unique_gift_variant_count")),
            _json_text(gift.get("background")),
            _json_text(gift.get("publisher_chat")),
            json.dumps(gift, ensure_ascii=False, separators=(",", ":")),
            position,
            now,
        ))
    if gifts and not normalized:
        raise ValueError("Telegram returned gifts without usable identifiers or sticker files")

    async with aiosqlite.connect(database_path) as db:
        await db.execute("BEGIN IMMEDIATE")
        for row in normalized:
            await db.execute(
                """INSERT INTO telegram_gift_catalog (
                       gift_id,title,sticker_file_id,sticker_file_unique_id,sticker_type,
                       sticker_emoji,sticker_set_name,sticker_width,sticker_height,
                       sticker_is_animated,sticker_is_video,sticker_mime_type,star_count,
                       upgrade_star_count,is_premium,has_colors,total_count,remaining_count,
                       personal_total_count,personal_remaining_count,unique_gift_variant_count,
                       background_json,publisher_chat_json,source_payload,position,synced_at,
                       is_available
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
                   ON CONFLICT(gift_id) DO UPDATE SET
                       title=excluded.title,
                       sticker_file_id=excluded.sticker_file_id,
                       sticker_file_unique_id=excluded.sticker_file_unique_id,
                       sticker_type=excluded.sticker_type,
                       sticker_emoji=excluded.sticker_emoji,
                       sticker_set_name=excluded.sticker_set_name,
                       sticker_width=excluded.sticker_width,
                       sticker_height=excluded.sticker_height,
                       sticker_is_animated=excluded.sticker_is_animated,
                       sticker_is_video=excluded.sticker_is_video,
                       sticker_mime_type=excluded.sticker_mime_type,
                       star_count=excluded.star_count,
                       upgrade_star_count=excluded.upgrade_star_count,
                       is_premium=excluded.is_premium,
                       has_colors=excluded.has_colors,
                       total_count=excluded.total_count,
                       remaining_count=excluded.remaining_count,
                       personal_total_count=excluded.personal_total_count,
                       personal_remaining_count=excluded.personal_remaining_count,
                       unique_gift_variant_count=excluded.unique_gift_variant_count,
                       background_json=excluded.background_json,
                       publisher_chat_json=excluded.publisher_chat_json,
                       source_payload=excluded.source_payload,
                       position=excluded.position,
                       synced_at=excluded.synced_at,
                       is_available=1""",
                row,
            )
        active_ids = [row[0] for row in normalized]
        if active_ids:
            placeholders = ",".join("?" for _ in active_ids)
            await db.execute(
                f"UPDATE telegram_gift_catalog SET is_available=0 WHERE gift_id NOT IN ({placeholders})",
                active_ids,
            )
        else:
            await db.execute("UPDATE telegram_gift_catalog SET is_available=0")
        await db.execute(
            """INSERT INTO telegram_gift_sync_state(id,last_synced_at,gift_count,source)
               VALUES(1,?,?,'telegram_bot_api')
               ON CONFLICT(id) DO UPDATE SET
                   last_synced_at=excluded.last_synced_at,
                   gift_count=excluded.gift_count,
                   source=excluded.source""",
            (now, len(normalized)),
        )
        await db.commit()
    return {
        "source": "telegram_bot_api",
        "synced_at": now,
        "gift_count": len(normalized),
    }


async def sync_telegram_gifts(database_path: Path, bot: Any) -> dict[str, Any]:
    gifts = await fetch_telegram_gifts(bot)
    return await store_telegram_gifts(database_path, gifts)


async def fetch_telegram_sticker(bot: Any, file_id: str, preferred_mime: str = "") -> tuple[bytes, str]:
    """Download a sticker without ever exposing the AuthBot token to the client."""
    token = str(getattr(bot, "token", "") or "").strip()
    if not token:
        raise RuntimeError("Telegram bot token is unavailable")
    base = f"https://api.telegram.org/bot{token}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        meta_response = await client.post(f"{base}/getFile", json={"file_id": file_id})
        meta_response.raise_for_status()
        meta_payload = meta_response.json()
        if not isinstance(meta_payload, dict) or not meta_payload.get("ok"):
            raise RuntimeError("Telegram getFile returned an unsuccessful response")
        result = meta_payload.get("result")
        file_path = str(result.get("file_path") or "") if isinstance(result, dict) else ""
        file_size = _optional_int(result.get("file_size")) if isinstance(result, dict) else None
        if not file_path:
            raise RuntimeError("Telegram getFile returned no file path")
        if file_size is not None and file_size > 20 * 1024 * 1024:
            raise ValueError("Telegram sticker file exceeds the supported size")
        file_url = f"https://api.telegram.org/file/bot{token}/{quote(file_path, safe='/')}"
        file_response = await client.get(file_url)
        file_response.raise_for_status()
        content = file_response.content
        if len(content) > 20 * 1024 * 1024:
            raise ValueError("Telegram sticker file exceeds the supported size")
    media_type = preferred_mime or mimetypes.guess_type(file_path)[0] or "application/octet-stream"
    return content, media_type


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
    mtproto_gift_provider: Callable[[], Any] | None = None,
) -> APIRouter:
    router = APIRouter()
    db_path = database_path if callable(database_path) else lambda: database_path
    telegram_gift_sync_lock = asyncio.Lock()

    async def ensure_telegram_gifts_fresh() -> dict[str, Any]:
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT last_synced_at,gift_count,source FROM telegram_gift_sync_state WHERE id=1"
            )
            state = await cur.fetchone()
        if state and now - int(state["last_synced_at"]) < 60:
            return dict(state)

        async with telegram_gift_sync_lock:
            now = int(time.time())
            async with aiosqlite.connect(db_path()) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute(
                    "SELECT last_synced_at,gift_count,source FROM telegram_gift_sync_state WHERE id=1"
                )
                state = await cur.fetchone()
            if state and now - int(state["last_synced_at"]) < 60:
                return dict(state)
            mtproto = mtproto_gift_provider() if mtproto_gift_provider else None
            if mtproto is not None:
                try:
                    return await mtproto.sync(db_path())
                except Exception:
                    # Bot API remains a safe read-only fallback if MTProto is temporarily unavailable.
                    pass

            bot = bot_provider()
            if bot is None:
                if state:
                    return dict(state)
                raise HTTPException(status_code=503, detail="Telegram gift catalog is not available yet")
            try:
                gifts = await fetch_telegram_gifts(bot)
                synced = await store_telegram_gifts(db_path(), gifts, now)
                return {
                    "last_synced_at": int(synced["synced_at"]),
                    "gift_count": int(synced["gift_count"]),
                    "source": str(synced["source"]),
                }
            except Exception as exc:
                if state:
                    return dict(state)
                raise HTTPException(
                    status_code=503,
                    detail="Не удалось загрузить каталог подарков Telegram. Проверьте BOT_TOKEN и настройки MTProto.",
                ) from exc

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

    async def require_owned_media(db: Any, media_id: str | None, owner_id: int) -> str | None:
        value = str(media_id or "").strip()
        if not value:
            return None
        if not re.fullmatch(r"[a-f0-9]{32}", value):
            raise HTTPException(status_code=400, detail="Некорректный идентификатор изображения")
        cur = await db.execute(
            "SELECT 1 FROM media_assets WHERE id=? AND owner_telegram_id=?",
            (value, owner_id),
        )
        if await cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="Изображение не найдено или принадлежит другому аккаунту")
        return value

    def media_storage_dir() -> Path:
        directory = Path(db_path()).parent / "waysgram_media"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    @router.post("/api/media/images", status_code=201)
    async def upload_image(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        declared_type = str(request.headers.get("content-type", "")).split(";", 1)[0].strip().lower()
        if not declared_type.startswith("image/") and declared_type != "application/octet-stream":
            raise HTTPException(status_code=415, detail="Загрузите файл изображения JPEG, PNG или WebP")
        declared_length = request.headers.get("content-length")
        if declared_length:
            try:
                if int(declared_length) > MAX_IMAGE_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Размер изображения превышает 10 МБ")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Некорректный Content-Length") from exc

        incoming = bytearray()
        async for chunk in request.stream():
            if len(incoming) + len(chunk) > MAX_IMAGE_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Размер изображения превышает 10 МБ")
            incoming.extend(chunk)
        if not incoming:
            raise HTTPException(status_code=400, detail="Файл изображения пуст")

        try:
            normalized, mime_type, extension = await asyncio.to_thread(
                _normalize_uploaded_image, bytes(incoming)
            )
        except ValueError as exc:
            raise HTTPException(status_code=415, detail=str(exc)) from exc

        now = int(time.time())
        media_id = secrets.token_hex(16)
        storage_name = media_id + extension
        file_path = media_storage_dir() / storage_name
        try:
            async with aiosqlite.connect(db_path()) as db:
                db.row_factory = aiosqlite.Row
                await db.execute("BEGIN IMMEDIATE")
                cur = await db.execute(
                    """SELECT COALESCE(SUM(size_bytes),0) AS total_bytes,
                              SUM(CASE WHEN created_at>? THEN 1 ELSE 0 END) AS recent_uploads
                       FROM media_assets WHERE owner_telegram_id=?""",
                    (now - 3600, uid),
                )
                quota = await cur.fetchone()
                if int(quota["total_bytes"] or 0) + len(normalized) > MAX_USER_MEDIA_BYTES:
                    await db.rollback()
                    raise HTTPException(status_code=413, detail="Достигнут лимит хранилища изображений аккаунта")
                if int(quota["recent_uploads"] or 0) >= MAX_USER_IMAGE_UPLOADS_PER_HOUR:
                    await db.rollback()
                    raise HTTPException(status_code=429, detail="Слишком много загрузок. Повторите позже.")

                await asyncio.to_thread(file_path.write_bytes, normalized)
                await db.execute(
                    """INSERT INTO media_assets
                       (id,owner_telegram_id,storage_name,mime_type,size_bytes,created_at)
                       VALUES(?,?,?,?,?,?)""",
                    (media_id, uid, storage_name, mime_type, len(normalized), now),
                )
                await db.commit()
        except Exception:
            await asyncio.to_thread(file_path.unlink, missing_ok=True)
            raise
        return {
            "id": media_id,
            "mime_type": mime_type,
            "size_bytes": len(normalized),
            "url": f"/api/media/{media_id}",
        }

    @router.get("/api/media/{media_id}")
    async def download_media(
        media_id: str,
        authorization: str | None = Header(default=None),
    ) -> Response:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if not re.fullmatch(r"[a-f0-9]{32}", media_id):
            raise HTTPException(status_code=404, detail="Изображение не найдено")

        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM media_assets WHERE id=?",
                (media_id,),
            )
            media = await cur.fetchone()
            if media is None:
                raise HTTPException(status_code=404, detail="Изображение не найдено")

            allowed = int(media["owner_telegram_id"]) == uid
            if not allowed:
                cur = await db.execute(
                    """SELECT 1 FROM messages
                       WHERE media_id=? AND
                       (sender_telegram_id=? OR recipient_telegram_id=?) LIMIT 1""",
                    (media_id, uid, uid),
                )
                allowed = await cur.fetchone() is not None
            if not allowed:
                cur = await db.execute(
                    """SELECT 1 FROM group_messages gm
                       JOIN group_members member ON member.group_id=gm.group_id
                       WHERE gm.media_id=? AND member.telegram_id=? LIMIT 1""",
                    (media_id, uid),
                )
                allowed = await cur.fetchone() is not None
            if not allowed:
                cur = await db.execute(
                    """SELECT 1 FROM channel_messages
                       WHERE media_id=? LIMIT 1""",
                    (media_id,),
                )
                allowed = await cur.fetchone() is not None
            if not allowed:
                raise HTTPException(status_code=404, detail="Изображение не найдено")

        file_path = media_storage_dir() / str(media["storage_name"])
        try:
            content = await asyncio.to_thread(file_path.read_bytes)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Файл изображения отсутствует на сервере") from exc
        return Response(
            content=content,
            media_type=str(media["mime_type"]),
            headers={
                "Cache-Control": "private, max-age=3600",
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": "inline",
            },
        )

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

    async def require_group_member(
        db: Any, group_id: int, telegram_id: int
    ) -> dict[str, Any]:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT gm.role,g.title,g.username,g.owner_telegram_id
               FROM group_members gm JOIN chat_groups g ON g.id=gm.group_id
               WHERE gm.group_id=? AND gm.telegram_id=?""",
            (group_id, telegram_id),
        )
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=403, detail="Вы не состоите в этой группе")
        return dict(row)

    async def current_bot(authorization: str | None) -> dict[str, Any]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Требуется токен бота")
        token = authorization[7:].strip()
        if not token:
            raise HTTPException(status_code=401, detail="Требуется токен бота")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT * FROM bots WHERE token_hash=? AND is_active=1",
                (_token_hash(token),),
            )
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Токен бота недействителен или отозван")
        return dict(row)

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
                "gift_auctions", "auction_bids", "telegram_gift_catalog",
                "telegram_gift_sticker_proxy", "groups", "group_members", "group_messages",
                "image_uploads", "message_media", "private_media_downloads",
                "long_poll_messages",
                "botfather", "bot_commands", "bot_runtime", "stars", "grams",
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

    async def settle_due_auctions(db: Any, now: int) -> int:
        cur = await db.execute(
            """SELECT id,gift_id,gift_name,current_bidder_id
               FROM gift_auctions
               WHERE status='active' AND ends_at<=?
               ORDER BY ends_at,id""",
            (now,),
        )
        due = await cur.fetchall()
        settled = 0
        for auction in due:
            auction_id = int(auction["id"])
            bidder_id = auction["current_bidder_id"]
            if bidder_id is not None:
                serial = "WG-" + secrets.token_hex(6).upper()
                await db.execute(
                    """INSERT INTO user_gifts
                       (serial_number,gift_id,gift_name,owner_telegram_id,acquired_at)
                       VALUES(?,?,?,?,?)""",
                    (
                        serial,
                        int(auction["gift_id"]),
                        str(auction["gift_name"]),
                        int(bidder_id),
                        now,
                    ),
                )
                await db.execute(
                    """INSERT INTO gift_transactions
                       (event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                       VALUES('auction_win',?,?,NULL,?,?)""",
                    (serial, str(auction["gift_name"]), int(bidder_id), now),
                )
            else:
                # No bids: return the reserved system gift to the market supply.
                await db.execute(
                    "UPDATE gift_catalog SET supply=supply+1 WHERE id=?",
                    (int(auction["gift_id"]),),
                )
            await db.execute(
                "UPDATE gift_auctions SET status='ended',settled_at=? WHERE id=? AND status='active'",
                (now, auction_id),
            )
            settled += 1
        return settled

    @router.get("/api/auctions")
    async def list_auctions(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            settled = await settle_due_auctions(db, now)
            cur = await db.execute(
                """SELECT id,gift_id,gift_name,starting_bid,current_bid,status,
                          starts_at,ends_at,settled_at,
                          (SELECT COUNT(*) FROM auction_bids b WHERE b.auction_id=a.id) AS bid_count
                   FROM gift_auctions a
                   ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'ended' THEN 1 ELSE 2 END,
                            ends_at DESC,id DESC
                   LIMIT 100"""
            )
            rows = await cur.fetchall()
            await db.commit()
        return {"auctions": [dict(row) for row in rows], "settled_count": settled}

    @router.post("/api/auctions/{auction_id}/bid", status_code=201)
    async def place_auction_bid(
        auction_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            amount = int(payload.get("amount", 0))
        except (TypeError, ValueError):
            amount = 0
        if not 1 <= amount <= 1_000_000_000:
            raise HTTPException(status_code=400, detail="Ставка должна быть от 1 до 1000000000 Stars")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            await settle_due_auctions(db, now)
            cur = await db.execute(
                """SELECT id,gift_name,starting_bid,current_bid,current_bidder_id,
                          status,starts_at,ends_at
                   FROM gift_auctions WHERE id=?""",
                (auction_id,),
            )
            auction = await cur.fetchone()
            if (
                not auction
                or str(auction["status"]) != "active"
                or int(auction["starts_at"]) > now
                or int(auction["ends_at"]) <= now
            ):
                await db.rollback()
                raise HTTPException(status_code=409, detail="Аукцион уже завершён или недоступен")
            previous_bid = int(auction["current_bid"])
            previous_bidder = auction["current_bidder_id"]
            minimum = max(int(auction["starting_bid"]), previous_bid + 1)
            if amount < minimum:
                await db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail=f"Минимальная следующая ставка: {minimum} Stars",
                )
            cur = await db.execute(
                "SELECT stars,is_banned FROM accounts WHERE telegram_id=?",
                (uid,),
            )
            bidder = await cur.fetchone()
            if not bidder or bidder["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Аккаунт недоступен")
            available = int(bidder["stars"])
            if previous_bidder is not None and int(previous_bidder) == uid:
                available += previous_bid
            if available < amount:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Stars для ставки")

            if previous_bidder is not None and previous_bid > 0:
                cur = await db.execute(
                    "SELECT stars FROM accounts WHERE telegram_id=?",
                    (int(previous_bidder),),
                )
                previous_account = await cur.fetchone()
                if previous_account:
                    refunded_balance = int(previous_account["stars"]) + previous_bid
                    await db.execute(
                        "UPDATE accounts SET stars=?,updated_at=? WHERE telegram_id=?",
                        (refunded_balance, now, int(previous_bidder)),
                    )
                    await db.execute(
                        """INSERT INTO economy_transactions
                           (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                           VALUES(?,'stars',?,?,?,NULL,?)""",
                        (
                            int(previous_bidder),
                            previous_bid,
                            refunded_balance,
                            f"auction_outbid_refund:{auction_id}",
                            now,
                        ),
                    )

            cur = await db.execute(
                "SELECT stars FROM accounts WHERE telegram_id=?",
                (uid,),
            )
            current_account = await cur.fetchone()
            new_balance = int(current_account["stars"]) - amount
            if new_balance < 0:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Stars для ставки")
            await db.execute(
                "UPDATE accounts SET stars=?,updated_at=? WHERE telegram_id=?",
                (new_balance, now, uid),
            )
            await db.execute(
                """INSERT INTO economy_transactions
                   (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                   VALUES(?,'stars',?,?,?,NULL,?)""",
                (uid, -amount, new_balance, f"auction_bid:{auction_id}", now),
            )
            await db.execute(
                """INSERT INTO auction_bids(auction_id,bidder_telegram_id,amount,created_at)
                   VALUES(?,?,?,?)""",
                (auction_id, uid, amount, now),
            )
            await db.execute(
                """UPDATE gift_auctions
                   SET current_bid=?,current_bidder_id=?
                   WHERE id=? AND status='active'""",
                (amount, uid, auction_id),
            )
            await db.commit()
        return {
            "status": "accepted",
            "auction_id": auction_id,
            "gift_name": str(auction["gift_name"]),
            "bid": amount,
            "currency": "stars",
            "stars_balance": new_balance,
            "ends_at": int(auction["ends_at"]),
        }

    @router.get("/api/telegram/gifts")
    async def telegram_gift_catalog(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        state = await ensure_telegram_gifts_fresh()
        source = str(state.get("source") or "telegram_bot_api")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            if source == "telegram_mtproto":
                cur = await db.execute(
                    """SELECT gift_id,title,sticker_emoji,sticker_set_name,sticker_width,
                              sticker_height,sticker_is_animated,sticker_is_video,
                              sticker_mime_type,stars,limited,sold_out,birthday,require_premium,
                              limited_per_user,peer_color_available,auction,availability_remains,
                              availability_total,availability_resale,convert_stars,first_sale_date,
                              last_sale_date,upgrade_stars,resell_min_stars,released_by_json,
                              per_user_total,per_user_remains,locked_until_date,auction_slug,
                              gifts_per_round,auction_start_date,upgrade_variants,background_json,
                              sticker_document_id,sticker_dc_id,sticker_size,position,synced_at
                       FROM telegram_mtproto_gift_catalog
                       WHERE is_available=1
                       ORDER BY position ASC"""
                )
                rows = await cur.fetchall()
            else:
                cur = await db.execute(
                    """SELECT gift_id,title,sticker_type,sticker_emoji,sticker_set_name,
                              sticker_width,sticker_height,sticker_is_animated,sticker_is_video,
                              sticker_mime_type,star_count,upgrade_star_count,is_premium,has_colors,
                              total_count,remaining_count,personal_total_count,personal_remaining_count,
                              unique_gift_variant_count,background_json,publisher_chat_json,
                              position,synced_at
                       FROM telegram_gift_catalog
                       WHERE is_available=1
                       ORDER BY position ASC"""
                )
                rows = await cur.fetchall()

        gifts: list[dict[str, Any]] = []
        for row in rows:
            if source == "telegram_mtproto":
                gift_id = str(row["gift_id"])
                sticker_url = f"/api/telegram/gifts/{quote(gift_id, safe='')}/sticker"
                released_by = json.loads(row["released_by_json"]) if row["released_by_json"] else None
                background = json.loads(row["background_json"]) if row["background_json"] else None
                gifts.append({
                    "id": gift_id,
                    "source": "telegram",
                    "title": str(row["title"]),
                    "emoji": str(row["sticker_emoji"] or ""),
                    "star_count": int(row["stars"]),
                    "currency": "telegram_stars",
                    "upgrade_star_count": row["upgrade_stars"],
                    "is_premium": bool(row["require_premium"]),
                    "has_colors": bool(row["peer_color_available"]),
                    "is_limited": bool(row["limited"]),
                    "sold_out": bool(row["sold_out"]),
                    "birthday": bool(row["birthday"]),
                    "require_premium": bool(row["require_premium"]),
                    "limited_per_user": bool(row["limited_per_user"]),
                    "auction": bool(row["auction"]),
                    "availability_resale": row["availability_resale"],
                    "convert_stars": row["convert_stars"],
                    "first_sale_date": row["first_sale_date"],
                    "last_sale_date": row["last_sale_date"],
                    "resell_min_stars": row["resell_min_stars"],
                    "released_by": released_by,
                    "per_user_total": row["per_user_total"],
                    "per_user_remains": row["per_user_remains"],
                    "locked_until_date": row["locked_until_date"],
                    "auction_slug": str(row["auction_slug"] or ""),
                    "gifts_per_round": row["gifts_per_round"],
                    "auction_start_date": row["auction_start_date"],
                    "upgrade_variants": row["upgrade_variants"],
                    "total_count": row["availability_total"],
                    "remaining_count": row["availability_remains"],
                    "personal_total_count": row["per_user_total"],
                    "personal_remaining_count": row["per_user_remains"],
                    "background": background,
                    "sticker": {
                        "type": "video" if bool(row["sticker_is_video"]) else (
                            "animated" if bool(row["sticker_is_animated"]) else "regular"
                        ),
                        "set_name": str(row["sticker_set_name"] or ""),
                        "width": row["sticker_width"],
                        "height": row["sticker_height"],
                        "is_animated": bool(row["sticker_is_animated"]),
                        "is_video": bool(row["sticker_is_video"]),
                        "mime_type": str(row["sticker_mime_type"] or ""),
                        "url": sticker_url,
                    },
                    "synced_at": int(row["synced_at"]),
                })
            else:
                gift_id = str(row["gift_id"])
                gifts.append({
                    "id": gift_id,
                    "source": "telegram",
                    "title": str(row["title"]),
                    "emoji": str(row["sticker_emoji"] or ""),
                    "star_count": int(row["star_count"]),
                    "currency": "telegram_stars",
                    "upgrade_star_count": row["upgrade_star_count"],
                    "is_premium": bool(row["is_premium"]),
                    "has_colors": bool(row["has_colors"]),
                    "is_limited": row["total_count"] is not None,
                    "total_count": row["total_count"],
                    "remaining_count": row["remaining_count"],
                    "personal_total_count": row["personal_total_count"],
                    "personal_remaining_count": row["personal_remaining_count"],
                    "unique_gift_variant_count": row["unique_gift_variant_count"],
                    "background": json.loads(row["background_json"]) if row["background_json"] else None,
                    "publisher_chat": json.loads(row["publisher_chat_json"]) if row["publisher_chat_json"] else None,
                    "sticker": {
                        "type": str(row["sticker_type"]),
                        "set_name": str(row["sticker_set_name"] or ""),
                        "width": row["sticker_width"],
                        "height": row["sticker_height"],
                        "is_animated": bool(row["sticker_is_animated"]),
                        "is_video": bool(row["sticker_is_video"]),
                        "mime_type": str(row["sticker_mime_type"] or ""),
                        "url": f"/api/telegram/gifts/{quote(gift_id, safe='')}/sticker",
                    },
                    "synced_at": int(row["synced_at"]),
                })

        synced_at = int(state["last_synced_at"])
        return {
            "source": source,
            "scope": "telegram_full_mtproto_catalog" if source == "telegram_mtproto" else "gifts_available_to_authbot",
            "currency": "telegram_stars",
            "synced_at": synced_at,
            "stale": int(time.time()) - synced_at >= 60,
            "count": len(gifts),
            "gifts": gifts,
        }

    @router.get("/api/telegram/gifts/{gift_id}/sticker")
    async def telegram_gift_sticker(
        gift_id: str,
        authorization: str | None = Header(default=None),
    ) -> Response:
        await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT source FROM telegram_gift_sync_state WHERE id=1"
            )
            state = await cur.fetchone()
        source = str(state["source"]) if state else "telegram_bot_api"

        if source == "telegram_mtproto":
            provider = mtproto_gift_provider() if mtproto_gift_provider else None
            if provider is None:
                raise HTTPException(status_code=503, detail="Telegram MTProto is not connected")
            try:
                content, media_type = await provider.download_sticker(gift_id)
            except LookupError as exc:
                raise HTTPException(status_code=404, detail="Подарок Telegram не найден в MTProto-каталоге") from exc
            except Exception as exc:
                raise HTTPException(status_code=502, detail="Не удалось загрузить стикер Telegram через MTProto") from exc
        else:
            async with aiosqlite.connect(db_path()) as db:
                cur = await db.execute(
                    """SELECT sticker_file_id,sticker_mime_type
                       FROM telegram_gift_catalog WHERE gift_id=? AND is_available=1""",
                    (gift_id,),
                )
                row = await cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Подарок Telegram не найден")
            bot = bot_provider()
            if bot is None:
                raise HTTPException(status_code=503, detail="Telegram Bot API недоступен")
            try:
                content, media_type = await fetch_telegram_sticker(
                    bot,
                    str(row[0]),
                    str(row[1] or ""),
                )
            except Exception as exc:
                raise HTTPException(status_code=502, detail="Не удалось загрузить стикер Telegram") from exc
        return Response(
            content=content,
            media_type=media_type,
            headers={"Cache-Control": "private, max-age=3600"},
        )

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

    @router.get("/api/channels/{channel_id}/admins")
    async def list_channel_admins(
        channel_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        channel = await channel_row(channel_id)
        uid = int(user["telegram_id"])
        owner_id = int(channel["owner_telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ca.telegram_id,a.username,a.display_name,ca.created_at
                   FROM channel_admins ca
                   LEFT JOIN accounts a ON a.telegram_id=ca.telegram_id
                   WHERE ca.channel_id=?
                   ORDER BY ca.created_at,ca.telegram_id""",
                (channel_id,),
            )
            rows = await cur.fetchall()
        role = "owner" if uid == owner_id else (
            "admin" if any(int(row["telegram_id"]) == uid for row in rows) else "member"
        )
        return {
            "channel_id": channel_id,
            "owner_telegram_id": owner_id,
            "my_role": role,
            "admins": [dict(row) for row in rows],
        }

    @router.get("/api/channels/{channel_id}/messages")
    async def list_channel_messages(
        channel_id: int,
        after_id: int = Query(default=0, ge=0),
        wait_seconds: int = Query(default=0, ge=0, le=20),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        deadline = time.monotonic() + (wait_seconds if after_id else 0)
        rows = []
        while True:
            await channel_row(channel_id)
            async with aiosqlite.connect(db_path()) as db:
                db.row_factory = aiosqlite.Row
                if after_id:
                    cur = await db.execute(
                        """SELECT id,channel_id,author_telegram_id AS author_id,body,media_id,created_at
                           FROM channel_messages WHERE channel_id=? AND id>?
                           ORDER BY id ASC LIMIT 100""",
                        (channel_id, after_id),
                    )
                else:
                    cur = await db.execute(
                        """SELECT id,channel_id,author_telegram_id AS author_id,body,media_id,created_at
                           FROM channel_messages WHERE channel_id=?
                           ORDER BY id DESC LIMIT 100""",
                        (channel_id,),
                    )
                rows = await cur.fetchall()
            if rows or time.monotonic() >= deadline:
                break
            await asyncio.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
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
        media_id = str(payload.get("media_id") or "").strip() or None
        body_value = str(payload.get("body") or "")
        body = _message_body(body_value if body_value.strip() else ("Изображение" if media_id else body_value))
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
            media_id = await require_owned_media(db, media_id, uid)
            cur = await db.execute(
                "SELECT COUNT(*) FROM channel_messages WHERE author_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= CHANNEL_POSTS_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит публикаций")
            cur = await db.execute(
                """INSERT INTO channel_messages
                   (channel_id,author_telegram_id,body,media_id,created_at)
                   VALUES(?,?,?,?,?)""",
                (channel_id, uid, body, media_id, now),
            )
            message_id = int(cur.lastrowid)
            result = {"id": message_id, "status": "published", "channel_id": channel_id, "author_id": uid, "body": body, "media_id": media_id, "created_at": now}
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
        wait_seconds: int = Query(default=0, ge=0, le=20),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if after_id and before_id:
            raise HTTPException(status_code=400, detail="Используйте только один курсор: after_id или before_id")
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (peer,))
            if not await cur.fetchone():
                raise HTTPException(status_code=404, detail="Собеседник не найден")

        params: tuple[Any, ...] = (uid, peer, peer, uid)
        base = """
            SELECT id,sender_telegram_id AS sender_id,
                   recipient_telegram_id AS recipient_id,body,media_id,created_at
            FROM messages WHERE
            ((sender_telegram_id=? AND recipient_telegram_id=?) OR
             (sender_telegram_id=? AND recipient_telegram_id=?))
        """
        deadline = time.monotonic() + (wait_seconds if after_id and not before_id else 0)
        rows = []
        while True:
            async with aiosqlite.connect(db_path()) as db:
                db.row_factory = aiosqlite.Row
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
            if rows or time.monotonic() >= deadline:
                break
            await asyncio.sleep(min(1.0, max(0.05, deadline - time.monotonic())))

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
        media_id = str(payload.get("media_id") or "").strip() or None
        body_value = str(payload.get("body") or "")
        body = _message_body(body_value if body_value.strip() else ("Изображение" if media_id else body_value))
        now = int(time.time())
        descriptor = idempotency_descriptor("/api/messages", payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, "/api/messages", descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            media_id = await require_owned_media(db, media_id, uid)
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
                """INSERT INTO messages
                   (sender_telegram_id,recipient_telegram_id,body,media_id,created_at)
                   VALUES(?,?,?,?,?)""",
                (uid, recipient_id, body, media_id, now),
            )
            message_id = int(cur.lastrowid)
            result = {
                "id": message_id,
                "status": "sent",
                "sender_id": uid,
                "recipient_id": recipient_id,
                "body": body,
                "media_id": media_id,
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

    # Group chats: membership and role checks are enforced on every read/write.
    @router.get("/api/groups")
    async def list_groups(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT g.id,g.username,g.title,g.description,g.owner_telegram_id,
                          gm.role,gm.joined_at,
                          (SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id) AS member_count,
                          (SELECT COUNT(*) FROM group_messages x WHERE x.group_id=g.id) AS message_count
                   FROM group_members gm
                   JOIN chat_groups g ON g.id=gm.group_id
                   WHERE gm.telegram_id=?
                   ORDER BY g.id DESC LIMIT 100""",
                (uid,),
            )
            rows = await cur.fetchall()
        return {"groups": [dict(row) for row in rows]}

    @router.post("/api/groups", status_code=201)
    async def create_group(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        title = payload.get("title")
        username = str(payload.get("username") or "").strip().lstrip("@").lower()
        description = str(payload.get("description") or "").strip()
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 80:
            raise HTTPException(status_code=400, detail="Название группы должно содержать 1–80 символов")
        if len(description) > 512:
            raise HTTPException(status_code=400, detail="Описание группы слишком длинное")
        if username and not re.fullmatch(r"[a-z][a-z0-9_]{3,31}", username):
            raise HTTPException(status_code=400, detail="Username группы должен содержать 4–32 символа")
        now = int(time.time())
        uid = int(user["telegram_id"])
        try:
            async with aiosqlite.connect(db_path()) as db:
                await db.execute("BEGIN IMMEDIATE")
                cur = await db.execute(
                    """INSERT INTO chat_groups(username,title,description,owner_telegram_id,created_at)
                       VALUES(?,?,?,?,?)""",
                    (username or None, title.strip(), description, uid, now),
                )
                group_id = int(cur.lastrowid)
                await db.execute(
                    "INSERT INTO group_members(group_id,telegram_id,role,joined_at) VALUES(?,?,'owner',?)",
                    (group_id, uid, now),
                )
                await db.commit()
        except aiosqlite.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username группы уже занят") from exc
        return {
            "id": group_id,
            "username": username,
            "title": title.strip(),
            "description": description,
            "owner_telegram_id": uid,
            "role": "owner",
            "created_at": now,
        }

    @router.get("/api/groups/{group_id}")
    async def get_group(
        group_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            membership = await require_group_member(db, group_id, uid)
            cur = await db.execute(
                """SELECT g.id,g.username,g.title,g.description,g.owner_telegram_id,g.created_at,
                          (SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id) AS member_count
                   FROM chat_groups g WHERE g.id=?""",
                (group_id,),
            )
            group = await cur.fetchone()
            cur = await db.execute(
                """SELECT gm.telegram_id,gm.role,gm.joined_at,a.username,a.display_name
                   FROM group_members gm LEFT JOIN accounts a ON a.telegram_id=gm.telegram_id
                   WHERE gm.group_id=? ORDER BY
                   CASE gm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                   gm.joined_at LIMIT 200""",
                (group_id,),
            )
            members = await cur.fetchall()
        result = dict(group)
        result["my_role"] = membership["role"]
        result["my_telegram_id"] = uid
        result["members"] = [dict(row) for row in members]
        return result

    @router.post("/api/groups/{group_id}/members", status_code=201)
    async def add_group_member(
        group_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            membership = await require_group_member(db, group_id, uid)
            if membership["role"] not in ("owner", "admin"):
                raise HTTPException(status_code=403, detail="Добавлять участников могут администраторы группы")
            target_id = 0
            if payload.get("telegram_id") is not None:
                try:
                    target_id = int(payload.get("telegram_id"))
                except (TypeError, ValueError):
                    target_id = 0
            elif payload.get("username") is not None:
                username = str(payload.get("username")).strip().lstrip("@")
                cur = await db.execute(
                    "SELECT telegram_id FROM accounts WHERE username=? COLLATE NOCASE",
                    (username,),
                )
                target = await cur.fetchone()
                target_id = int(target["telegram_id"]) if target else 0
            if target_id <= 0:
                raise HTTPException(status_code=404, detail="Пользователь не найден")
            cur = await db.execute(
                "SELECT is_banned FROM accounts WHERE telegram_id=?",
                (target_id,),
            )
            target = await cur.fetchone()
            if not target or target["is_banned"]:
                raise HTTPException(status_code=404, detail="Пользователь не найден или заблокирован")
            now = int(time.time())
            cur = await db.execute(
                """INSERT OR IGNORE INTO group_members(group_id,telegram_id,role,joined_at)
                   VALUES(?,?,'member',?)""",
                (group_id, target_id, now),
            )
            await db.commit()
        return {
            "group_id": group_id,
            "telegram_id": target_id,
            "joined": cur.rowcount == 1,
        }

    @router.delete("/api/groups/{group_id}/members/{telegram_id}")
    async def remove_group_member(
        group_id: int,
        telegram_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            actor = await require_group_member(db, group_id, uid)
            target = await require_group_member(db, group_id, telegram_id)
            if telegram_id == uid:
                if target["role"] == "owner":
                    raise HTTPException(status_code=409, detail="Владелец не может покинуть группу без передачи владения")
            elif actor["role"] not in ("owner", "admin") or target["role"] == "owner":
                raise HTTPException(status_code=403, detail="Недостаточно прав для удаления участника")
            cur = await db.execute(
                "DELETE FROM group_members WHERE group_id=? AND telegram_id=?",
                (group_id, telegram_id),
            )
            await db.commit()
        return {"removed": cur.rowcount == 1, "group_id": group_id, "telegram_id": telegram_id}

    @router.post("/api/groups/{group_id}/admins", status_code=201)
    async def promote_group_admin(
        group_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            target_id = int(payload.get("telegram_id", 0))
        except (TypeError, ValueError):
            target_id = 0
        if target_id <= 0:
            raise HTTPException(status_code=400, detail="Некорректный Telegram ID")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            owner = await require_group_member(db, group_id, uid)
            if owner["role"] != "owner":
                raise HTTPException(status_code=403, detail="Назначать администраторов может только владелец")
            target = await require_group_member(db, group_id, target_id)
            if target["role"] == "owner":
                raise HTTPException(status_code=409, detail="Владелец уже обладает полными правами")
            await db.execute(
                "UPDATE group_members SET role='admin' WHERE group_id=? AND telegram_id=?",
                (group_id, target_id),
            )
            await db.commit()
        return {"group_id": group_id, "telegram_id": target_id, "role": "admin"}

    @router.delete("/api/groups/{group_id}/admins/{telegram_id}")
    async def demote_group_admin(
        group_id: int,
        telegram_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            owner = await require_group_member(db, group_id, uid)
            if owner["role"] != "owner":
                raise HTTPException(status_code=403, detail="Изменять права может только владелец")
            cur = await db.execute(
                "UPDATE group_members SET role='member' WHERE group_id=? AND telegram_id=? AND role='admin'",
                (group_id, telegram_id),
            )
            await db.commit()
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Администратор группы не найден")
        return {"group_id": group_id, "telegram_id": telegram_id, "role": "member"}

    @router.get("/api/groups/{group_id}/messages")
    async def list_group_messages(
        group_id: int,
        after_id: int = Query(default=0, ge=0),
        wait_seconds: int = Query(default=0, ge=0, le=20),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        deadline = time.monotonic() + (wait_seconds if after_id else 0)
        rows = []
        while True:
            async with aiosqlite.connect(db_path()) as db:
                await require_group_member(db, group_id, uid)
                db.row_factory = aiosqlite.Row
                if after_id:
                    cur = await db.execute(
                        """SELECT id,group_id,sender_telegram_id AS sender_id,body,media_id,created_at
                           FROM group_messages WHERE group_id=? AND id>? ORDER BY id ASC LIMIT 100""",
                        (group_id, after_id),
                    )
                else:
                    cur = await db.execute(
                        """SELECT id,group_id,sender_telegram_id AS sender_id,body,media_id,created_at
                           FROM group_messages WHERE group_id=? ORDER BY id DESC LIMIT 100""",
                        (group_id,),
                    )
                rows = await cur.fetchall()
            if rows or time.monotonic() >= deadline:
                break
            await asyncio.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
        items = [dict(row) for row in rows]
        if not after_id:
            items.reverse()
        return {"messages": items, "next_after_id": items[-1]["id"] if items else 0}

    @router.post("/api/groups/{group_id}/messages", status_code=201)
    async def send_group_message(
        group_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        media_id = str(payload.get("media_id") or "").strip() or None
        body_value = str(payload.get("body") or "")
        body = _message_body(body_value if body_value.strip() else ("Изображение" if media_id else body_value))
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            await require_group_member(db, group_id, uid)
            media_id = await require_owned_media(db, media_id, uid)
            cur = await db.execute(
                "SELECT COUNT(*) FROM group_messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит отправки сообщений")
            cur = await db.execute(
                """INSERT INTO group_messages
                   (group_id,sender_telegram_id,body,media_id,created_at)
                   VALUES(?,?,?,?,?)""",
                (group_id, uid, body, media_id, now),
            )
            message_id = int(cur.lastrowid)
            await db.commit()
        return {
            "id": message_id,
            "group_id": group_id,
            "sender_id": uid,
            "body": body,
            "media_id": media_id,
            "created_at": now,
        }

    # Internal BotFather registry and chat API for bots created inside WaysGram.
    @router.get("/api/bots")
    async def list_owned_bots(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,name,username,about,description,token_prefix,is_active,created_at,updated_at
                   FROM bots WHERE owner_telegram_id=? ORDER BY id DESC LIMIT 100""",
                (int(user["telegram_id"]),),
            )
            rows = await cur.fetchall()
        return {"bots": [dict(row) for row in rows]}

    @router.post("/api/bots", status_code=201)
    async def create_owned_bot(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        name = payload.get("name")
        username = str(payload.get("username") or "").strip().lstrip("@").lower()
        about = str(payload.get("about") or "").strip()
        description = str(payload.get("description") or "").strip()
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
            raise HTTPException(status_code=400, detail="Имя бота должно содержать 1–64 символа")
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,28}_bot", username):
            raise HTTPException(status_code=400, detail="Username бота должен иметь формат example_bot")
        if len(about) > 120 or len(description) > 512:
            raise HTTPException(status_code=400, detail="Описание бота слишком длинное")
        uid = int(user["telegram_id"])
        now = int(time.time())
        token = "wgbot_" + secrets.token_urlsafe(32)
        try:
            async with aiosqlite.connect(db_path()) as db:
                await db.execute("BEGIN IMMEDIATE")
                cur = await db.execute(
                    "SELECT COUNT(*) FROM bots WHERE owner_telegram_id=? AND is_active=1",
                    (uid,),
                )
                if int((await cur.fetchone())[0]) >= 20:
                    await db.rollback()
                    raise HTTPException(status_code=409, detail="Можно создать не более 20 активных ботов")
                cur = await db.execute(
                    """INSERT INTO bots
                       (owner_telegram_id,name,username,about,description,token_hash,token_prefix,
                        is_active,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,1,?,?)""",
                    (
                        uid,name.strip(),username,about,description,_token_hash(token),
                        token[:12],now,now,
                    ),
                )
                bot_id = int(cur.lastrowid)
                await db.commit()
        except aiosqlite.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username бота уже занят") from exc
        return {
            "id": bot_id,
            "name": name.strip(),
            "username": username,
            "token": token,
            "token_notice": "Токен показывается только при создании или сбросе. Сохрани его в защищённом месте.",
            "is_active": True,
            "created_at": now,
        }

    @router.get("/api/bots/by-username/{username}")
    async def get_public_bot(
        username: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await current_user(authorization)
        key = username.strip().lstrip("@")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,name,username,about,description,created_at
                   FROM bots WHERE username=? COLLATE NOCASE AND is_active=1""",
                (key,),
            )
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Бот не найден")
        return dict(row)

    @router.get("/api/bots/{bot_id}")
    async def get_owned_bot(
        bot_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,name,username,about,description,token_prefix,is_active,created_at,updated_at
                   FROM bots WHERE id=? AND owner_telegram_id=?""",
                (bot_id,int(user["telegram_id"])),
            )
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Бот не найден")
        return dict(row)

    @router.patch("/api/bots/{bot_id}")
    async def update_owned_bot(
        bot_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        allowed = {}
        if "name" in payload:
            name = payload["name"]
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64:
                raise HTTPException(status_code=400, detail="Имя бота должно содержать 1–64 символа")
            allowed["name"] = name.strip()
        if "about" in payload:
            about = str(payload["about"]).strip()
            if len(about) > 120:
                raise HTTPException(status_code=400, detail="Краткое описание слишком длинное")
            allowed["about"] = about
        if "description" in payload:
            description = str(payload["description"]).strip()
            if len(description) > 512:
                raise HTTPException(status_code=400, detail="Описание слишком длинное")
            allowed["description"] = description
        if not allowed:
            raise HTTPException(status_code=400, detail="Нет полей для изменения")
        fields = ",".join(f"{key}=?" for key in allowed)
        values = list(allowed.values()) + [int(time.time()),bot_id,uid]
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                f"UPDATE bots SET {fields},updated_at=? WHERE id=? AND owner_telegram_id=?",
                values,
            )
            await db.commit()
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Бот не найден")
        return {"updated": True, "bot_id": bot_id}

    @router.delete("/api/bots/{bot_id}")
    async def revoke_owned_bot(
        bot_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "UPDATE bots SET is_active=0,updated_at=? WHERE id=? AND owner_telegram_id=?",
                (int(time.time()),bot_id,int(user["telegram_id"])),
            )
            await db.commit()
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Бот не найден")
        return {"revoked": True, "bot_id": bot_id}

    @router.post("/api/bots/{bot_id}/token/reset")
    async def reset_owned_bot_token(
        bot_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        token = "wgbot_" + secrets.token_urlsafe(32)
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                """UPDATE bots SET token_hash=?,token_prefix=?,updated_at=?
                   WHERE id=? AND owner_telegram_id=? AND is_active=1""",
                (_token_hash(token),token[:12],int(time.time()),bot_id,int(user["telegram_id"])),
            )
            await db.commit()
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Активный бот не найден")
        return {"bot_id": bot_id, "token": token}

    @router.get("/api/bots/{bot_id}/commands")
    async def list_bot_commands(
        bot_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT 1 FROM bots WHERE id=? AND owner_telegram_id=?",
                (bot_id,int(user["telegram_id"])),
            )
            if not await cur.fetchone():
                raise HTTPException(status_code=404, detail="Бот не найден")
            cur = await db.execute(
                "SELECT command,description FROM bot_commands WHERE bot_id=? ORDER BY command",
                (bot_id,),
            )
            rows = await cur.fetchall()
        return {"commands": [dict(row) for row in rows]}

    @router.put("/api/bots/{bot_id}/commands")
    async def replace_bot_commands(
        bot_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        commands = payload.get("commands")
        if not isinstance(commands, list) or len(commands) > 100:
            raise HTTPException(status_code=400, detail="Передайте массив из не более чем 100 команд")
        normalized = []
        seen = set()
        for item in commands:
            if not isinstance(item, dict):
                raise HTTPException(status_code=400, detail="Некорректная команда")
            command = str(item.get("command") or "").strip().lower().lstrip("/")
            description = str(item.get("description") or "").strip()
            if not re.fullmatch(r"[a-z0-9_]{1,32}", command) or len(description) > 256:
                raise HTTPException(status_code=400, detail="Проверьте имя или описание команды")
            if command in seen:
                raise HTTPException(status_code=400, detail="Команды должны быть уникальными")
            seen.add(command)
            normalized.append((bot_id,command,description))
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "SELECT 1 FROM bots WHERE id=? AND owner_telegram_id=? AND is_active=1",
                (bot_id,int(user["telegram_id"])),
            )
            if not await cur.fetchone():
                raise HTTPException(status_code=404, detail="Активный бот не найден")
            await db.execute("DELETE FROM bot_commands WHERE bot_id=?",(bot_id,))
            if normalized:
                await db.executemany(
                    "INSERT INTO bot_commands(bot_id,command,description) VALUES(?,?,?)",
                    normalized,
                )
            await db.commit()
        return {"bot_id": bot_id, "commands": [{"command":x[1],"description":x[2]} for x in normalized]}

    @router.post("/api/bots/{bot_id}/messages", status_code=201)
    async def send_message_to_bot(
        bot_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        body = _message_body(payload.get("body", ""))
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT id FROM bots WHERE id=? AND is_active=1",
                (bot_id,),
            )
            if not await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=404, detail="Бот не найден")
            await db.execute(
                """INSERT INTO bot_chats(bot_id,user_telegram_id,created_at,last_activity)
                   VALUES(?,?,?,?) ON CONFLICT(bot_id,user_telegram_id)
                   DO UPDATE SET last_activity=excluded.last_activity""",
                (bot_id,uid,now,now),
            )
            cur = await db.execute(
                """INSERT INTO bot_messages(bot_id,user_telegram_id,sender_type,body,created_at)
                   VALUES(?,?,'user',?,?)""",
                (bot_id,uid,body,now),
            )
            message_id = int(cur.lastrowid)
            await db.commit()
        return {"id":message_id,"bot_id":bot_id,"sender":"user","body":body,"created_at":now}

    @router.get("/api/bots/{bot_id}/messages")
    async def list_bot_chat_messages(
        bot_id: int,
        after_id: int = Query(default=0, ge=0),
        wait_seconds: int = Query(default=0, ge=0, le=20),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        deadline = time.monotonic() + (wait_seconds if after_id else 0)
        rows = []
        while True:
            async with aiosqlite.connect(db_path()) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute(
                    "SELECT 1 FROM bot_chats WHERE bot_id=? AND user_telegram_id=?",
                    (bot_id,uid),
                )
                if not await cur.fetchone():
                    raise HTTPException(status_code=404, detail="Чат с ботом ещё не создан")
                if after_id:
                    cur = await db.execute(
                        """SELECT id,bot_id,user_telegram_id,sender_type AS sender,body,created_at
                           FROM bot_messages WHERE bot_id=? AND user_telegram_id=? AND id>?
                           ORDER BY id ASC LIMIT 100""",
                        (bot_id,uid,after_id),
                    )
                else:
                    cur = await db.execute(
                        """SELECT id,bot_id,user_telegram_id,sender_type AS sender,body,created_at
                           FROM bot_messages WHERE bot_id=? AND user_telegram_id=?
                           ORDER BY id DESC LIMIT 100""",
                        (bot_id,uid),
                    )
                rows = await cur.fetchall()
            if rows or time.monotonic() >= deadline:
                break
            await asyncio.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
        items = [dict(row) for row in rows]
        if not after_id:
            items.reverse()
        return {"messages":items,"next_after_id":items[-1]["id"] if items else 0}

    @router.get("/api/bot-api/getUpdates")
    async def bot_get_updates(
        offset: int = Query(default=0, ge=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        bot = await current_bot(authorization)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,user_telegram_id AS chat_id,body AS text,created_at
                   FROM bot_messages
                   WHERE bot_id=? AND sender_type='user' AND id>?
                   ORDER BY id ASC LIMIT 100""",
                (int(bot["id"]),offset),
            )
            rows = await cur.fetchall()
        return {"ok":True,"result":[dict(row) for row in rows]}

    @router.post("/api/bot-api/sendMessage")
    async def bot_send_message(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        bot = await current_bot(authorization)
        try:
            chat_id = int(payload.get("chat_id",0))
        except (TypeError,ValueError):
            chat_id = 0
        body = _message_body(payload.get("text",""))
        if chat_id <= 0:
            raise HTTPException(status_code=400, detail="Некорректный chat_id")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT 1 FROM bot_chats WHERE bot_id=? AND user_telegram_id=?",
                (int(bot["id"]),chat_id),
            )
            if not await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=404, detail="Пользователь ещё не запускал этого бота")
            cur = await db.execute(
                """INSERT INTO bot_messages(bot_id,user_telegram_id,sender_type,body,created_at)
                   VALUES(?,?,'bot',?,?)""",
                (int(bot["id"]),chat_id,body,now),
            )
            message_id = int(cur.lastrowid)
            await db.execute(
                "UPDATE bot_chats SET last_activity=? WHERE bot_id=? AND user_telegram_id=?",
                (now,int(bot["id"]),chat_id),
            )
            await db.commit()
        return {
            "ok":True,
            "result":{"message_id":message_id,"chat":{"id":chat_id},"text":body},
        }

    return router
