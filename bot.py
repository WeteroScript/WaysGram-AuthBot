from __future__ import annotations

import asyncio
import logging
import os
import random
import re
import secrets
import time
from pathlib import Path
from typing import Any

import aiosqlite
import httpx
from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
import uvicorn

# All secrets are read only from hosting environment variables.
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_ID", "8888957702"))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", "data/waysgram_authbot.sqlite3"))
INTERNAL_API_TOKEN = os.getenv("INTERNAL_API_TOKEN", "").strip()
INTERNAL_API_HOST = os.getenv("INTERNAL_API_HOST", "0.0.0.0")
INTERNAL_API_PORT = int(os.getenv("INTERNAL_API_PORT", "8081"))
PHONE_PROVIDER_URL = os.getenv("PHONE_PROVIDER_URL", "").rstrip("/")
PHONE_PROVIDER_TOKEN = os.getenv("PHONE_PROVIDER_TOKEN", "").strip()

PHONE_RE = re.compile(r"^\+1\d{10}$")
OTP_RE = re.compile(r"^\d{6}$")
EMOJI = ["🐱", "🐶", "🦊", "🐼", "🐸", "🐵", "🐧", "🐰"]

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("waysgram-authbot")

TEXT: dict[str, dict[str, str]] = {
    "ru": {
        "choose_language": "Выберите язык / Choose your language:",
        "captcha_prompt": "Проверка: нажмите на эмодзи {emoji}.",
        "captcha_failed": "Проверка не пройдена. Попробуйте ещё раз.",
        "welcome": "Проверка пройдена. Главное меню WaysGram:",
        "get_number": "Получить номер",
        "get_code": "Получить код",
        "settings": "Настройки",
        "number_exists": "Ваш номер WaysGram: {number}",
        "provider_missing": "Автоматическая выдача номеров пока не подключена. Нужен API провайдера, который выделяет реальные номера +1.",
        "number_error": "Не удалось получить номер от провайдера. Попробуйте позже или обратитесь к администратору.",
        "number_ready": "Ваш номер WaysGram: {number}",
        "need_number": "Сначала получите номер WaysGram.",
        "code_missing": "Для этого номера пока нет активного кода WaysGram.",
        "code_ready": "Ваш код входа WaysGram: {code}\nСрок действия: {minutes} мин. Не передавайте его другим людям.",
        "settings_title": "Настройки языка:",
        "admin_denied": "Доступ запрещён.",
        "admin_title": "Панель администратора WaysGram",
        "admin_stats": "Пользователей: {users}\nВыдано номеров: {numbers}\nАктивных кодов: {codes}",
        "admin_provider": "Провайдер номеров: {status}\nВнутренний API: {api}",
        "admin_recent_empty": "Пользователей пока нет.",
        "admin_recent": "Последние пользователи (Telegram ID):\n{items}",
        "code_push": "Для вашего аккаунта WaysGram поступил код входа: {code}\nСрок действия: {minutes} мин.",
    },
    "en": {
        "choose_language": "Choose your language:",
        "captcha_prompt": "Verification: tap the {emoji} emoji.",
        "captcha_failed": "Verification failed. Please try again.",
        "welcome": "Verification passed. WaysGram main menu:",
        "get_number": "Get number",
        "get_code": "Get code",
        "settings": "Settings",
        "number_exists": "Your WaysGram number: {number}",
        "provider_missing": "Automatic number provisioning is not connected yet. A provider API that allocates real +1 numbers is required.",
        "number_error": "The provider could not allocate a number. Try again later or contact the administrator.",
        "number_ready": "Your WaysGram number: {number}",
        "need_number": "Get a WaysGram number first.",
        "code_missing": "There is no active WaysGram code for this number yet.",
        "code_ready": "Your WaysGram login code: {code}\nExpires in {minutes} min. Do not share it with anyone.",
        "settings_title": "Language settings:",
        "admin_denied": "Access denied.",
        "admin_title": "WaysGram admin panel",
        "admin_stats": "Users: {users}\nAllocated numbers: {numbers}\nActive codes: {codes}",
        "admin_provider": "Number provider: {status}\nInternal API: {api}",
        "admin_recent_empty": "There are no users yet.",
        "admin_recent": "Recent users (Telegram IDs):\n{items}",
        "code_push": "A WaysGram login code was issued for your account: {code}\nExpires in {minutes} min.",
    },
}


def tr(lang: str | None, key: str, **values: Any) -> str:
    selected = lang if lang in TEXT else "en"
    return TEXT[selected][key].format(**values)


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path

    async def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    telegram_id INTEGER PRIMARY KEY,
                    chat_id INTEGER NOT NULL,
                    language TEXT,
                    verified INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS numbers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telegram_id INTEGER NOT NULL UNIQUE REFERENCES users(telegram_id),
                    number TEXT NOT NULL UNIQUE,
                    provider_ref TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    number TEXT NOT NULL,
                    code TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auth_codes_number_expiry
                    ON auth_codes(number, expires_at DESC);
                """
            )
            cur = await db.execute("PRAGMA table_info(users)")
            columns = {str(row[1]) for row in await cur.fetchall()}
            if "verified" not in columns:
                await db.execute(
                    "ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0"
                )
            await db.commit()

    async def upsert_user(self, telegram_id: int, chat_id: int) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                """INSERT INTO users(telegram_id, chat_id, created_at)
                   VALUES(?, ?, ?) ON CONFLICT(telegram_id)
                   DO UPDATE SET chat_id=excluded.chat_id""",
                (telegram_id, chat_id, int(time.time())),
            )
            await db.commit()

    async def set_language(self, telegram_id: int, language: str) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "UPDATE users SET language=?, verified=0 WHERE telegram_id=?",
                (language, telegram_id),
            )
            await db.commit()

    async def set_verified(self, telegram_id: int, verified: bool) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "UPDATE users SET verified=? WHERE telegram_id=?",
                (1 if verified else 0, telegram_id),
            )
            await db.commit()

    async def get_user(self, telegram_id: int) -> dict[str, Any] | None:
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT telegram_id, chat_id, language, verified FROM users WHERE telegram_id=?",
                (telegram_id,),
            )
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_number(self, telegram_id: int) -> str | None:
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                "SELECT number FROM numbers WHERE telegram_id=?", (telegram_id,)
            )
            row = await cur.fetchone()
            return str(row[0]) if row else None

    async def save_number(self, telegram_id: int, number: str, provider_ref: str) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO numbers(telegram_id, number, provider_ref, created_at) VALUES(?, ?, ?, ?)",
                (telegram_id, number, provider_ref, int(time.time())),
            )
            await db.commit()

    async def resolve_number(self, number: str) -> dict[str, Any] | None:
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT n.telegram_id, u.chat_id, u.language
                   FROM numbers n JOIN users u ON u.telegram_id=n.telegram_id
                   WHERE n.number=?""",
                (number,),
            )
            row = await cur.fetchone()
            return dict(row) if row else None

    async def save_code(self, number: str, code: str, expires_in: int) -> None:
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
            await db.execute("DELETE FROM auth_codes WHERE number=?", (number,))
            await db.execute(
                "INSERT INTO auth_codes(number, code, expires_at, created_at) VALUES(?, ?, ?, ?)",
                (number, code, now + expires_in, now),
            )
            await db.commit()

    async def latest_code(self, number: str) -> tuple[str, int] | None:
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                """SELECT code, expires_at FROM auth_codes
                   WHERE number=? AND expires_at>? ORDER BY id DESC LIMIT 1""",
                (number, now),
            )
            row = await cur.fetchone()
            if not row:
                return None
            return str(row[0]), int(row[1]) - now

    async def stats(self) -> tuple[int, int, int]:
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute("SELECT COUNT(*) FROM users")
            users = int((await cur.fetchone())[0])
            cur = await db.execute("SELECT COUNT(*) FROM numbers")
            numbers = int((await cur.fetchone())[0])
            cur = await db.execute(
                "SELECT COUNT(*) FROM auth_codes WHERE expires_at>?", (now,)
            )
            codes = int((await cur.fetchone())[0])
            return users, numbers, codes

    async def recent_users(self) -> list[int]:
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                "SELECT telegram_id FROM users ORDER BY created_at DESC LIMIT 10"
            )
            return [int(row[0]) for row in await cur.fetchall()]


class ProviderNotConfigured(RuntimeError):
    pass


class PhoneNumberProvider:
    """Generic adapter contract; substitute a provider-specific adapter when selected."""

    async def reserve(self, telegram_id: int) -> tuple[str, str]:
        if not PHONE_PROVIDER_URL or not PHONE_PROVIDER_TOKEN:
            raise ProviderNotConfigured
        url = f"{PHONE_PROVIDER_URL}/v1/numbers/reserve"
        headers = {"Authorization": f"Bearer {PHONE_PROVIDER_TOKEN}"}
        payload = {
            "country_code": "US",
            "customer_reference": f"waysgram:{telegram_id}",
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
        number = str(data.get("number", ""))
        provider_ref = str(data.get("id", ""))
        if not PHONE_RE.fullmatch(number) or not provider_ref:
            raise ValueError("Provider response has an invalid number or id")
        return number, provider_ref


store = Store(DATABASE_PATH)
provider = PhoneNumberProvider()
bot: Bot | None = None
router = Router()
app = FastAPI(title="WaysGram AuthBot internal API", docs_url=None, redoc_url=None)
CHALLENGES: dict[str, tuple[int, str, list[str], float]] = {}
USER_LOCKS: dict[int, asyncio.Lock] = {}


def main_keyboard(lang: str) -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text=tr(lang, "get_number"))],
            [KeyboardButton(text=tr(lang, "get_code"))],
            [KeyboardButton(text=tr(lang, "settings"))],
        ],
        resize_keyboard=True,
    )


def language_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[
            InlineKeyboardButton(text="Русский", callback_data="lang:ru"),
            InlineKeyboardButton(text="English", callback_data="lang:en"),
        ]]
    )


async def ask_captcha(message: Message, telegram_id: int, lang: str) -> None:
    target = random.choice(EMOJI)
    choices = random.sample(EMOJI, 5)
    if target not in choices:
        choices[random.randrange(len(choices))] = target
    random.shuffle(choices)
    challenge_id = secrets.token_urlsafe(6).replace("-", "a").replace("_", "b")[:10]
    CHALLENGES[challenge_id] = (telegram_id, target, choices, time.time() + 180)
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=e, callback_data=f"cap:{challenge_id}:{i}")
         for i, e in enumerate(choices[:3])],
        [InlineKeyboardButton(text=e, callback_data=f"cap:{challenge_id}:{i}")
         for i, e in enumerate(choices[3:])],
    ])
    await message.answer(tr(lang, "captcha_prompt", emoji=target), reply_markup=keyboard)


@router.message(CommandStart())
async def start_handler(message: Message) -> None:
    if not message.from_user:
        return
    await store.upsert_user(message.from_user.id, message.chat.id)
    await store.set_verified(message.from_user.id, False)
    user = await store.get_user(message.from_user.id)
    if not user or not user.get("language"):
        await message.answer(tr(None, "choose_language"), reply_markup=language_keyboard())
    else:
        await ask_captcha(message, message.from_user.id, str(user["language"]))


@router.callback_query(F.data.startswith("lang:"))
async def language_handler(callback: CallbackQuery) -> None:
    if not callback.from_user or not callback.message or not callback.data:
        return
    language = callback.data.split(":", 1)[1]
    if language not in ("ru", "en"):
        await callback.answer()
        return
    await store.upsert_user(callback.from_user.id, callback.message.chat.id)
    await store.set_language(callback.from_user.id, language)
    await callback.answer()
    await ask_captcha(callback.message, callback.from_user.id, language)


@router.callback_query(F.data.startswith("cap:"))
async def captcha_handler(callback: CallbackQuery) -> None:
    if not callback.from_user or not callback.message or not callback.data:
        return
    parts = callback.data.split(":")
    if len(parts) != 3:
        await callback.answer()
        return
    challenge = CHALLENGES.pop(parts[1], None)
    user = await store.get_user(callback.from_user.id)
    lang = str(user.get("language") if user else "en")
    if not challenge or challenge[0] != callback.from_user.id or challenge[3] < time.time():
        await callback.answer("Expired", show_alert=True)
        await ask_captcha(callback.message, callback.from_user.id, lang)
        return
    try:
        selected = challenge[2][int(parts[2])]
    except (ValueError, IndexError):
        await callback.answer()
        return
    if selected != challenge[1]:
        await callback.answer(tr(lang, "captcha_failed"), show_alert=True)
        await ask_captcha(callback.message, callback.from_user.id, lang)
        return
    await store.set_verified(callback.from_user.id, True)
    await callback.answer()
    await callback.message.answer(tr(lang, "welcome"), reply_markup=main_keyboard(lang))


@router.message(F.text.in_(["Получить номер", "Get number"]))
async def get_number_handler(message: Message) -> None:
    if not message.from_user:
        return
    user = await store.get_user(message.from_user.id)
    lang = str(user.get("language") if user else "en")
    if not user or not user.get("verified"):
        await ask_captcha(message, message.from_user.id, lang)
        return
    lock = USER_LOCKS.setdefault(message.from_user.id, asyncio.Lock())
    async with lock:
        existing = await store.get_number(message.from_user.id)
        if existing:
            await message.answer(tr(lang, "number_exists", number=existing))
            return
        try:
            number, provider_ref = await provider.reserve(message.from_user.id)
            await store.save_number(message.from_user.id, number, provider_ref)
        except ProviderNotConfigured:
            await message.answer(tr(lang, "provider_missing"))
            return
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("Number allocation failed (%s)", type(exc).__name__)
            await message.answer(tr(lang, "number_error"))
            return
        await message.answer(tr(lang, "number_ready", number=number))


@router.message(F.text.in_(["Получить код", "Get code"]))
async def get_code_handler(message: Message) -> None:
    if not message.from_user:
        return
    user = await store.get_user(message.from_user.id)
    lang = str(user.get("language") if user else "en")
    if not user or not user.get("verified"):
        await ask_captcha(message, message.from_user.id, lang)
        return
    number = await store.get_number(message.from_user.id)
    if not number:
        await message.answer(tr(lang, "need_number"))
        return
    result = await store.latest_code(number)
    if not result:
        await message.answer(tr(lang, "code_missing"))
        return
    code, seconds_left = result
    minutes = max(1, (seconds_left + 59) // 60)
    await message.answer(tr(lang, "code_ready", code=code, minutes=minutes))


@router.message(F.text.in_(["Настройки", "Settings"]))
async def settings_handler(message: Message) -> None:
    if not message.from_user:
        return
    user = await store.get_user(message.from_user.id)
    lang = str(user.get("language") if user else "en")
    if not user or not user.get("verified"):
        await ask_captcha(message, message.from_user.id, lang)
        return
    await message.answer(tr(lang, "settings_title"), reply_markup=language_keyboard())


@router.message(Command("admin"))
async def admin_handler(message: Message) -> None:
    if not message.from_user or message.from_user.id != ADMIN_ID:
        user = await store.get_user(message.from_user.id) if message.from_user else None
        await message.answer(tr(user.get("language") if user else "en", "admin_denied"))
        return
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Statistics", callback_data="adm:stats")],
        [InlineKeyboardButton(text="Provider status", callback_data="adm:provider")],
        [InlineKeyboardButton(text="Recent users", callback_data="adm:recent")],
    ])
    await message.answer(tr("en", "admin_title"), reply_markup=keyboard)


@router.callback_query(F.data.startswith("adm:"))
async def admin_callback(callback: CallbackQuery) -> None:
    if not callback.from_user or callback.from_user.id != ADMIN_ID or not callback.data:
        await callback.answer("Access denied", show_alert=True)
        return
    action = callback.data.split(":", 1)[1]
    if action == "stats":
        users, numbers, codes = await store.stats()
        response = tr("en", "admin_stats", users=users, numbers=numbers, codes=codes)
    elif action == "provider":
        provider_status = "configured" if PHONE_PROVIDER_URL and PHONE_PROVIDER_TOKEN else "not configured"
        api_status = "configured" if INTERNAL_API_TOKEN else "not configured"
        response = tr("en", "admin_provider", status=provider_status, api=api_status)
    elif action == "recent":
        items = await store.recent_users()
        response = tr("en", "admin_recent", items="\n".join(map(str, items))) if items else tr("en", "admin_recent_empty")
    else:
        response = "Unknown action"
    await callback.answer()
    if callback.message:
        await callback.message.answer(response)


class NumberResolveRequest(BaseModel):
    number: str = Field(min_length=12, max_length=12)


class AuthCodeDeliveryRequest(BaseModel):
    number: str = Field(min_length=12, max_length=12)
    code: str = Field(pattern=r"^\d{6}$")
    expires_in: int = Field(default=300, ge=30, le=600)


def verify_internal_token(value: str | None) -> None:
    if not INTERNAL_API_TOKEN:
        raise HTTPException(status_code=503, detail="Internal API token is not configured")
    if value is None or not secrets.compare_digest(value, INTERNAL_API_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "waysgram-authbot"}


@app.post("/internal/v1/number/resolve")
async def resolve_number(
    payload: NumberResolveRequest,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, Any]:
    verify_internal_token(x_internal_token)
    if not PHONE_RE.fullmatch(payload.number):
        raise HTTPException(status_code=422, detail="Invalid +1 number format")
    owner = await store.resolve_number(payload.number)
    if not owner:
        raise HTTPException(status_code=404, detail="Number is not assigned")
    return {"assigned": True, "telegram_user_id": owner["telegram_id"]}


@app.post("/internal/v1/auth-code")
async def deliver_auth_code(
    payload: AuthCodeDeliveryRequest,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, str]:
    verify_internal_token(x_internal_token)
    if not PHONE_RE.fullmatch(payload.number) or not OTP_RE.fullmatch(payload.code):
        raise HTTPException(status_code=422, detail="Invalid number or code format")
    owner = await store.resolve_number(payload.number)
    if not owner:
        raise HTTPException(status_code=404, detail="Number is not assigned")
    await store.save_code(payload.number, payload.code, payload.expires_in)
    if bot is None:
        raise HTTPException(status_code=503, detail="Bot is not ready")
    lang = str(owner.get("language") or "en")
    minutes = max(1, (payload.expires_in + 59) // 60)
    try:
        await bot.send_message(
            chat_id=int(owner["chat_id"]),
            text=tr(lang, "code_push", code=payload.code, minutes=minutes),
        )
    except Exception as exc:
        log.warning("Could not deliver WaysGram code (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not deliver bot message") from exc
    return {"status": "delivered"}


async def main() -> None:
    global bot
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN environment variable is required")
    await store.init()
    bot = Bot(token=BOT_TOKEN)
    dispatcher = Dispatcher()
    dispatcher.include_router(router)

    if not INTERNAL_API_TOKEN:
        log.warning("INTERNAL_API_TOKEN is not set; backend API endpoints will reject requests")
    if not PHONE_PROVIDER_URL or not PHONE_PROVIDER_TOKEN:
        log.warning("Phone provider is not configured; automatic +1 number allocation is disabled")

    config = uvicorn.Config(
        app,
        host=INTERNAL_API_HOST,
        port=INTERNAL_API_PORT,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
    server = uvicorn.Server(config)
    try:
        await asyncio.gather(dispatcher.start_polling(bot), server.serve())
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
