from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import re
import secrets
import time
from datetime import datetime, timezone
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
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from messenger_api import build_messenger_router, init_messenger_storage, sync_telegram_gifts
from telegram_mtproto import TelegramMTProtoGiftCatalog

# All secrets are read only from hosting environment variables.
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_ID", "8888957702"))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", "data/waysgram_authbot.sqlite3"))
INTERNAL_API_TOKEN = os.getenv("INTERNAL_API_TOKEN", "").strip()
OTP_FERNET_KEY = os.getenv("OTP_FERNET_KEY", "").strip()
TELESRV_OTP_WEBHOOK_SECRET = os.getenv("TELESRV_OTP_WEBHOOK_SECRET", "").strip()
INTERNAL_API_HOST = os.getenv("INTERNAL_API_HOST", "0.0.0.0")
INTERNAL_API_PORT = int(os.getenv("INTERNAL_API_PORT") or os.getenv("PORT") or "8081")
try:
    TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", "0") or "0")
except ValueError:
    TELEGRAM_API_ID = 0
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "").strip()

PHONE_RE = re.compile(r"^\+1\d{10}$")
OTP_RE = re.compile(r"^\d{6}$")
EMOJI = ["🐱", "🐶", "🦊", "🐼", "🐸", "🐵", "🐧", "🐰", "🦁", "🐨", "🐯", "🐹"]

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
        "provider_missing": "Не удалось создать виртуальный номер. Повторите попытку позже.",
        "number_error": "Не удалось создать виртуальный номер. Попробуйте ещё раз позже.",
        "number_ready": "Ваш номер WaysGram: {number}",
        "need_number": "Сначала получите номер WaysGram.",
        "code_missing": "Для этого номера пока нет активного кода WaysGram.",
        "code_ready": "Ваш код входа WaysGram: {code}\nСрок действия: {minutes} мин. Не передавайте его другим людям.",
        "settings_title": "Настройки языка:",
        "admin_denied": "Доступ запрещён.",
        "admin_title": "Панель администратора WaysGram",
        "admin_stats": "Пользователей: {users}\nВыдано номеров: {numbers}\nАктивных кодов: {codes}",
        "admin_provider": "Генерация номеров: {status}\nВнутренний API: {api}",
        "admin_recent_empty": "Пользователей пока нет.",
        "admin_recent": "Последние пользователи (Telegram ID):\n{items}",
        "code_push": "Код WaysGram готов. Нажмите «Получить код» в меню бота.",
        "admin_numbers_empty": "Выданных номеров пока нет.",
        "admin_numbers": "Выданные виртуальные номера:\n{items}",
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
        "provider_missing": "Could not create a virtual number. Please try again later.",
        "number_error": "Could not create your virtual number. Please try again later.",
        "number_ready": "Your WaysGram number: {number}",
        "need_number": "Get a WaysGram number first.",
        "code_missing": "There is no active WaysGram code for this number yet.",
        "code_ready": "Your WaysGram login code: {code}\nExpires in {minutes} min. Do not share it with anyone.",
        "settings_title": "Language settings:",
        "admin_denied": "Access denied.",
        "admin_title": "WaysGram admin panel",
        "admin_stats": "Users: {users}\nAllocated numbers: {numbers}\nActive codes: {codes}",
        "admin_provider": "Number generation: {status}\nInternal API: {api}",
        "admin_recent_empty": "There are no users yet.",
        "admin_recent": "Recent users (Telegram IDs):\n{items}",
        "code_push": "Your WaysGram code is ready. Tap “Get code” in the bot menu.",
        "admin_numbers_empty": "No virtual numbers have been issued yet.",
        "admin_numbers": "Issued virtual numbers:\\n{items}",
    },
}


def tr(lang: str | None, key: str, **values: Any) -> str:
    selected = lang if lang in TEXT else "en"
    return TEXT[selected][key].format(**values)


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.fernet: Fernet | None = None

    def configure_otp_encryption(self, key: str) -> None:
        try:
            self.fernet = Fernet(key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError("OTP_FERNET_KEY must be a valid Fernet key") from exc

    def _encrypt_code(self, code: str) -> str:
        if self.fernet is None:
            raise RuntimeError("OTP encryption is not configured")
        return self.fernet.encrypt(code.encode("ascii")).decode("ascii")

    def _decrypt_code(self, value: str) -> str:
        if self.fernet is None:
            raise RuntimeError("OTP encryption is not configured")
        return self.fernet.decrypt(value.encode("ascii")).decode("ascii")

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
                    created_at INTEGER NOT NULL,
                    last_code_requested_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS auth_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    number TEXT NOT NULL,
                    code TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auth_codes_number_expiry
                    ON auth_codes(number, expires_at DESC);
                CREATE TABLE IF NOT EXISTS telesrv_otp_deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    payload_sha256 TEXT NOT NULL,
                    number TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    telegram_message_id INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                """
            )
            cur = await db.execute("PRAGMA table_info(users)")
            columns = {str(row[1]) for row in await cur.fetchall()}
            if "verified" not in columns:
                await db.execute(
                    "ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0"
                )
            cur = await db.execute("PRAGMA table_info(auth_codes)")
            code_columns = {str(row[1]) for row in await cur.fetchall()}
            if "attempts" not in code_columns:
                await db.execute(
                    "ALTER TABLE auth_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
                )
            if "encrypted" not in code_columns:
                await db.execute(
                    "ALTER TABLE auth_codes ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0"
                )
            # Encrypt legacy codes from an earlier bot version.
            if self.fernet is not None:
                cur = await db.execute("SELECT id, code FROM auth_codes WHERE encrypted=0")
                for row_id, plain_code in await cur.fetchall():
                    await db.execute(
                        "UPDATE auth_codes SET code=?, encrypted=1 WHERE id=?",
                        (self._encrypt_code(str(plain_code)), row_id),
                    )
            cur = await db.execute("PRAGMA table_info(numbers)")
            number_columns = {str(row[1]) for row in await cur.fetchall()}
            if "last_code_requested_at" not in number_columns:
                await db.execute(
                    "ALTER TABLE numbers ADD COLUMN last_code_requested_at INTEGER NOT NULL DEFAULT 0"
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

    async def allocate_number(self, telegram_id: int) -> str:
        # Internal WaysGram identifier only; it is not a carrier-issued phone line.
        async with aiosqlite.connect(self.path) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT number FROM numbers WHERE telegram_id=?", (telegram_id,)
            )
            existing = await cur.fetchone()
            if existing:
                await db.commit()
                return str(existing[0])
            for _ in range(100):
                number = "+1" + f"{secrets.randbelow(10_000_000_000):010d}"
                cur = await db.execute(
                    """INSERT OR IGNORE INTO numbers
                       (telegram_id, number, provider_ref, created_at)
                       VALUES(?, ?, 'internal', ?)""",
                    (telegram_id, number, int(time.time())),
                )
                if cur.rowcount == 1:
                    await db.commit()
                    return number
                cur = await db.execute(
                    "SELECT number FROM numbers WHERE telegram_id=?", (telegram_id,)
                )
                existing = await cur.fetchone()
                if existing:
                    await db.commit()
                    return str(existing[0])
            await db.rollback()
        raise RuntimeError("Could not allocate a unique internal number")

    async def resolve_number(self, number: str) -> dict[str, Any] | None:
        async with aiosqlite.connect(self.path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT n.telegram_id, u.chat_id, u.language, u.verified
                   FROM numbers n JOIN users u ON u.telegram_id=n.telegram_id
                   WHERE n.number=?""",
                (number,),
            )
            row = await cur.fetchone()
            return dict(row) if row else None

    async def save_code(self, number: str, code: str, expires_in: int) -> bool:
        now = int(time.time())
        encrypted_code = self._encrypt_code(code)
        async with aiosqlite.connect(self.path) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT last_code_requested_at FROM numbers WHERE number=?",
                (number,),
            )
            row = await cur.fetchone()
            if not row or now - int(row[0]) < 30:
                await db.rollback()
                return False
            await db.execute(
                "UPDATE numbers SET last_code_requested_at=? WHERE number=?",
                (now, number),
            )
            await db.execute("DELETE FROM auth_codes WHERE number=?", (number,))
            await db.execute(
                """INSERT INTO auth_codes
                   (number, code, expires_at, attempts, encrypted, created_at)
                   VALUES(?, ?, ?, 0, 1, ?)""",
                (number, encrypted_code, now + expires_in, now),
            )
            await db.commit()
            return True

    async def save_telesrv_code(
        self,
        number: str,
        code: str,
        expires_at: int,
        delivery_id: str,
        payload_sha256: str,
    ) -> tuple[str, int]:
        """Persist a signed MTProto-server OTP and an idempotent delivery receipt.

        Returns (status, telegram_message_id). Status is one of stored,
        delivered, conflict, expired, unknown_number, or rate_limited.
        """
        now = int(time.time())
        encrypted_code = self._encrypt_code(code)
        async with aiosqlite.connect(self.path) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT payload_sha256,status,expires_at,telegram_message_id
                   FROM telesrv_otp_deliveries WHERE delivery_id=?""",
                (delivery_id,),
            )
            existing = await cur.fetchone()
            if existing:
                saved_hash, status, saved_expiry, message_id = existing
                if not secrets.compare_digest(str(saved_hash), payload_sha256):
                    await db.rollback()
                    return "conflict", 0
                if int(saved_expiry) <= now:
                    await db.rollback()
                    return "expired", int(message_id)
                await db.commit()
                return str(status), int(message_id)

            cur = await db.execute(
                "SELECT last_code_requested_at FROM numbers WHERE number=?",
                (number,),
            )
            row = await cur.fetchone()
            if not row:
                await db.rollback()
                return "unknown_number", 0
            if now - int(row[0]) < 30:
                await db.rollback()
                return "rate_limited", 0
            if expires_at <= now or expires_at - now > 900:
                await db.rollback()
                return "expired", 0

            await db.execute(
                "UPDATE numbers SET last_code_requested_at=? WHERE number=?",
                (now, number),
            )
            await db.execute("DELETE FROM auth_codes WHERE number=?", (number,))
            await db.execute(
                """INSERT INTO auth_codes
                   (number,code,expires_at,attempts,encrypted,created_at)
                   VALUES(?,?,?,0,1,?)""",
                (number, encrypted_code, expires_at, now),
            )
            await db.execute(
                """INSERT INTO telesrv_otp_deliveries
                   (delivery_id,payload_sha256,number,expires_at,status,
                    telegram_message_id,created_at,updated_at)
                   VALUES(?,?,?,?, 'stored',0,?,?)""",
                (delivery_id, payload_sha256, number, expires_at, now, now),
            )
            await db.commit()
            return "stored", 0

    async def mark_telesrv_delivery_sent(self, delivery_id: str, message_id: int) -> None:
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                """UPDATE telesrv_otp_deliveries
                   SET status='delivered',telegram_message_id=?,updated_at=?
                   WHERE delivery_id=? AND status='stored'""",
                (max(0, int(message_id)), now, delivery_id),
            )
            await db.commit()

    async def latest_code(self, number: str) -> tuple[str, int] | None:
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                """SELECT id, code, expires_at, encrypted FROM auth_codes
                   WHERE number=? AND expires_at>? ORDER BY id DESC LIMIT 1""",
                (number, now),
            )
            row = await cur.fetchone()
            if not row:
                return None
            row_id, stored_code, expires_at, encrypted = row
            try:
                code = self._decrypt_code(str(stored_code)) if encrypted else str(stored_code)
            except (InvalidToken, UnicodeDecodeError, ValueError):
                await db.execute("DELETE FROM auth_codes WHERE id=?", (row_id,))
                await db.commit()
                log.error("Deleted an OTP that could not be decrypted")
                return None
            return code, int(expires_at) - now

    async def verify_code(self, number: str, code: str) -> bool:
        now = int(time.time())
        async with aiosqlite.connect(self.path) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT id, code, expires_at, attempts, encrypted
                   FROM auth_codes WHERE number=? ORDER BY id DESC LIMIT 1""",
                (number,),
            )
            row = await cur.fetchone()
            if not row:
                await db.rollback()
                return False
            row_id, stored_code, expires_at, attempts, encrypted = row
            if int(expires_at) <= now or int(attempts) >= 5:
                await db.execute("DELETE FROM auth_codes WHERE id=?", (row_id,))
                await db.commit()
                return False
            try:
                saved_code = self._decrypt_code(str(stored_code)) if encrypted else str(stored_code)
            except (InvalidToken, UnicodeDecodeError, ValueError):
                await db.execute("DELETE FROM auth_codes WHERE id=?", (row_id,))
                await db.commit()
                log.error("Deleted an OTP that could not be decrypted during verification")
                return False
            if secrets.compare_digest(saved_code, code):
                await db.execute("DELETE FROM auth_codes WHERE id=?", (row_id,))
                await db.commit()
                return True
            next_attempts = int(attempts) + 1
            if next_attempts >= 5:
                await db.execute("DELETE FROM auth_codes WHERE id=?", (row_id,))
            else:
                await db.execute(
                    "UPDATE auth_codes SET attempts=? WHERE id=?",
                    (next_attempts, row_id),
                )
            await db.commit()
            return False

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

    async def number_inventory(self, limit: int = 20) -> list[tuple[str, int, bool]]:
        async with aiosqlite.connect(self.path) as db:
            cur = await db.execute(
                """SELECT n.number, n.telegram_id, u.verified
                   FROM numbers n JOIN users u ON u.telegram_id=n.telegram_id
                   ORDER BY n.created_at DESC LIMIT ?""",
                (limit,),
            )
            return [
                (str(row[0]), int(row[1]), bool(row[2]))
                for row in await cur.fetchall()
            ]


store = Store(DATABASE_PATH)
bot: Bot | None = None
mtproto_client: Any | None = None
mtproto_gift_catalog: TelegramMTProtoGiftCatalog | None = None
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


def language_keyboard(include_back: bool = False) -> InlineKeyboardMarkup:
    rows = [[
        InlineKeyboardButton(text="Русский", callback_data="lang:ru"),
        InlineKeyboardButton(text="English", callback_data="lang:en"),
    ]]
    if include_back:
        rows.append([InlineKeyboardButton(text="->", callback_data="nav:menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def ask_captcha(message: Message, telegram_id: int, lang: str) -> None:
    now = time.time()
    for old_id, challenge in list(CHALLENGES.items()):
        if challenge[3] <= now:
            CHALLENGES.pop(old_id, None)

    target = random.choice(EMOJI)
    choices = random.sample(EMOJI, 9)
    if target not in choices:
        choices[random.randrange(len(choices))] = target
    random.shuffle(choices)
    challenge_id = secrets.token_urlsafe(8).replace("-", "a").replace("_", "b")[:12]
    CHALLENGES[challenge_id] = (telegram_id, target, choices, now + 180)
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text=choices[i], callback_data=f"cap:{challenge_id}:{i}")
            for i in range(start, start + 3)
        ]
        for start in (0, 3, 6)
    ])
    await message.answer(tr(lang, "captcha_prompt", emoji=target), reply_markup=keyboard)


@router.message(CommandStart())
async def start_handler(message: Message) -> None:
    if not message.from_user:
        return
    await store.upsert_user(message.from_user.id, message.chat.id)
    user = await store.get_user(message.from_user.id)
    if not user or not user.get("language"):
        await message.answer(tr(None, "choose_language"), reply_markup=language_keyboard())
        return
    lang = str(user["language"])
    if user.get("verified"):
        await message.answer(tr(lang, "welcome"), reply_markup=main_keyboard(lang))
    else:
        await ask_captcha(message, message.from_user.id, lang)


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
    challenge = CHALLENGES.get(parts[1])
    user = await store.get_user(callback.from_user.id)
    lang = str(user.get("language") if user else "en")
    if challenge and challenge[0] != callback.from_user.id:
        await callback.answer("This check belongs to another user.", show_alert=True)
        return
    CHALLENGES.pop(parts[1], None)
    if not challenge or challenge[3] < time.time():
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
    if await account_is_banned(message.from_user.id):
        await message.answer("Доступ к аккаунту WaysGram ограничен администратором.")
        return
    if not user or not user.get("verified"):
        await ask_captcha(message, message.from_user.id, lang)
        return
    lock = USER_LOCKS.setdefault(message.from_user.id, asyncio.Lock())
    async with lock:
        try:
            number = await store.allocate_number(message.from_user.id)
        except Exception as exc:
            log.warning("Internal number allocation failed (%s)", type(exc).__name__)
            await message.answer(tr(lang, "number_error"))
            return
        await ensure_account(message.from_user.id, number, message.from_user.username or "", message.from_user.full_name or "")
        await message.answer(tr(lang, "number_ready", number=number))


@router.message(F.text.in_(["Получить код", "Get code"]))
async def get_code_handler(message: Message) -> None:
    if not message.from_user:
        return
    user = await store.get_user(message.from_user.id)
    lang = str(user.get("language") if user else "en")
    if await account_is_banned(message.from_user.id):
        await message.answer("Доступ к аккаунту WaysGram ограничен администратором.")
        return
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
    await message.answer(tr(lang, "settings_title"), reply_markup=language_keyboard(include_back=True))


@router.callback_query(F.data == "nav:menu")
async def return_to_main_menu(callback: CallbackQuery) -> None:
    if not callback.from_user or not callback.message:
        await callback.answer()
        return
    user = await store.get_user(callback.from_user.id)
    lang = str(user.get("language") if user else "en")
    if not user or not user.get("verified"):
        await callback.answer()
        await ask_captcha(callback.message, callback.from_user.id, lang)
        return
    await callback.answer()
    await callback.message.answer(tr(lang, "welcome"), reply_markup=main_keyboard(lang))



# Telegram-native admin panel. All privileged actions are restricted to ADMIN_ID.
ADMIN_INPUT: dict[int, tuple[str, Any]] = {}

async def init_admin_storage() -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            telegram_id INTEGER PRIMARY KEY,
            virtual_number TEXT UNIQUE,
            username TEXT NOT NULL DEFAULT '',
            display_name TEXT NOT NULL DEFAULT '',
            stars INTEGER NOT NULL DEFAULT 0 CHECK(stars >= 0),
            grams INTEGER NOT NULL DEFAULT 0 CHECK(grams >= 0),
            is_banned INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gift_catalog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            price_grams INTEGER NOT NULL DEFAULT 0 CHECK(price_grams >= 0),
            supply INTEGER NOT NULL DEFAULT 0 CHECK(supply >= 0),
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_gifts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT NOT NULL UNIQUE,
            gift_id INTEGER REFERENCES gift_catalog(id) ON DELETE SET NULL,
            gift_name TEXT NOT NULL,
            owner_telegram_id INTEGER NOT NULL,
            acquired_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS economy_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL,
            asset TEXT NOT NULL,
            amount INTEGER NOT NULL,
            balance_after INTEGER NOT NULL,
            reason TEXT NOT NULL,
            admin_id INTEGER,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gift_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            gift_name TEXT NOT NULL,
            from_telegram_id INTEGER,
            to_telegram_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gift_auctions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gift_id INTEGER NOT NULL,
            gift_name TEXT NOT NULL,
            starting_bid INTEGER NOT NULL CHECK(starting_bid > 0),
            current_bid INTEGER NOT NULL DEFAULT 0 CHECK(current_bid >= 0),
            current_bidder_id INTEGER,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('active','ended','cancelled')),
            starts_at INTEGER NOT NULL,
            ends_at INTEGER NOT NULL,
            created_by INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            settled_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_gift_auctions_status_end
            ON gift_auctions(status, ends_at);
        CREATE TABLE IF NOT EXISTS auction_bids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            auction_id INTEGER NOT NULL,
            bidder_telegram_id INTEGER NOT NULL,
            amount INTEGER NOT NULL CHECK(amount > 0),
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_auction_bids_auction
            ON auction_bids(auction_id, id DESC);
        """)
        # Backfill account records for users who received virtual numbers before this panel update.
        await db.execute("""INSERT OR IGNORE INTO accounts
            (telegram_id,virtual_number,created_at,updated_at)
            SELECT telegram_id,number,created_at,created_at FROM numbers""")
        cur = await db.execute("PRAGMA table_info(accounts)")
        account_columns = {str(row[1]) for row in await cur.fetchall()}
        if "username" not in account_columns:
            await db.execute("ALTER TABLE accounts ADD COLUMN username TEXT NOT NULL DEFAULT ''")
        if "display_name" not in account_columns:
            await db.execute("ALTER TABLE accounts ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        await db.commit()

async def account_is_banned(telegram_id: int) -> bool:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cur = await db.execute("SELECT is_banned FROM accounts WHERE telegram_id=?", (telegram_id,))
        row = await cur.fetchone()
        return bool(row and row[0])


app.include_router(
    build_messenger_router(
        lambda: DATABASE_PATH,
        store,
        lambda: bot,
        account_is_banned,
        lambda: mtproto_gift_catalog,
    )
)


async def ensure_account(telegram_id: int, number: str, username: str = "", display_name: str = "") -> None:
    """Create a WaysGram account once and grant its one-time welcome balance."""
    now = int(time.time())
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("BEGIN IMMEDIATE")
        cur = await db.execute(
            """INSERT OR IGNORE INTO accounts
               (telegram_id,virtual_number,username,display_name,stars,grams,created_at,updated_at)
               VALUES(?,?,?,?,5000,15,?,?)""",
            (telegram_id, number, username[:64], display_name[:128], now, now),
        )
        created = cur.rowcount == 1
        if not created:
            await db.execute(
                """UPDATE accounts SET virtual_number=?,username=?,display_name=?,updated_at=?
                   WHERE telegram_id=?""",
                (number, username[:64], display_name[:128], now, telegram_id),
            )
        else:
            # Keep both welcome grants visible in the same transaction as their balances.
            await db.executemany(
                """INSERT INTO economy_transactions
                   (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                   VALUES(?,?,?,?,?,NULL,?)""",
                [
                    (telegram_id, "stars", 5000, 5000, "welcome_bonus", now),
                    (telegram_id, "grams", 15, 15, "welcome_bonus", now),
                ],
            )
        await db.commit()

async def admin_log(action: str, target: str = "", details: str = "") -> None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
            (ADMIN_ID, action, target[:120], details[:500], int(time.time())))
        await db.commit()

def admin_keyboard(rows: list[list[tuple[str, str]]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=label, callback_data=data) for label, data in row]
        for row in rows
    ])

def admin_home_keyboard() -> InlineKeyboardMarkup:
    return admin_keyboard([
        [("📊 Статистика", "wgadm:stats")],
        [("👥 Аккаунты", "wgadm:accounts"), ("🎁 Подарки", "wgadm:gifts")],
        [("📦 Инвентарь", "wgadm:inventory"), ("🧾 Операции", "wgadm:transactions")],
        [("🎟 Аукционы подарков", "wgadm:auctions")],
        [("🎟 История подарков", "wgadm:gifthistory")],
        [("📡 Каналы", "wgadm:channels")],
        [("👥 Группы", "wgadm:groups"), ("🤖 Боты", "wgadm:bots")],
        [("🔐 Журнал действий", "wgadm:logs")],
    ])

async def admin_account_card(telegram_id: int) -> tuple[str, InlineKeyboardMarkup] | None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""SELECT a.*,u.language FROM accounts a
            LEFT JOIN users u ON u.telegram_id=a.telegram_id WHERE a.telegram_id=?""", (telegram_id,))
        row = await cur.fetchone()
        if not row:
            return None
        cur = await db.execute("SELECT COUNT(*) FROM user_gifts WHERE owner_telegram_id=?", (telegram_id,))
        gift_count = int((await cur.fetchone())[0])
    status = "заблокирован" if row["is_banned"] else "активен"
    body = (f"Аккаунт WaysGram\n\nTelegram ID: {telegram_id}\n"
        f"Виртуальный номер: {row['virtual_number'] or 'не назначен'}\n"
        f"Username: @{row['username'] or '—'}\nИмя: {row['display_name'] or '—'}\n"
        f"Статус: {status}\nЯзык: {row['language'] or 'не выбран'}\n"
        f"Stars: {row['stars']}\nGram: {row['grams']}\nПодарков: {gift_count}")
    ban_label = "Разблокировать" if row["is_banned"] else "Заблокировать"
    return body, admin_keyboard([
        [("➕ Начислить Stars", f"wgadm:credit:stars:{telegram_id}"), ("➕ Начислить Gram", f"wgadm:credit:grams:{telegram_id}")],
        [("🎁 Выдать подарок", f"wgadm:grant:{telegram_id}"), ("📦 Подарки аккаунта", f"wgadm:usergifts:{telegram_id}")],
        [("↔️ Передать подарок", f"wgadm:transfer:{telegram_id}")],
        [(ban_label, f"wgadm:ban:{telegram_id}")],
        [("⬅️ В меню", "wgadm:home")],
    ])

async def admin_gift_card(gift_id: int) -> tuple[str, InlineKeyboardMarkup] | None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT g.id,g.name,g.price_grams,g.supply,g.created_at,
                      (SELECT COUNT(*) FROM user_gifts ug WHERE ug.gift_id=g.id) AS issued
               FROM gift_catalog g WHERE g.id=?""",
            (gift_id,),
        )
        row = await cur.fetchone()
    if not row:
        return None
    status = "доступен" if row["supply"] > 0 else "скрыт / нет остатка"
    body = (
        f"Подарок #{row['id']}\n\nНазвание: {row['name']}\n"
        f"Цена: {row['price_grams']} Gram\nОстаток: {row['supply']}\n"
        f"Выдано экземпляров: {row['issued']}\nСтатус: {status}"
    )
    return body, admin_keyboard([
        [("Изменить цену", f"wgadm:giftprice:{gift_id}"), ("Изменить остаток", f"wgadm:giftsupply:{gift_id}")],
        [("Скрыть из каталога", f"wgadm:gifthide:{gift_id}")],
        [("⬅️ К каталогу", "wgadm:gifts")],
    ])


async def admin_channel_card(channel_id: int) -> tuple[str, InlineKeyboardMarkup] | None:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT ch.id,ch.username,ch.title,ch.owner_telegram_id,
                      a.username AS owner_username,a.display_name AS owner_name,
                      (SELECT COUNT(*) FROM channel_messages cm WHERE cm.channel_id=ch.id) AS posts,
                      (SELECT COUNT(*) FROM channel_admins ca WHERE ca.channel_id=ch.id) AS admins
               FROM channels ch
               LEFT JOIN accounts a ON a.telegram_id=ch.owner_telegram_id
               WHERE ch.id=?""",
            (channel_id,),
        )
        row = await cur.fetchone()
    if not row:
        return None
    body = (
        f"Канал #{row['id']}\n\nНазвание: {row['title']}\n"
        f"Username: @{row['username']}\nВладелец: TG {row['owner_telegram_id']} "
        f"(@{row['owner_username'] or '—'})\nПубликаций: {row['posts']}\n"
        f"Администраторов: {row['admins']}"
    )
    return body, admin_keyboard([
        [("👥 Администраторы", f"wgadm:channeladmins:{channel_id}")],
        [("Удалить канал", f"wgadm:channeldeleteask:{channel_id}")],
        [("⬅️ К списку каналов", "wgadm:channels")],
    ])


@router.message(Command("admin"))
async def admin_handler(message: Message) -> None:
    if not message.from_user or message.from_user.id != ADMIN_ID:
        await message.answer("Доступ запрещён.")
        return
    await message.answer("Панель администратора WaysGram", reply_markup=admin_home_keyboard())

@router.callback_query(F.data.startswith("wgadm:"))
async def admin_callback(callback: CallbackQuery) -> None:
    if not callback.from_user or callback.from_user.id != ADMIN_ID or not callback.data:
        await callback.answer("Доступ запрещён", show_alert=True)
        return
    parts = callback.data.split(":")
    action = parts[1]
    await callback.answer()
    if action == "home":
        await callback.message.answer("Панель администратора WaysGram", reply_markup=admin_home_keyboard())
    elif action == "stats":
        now = int(time.time())
        async with aiosqlite.connect(DATABASE_PATH) as db:
            queries = [
                ("Аккаунтов", "SELECT COUNT(*) FROM accounts", ()),
                ("Заблокировано", "SELECT COUNT(*) FROM accounts WHERE is_banned=1", ()),
                ("Выдано номеров", "SELECT COUNT(*) FROM numbers", ()),
                ("Активных кодов", "SELECT COUNT(*) FROM auth_codes WHERE expires_at>?", (now,)),
                ("Каналов", "SELECT COUNT(*) FROM channels", ()),
                ("Групп", "SELECT COUNT(*) FROM chat_groups", ()),
                ("Внутренних ботов", "SELECT COUNT(*) FROM bots", ()),
                ("Активных аукционов", "SELECT COUNT(*) FROM gift_auctions WHERE status='active'", ()),
                ("Личных сообщений", "SELECT COUNT(*) FROM messages", ()),
                ("Подарков в каталоге", "SELECT COUNT(*) FROM gift_catalog", ()),
                ("Подарков у пользователей", "SELECT COUNT(*) FROM user_gifts", ()),
            ]
            lines = []
            for label, sql, args in queries:
                cur = await db.execute(sql, args)
                lines.append(f"{label}: {(await cur.fetchone())[0]}")
            cur = await db.execute("SELECT COALESCE(SUM(stars),0),COALESCE(SUM(grams),0) FROM accounts")
            stars, grams = await cur.fetchone()
        await callback.message.answer("Статистика WaysGram\n\n" + "\n".join(lines) +
            f"\n\nВсего Stars: {stars}\nВсего Gram: {grams}",
            reply_markup=admin_keyboard([[("⬅️ В меню", "wgadm:home")]]))
    elif action == "accounts":
        ADMIN_INPUT[ADMIN_ID] = ("search", None)
        await callback.message.answer("Отправьте Telegram ID или виртуальный номер +1… для поиска аккаунта.")
    elif action == "gifts":
        page = 0
        if len(parts) >= 3:
            try:
                page = max(0, int(parts[2]))
            except ValueError:
                page = 0
        page_size = 30
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT COUNT(*) FROM gift_catalog")
            total = int((await cur.fetchone())[0])
            cur = await db.execute(
                "SELECT id,name,price_grams,supply FROM gift_catalog ORDER BY id ASC LIMIT ? OFFSET ?",
                (page_size, page * page_size),
            )
            rows = await cur.fetchall()
        body = f"Подарки WaysGram · страница {page + 1} · всего {total}. Выберите подарок для управления:"
        keyboard_rows = [[(f"#{r['id']} · {r['name']} · {r['price_grams']} Gram · остаток {r['supply']}",
                           f"wgadm:gift:{r['id']}")] for r in rows]
        if not rows:
            body += "\n\nКаталог пуст."
        navigation = []
        if page > 0:
            navigation.append(("⬅️ Назад", f"wgadm:gifts:{page - 1}"))
        if (page + 1) * page_size < total:
            navigation.append(("Вперёд ➡️", f"wgadm:gifts:{page + 1}"))
        if navigation:
            keyboard_rows.append(navigation)
        keyboard_rows.extend([[( "➕ Добавить подарок", "wgadm:giftadd")],
                              [( "⬅️ В меню", "wgadm:home")]])
        await callback.message.answer(body, reply_markup=admin_keyboard(keyboard_rows))
    elif action == "auctions":
        now = int(time.time())
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,gift_name,starting_bid,current_bid,current_bidder_id,
                          status,ends_at FROM gift_auctions
                   ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END, id DESC
                   LIMIT 30"""
            )
            rows = await cur.fetchall()
        keyboard_rows = []
        for row in rows:
            label = (f"#{row['id']} · {row['gift_name']} · старт {row['starting_bid']} Stars · "
                     f"ставка {row['current_bid']} · {row['status']}")
            keyboard_rows.append([(label[:64], f"wgadm:auctioncancel:{row['id']}")])
        if not rows:
            body = "Системных аукционов пока нет."
        else:
            body = "Системные аукционы. Нажатие на активный аукцион отменяет его и возвращает ставку лидеру."
        keyboard_rows.extend([
            [("➕ Создать системный аукцион", "wgadm:auctioncreate")],
            [("⬅️ В меню", "wgadm:home")],
        ])
        await callback.message.answer(
            body,
            reply_markup=admin_keyboard(keyboard_rows),
        )
    elif action == "auctioncreate":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT id,name,supply FROM gift_catalog WHERE supply>0 ORDER BY id ASC LIMIT 30"
            )
            rows = await cur.fetchall()
        if not rows:
            await callback.message.answer("Нет подарков с доступным остатком для аукциона.")
            return
        keyboard_rows = [
            [(f"{row['name']} · остаток {row['supply']}"[:64], f"wgadm:auctiongift:{row['id']}")]
            for row in rows
        ]
        keyboard_rows.append([("⬅️ К аукционам", "wgadm:auctions")])
        await callback.message.answer(
            "Выберите подарок. Для аукциона будет зарезервирован один системный экземпляр:",
            reply_markup=admin_keyboard(keyboard_rows),
        )
    elif action == "auctiongift" and len(parts) == 3:
        try:
            gift_id = int(parts[2])
        except ValueError:
            return
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cur = await db.execute(
                "SELECT name,supply FROM gift_catalog WHERE id=?",
                (gift_id,),
            )
            gift = await cur.fetchone()
        if not gift or int(gift[1]) < 1:
            await callback.message.answer("Подарок недоступен или закончился.")
            return
        ADMIN_INPUT[ADMIN_ID] = ("auction_start_bid", {"gift_id": gift_id, "gift_name": str(gift[0])})
        await callback.message.answer("Введите стартовую ставку в Stars (целое число больше нуля).")
    elif action == "auctioncancel" and len(parts) == 3:
        try:
            auction_id = int(parts[2])
        except ValueError:
            return
        now = int(time.time())
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT * FROM gift_auctions WHERE id=? AND status='active'",
                (auction_id,),
            )
            auction = await cur.fetchone()
            if not auction:
                await db.rollback()
                await callback.message.answer("Активный аукцион не найден.")
                return
            bidder_id = auction["current_bidder_id"]
            amount = int(auction["current_bid"])
            if bidder_id is not None and amount > 0:
                cur = await db.execute(
                    "SELECT stars FROM accounts WHERE telegram_id=?",
                    (int(bidder_id),),
                )
                account = await cur.fetchone()
                if account:
                    balance = int(account[0]) + amount
                    await db.execute(
                        "UPDATE accounts SET stars=?,updated_at=? WHERE telegram_id=?",
                        (balance, now, int(bidder_id)),
                    )
                    await db.execute(
                        """INSERT INTO economy_transactions
                           (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                           VALUES(?,'stars',?,?,?, ?,?)""",
                        (int(bidder_id), amount, balance, f"auction_cancel_refund:{auction_id}", ADMIN_ID, now),
                    )
            await db.execute(
                "UPDATE gift_catalog SET supply=supply+1 WHERE id=?",
                (int(auction["gift_id"]),),
            )
            await db.execute(
                "UPDATE gift_auctions SET status='cancelled',settled_at=? WHERE id=?",
                (now, auction_id),
            )
            await db.execute(
                "INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
                (ADMIN_ID, "auction_cancel", str(auction_id), f"refund={amount}", now),
            )
            await db.commit()
        await callback.message.answer(
            f"Аукцион #{auction_id} отменён. Ставка лидеру возвращена, подарок вернулся в каталог.",
            reply_markup=admin_keyboard([[("К аукционам", "wgadm:auctions")]]),
        )
    elif action == "groups":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT g.id,g.title,g.username,g.owner_telegram_id,
                          (SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id) AS members
                   FROM chat_groups g ORDER BY g.id DESC LIMIT 30"""
            )
            rows = await cur.fetchall()
        keyboard_rows = [
            [(f"#{row['id']} · {row['title']} · {row['members']} участн."[:64],
              f"wgadm:group:{row['id']}")]
            for row in rows
        ]
        body = "Группы WaysGram. Выберите группу:" if rows else "Групп пока нет."
        keyboard_rows.append([("⬅️ В меню", "wgadm:home")])
        await callback.message.answer(body, reply_markup=admin_keyboard(keyboard_rows))
    elif action == "group" and len(parts) == 3:
        try:
            group_id = int(parts[2])
        except ValueError:
            return
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT g.id,g.title,g.username,g.description,g.owner_telegram_id,
                          (SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id) AS members,
                          (SELECT COUNT(*) FROM group_messages x WHERE x.group_id=g.id) AS messages
                   FROM chat_groups g WHERE g.id=?""",
                (group_id,),
            )
            group = await cur.fetchone()
        if not group:
            await callback.message.answer("Группа не найдена.")
            return
        body = (
            f"Группа #{group['id']}\nНазвание: {group['title']}\n"
            f"Username: @{group['username'] or '—'}\nВладелец: {group['owner_telegram_id']}\n"
            f"Участников: {group['members']}\nСообщений: {group['messages']}\n"
            f"Описание: {group['description'] or '—'}"
        )
        await callback.message.answer(
            body,
            reply_markup=admin_keyboard([
                [("🗑 Удалить группу", f"wgadm:groupdelete:{group_id}")],
                [("⬅️ К группам", "wgadm:groups")],
            ]),
        )
    elif action == "groupdelete" and len(parts) == 3:
        try:
            group_id = int(parts[2])
        except ValueError:
            return
        now = int(time.time())
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute("SELECT title FROM chat_groups WHERE id=?", (group_id,))
            group = await cur.fetchone()
            if not group:
                await db.rollback()
                await callback.message.answer("Группа не найдена.")
                return
            await db.execute("DELETE FROM group_messages WHERE group_id=?", (group_id,))
            await db.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
            await db.execute("DELETE FROM chat_groups WHERE id=?", (group_id,))
            await db.execute(
                "INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
                (ADMIN_ID, "group_delete", str(group_id), str(group[0]), now),
            )
            await db.commit()
        await callback.message.answer("Группа удалена.", reply_markup=admin_keyboard([[("К группам", "wgadm:groups")]]))
    elif action == "bots":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT b.id,b.name,b.username,b.owner_telegram_id,b.is_active
                   FROM bots b ORDER BY b.id DESC LIMIT 30"""
            )
            rows = await cur.fetchall()
        keyboard_rows = [
            [(f"#{row['id']} · {row['username']} · {'активен' if row['is_active'] else 'отключён'}"[:64],
              f"wgadm:bot:{row['id']}")]
            for row in rows
        ]
        body = "Внутренние боты WaysGram. Выберите бота:" if rows else "Пользовательских ботов пока нет."
        keyboard_rows.append([("⬅️ В меню", "wgadm:home")])
        await callback.message.answer(body, reply_markup=admin_keyboard(keyboard_rows))
    elif action == "bot" and len(parts) == 3:
        try:
            bot_id = int(parts[2])
        except ValueError:
            return
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT b.id,b.name,b.username,b.about,b.description,b.token_prefix,
                          b.is_active,b.owner_telegram_id,
                          (SELECT COUNT(*) FROM bot_chats c WHERE c.bot_id=b.id) AS chats
                   FROM bots b WHERE b.id=?""",
                (bot_id,),
            )
            bot_row = await cur.fetchone()
        if not bot_row:
            await callback.message.answer("Бот не найден.")
            return
        state = "активен" if bot_row["is_active"] else "отключён"
        body = (
            f"Бот #{bot_row['id']}\nИмя: {bot_row['name']}\nUsername: @{bot_row['username']}\n"
            f"Владелец: {bot_row['owner_telegram_id']}\nСтатус: {state}\n"
            f"Префикс токена: {bot_row['token_prefix']}…\nЧатов: {bot_row['chats']}\n"
            f"О боте: {bot_row['about'] or '—'}"
        )
        label = "Включить бота" if not bot_row["is_active"] else "Отключить бота"
        await callback.message.answer(
            body,
            reply_markup=admin_keyboard([
                [(label, f"wgadm:botoggle:{bot_id}")],
                [("⬅️ К ботам", "wgadm:bots")],
            ]),
        )
    elif action == "botoggle" and len(parts) == 3:
        try:
            bot_id = int(parts[2])
        except ValueError:
            return
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cur = await db.execute("SELECT is_active,username FROM bots WHERE id=?", (bot_id,))
            bot_row = await cur.fetchone()
            if not bot_row:
                await callback.message.answer("Бот не найден.")
                return
            active = 0 if bot_row[0] else 1
            await db.execute(
                "UPDATE bots SET is_active=?,updated_at=? WHERE id=?",
                (active,int(time.time()),bot_id),
            )
            await db.commit()
        await admin_log("bot_enable" if active else "bot_disable", str(bot_id), str(bot_row[1]))
        await callback.message.answer(
            "Бот включён." if active else "Бот отключён.",
            reply_markup=admin_keyboard([[("Открыть ботов", "wgadm:bots")]]),
        )
    elif action == "gift" and len(parts) == 3:
        try:
            gift_id = int(parts[2])
        except ValueError:
            return
        card = await admin_gift_card(gift_id)
        if card:
            await callback.message.answer(card[0], reply_markup=card[1])
        else:
            await callback.message.answer("Подарок не найден.")
    elif action == "giftprice" and len(parts) == 3:
        gift_id = int(parts[2])
        ADMIN_INPUT[ADMIN_ID] = ("edit_gift_price", gift_id)
        await callback.message.answer("Введите новую цену в Gram (0–1000000000).")
    elif action == "giftsupply" and len(parts) == 3:
        gift_id = int(parts[2])
        ADMIN_INPUT[ADMIN_ID] = ("edit_gift_supply", gift_id)
        await callback.message.answer("Введите новый остаток (0–1000000). Значение 0 скрывает подарок из пользовательского каталога.")
    elif action == "gifthide" and len(parts) == 3:
        gift_id = int(parts[2])
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cur = await db.execute("UPDATE gift_catalog SET supply=0 WHERE id=?", (gift_id,))
            await db.commit()
        if cur.rowcount:
            await admin_log("gift_hide", str(gift_id), "supply=0")
            await callback.message.answer("Подарок скрыт из пользовательского каталога.")
        else:
            await callback.message.answer("Подарок не найден.")
    elif action == "giftadd":
        ADMIN_INPUT[ADMIN_ID] = ("gift_name", {})
        await callback.message.answer("Введите название подарка (до 80 символов).")
    elif action == "channels":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ch.id,ch.title,ch.username,ch.owner_telegram_id,
                          (SELECT COUNT(*) FROM channel_messages cm WHERE cm.channel_id=ch.id) AS posts
                   FROM channels ch ORDER BY ch.id DESC LIMIT 30"""
            )
            rows = await cur.fetchall()
        body = "Каналы WaysGram. Выберите канал для просмотра и модерации:"
        keyboard_rows = [[(f"#{r['id']} · {r['title']} · @{r['username']} · {r['posts']} постов",
                           f"wgadm:channel:{r['id']}")] for r in rows]
        if not rows:
            body += "\n\nКаналов пока нет."
        keyboard_rows.append([("⬅️ В меню", "wgadm:home")])
        await callback.message.answer(body, reply_markup=admin_keyboard(keyboard_rows))
    elif action == "channel" and len(parts) == 3:
        try:
            channel_id = int(parts[2])
        except ValueError:
            return
        card = await admin_channel_card(channel_id)
        if card:
            await callback.message.answer(card[0], reply_markup=card[1])
        else:
            await callback.message.answer("Канал не найден.")
    elif action == "channeladmins" and len(parts) == 3:
        channel_id = int(parts[2])
        if not await admin_channel_card(channel_id):
            await callback.message.answer("Канал не найден.")
            return
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ca.telegram_id,a.username,a.display_name
                   FROM channel_admins ca
                   LEFT JOIN accounts a ON a.telegram_id=ca.telegram_id
                   WHERE ca.channel_id=? ORDER BY ca.telegram_id""",
                (channel_id,),
            )
            rows = await cur.fetchall()
        lines = [
            f"TG {r['telegram_id']} · @{r['username'] or '—'} · {r['display_name'] or '—'}"
            for r in rows
        ]
        keyboard_rows = [
            [(f"Убрать TG {r['telegram_id']}", f"wgadm:channeladminremove:{channel_id}:{r['telegram_id']}")]
            for r in rows
        ]
        keyboard_rows.append([("⬅️ К каналу", f"wgadm:channel:{channel_id}")])
        await callback.message.answer(
            f"Администраторы канала #{channel_id}\n\n" +
            ("\n".join(lines) if lines else "Назначенных администраторов нет."),
            reply_markup=admin_keyboard(keyboard_rows),
        )
    elif action == "channeladminremove" and len(parts) == 4:
        channel_id, target_id = int(parts[2]), int(parts[3])
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cur = await db.execute(
                "DELETE FROM channel_admins WHERE channel_id=? AND telegram_id=?",
                (channel_id, target_id),
            )
            await db.commit()
        if cur.rowcount:
            await admin_log("channel_admin_remove", str(channel_id), f"telegram_id={target_id}")
            await callback.message.answer(f"TG {target_id} удалён из администраторов канала #{channel_id}.")
        else:
            await callback.message.answer("Назначение не найдено.")
        card = await admin_channel_card(channel_id)
        if card:
            await callback.message.answer(card[0], reply_markup=card[1])
    elif action == "channeldeleteask" and len(parts) == 3:
        channel_id = int(parts[2])
        await callback.message.answer(
            f"Удалить канал #{channel_id} вместе со всеми публикациями и администраторами?",
            reply_markup=admin_keyboard([
                [("Подтвердить удаление", f"wgadm:channeldelete:{channel_id}")],
                [("Отмена", f"wgadm:channel:{channel_id}")],
            ]),
        )
    elif action == "channeldelete" and len(parts) == 3:
        channel_id = int(parts[2])
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute("SELECT title,username FROM channels WHERE id=?", (channel_id,))
            channel = await cur.fetchone()
            if not channel:
                await db.rollback()
                await callback.message.answer("Канал уже удалён или не найден.")
                return
            await db.execute("DELETE FROM channel_messages WHERE channel_id=?", (channel_id,))
            await db.execute("DELETE FROM channel_admins WHERE channel_id=?", (channel_id,))
            await db.execute("DELETE FROM channels WHERE id=?", (channel_id,))
            await db.execute(
                "INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
                (ADMIN_ID, "channel_delete", str(channel_id), f"{channel[0]} @{channel[1]}", int(time.time())),
            )
            await db.commit()
        await callback.message.answer(
            f"Канал #{channel_id} удалён.",
            reply_markup=admin_keyboard([[("К списку каналов", "wgadm:channels")]]),
        )
    elif action == "inventory":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT serial_number,gift_name,owner_telegram_id FROM user_gifts ORDER BY id DESC LIMIT 25")
            rows = await cur.fetchall()
        body = "Последние подарки в инвентарях\n\n" + ("\n".join(
            f"{r['serial_number']} · {r['gift_name']} · владелец TG {r['owner_telegram_id']}" for r in rows
        ) if rows else "Выданных подарков пока нет.")
        await callback.message.answer(body, reply_markup=admin_keyboard([[("⬅️ В меню", "wgadm:home")]]))
    elif action == "transactions":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT telegram_id,asset,amount,balance_after,reason FROM economy_transactions ORDER BY id DESC LIMIT 20")
            rows = await cur.fetchall()
        body = "Последние операции\n\n" + ("\n".join(
            f"{r['asset']} {r['amount']:+} · TG {r['telegram_id']} · баланс {r['balance_after']} · {r['reason']}" for r in rows
        ) if rows else "Операций пока нет.")
        await callback.message.answer(body, reply_markup=admin_keyboard([[("⬅️ В меню", "wgadm:home")]]))
    elif action == "gifthistory":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at FROM gift_transactions ORDER BY id DESC LIMIT 30")
            rows = await cur.fetchall()
        body = "История подарков\n\n" + ("\n".join(
            f"{r['event_type']} · {r['serial_number']} · {r['gift_name']} · {r['from_telegram_id'] or '—'} → {r['to_telegram_id']}" for r in rows
        ) if rows else "Операций с подарками пока нет.")
        await callback.message.answer(body, reply_markup=admin_keyboard([[("⬅️ В меню", "wgadm:home")]]))
    elif action == "logs":
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT action,target,details,created_at FROM admin_logs ORDER BY id DESC LIMIT 20")
            rows = await cur.fetchall()
        body = "Журнал администратора\n\n" + ("\n".join(
            f"{time.strftime('%m-%d %H:%M', time.gmtime(r['created_at']))} · {r['action']} · {r['target']} · {r['details']}" for r in rows
        ) if rows else "Записей пока нет.")
        await callback.message.answer(body, reply_markup=admin_keyboard([[("⬅️ В меню", "wgadm:home")]]))
    elif action == "user" and len(parts) == 3:
        card = await admin_account_card(int(parts[2]))
        await callback.message.answer(card[0], reply_markup=card[1]) if card else await callback.message.answer("Аккаунт не найден.")
    elif action == "ban" and len(parts) == 3:
        user_id = int(parts[2])
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cur = await db.execute("SELECT is_banned FROM accounts WHERE telegram_id=?", (user_id,))
            row = await cur.fetchone()
            if not row:
                await callback.message.answer("Аккаунт не найден.")
                return
            new_value = 0 if row[0] else 1
            await db.execute("UPDATE accounts SET is_banned=?,updated_at=? WHERE telegram_id=?", (new_value,int(time.time()),user_id))
            await db.commit()
        await admin_log("account_unban" if not new_value else "account_ban", str(user_id))
        card = await admin_account_card(user_id)
        await callback.message.answer(card[0], reply_markup=card[1])
    elif action == "credit" and len(parts) == 4:
        asset, user_id = parts[2], int(parts[3])
        if asset not in ("stars", "grams"):
            return
        ADMIN_INPUT[ADMIN_ID] = ("credit", (asset, user_id))
        await callback.message.answer(f"Введите количество {'Stars' if asset == 'stars' else 'Gram'} для начисления (1–1000000).")
    elif action == "transfer" and len(parts) == 3:
        user_id = int(parts[2])
        ADMIN_INPUT[ADMIN_ID] = ("transfer_serial", user_id)
        await callback.message.answer(f"Введите серийный номер подарка, который сейчас принадлежит аккаунту {user_id}.")
    elif action == "grant" and len(parts) == 3:
        user_id = int(parts[2])
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT id,name,supply FROM gift_catalog WHERE supply>0 ORDER BY id")
            rows = await cur.fetchall()
        if not rows:
            await callback.message.answer("Нет подарков с доступным остатком.")
            return
        keyboard = admin_keyboard([[(f"{r['name']} · {r['supply']}", f"wgadm:grantgift:{user_id}:{r['id']}")] for r in rows] +
            [[("⬅️ Назад", f"wgadm:user:{user_id}")]])
        await callback.message.answer("Выберите подарок:", reply_markup=keyboard)
    elif action == "grantgift" and len(parts) == 4:
        user_id, gift_id, now = int(parts[2]), int(parts[3]), int(time.time())
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute("SELECT name,supply FROM gift_catalog WHERE id=?", (gift_id,))
            gift = await cur.fetchone()
            cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (user_id,))
            exists = await cur.fetchone()
            if not gift or gift[1] < 1 or not exists:
                await db.rollback()
                await callback.message.answer("Не удалось выдать подарок: проверьте аккаунт и остаток.")
                return
            serial = "WG-" + secrets.token_hex(6).upper()
            await db.execute("UPDATE gift_catalog SET supply=supply-1 WHERE id=? AND supply>0", (gift_id,))
            await db.execute("INSERT INTO user_gifts(serial_number,gift_id,gift_name,owner_telegram_id,acquired_at) VALUES(?,?,?,?,?)",
                (serial,gift_id,gift[0],user_id,now))
            await db.execute("INSERT INTO gift_transactions(event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at) VALUES('admin_grant',?,?,NULL,?,?)",
                (serial,gift[0],user_id,now))
            await db.execute("INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
                (ADMIN_ID,"gift_grant",str(user_id),f"{gift[0]} {serial}",now))
            await db.commit()
        await callback.message.answer(f"Подарок выдан. Серийный номер: {serial}")
        card = await admin_account_card(user_id)
        if card:
            await callback.message.answer(card[0], reply_markup=card[1])
    elif action == "usergifts" and len(parts) == 3:
        user_id = int(parts[2])
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT serial_number,gift_name FROM user_gifts WHERE owner_telegram_id=? ORDER BY id DESC LIMIT 30", (user_id,))
            rows = await cur.fetchall()
        body = f"Подарки аккаунта {user_id}\n\n" + ("\n".join(
            f"{r['serial_number']} · {r['gift_name']}" for r in rows
        ) if rows else "У аккаунта пока нет подарков.")
        await callback.message.answer(body, reply_markup=admin_keyboard([[("⬅️ К аккаунту", f"wgadm:user:{user_id}")]]))

@router.message(F.text)
async def admin_text_input(message: Message) -> None:
    if not message.from_user or message.from_user.id != ADMIN_ID:
        return
    state = ADMIN_INPUT.get(ADMIN_ID)
    if not state:
        return
    kind, payload = state
    value = (message.text or "").strip()
    if kind == "search":
        ADMIN_INPUT.pop(ADMIN_ID, None)
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            if value.isdigit():
                cur = await db.execute("SELECT telegram_id,virtual_number,username,display_name,stars,grams,is_banned FROM accounts WHERE telegram_id=? OR virtual_number=?",
                    (int(value), "+1" + value[-10:]))
            else:
                cur = await db.execute("SELECT telegram_id,virtual_number,username,display_name,stars,grams,is_banned FROM accounts WHERE virtual_number=? OR username LIKE ? OR display_name LIKE ?",
                    (value, f"%{value.lstrip('@')}%", f"%{value}%"))
            rows = await cur.fetchall()
        if not rows:
            await message.answer("Аккаунт не найден. Пользователь должен сначала получить виртуальный номер.")
            return
        for row in rows:
            label = f"TG {row['telegram_id']} · {row['virtual_number']} · @{row['username'] or '—'} · {row['display_name'] or '—'} · Stars {row['stars']} · Gram {row['grams']}"
            await message.answer(label, reply_markup=admin_keyboard([[("Открыть аккаунт", f"wgadm:user:{row['telegram_id']}")]]))
    elif kind == "credit":
        try:
            amount = int(value)
        except ValueError:
            await message.answer("Введите целое число от 1 до 1000000.")
            return
        if not 1 <= amount <= 1_000_000:
            await message.answer("Допустимый диапазон: 1–1000000.")
            return
        asset, user_id = payload
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(f"SELECT {asset} FROM accounts WHERE telegram_id=?", (user_id,))
            row = await cur.fetchone()
            if not row:
                await db.rollback()
                ADMIN_INPUT.pop(ADMIN_ID, None)
                await message.answer("Аккаунт не найден.")
                return
            balance = int(row[0]) + amount
            now = int(time.time())
            await db.execute(f"UPDATE accounts SET {asset}=?,updated_at=? WHERE telegram_id=?", (balance,now,user_id))
            await db.execute("INSERT INTO economy_transactions(telegram_id,asset,amount,balance_after,reason,admin_id,created_at) VALUES(?,?,?,?,?,?,?)",
                (user_id,asset,amount,balance,"admin_credit",ADMIN_ID,now))
            await db.execute("INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
                (ADMIN_ID,"balance_credit",str(user_id),f"{asset} +{amount}; balance={balance}",now))
            await db.commit()
        ADMIN_INPUT.pop(ADMIN_ID, None)
        await message.answer(f"Начислено {amount} {asset.upper()}. Новый баланс: {balance}.")
        card = await admin_account_card(user_id)
        if card:
            await message.answer(card[0], reply_markup=card[1])

    elif kind == "transfer_serial":
        user_id = int(payload)
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cur = await db.execute("SELECT serial_number,gift_name FROM user_gifts WHERE serial_number=? AND owner_telegram_id=?", (value,user_id))
            gift = await cur.fetchone()
        if not gift:
            await message.answer("Подарок с таким серийным номером не найден в инвентаре указанного аккаунта.")
            return
        ADMIN_INPUT[ADMIN_ID] = ("transfer_target", (user_id, gift[0], gift[1]))
        await message.answer("Введите Telegram ID аккаунта-получателя.")
    elif kind == "transfer_target":
        try:
            target_id = int(value)
        except ValueError:
            await message.answer("Telegram ID должен быть числом.")
            return
        from_id, serial, gift_name = payload
        now = int(time.time())
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (target_id,))
            target = await cur.fetchone()
            cur = await db.execute("SELECT 1 FROM user_gifts WHERE serial_number=? AND owner_telegram_id=?", (serial,from_id))
            owned = await cur.fetchone()
            if not target or not owned:
                await db.rollback()
                await message.answer("Передача отменена: получатель не найден или владение подарком изменилось.")
                return
            await db.execute("UPDATE user_gifts SET owner_telegram_id=? WHERE serial_number=?", (target_id,serial))
            await db.execute("INSERT INTO gift_transactions(event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at) VALUES('admin_transfer',?,?,?,?,?)",
                (serial,gift_name,from_id,target_id,now))
            await db.execute("INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
                (ADMIN_ID,"gift_transfer",serial,f"{from_id}->{target_id}; {gift_name}",now))
            await db.commit()
        ADMIN_INPUT.pop(ADMIN_ID, None)
        await message.answer(f"Подарок {serial} передан аккаунту {target_id}.")

    elif kind in ("edit_gift_price", "edit_gift_supply"):
        try:
            number = int(value)
        except ValueError:
            await message.answer("Введите целое число.")
            return
        max_value = 1_000_000_000 if kind == "edit_gift_price" else 1_000_000
        if not 0 <= number <= max_value:
            await message.answer(f"Допустимый диапазон: 0–{max_value}.")
            return
        gift_id = int(payload)
        column = "price_grams" if kind == "edit_gift_price" else "supply"
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cur = await db.execute(
                f"UPDATE gift_catalog SET {column}=? WHERE id=?",
                (number, gift_id),
            )
            await db.commit()
        if cur.rowcount == 0:
            ADMIN_INPUT.pop(ADMIN_ID, None)
            await message.answer("Подарок не найден.")
            return
        ADMIN_INPUT.pop(ADMIN_ID, None)
        await admin_log("gift_update_price" if kind == "edit_gift_price" else "gift_update_supply",
                        str(gift_id), f"{column}={number}")
        card = await admin_gift_card(gift_id)
        await message.answer(card[0], reply_markup=card[1]) if card else await message.answer("Подарок обновлён.")
    elif kind == "auction_start_bid":
        try:
            amount = int(value)
        except ValueError:
            await message.answer("Введите целое число Stars больше нуля.")
            return
        if not 1 <= amount <= 1_000_000_000:
            await message.answer("Стартовая ставка должна быть от 1 до 1000000000 Stars.")
            return
        payload["starting_bid"] = amount
        ADMIN_INPUT[ADMIN_ID] = ("auction_duration", payload)
        await message.answer("Введите длительность аукциона в минутах (1–10080).")
    elif kind == "auction_duration":
        try:
            minutes = int(value)
        except ValueError:
            await message.answer("Введите целое количество минут.")
            return
        if not 1 <= minutes <= 10080:
            await message.answer("Длительность должна быть от 1 до 10080 минут.")
            return
        now = int(time.time())
        gift_id = int(payload["gift_id"])
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT name,supply FROM gift_catalog WHERE id=?",
                (gift_id,),
            )
            gift = await cur.fetchone()
            if not gift or int(gift[1]) < 1:
                await db.rollback()
                ADMIN_INPUT.pop(ADMIN_ID, None)
                await message.answer("Подарок закончился. Выберите другой подарок.")
                return
            cur = await db.execute(
                "UPDATE gift_catalog SET supply=supply-1 WHERE id=? AND supply>0",
                (gift_id,),
            )
            if cur.rowcount != 1:
                await db.rollback()
                ADMIN_INPUT.pop(ADMIN_ID, None)
                await message.answer("Не удалось зарезервировать подарок.")
                return
            cur = await db.execute(
                """INSERT INTO gift_auctions
                   (gift_id,gift_name,starting_bid,current_bid,status,starts_at,ends_at,
                    created_by,created_at)
                   VALUES(?,?,?,0,'active',?,?,?,?)""",
                (
                    gift_id,
                    str(gift[0]),
                    int(payload["starting_bid"]),
                    now,
                    now + minutes * 60,
                    ADMIN_ID,
                    now,
                ),
            )
            auction_id = int(cur.lastrowid)
            await db.execute(
                "INSERT INTO admin_logs(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
                (
                    ADMIN_ID,
                    "auction_create",
                    str(auction_id),
                    f"{gift[0]}; starting_bid={payload['starting_bid']}; duration_minutes={minutes}",
                    now,
                ),
            )
            await db.commit()
        ADMIN_INPUT.pop(ADMIN_ID, None)
        await message.answer(
            f"Создан системный аукцион #{auction_id}: {gift[0]}. "
            f"Старт: {payload['starting_bid']} Stars. Длительность: {minutes} мин.",
            reply_markup=admin_keyboard([[("Открыть аукционы", "wgadm:auctions")]]),
        )
    elif kind == "gift_name":
        if not value or len(value) > 80:
            await message.answer("Название должно содержать 1–80 символов.")
            return
        payload["name"] = value
        ADMIN_INPUT[ADMIN_ID] = ("gift_price", payload)
        await message.answer("Введите стоимость в Gram (целое число от 0).")
    elif kind == "gift_price":
        try:
            price = int(value)
        except ValueError:
            await message.answer("Введите целое неотрицательное число.")
            return
        if not 0 <= price <= 1_000_000_000:
            await message.answer("Стоимость должна быть от 0 до 1000000000.")
            return
        payload["price"] = price
        ADMIN_INPUT[ADMIN_ID] = ("gift_supply", payload)
        await message.answer("Введите количество экземпляров.")
    elif kind == "gift_supply":
        try:
            supply = int(value)
        except ValueError:
            await message.answer("Введите целое неотрицательное число.")
            return
        if not 0 <= supply <= 1_000_000:
            await message.answer("Количество должно быть от 0 до 1000000.")
            return
        try:
            async with aiosqlite.connect(DATABASE_PATH) as db:
                cur = await db.execute("INSERT INTO gift_catalog(name,price_grams,supply,created_at) VALUES(?,?,?,?)",
                    (payload["name"],payload["price"],supply,int(time.time())))
                await db.commit()
                gift_id = cur.lastrowid
        except aiosqlite.IntegrityError:
            ADMIN_INPUT.pop(ADMIN_ID, None)
            await message.answer("Подарок с таким названием уже существует.")
            return
        ADMIN_INPUT.pop(ADMIN_ID, None)
        await admin_log("gift_create",str(gift_id),f"{payload['name']}; price={payload['price']}; supply={supply}")
        await message.answer(f"Подарок добавлен: {payload['name']} · {payload['price']} Gram · остаток {supply}.",
            reply_markup=admin_keyboard([[("Открыть каталог", "wgadm:gifts")]]))

class NumberResolveRequest(BaseModel):
    number: str = Field(min_length=12, max_length=12)


class AuthCodeRequest(BaseModel):
    number: str = Field(min_length=12, max_length=12)


class CodeVerifyRequest(BaseModel):
    number: str = Field(min_length=12, max_length=12)
    code: str = Field(pattern=r"^\d{6}$")


def verify_internal_token(value: str | None) -> None:
    if not INTERNAL_API_TOKEN:
        raise HTTPException(status_code=503, detail="Internal API token is not configured")
    if value is None or not secrets.compare_digest(value, INTERNAL_API_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
async def health() -> dict[str, str]:
    # Keep the existing Android REST client's readiness contract.
    return {"status": "online", "service": "waysgram-authbot"}


@app.post("/internal/v1/telegram/gifts/sync")
async def sync_telegram_gifts_internal(
    x_internal_token: str | None = Header(default=None),
) -> dict[str, Any]:
    verify_internal_token(x_internal_token)
    if bot is None:
        raise HTTPException(status_code=503, detail="Telegram bot is not ready")
    try:
        if mtproto_gift_catalog is not None:
            result = await mtproto_gift_catalog.sync(DATABASE_PATH)
        else:
            result = await sync_telegram_gifts(DATABASE_PATH, bot)
    except Exception as exc:
        log.warning("Telegram gift catalog sync failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail="Не удалось синхронизировать каталог подарков Telegram",
        ) from exc
    log.info("Synchronized %s Telegram gifts", result["gift_count"])
    return result


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
    if not owner.get("verified"):
        raise HTTPException(status_code=403, detail="Bot verification is required")
    if await account_is_banned(int(owner["telegram_id"])):
        raise HTTPException(status_code=403, detail="WaysGram account is suspended")
    return {"assigned": True, "telegram_user_id": owner["telegram_id"]}


@app.post("/internal/v1/auth-code/request")
async def request_auth_code(
    payload: AuthCodeRequest,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, str]:
    verify_internal_token(x_internal_token)
    if not PHONE_RE.fullmatch(payload.number):
        raise HTTPException(status_code=422, detail="Invalid internal number format")
    owner = await store.resolve_number(payload.number)
    if not owner:
        raise HTTPException(status_code=404, detail="Number is not assigned")
    if not owner.get("verified"):
        raise HTTPException(status_code=403, detail="Bot verification is required")
    if await account_is_banned(int(owner["telegram_id"])):
        raise HTTPException(status_code=403, detail="WaysGram account is suspended")
    code = f"{secrets.randbelow(1_000_000):06d}"
    if not await store.save_code(payload.number, code, 300):
        raise HTTPException(status_code=429, detail="Code request is rate limited")
    if bot is None:
        raise HTTPException(status_code=503, detail="Bot is not ready")
    lang = str(owner.get("language") or "en")
    try:
        await bot.send_message(
            chat_id=int(owner["chat_id"]),
            text=tr(lang, "code_push"),
        )
    except Exception as exc:
        log.warning("Could not deliver WaysGram code (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not deliver bot message") from exc
    return {"status": "delivered"}


@app.post("/internal/v1/auth-code/verify")
async def verify_auth_code(
    payload: CodeVerifyRequest,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, bool]:
    verify_internal_token(x_internal_token)
    if not PHONE_RE.fullmatch(payload.number):
        raise HTTPException(status_code=422, detail="Invalid internal number format")
    owner = await store.resolve_number(payload.number)
    if not owner or not owner.get("verified") or await account_is_banned(int(owner["telegram_id"])):
        return {"valid": False}
    return {"valid": await store.verify_code(payload.number, payload.code)}


def _telesrv_webhook_error(status_code: int, error_code: str, retryable: bool) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"accepted": False, "error_code": error_code, "retryable": retryable},
    )


@app.post("/internal/v1/telesrv/otp")
async def receive_telesrv_otp(request: Request) -> JSONResponse:
    """Receive a login code generated by the self-hosted MTProto server.

    The code is not verified here. AuthWaysGram_bot only delivers it to the
    verified owner of the internal virtual number; the MTProto server remains
    the authority that validates auth.signIn.
    """
    secret = TELESRV_OTP_WEBHOOK_SECRET
    if not secret:
        return _telesrv_webhook_error(503, "WEBHOOK_NOT_CONFIGURED", False)
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return _telesrv_webhook_error(415, "CONTENT_TYPE_INVALID", False)

    raw_body = await request.body()
    if not raw_body or len(raw_body) > 64 * 1024:
        return _telesrv_webhook_error(413, "REQUEST_TOO_LARGE", False)

    timestamp = request.headers.get("X-Telesrv-Timestamp", "")
    try:
        issued_at = int(timestamp)
    except (TypeError, ValueError):
        return _telesrv_webhook_error(401, "SIGNATURE_INVALID", False)
    if abs(int(time.time()) - issued_at) > 300:
        return _telesrv_webhook_error(401, "TIMESTAMP_EXPIRED", False)

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + raw_body,
        hashlib.sha256,
    ).hexdigest()
    provided = request.headers.get("X-Telesrv-Signature", "")
    if not hmac.compare_digest(provided, expected):
        return _telesrv_webhook_error(401, "SIGNATURE_INVALID", False)

    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _telesrv_webhook_error(400, "JSON_INVALID", False)
    if not isinstance(payload, dict):
        return _telesrv_webhook_error(400, "JSON_INVALID", False)

    delivery_id = str(payload.get("delivery_id", "")).strip()
    idempotency_key = request.headers.get("Idempotency-Key", "")
    if (
        payload.get("version") != "1"
        or not delivery_id
        or len(delivery_id) > 128
        or not hmac.compare_digest(delivery_id, idempotency_key)
    ):
        return _telesrv_webhook_error(400, "DELIVERY_ID_INVALID", False)
    if payload.get("purpose") != "login_sms" or payload.get("channel") != "sms":
        return _telesrv_webhook_error(422, "PURPOSE_UNSUPPORTED", False)

    recipient = str(payload.get("recipient", "")).strip()
    if PHONE_RE.fullmatch(recipient):
        number = recipient
    elif re.fullmatch(r"1[0-9]{10}", recipient):
        number = "+" + recipient
    else:
        return _telesrv_webhook_error(422, "RECIPIENT_INVALID", False)

    code = str(payload.get("code", "")).strip()
    if not OTP_RE.fullmatch(code):
        return _telesrv_webhook_error(422, "CODE_INVALID", False)

    try:
        expiry_text = str(payload.get("expires_at", "")).strip()
        expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            raise ValueError("timezone is required")
        expires_at = int(expiry.astimezone(timezone.utc).timestamp())
        expires_in = int(payload.get("expires_in", 0))
    except (TypeError, ValueError, OverflowError):
        return _telesrv_webhook_error(422, "EXPIRY_INVALID", False)
    now = int(time.time())
    if expires_at <= now or expires_at - now > 900 or expires_in < 1 or expires_in > 900:
        return _telesrv_webhook_error(422, "EXPIRY_INVALID", False)

    owner = await store.resolve_number(number)
    if not owner:
        return _telesrv_webhook_error(404, "NUMBER_NOT_ASSIGNED", False)
    if not owner.get("verified") or await account_is_banned(int(owner["telegram_id"])):
        return _telesrv_webhook_error(403, "ACCOUNT_NOT_VERIFIED", False)
    if bot is None:
        return _telesrv_webhook_error(503, "BOT_NOT_READY", True)

    payload_sha256 = hashlib.sha256(raw_body).hexdigest()
    status, saved_message_id = await store.save_telesrv_code(
        number=number,
        code=code,
        expires_at=expires_at,
        delivery_id=delivery_id,
        payload_sha256=payload_sha256,
    )
    if status == "conflict":
        return _telesrv_webhook_error(409, "IDEMPOTENCY_CONFLICT", False)
    if status == "expired":
        return _telesrv_webhook_error(410, "CODE_EXPIRED", False)
    if status == "unknown_number":
        return _telesrv_webhook_error(404, "NUMBER_NOT_ASSIGNED", False)
    if status == "rate_limited":
        return _telesrv_webhook_error(429, "RATE_LIMITED", True)
    if status == "delivered":
        return JSONResponse(
            status_code=200,
            content={"accepted": True, "message_id": str(saved_message_id) if saved_message_id else ""},
        )

    language = str(owner.get("language") or "en")
    try:
        sent = await bot.send_message(
            chat_id=int(owner["chat_id"]),
            text=tr(language, "code_push"),
        )
        telegram_message_id = int(getattr(sent, "message_id", 0) or 0)
        await store.mark_telesrv_delivery_sent(delivery_id, telegram_message_id)
    except Exception as exc:
        log.warning("MTProto login-code notification failed (%s)", type(exc).__name__)
        # Leave the encrypted code and pending receipt intact. A retry with the
        # same delivery ID can resend the notification without replacing OTP.
        return _telesrv_webhook_error(502, "BOT_DELIVERY_FAILED", True)

    return JSONResponse(
        status_code=200,
        content={"accepted": True, "message_id": str(telegram_message_id) if telegram_message_id else ""},
    )


async def main() -> None:
    global bot, mtproto_client, mtproto_gift_catalog
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN environment variable is required")
    if not OTP_FERNET_KEY:
        raise RuntimeError(
            "OTP_FERNET_KEY is missing. Generate it with "
            "`python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())` and add it to the "
            "hosting environment variables. Keep the same key across restarts."
        )
    store.configure_otp_encryption(OTP_FERNET_KEY)
    await store.init()
    await init_admin_storage()
    await init_messenger_storage(DATABASE_PATH)
    bot = Bot(token=BOT_TOKEN)
    if TELEGRAM_API_ID > 0 and TELEGRAM_API_HASH:
        try:
            from telethon import TelegramClient

            DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
            session_base = DATABASE_PATH.parent / "waysgram_mtproto"
            mtproto_client = TelegramClient(
                str(session_base),
                TELEGRAM_API_ID,
                TELEGRAM_API_HASH,
            )
            await mtproto_client.start(bot_token=BOT_TOKEN)
            identity = await mtproto_client.get_me()
            if identity is None or not bool(getattr(identity, "bot", False)):
                raise RuntimeError("MTProto identity is not an authorized bot")
            session_file = Path(str(session_base) + ".session")
            if session_file.exists():
                os.chmod(session_file, 0o600)
            mtproto_gift_catalog = TelegramMTProtoGiftCatalog(mtproto_client)
            sync_result = await mtproto_gift_catalog.sync(DATABASE_PATH)
            log.info(
                "Loaded %s Telegram gifts through MTProto",
                sync_result["gift_count"],
            )
        except Exception as exc:
            log.warning("MTProto gift catalog unavailable (%s); using Bot API fallback", type(exc).__name__)
            mtproto_gift_catalog = None
            if mtproto_client is not None:
                try:
                    await mtproto_client.disconnect()
                except Exception:
                    pass
                mtproto_client = None
    elif TELEGRAM_API_ID or TELEGRAM_API_HASH:
        log.warning("Both TELEGRAM_API_ID and TELEGRAM_API_HASH are required for MTProto; using Bot API fallback")
    else:
        log.info("Telegram MTProto catalog is disabled; configure TELEGRAM_API_ID and TELEGRAM_API_HASH to enable it")

    try:
        if mtproto_gift_catalog is None:
            sync_result = await sync_telegram_gifts(DATABASE_PATH, bot)
            log.info("Loaded %s Telegram gifts through Bot API fallback", sync_result["gift_count"])
    except Exception as exc:
        # Keep login and the rest of the API online if Telegram's catalog is temporarily unavailable.
        log.warning("Initial Telegram gift catalog sync failed (%s)", type(exc).__name__)
    dispatcher = Dispatcher()
    dispatcher.include_router(router)

    if not INTERNAL_API_TOKEN:
        log.warning("INTERNAL_API_TOKEN is not set; backend API endpoints will reject requests")

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
        if mtproto_client is not None:
            try:
                await mtproto_client.disconnect()
            except Exception as exc:
                log.warning("Could not disconnect MTProto client (%s)", type(exc).__name__)
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
