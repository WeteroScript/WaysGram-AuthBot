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
from cryptography.fernet import Fernet, InvalidToken

# All secrets are read only from hosting environment variables.
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_ID", "8888957702"))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", "data/waysgram_authbot.sqlite3"))
INTERNAL_API_TOKEN = os.getenv("INTERNAL_API_TOKEN", "").strip()
OTP_FERNET_KEY = os.getenv("OTP_FERNET_KEY", "").strip()
INTERNAL_API_HOST = os.getenv("INTERNAL_API_HOST", "0.0.0.0")
INTERNAL_API_PORT = int(os.getenv("INTERNAL_API_PORT") or os.getenv("PORT") or "8081")

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


@router.message(Command("admin"))
async def admin_handler(message: Message) -> None:
    if not message.from_user or message.from_user.id != ADMIN_ID:
        user = await store.get_user(message.from_user.id) if message.from_user else None
        await message.answer(tr(user.get("language") if user else "en", "admin_denied"))
        return
    admin_user = await store.get_user(message.from_user.id)
    lang = str(admin_user.get("language") if admin_user else "ru")
    labels = (
        ("Статистика", "Статус сервиса", "Номера", "Последние пользователи")
        if lang == "ru"
        else ("Statistics", "Service status", "Numbers", "Recent users")
    )
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=labels[0], callback_data="adm:stats")],
        [InlineKeyboardButton(text=labels[1], callback_data="adm:provider")],
        [InlineKeyboardButton(text=labels[2], callback_data="adm:numbers")],
        [InlineKeyboardButton(text=labels[3], callback_data="adm:recent")],
    ])
    await message.answer(tr(lang, "admin_title"), reply_markup=keyboard)

@router.callback_query(F.data.startswith("adm:"))
async def admin_callback(callback: CallbackQuery) -> None:
    if not callback.from_user or callback.from_user.id != ADMIN_ID or not callback.data:
        await callback.answer("Access denied", show_alert=True)
        return
    admin_user = await store.get_user(callback.from_user.id)
    lang = str(admin_user.get("language") if admin_user else "ru")
    action = callback.data.split(":", 1)[1]
    if action == "stats":
        users, numbers, codes = await store.stats()
        response = tr(lang, "admin_stats", users=users, numbers=numbers, codes=codes)
    elif action == "provider":
        number_status = "активна" if lang == "ru" else "active"
        api_status = ("настроен" if INTERNAL_API_TOKEN else "не настроен") if lang == "ru" else ("configured" if INTERNAL_API_TOKEN else "not configured")
        response = tr(lang, "admin_provider", status=number_status, api=api_status)
    elif action == "numbers":
        rows = await store.number_inventory()
        if rows:
            items = "\n".join(
                f"{number} — TG {telegram_id} — {'verified' if verified else 'not verified'}"
                for number, telegram_id, verified in rows
            )
            response = tr(lang, "admin_numbers", items=items)
        else:
            response = tr(lang, "admin_numbers_empty")
    elif action == "recent":
        items = await store.recent_users()
        response = tr(lang, "admin_recent", items="\n".join(map(str, items))) if items else tr(lang, "admin_recent_empty")
    else:
        response = "Unknown action"
    await callback.answer()
    if callback.message:
        await callback.message.answer(response)

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
    if not owner.get("verified"):
        raise HTTPException(status_code=403, detail="Bot verification is required")
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
    if not owner or not owner.get("verified"):
        return {"valid": False}
    return {"valid": await store.verify_code(payload.number, payload.code)}


async def main() -> None:
    global bot
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
    bot = Bot(token=BOT_TOKEN)
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
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
