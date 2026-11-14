from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import mimetypes
import os
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from io import BytesIO
from urllib.parse import quote, unquote, urlsplit
from pathlib import Path
from typing import Any, Callable

import aiosqlite
import db_split  # noqa: F401  # two-file database layout
import httpx
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


SESSION_TTL = 60 * 60 * 24 * 30
DM_MESSAGES_PER_MINUTE = 30
CHANNEL_POSTS_PER_MINUTE = 20
LOGIN_REQUESTS_PER_IP_PER_HOUR = 100
MAX_MESSAGE_LENGTH = 4000
MAX_IMAGE_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_DOCUMENT_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
MAX_USER_MEDIA_BYTES = 100 * 1024 * 1024
MAX_USER_IMAGE_UPLOADS_PER_HOUR = 30
PHONE_RE = re.compile(r"^\+1[0-9]{10}$")
GIFT_SERIAL_RE = re.compile(r"^WG-[A-F0-9]{12}$")
LOGGER = logging.getLogger(__name__)
FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
FCM_TOKEN_URI = "https://oauth2.googleapis.com/token"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _firebase_service_account() -> dict[str, Any] | None:
    """Load FCM HTTP v1 service-account credentials without exposing them to clients."""
    raw = os.getenv("FCM_SERVICE_ACCOUNT_JSON", "").strip()
    file_path = os.getenv("FCM_SERVICE_ACCOUNT_FILE", "").strip()
    try:
        if raw:
            credentials = json.loads(raw)
        elif file_path:
            credentials = json.loads(Path(file_path).read_text(encoding="utf-8"))
        else:
            return None
        if not isinstance(credentials, dict):
            return None
        required = ("project_id", "client_email", "private_key")
        if any(not isinstance(credentials.get(key), str) or not credentials[key].strip() for key in required):
            return None
        return credentials
    except (OSError, ValueError, TypeError):
        return None


def _firebase_assertion(credentials: dict[str, Any], now: int) -> str:
    header = _b64url(json.dumps(
        {"alg": "RS256", "typ": "JWT"},
        separators=(",", ":"),
    ).encode("utf-8"))
    claims = _b64url(json.dumps(
        {
            "iss": credentials["client_email"],
            "scope": FCM_SCOPE,
            "aud": credentials.get("token_uri") or FCM_TOKEN_URI,
            "iat": now,
            "exp": now + 3600,
        },
        separators=(",", ":"),
    ).encode("utf-8"))
    signing_input = f"{header}.{claims}"
    private_key = serialization.load_pem_private_key(
        credentials["private_key"].encode("utf-8"),
        password=None,
    )
    signature = private_key.sign(
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{signing_input}.{_b64url(signature)}"




def _external_api_base_url(request: Request) -> str:
    """Return the canonical public API origin for links shared with clients."""
    configured = os.getenv("PUBLIC_API_BASE_URL", "").strip()
    if not configured:
        return str(request.base_url).rstrip("/")

    parsed = urlsplit(configured)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise HTTPException(
            status_code=500,
            detail="PUBLIC_API_BASE_URL must be an absolute HTTP(S) origin",
        )
    return f"{parsed.scheme}://{parsed.netloc}"



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


def _normalize_uploaded_document(raw: bytes, filename: str) -> tuple[bytes, str, str, str]:
    """Validate an allowlisted document, audio, video or archive without unpacking it."""
    safe_name = str(filename or "document").replace("\\", "/").rsplit("/", 1)[-1]
    safe_name = re.sub(r"[\x00-\x1f\x7f]", "", safe_name).strip(" .")[:120]
    if not safe_name:
        safe_name = "document"
    extension = Path(safe_name).suffix.lower()

    if extension == ".pdf":
        if len(raw) < 16 or not raw.startswith(b"%PDF-") or b"%%EOF" not in raw[-2048:]:
            raise ValueError("Файл не является корректным PDF")
        return raw, "application/pdf", ".pdf", safe_name

    if extension in {".txt", ".csv"}:
        try:
            decoded = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Текстовые документы должны быть в UTF-8") from exc
        if "\x00" in decoded or any(
            ord(char) < 32 and char not in "\t\n\r" for char in decoded
        ):
            raise ValueError("Текстовый документ содержит недопустимые управляющие символы")
        normalized = decoded.encode("utf-8")
        mime_type = "text/csv" if extension == ".csv" else "text/plain"
        return normalized, mime_type, extension, safe_name

    if extension in {".mp4", ".m4v", ".mov"}:
        if len(raw) < 12 or raw[4:8] != b"ftyp":
            raise ValueError("Файл не является корректным MP4/MOV")
        mime_type = "video/quicktime" if extension == ".mov" else "video/mp4"
        return raw, mime_type, extension, safe_name

    if extension == ".webm":
        if len(raw) < 4 or not raw.startswith(b"\x1a\x45\xdf\xa3"):
            raise ValueError("Файл не является корректным WebM")
        return raw, "video/webm", extension, safe_name

    if extension == ".mkv":
        if len(raw) < 4 or not raw.startswith(b"\x1a\x45\xdf\xa3"):
            raise ValueError("Файл не является корректным Matroska")
        return raw, "video/x-matroska", extension, safe_name

    if extension == ".mp3":
        has_id3 = raw.startswith(b"ID3")
        has_frame_sync = len(raw) >= 2 and raw[0] == 0xFF and (raw[1] & 0xE0) == 0xE0
        if not (has_id3 or has_frame_sync):
            raise ValueError("Файл не является корректным MP3")
        return raw, "audio/mpeg", extension, safe_name

    if extension == ".m4a":
        if len(raw) < 12 or raw[4:8] != b"ftyp":
            raise ValueError("Файл не является корректным M4A")
        return raw, "audio/mp4", extension, safe_name

    if extension == ".ogg":
        if len(raw) < 4 or not raw.startswith(b"OggS"):
            raise ValueError("Файл не является корректным OGG")
        return raw, "audio/ogg", extension, safe_name

    if extension == ".wav":
        if len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
            raise ValueError("Файл не является корректным WAV")
        return raw, "audio/wav", extension, safe_name

    if extension == ".zip":
        if len(raw) < 4 or raw[:4] not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            raise ValueError("Файл не является корректным ZIP-архивом")
        return raw, "application/zip", extension, safe_name

    raise ValueError(
        "Поддерживаются PDF, TXT, CSV, ZIP, MP4, M4V, MOV, WebM, MKV, MP3, M4A, OGG и WAV"
    )


COLLECTIBLE_TRAITS_VERSION = 1
COLLECTIBLE_TRAIT_TIERS = (
    (6000, "Обычная", {
        "models": ("Искра", "Полярный свет", "Призма", "Лунный отблеск", "Северное сияние"),
        "symbols": ("✦", "✧", "❖", "☾", "✺"),
        "backdrops": (
            "Аметистовый · #7C4DFF", "Лазурный · #168AAD", "Изумрудный · #2A9D8F",
            "Рубиновый · #D62828", "Сапфировый · #4361EE",
        ),
    }),
    (2500, "Необычная", {
        "models": ("Комета", "Кристальный сад", "Солнечный ореол", "Звёздный след"),
        "symbols": ("✵", "❈", "♢", "☼"),
        "backdrops": (
            "Бирюзовый · #20B2AA", "Янтарный · #FFB703",
            "Лавандовый · #B8A1E3", "Малахитовый · #00A676",
        ),
    }),
    (1000, "Редкая", {
        "models": ("Небесный феникс", "Драконий камень", "Галактическая корона"),
        "symbols": ("♛", "☄", "❂"),
        "backdrops": ("Опаловый · #A8DADC", "Кобальтовый · #0047AB", "Гранатовый · #800020"),
    }),
    (400, "Эпическая", {
        "models": ("Королевская реликвия", "Сердце кометы"),
        "symbols": ("♜", "✹"),
        "backdrops": ("Платиновый · #E5E4E2", "Затмение · #191970"),
    }),
    (100, "Легендарная", {
        "models": ("Вечное пламя",),
        "symbols": ("✷",),
        "backdrops": ("Золотой · #D4AF37",),
    }),
)


def _generate_collectible_traits() -> dict[str, Any]:
    """Create one immutable, server-generated trait set for a WaysGram collectible."""
    roll = secrets.randbelow(10_000)
    boundary = 0
    selected_tier = COLLECTIBLE_TRAIT_TIERS[-1]
    for tier in COLLECTIBLE_TRAIT_TIERS:
        boundary += tier[0]
        if roll < boundary:
            selected_tier = tier
            break
    rarity, traits = selected_tier[1], selected_tier[2]
    return {
        "version": COLLECTIBLE_TRAITS_VERSION,
        "rarity": rarity,
        "model": secrets.choice(traits["models"]),
        "symbol": secrets.choice(traits["symbols"]),
        "backdrop": secrets.choice(traits["backdrops"]),
    }


def _has_collectible_traits(attributes: Any) -> bool:
    if not isinstance(attributes, dict):
        return False
    traits = attributes.get("collectible_traits")
    if not isinstance(traits, dict) or traits.get("version") != COLLECTIBLE_TRAITS_VERSION:
        return False
    return all(
        isinstance(traits.get(key), str) and bool(traits[key].strip())
        for key in ("rarity", "model", "symbol", "backdrop")
    )


async def init_messenger_storage(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    # Move legacy messenger tables before creating the split-schema versions.
    await db_split.migrate_legacy(database_path)
    async with aiosqlite.connect(database_path) as db:
        await db.executescript(
            db_split.qualify_ddl(
            """
            CREATE TABLE IF NOT EXISTS api_sessions (
                token_hash TEXT PRIMARY KEY,
                telegram_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS push_devices (
                token_hash TEXT PRIMARY KEY,
                token_value TEXT NOT NULL,
                telegram_id INTEGER NOT NULL,
                session_token_hash TEXT NOT NULL,
                platform TEXT NOT NULL DEFAULT 'android',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_push_devices_user
                ON push_devices(telegram_id,updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_push_devices_session
                ON push_devices(session_token_hash);
            CREATE TABLE IF NOT EXISTS media_assets (
                id TEXT PRIMARY KEY,
                owner_telegram_id INTEGER NOT NULL,
                storage_name TEXT NOT NULL UNIQUE,
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
                created_at INTEGER NOT NULL,
                original_name TEXT
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
                created_at INTEGER NOT NULL,
                forwarded_from_telegram_id INTEGER,
                forwarded_from_message_id INTEGER,
                media_album_id TEXT,
                media_album_index INTEGER NOT NULL DEFAULT 0,
                media_album_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS message_gifts (
                message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                serial_number TEXT NOT NULL,
                gift_name TEXT NOT NULL,
                telegram_gift_id TEXT NOT NULL DEFAULT '',
                upgrade_level INTEGER NOT NULL DEFAULT 0,
                attributes_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_message_gifts_serial
                ON message_gifts(serial_number);
            CREATE INDEX IF NOT EXISTS idx_api_messages_pair
                ON messages(sender_telegram_id, recipient_telegram_id, id);
            CREATE INDEX IF NOT EXISTS idx_api_messages_sender_time
                ON messages(sender_telegram_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_api_messages_recipient_time
                ON messages(recipient_telegram_id, created_at);
            CREATE TABLE IF NOT EXISTS message_hidden_for (
                message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                telegram_id INTEGER NOT NULL,
                hidden_at INTEGER NOT NULL,
                PRIMARY KEY(message_id,telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_message_hidden_for_user
                ON message_hidden_for(telegram_id,message_id);
            CREATE TABLE IF NOT EXISTS message_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                chat_id INTEGER NOT NULL DEFAULT 0,
                user_a INTEGER NOT NULL DEFAULT 0,
                user_b INTEGER NOT NULL DEFAULT 0,
                message_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                actor_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_message_events_scope
                ON message_events(scope, chat_id, id);
            CREATE TABLE IF NOT EXISTS read_markers (
                telegram_id INTEGER NOT NULL,
                scope TEXT NOT NULL,
                peer_id INTEGER NOT NULL,
                last_read_id INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(telegram_id, scope, peer_id)
            );
            CREATE TABLE IF NOT EXISTS typing_indicators (
                scope TEXT NOT NULL CHECK(scope IN ('dm','group')),
                chat_id INTEGER NOT NULL,
                user_telegram_id INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY(scope,chat_id,user_telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_typing_indicators_expiry
                ON typing_indicators(expires_at);
            CREATE TABLE IF NOT EXISTS message_reactions (
                scope TEXT NOT NULL CHECK(scope IN ('dm','group','channel')),
                chat_id INTEGER NOT NULL DEFAULT 0,
                message_id INTEGER NOT NULL,
                user_telegram_id INTEGER NOT NULL,
                reaction TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(scope,chat_id,message_id,user_telegram_id,reaction)
            );
            CREATE INDEX IF NOT EXISTS idx_message_reactions_message
                ON message_reactions(scope,chat_id,message_id,reaction);
            CREATE TABLE IF NOT EXISTS pinned_messages (
                scope TEXT NOT NULL CHECK(scope IN ('dm','group','channel')),
                chat_id INTEGER NOT NULL DEFAULT 0,
                message_id INTEGER NOT NULL,
                pinned_by INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(scope,chat_id,message_id)
            );
            CREATE INDEX IF NOT EXISTS idx_pinned_messages_created
                ON pinned_messages(scope,chat_id,created_at DESC);
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
            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                telegram_id INTEGER NOT NULL,
                joined_at INTEGER NOT NULL,
                PRIMARY KEY(channel_id, telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_channel_members_user
                ON channel_members(telegram_id,channel_id);
            CREATE TABLE IF NOT EXISTS channel_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                author_telegram_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                media_album_id TEXT,
                media_album_index INTEGER NOT NULL DEFAULT 0,
                media_album_count INTEGER NOT NULL DEFAULT 0
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
            CREATE TABLE IF NOT EXISTS cloud_drafts (
                owner_telegram_id INTEGER NOT NULL,
                scope TEXT NOT NULL CHECK(scope IN ('dm','group','channel')),
                peer_id INTEGER NOT NULL CHECK(peer_id > 0),
                body TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(owner_telegram_id,scope,peer_id)
            );
            CREATE INDEX IF NOT EXISTS idx_cloud_drafts_updated
                ON cloud_drafts(owner_telegram_id,updated_at DESC);
            CREATE TABLE IF NOT EXISTS scheduled_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_telegram_id INTEGER NOT NULL,
                recipient_telegram_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                scheduled_at INTEGER NOT NULL,
                repeat_interval_seconds INTEGER NOT NULL DEFAULT 0
                    CHECK(repeat_interval_seconds IN (0,86400,604800)),
                created_at INTEGER NOT NULL,
                silent INTEGER NOT NULL DEFAULT 0 CHECK(silent IN (0,1)),
                time_zone TEXT NOT NULL DEFAULT 'UTC',
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','sent','cancelled','failed')),
                message_id INTEGER,
                error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_scheduled_messages_due
                ON scheduled_messages(status,scheduled_at,id);
            CREATE INDEX IF NOT EXISTS idx_scheduled_messages_owner
                ON scheduled_messages(sender_telegram_id,recipient_telegram_id,status);
            CREATE TABLE IF NOT EXISTS telegram_gift_prices (
                gift_id TEXT PRIMARY KEY,
                price_stars INTEGER NOT NULL DEFAULT 0 CHECK(price_stars >= 0),
                supply INTEGER NOT NULL DEFAULT 0 CHECK(supply >= 0),
                sold INTEGER NOT NULL DEFAULT 0 CHECK(sold >= 0),
                updated_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS gift_market_listings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT NOT NULL UNIQUE,
                seller_telegram_id INTEGER NOT NULL,
                price_grams INTEGER NOT NULL CHECK(price_grams > 0),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK(status IN ('active','sold','cancelled')),
                buyer_telegram_id INTEGER,
                created_at INTEGER NOT NULL,
                sold_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_gift_market_status_time
                ON gift_market_listings(status,created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_gift_market_seller
                ON gift_market_listings(seller_telegram_id,status);
            CREATE TABLE IF NOT EXISTS gift_collectible_auctions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT NOT NULL,
                seller_telegram_id INTEGER NOT NULL,
                starting_price_grams INTEGER NOT NULL CHECK(starting_price_grams > 0),
                current_bid_grams INTEGER NOT NULL DEFAULT 0 CHECK(current_bid_grams >= 0),
                highest_bidder_telegram_id INTEGER,
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK(status IN ('active','sold','ended','cancelled')),
                starts_at INTEGER NOT NULL,
                ends_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                settled_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_gift_collectible_auctions_status_end
                ON gift_collectible_auctions(status,ends_at);
            CREATE INDEX IF NOT EXISTS idx_gift_collectible_auctions_serial
                ON gift_collectible_auctions(serial_number,status);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_gift_collectible_auctions_active_serial
                ON gift_collectible_auctions(serial_number) WHERE status='active';
            CREATE TABLE IF NOT EXISTS gift_collectible_auction_bids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                auction_id INTEGER NOT NULL,
                bidder_telegram_id INTEGER NOT NULL,
                amount_grams INTEGER NOT NULL CHECK(amount_grams > 0),
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gift_collectible_auction_bids
                ON gift_collectible_auction_bids(auction_id,id DESC);
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
                created_at INTEGER NOT NULL,
                slow_mode_seconds INTEGER NOT NULL DEFAULT 0
                    CHECK(slow_mode_seconds IN (0,5,10,15,30,60,120,300))
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
            CREATE TABLE IF NOT EXISTS group_invites (
                token_hash TEXT PRIMARY KEY,
                group_id INTEGER NOT NULL,
                created_by INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                max_uses INTEGER,
                uses INTEGER NOT NULL DEFAULT 0 CHECK(uses >= 0),
                require_approval INTEGER NOT NULL DEFAULT 0 CHECK(require_approval IN (0,1)),
                revoked_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_group_invites_group
                ON group_invites(group_id,created_at DESC);
            CREATE TABLE IF NOT EXISTS group_join_requests (
                group_id INTEGER NOT NULL,
                telegram_id INTEGER NOT NULL,
                invite_token_hash TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','approved','declined')),
                reviewed_by INTEGER,
                reviewed_at INTEGER,
                PRIMARY KEY(group_id,telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_group_join_requests_status
                ON group_join_requests(group_id,status,requested_at);
            CREATE TABLE IF NOT EXISTS contacts (
                owner_telegram_id INTEGER NOT NULL,
                contact_telegram_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(owner_telegram_id,contact_telegram_id),
                CHECK(owner_telegram_id<>contact_telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_contacts_contact
                ON contacts(contact_telegram_id,owner_telegram_id);
            CREATE TABLE IF NOT EXISTS contact_notes (
                owner_telegram_id INTEGER NOT NULL,
                contact_telegram_id INTEGER NOT NULL,
                note TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(owner_telegram_id,contact_telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_contact_notes_updated
                ON contact_notes(owner_telegram_id,updated_at DESC);
            CREATE TABLE IF NOT EXISTS blocked_users (
                owner_telegram_id INTEGER NOT NULL,
                blocked_telegram_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(owner_telegram_id,blocked_telegram_id),
                CHECK(owner_telegram_id<>blocked_telegram_id)
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_users_target
                ON blocked_users(blocked_telegram_id,owner_telegram_id);
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                sender_telegram_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                media_album_id TEXT,
                media_album_index INTEGER NOT NULL DEFAULT 0,
                media_album_count INTEGER NOT NULL DEFAULT 0
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
        )
        # A database from an older version keeps everything in one file: move the messenger tables out first,
        # because a table left in the main file would hide the one in the messenger file.
        await db_split.migrate_legacy_with(db, database_path)
        cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info(user_gifts)")
        user_gift_columns = {str(row[1]) for row in await cur.fetchall()}
        if "upgrade_level" not in user_gift_columns:
            await db.execute(
                f"ALTER TABLE {db_split.SCHEMA}.user_gifts "
                "ADD COLUMN upgrade_level INTEGER NOT NULL DEFAULT 0 CHECK(upgrade_level >= 0)"
            )
        if "attributes_json" not in user_gift_columns:
            await db.execute(
                f"ALTER TABLE {db_split.SCHEMA}.user_gifts "
                "ADD COLUMN attributes_json TEXT NOT NULL DEFAULT '{}'"
            )
        cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info(chat_groups)")
        chat_group_columns = {str(row[1]) for row in await cur.fetchall()}
        if "slow_mode_seconds" not in chat_group_columns:
            await db.execute(
                f"ALTER TABLE {db_split.SCHEMA}.chat_groups "
                "ADD COLUMN slow_mode_seconds INTEGER NOT NULL DEFAULT 0 "
                "CHECK(slow_mode_seconds IN (0,5,10,15,30,60,120,300))"
            )
        cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info(group_invites)")
        group_invite_columns = {str(row[1]) for row in await cur.fetchall()}
        if "require_approval" not in group_invite_columns:
            await db.execute(
                f"ALTER TABLE {db_split.SCHEMA}.group_invites "
                "ADD COLUMN require_approval INTEGER NOT NULL DEFAULT 0 CHECK(require_approval IN (0,1))"
            )
        cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info(channels)")
        channel_columns = {str(row[1]) for row in await cur.fetchall()}
        if "is_public" not in channel_columns:
            await db.execute(
                f"ALTER TABLE {db_split.SCHEMA}.channels "
                "ADD COLUMN is_public INTEGER NOT NULL DEFAULT 1 CHECK(is_public IN (0,1))"
            )
        if "invite_token" not in channel_columns:
            await db.execute(f"ALTER TABLE {db_split.SCHEMA}.channels ADD COLUMN invite_token TEXT")
        await db.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {db_split.SCHEMA}.idx_api_channels_invite_token "
            "ON channels(invite_token)"
        )
        await db.execute(
            """INSERT OR IGNORE INTO channel_members(channel_id,telegram_id,joined_at)
               SELECT id,owner_telegram_id,created_at FROM channels"""
        )
        cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info(media_assets)")
        media_columns = {str(row[1]) for row in await cur.fetchall()}
        if "original_name" not in media_columns:
            await db.execute(f"ALTER TABLE {db_split.SCHEMA}.media_assets ADD COLUMN original_name TEXT")
        cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info(scheduled_messages)")
        scheduled_columns = {str(row[1]) for row in await cur.fetchall()}
        if "repeat_interval_seconds" not in scheduled_columns:
            await db.execute(
                f"ALTER TABLE {db_split.SCHEMA}.scheduled_messages "
                "ADD COLUMN repeat_interval_seconds INTEGER NOT NULL DEFAULT 0"
            )
        if "time_zone" not in scheduled_columns:
            await db.execute(
                f"ALTER TABLE {db_split.SCHEMA}.scheduled_messages "
                "ADD COLUMN time_zone TEXT NOT NULL DEFAULT 'UTC'"
            )
        for table_name in ("messages", "group_messages", "channel_messages"):
            cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info({table_name})")
            columns = {str(row[1]) for row in await cur.fetchall()}
            if "media_id" not in columns:
                await db.execute(f"ALTER TABLE {db_split.SCHEMA}.{table_name} ADD COLUMN media_id TEXT")
            if "edited_at" not in columns:
                await db.execute(f"ALTER TABLE {db_split.SCHEMA}.{table_name} ADD COLUMN edited_at INTEGER")
            if "reply_to_id" not in columns:
                await db.execute(f"ALTER TABLE {db_split.SCHEMA}.{table_name} ADD COLUMN reply_to_id INTEGER")
            if table_name == "messages":
                if "forwarded_from_telegram_id" not in columns:
                    await db.execute(f"ALTER TABLE {db_split.SCHEMA}.messages ADD COLUMN forwarded_from_telegram_id INTEGER")
                if "forwarded_from_message_id" not in columns:
                    await db.execute(f"ALTER TABLE {db_split.SCHEMA}.messages ADD COLUMN forwarded_from_message_id INTEGER")
                if "media_album_id" not in columns:
                    await db.execute(f"ALTER TABLE {db_split.SCHEMA}.messages ADD COLUMN media_album_id TEXT")
                if "media_album_index" not in columns:
                    await db.execute(
                        f"ALTER TABLE {db_split.SCHEMA}.messages "
                        "ADD COLUMN media_album_index INTEGER NOT NULL DEFAULT 0"
                    )
                if "media_album_count" not in columns:
                    await db.execute(
                        f"ALTER TABLE {db_split.SCHEMA}.messages "
                        "ADD COLUMN media_album_count INTEGER NOT NULL DEFAULT 0"
                    )
        for table_name in ("group_messages", "channel_messages"):
            cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.table_info({table_name})")
            columns = {str(row[1]) for row in await cur.fetchall()}
            if "media_album_id" not in columns:
                await db.execute(
                    f"ALTER TABLE {db_split.SCHEMA}.{table_name} ADD COLUMN media_album_id TEXT"
                )
            if "media_album_index" not in columns:
                await db.execute(
                    f"ALTER TABLE {db_split.SCHEMA}.{table_name} "
                    "ADD COLUMN media_album_index INTEGER NOT NULL DEFAULT 0"
                )
            if "media_album_count" not in columns:
                await db.execute(
                    f"ALTER TABLE {db_split.SCHEMA}.{table_name} "
                    "ADD COLUMN media_album_count INTEGER NOT NULL DEFAULT 0"
                )
        # Read marks arrived in a later version: whatever existed before them counts as read, once.
        cur = await db.execute(f"PRAGMA {db_split.SCHEMA}.user_version")
        if int((await cur.fetchone())[0]) < 1:
            marked_at = int(time.time())
            await db.execute(
                """INSERT OR IGNORE INTO read_markers(telegram_id,scope,peer_id,last_read_id,updated_at)
                   SELECT recipient_telegram_id,'dm',sender_telegram_id,MAX(id),?
                   FROM messages GROUP BY recipient_telegram_id,sender_telegram_id""",
                (marked_at,),
            )
            await db.execute(
                """INSERT OR IGNORE INTO read_markers(telegram_id,scope,peer_id,last_read_id,updated_at)
                   SELECT gm.telegram_id,'group',gm.group_id,
                          COALESCE((SELECT MAX(x.id) FROM group_messages x WHERE x.group_id=gm.group_id),0),?
                   FROM group_members gm""",
                (marked_at,),
            )
            await db.execute(
                """INSERT OR IGNORE INTO read_markers(telegram_id,scope,peer_id,last_read_id,updated_at)
                   SELECT ch.owner_telegram_id,'channel',ch.id,
                          COALESCE((SELECT MAX(x.id) FROM channel_messages x WHERE x.channel_id=ch.id),0),?
                   FROM channels ch""",
                (marked_at,),
            )
            await db.commit()
            await db.execute(f"PRAGMA {db_split.SCHEMA}.user_version=1")
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

        # Previously upgraded gifts did not have collectible traits. Backfill
        # them once so existing owners keep their upgrades and receive the new
        # collectible metadata without paying for another upgrade.
        cur = await db.execute(
            "SELECT id,attributes_json FROM user_gifts WHERE upgrade_level>0"
        )
        upgraded_gifts = await cur.fetchall()
        for gift_id, raw_attributes in upgraded_gifts:
            try:
                attributes = json.loads(str(raw_attributes or "{}"))
            except (TypeError, ValueError):
                attributes = {}
            if not isinstance(attributes, dict):
                attributes = {}
            if _has_collectible_traits(attributes):
                continue
            attributes["collectible_traits"] = _generate_collectible_traits()
            await db.execute(
                "UPDATE user_gifts SET attributes_json=? WHERE id=?",
                (json.dumps(attributes, ensure_ascii=False, separators=(",", ":")), gift_id),
            )
        await db.commit()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _avatar_of(row: Any) -> str:
    try:
        return str(row["avatar_media_id"] or "")
    except (KeyError, IndexError):
        return ""


def _bio_of(row: Any) -> str:
    try:
        return str(row["bio"] or "")
    except (KeyError, IndexError):
        return ""


def _public_account(row: Any, include_phone: bool = False) -> dict[str, Any]:
    result = {
        "id": int(row["telegram_id"]),
        "username": str(row["username"] or ""),
        "display_name": str(row["display_name"] or ""),
        "avatar_media_id": _avatar_of(row),
        "bio": _bio_of(row),
    }
    if include_phone:
        result["phone"] = row["virtual_number"]
    result["stars"] = int(row["stars"])
    result["grams"] = int(row["grams"])
    result["is_premium"] = True  # every WaysGram account has Premium, permanently
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


def _next_recurring_scheduled_timestamp(
    scheduled_at: int,
    now: int,
    repeat_interval_seconds: int,
    time_zone: str,
) -> int:
    """Advance a daily/weekly recurrence in its original local time zone."""
    if repeat_interval_seconds not in (86400, 604800):
        raise ValueError("Unsupported recurring schedule interval")
    zone = ZoneInfo(time_zone)
    local_schedule = datetime.fromtimestamp(int(scheduled_at), tz=zone)
    interval_days = 1 if repeat_interval_seconds == 86400 else 7
    next_local = local_schedule + timedelta(days=interval_days)
    while int(next_local.timestamp()) <= int(now):
        next_local += timedelta(days=interval_days)
    return int(next_local.timestamp())


def build_messenger_router(
    database_path: Path | Callable[[], Path],
    auth_store: Any,
    bot_provider: Callable[[], Any],
    account_is_banned: Callable[[int], Any],
    mtproto_gift_provider: Callable[[], Any] | None = None,
    admin_id: int | None = None,
) -> APIRouter:
    router = APIRouter()
    db_path = database_path if callable(database_path) else lambda: database_path
    telegram_gift_sync_lock = asyncio.Lock()
    fcm_access_token_cache: dict[str, Any] = {}
    fcm_access_token_lock = asyncio.Lock()

    async def get_fcm_access_token(credentials: dict[str, Any]) -> tuple[str, str]:
        project_id = str(credentials["project_id"]).strip()
        now = int(time.time())
        async with fcm_access_token_lock:
            cached = fcm_access_token_cache
            if (
                cached.get("project_id") == project_id
                and int(cached.get("expires_at", 0)) > now + 60
                and isinstance(cached.get("access_token"), str)
            ):
                return project_id, str(cached["access_token"])
            assertion = await asyncio.to_thread(_firebase_assertion, credentials, now)
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                response = await client.post(
                    str(credentials.get("token_uri") or FCM_TOKEN_URI),
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                        "assertion": assertion,
                    },
                )
                response.raise_for_status()
                token_payload = response.json()
            access_token = str(token_payload.get("access_token") or "")
            expires_in = int(token_payload.get("expires_in") or 0)
            if not access_token or expires_in <= 0:
                raise RuntimeError("Firebase OAuth returned an invalid access token")
            fcm_access_token_cache.clear()
            fcm_access_token_cache.update({
                "project_id": project_id,
                "access_token": access_token,
                "expires_at": now + expires_in,
            })
            return project_id, access_token

    async def deliver_push_notifications(
        account_ids: list[int],
        title: str,
        body: str,
        data: dict[str, str],
    ) -> None:
        """Send best-effort FCM notifications only to devices with a live WaysGram session."""
        credentials = _firebase_service_account()
        if not credentials:
            return
        recipients = sorted({int(value) for value in account_ids if int(value) > 0})
        if not recipients:
            return
        placeholders = ",".join("?" for _ in recipients)
        try:
            async with aiosqlite.connect(db_path()) as db:
                cur = await db.execute(
                    f"""SELECT DISTINCT d.token_hash,d.token_value
                        FROM push_devices d
                        JOIN api_sessions s
                          ON s.token_hash=d.session_token_hash
                         AND s.telegram_id=d.telegram_id
                         AND s.expires_at>?
                        JOIN accounts a ON a.telegram_id=d.telegram_id AND a.is_banned=0
                        WHERE d.telegram_id IN ({placeholders})
                        ORDER BY d.updated_at DESC LIMIT 500""",
                    (int(time.time()), *recipients),
                )
                devices = await cur.fetchall()
            if not devices:
                return
            project_id, access_token = await get_fcm_access_token(credentials)
            notification_data = {
                "waysgram": "1",
                **{
                    str(key): str(value)
                    for key, value in data.items()
                    if str(key) != "waysgram" and value is not None
                },
            }
            notification_message = {
                "notification": {
                    "title": str(title or "WaysGram")[:80],
                    "body": str(body or "Новое сообщение")[:180],
                },
                "data": notification_data,
                "android": {
                    "priority": "HIGH",
                    "notification": {"channel_id": "waysgram_messages"},
                },
            }
            async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
                for token_hash, token_value in devices:
                    response = await client.post(
                        f"https://fcm.googleapis.com/v1/projects/{quote(project_id, safe='')}/messages:send",
                        headers={"Authorization": f"Bearer {access_token}"},
                        json={"message": {**notification_message, "token": str(token_value)}},
                    )
                    if response.status_code == 404:
                        async with aiosqlite.connect(db_path()) as db:
                            await db.execute(
                                "DELETE FROM push_devices WHERE token_hash=?",
                                (str(token_hash),),
                            )
                            await db.commit()
                    elif response.status_code >= 400:
                        LOGGER.warning("FCM delivery failed with HTTP %s", response.status_code)
        except Exception as exc:
            LOGGER.warning("FCM delivery skipped after %s", type(exc).__name__)


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

    def public_session_id(token_hash: str) -> str:
        return hashlib.sha256(
            ("waysgram-session-id:" + token_hash).encode("utf-8")
        ).hexdigest()[:32]

    @router.post("/api/push/register")
    async def register_push_device(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        raw_token = payload.get("token")
        if not isinstance(raw_token, str):
            raise HTTPException(status_code=400, detail="Некорректный FCM token")
        device_token = raw_token.strip()
        if (
            not 20 <= len(device_token) <= 4096
            or any(ord(char) < 33 or ord(char) > 126 for char in device_token)
        ):
            raise HTTPException(status_code=400, detail="Некорректный FCM token")
        platform = str(payload.get("platform") or "android").strip().lower()
        if platform != "android":
            raise HTTPException(status_code=400, detail="Поддерживается только Android")
        now = int(time.time())
        uid = int(user["telegram_id"])
        session_hash = _token_hash(authorization[7:].strip())
        token_hash = _token_hash(device_token)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute(
                """INSERT INTO push_devices(
                       token_hash,token_value,telegram_id,session_token_hash,
                       platform,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(token_hash) DO UPDATE SET
                       token_value=excluded.token_value,
                       telegram_id=excluded.telegram_id,
                       session_token_hash=excluded.session_token_hash,
                       platform=excluded.platform,
                       updated_at=excluded.updated_at""",
                (token_hash, device_token, uid, session_hash, platform, now, now),
            )
            await db.commit()
        return {"status": "registered", "platform": platform}

    @router.get("/api/auth/sessions")
    async def list_auth_sessions(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        current_hash = _token_hash(authorization[7:].strip())
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute(
                "DELETE FROM api_sessions WHERE telegram_id=? AND expires_at<=?",
                (uid, now),
            )
            cur = await db.execute(
                """SELECT token_hash,created_at,expires_at
                   FROM api_sessions WHERE telegram_id=?
                   ORDER BY created_at DESC,token_hash""",
                (uid,),
            )
            rows = await cur.fetchall()
            await db.commit()
        sessions = [
            {
                "id": public_session_id(str(row["token_hash"])),
                "created_at": int(row["created_at"]),
                "expires_at": int(row["expires_at"]),
                "is_current": hmac.compare_digest(str(row["token_hash"]), current_hash),
            }
            for row in rows
        ]
        return {"sessions": sessions, "count": len(sessions)}

    @router.delete("/api/auth/sessions/{session_id}")
    async def revoke_auth_session(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        if not re.fullmatch(r"[a-f0-9]{32}", session_id):
            raise HTTPException(status_code=400, detail="Некорректный ID сеанса")
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT token_hash FROM api_sessions WHERE telegram_id=?",
                (uid,),
            )
            rows = await cur.fetchall()
            token_hash = next(
                (
                    str(row["token_hash"])
                    for row in rows
                    if hmac.compare_digest(public_session_id(str(row["token_hash"])), session_id)
                ),
                None,
            )
            if token_hash is None:
                raise HTTPException(status_code=404, detail="Сеанс не найден")
            await db.execute(
                "DELETE FROM push_devices WHERE session_token_hash=?",
                (token_hash,),
            )
            cur = await db.execute(
                "DELETE FROM api_sessions WHERE telegram_id=? AND token_hash=?",
                (uid, token_hash),
            )
            await db.commit()
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Сеанс не найден")
        return {"status": "revoked", "session_id": session_id}

    @router.post("/api/auth/sessions/revoke-others")
    async def revoke_other_auth_sessions(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        current_hash = _token_hash(authorization[7:].strip())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute(
                """DELETE FROM push_devices WHERE session_token_hash IN (
                       SELECT token_hash FROM api_sessions
                       WHERE telegram_id=? AND token_hash<>?
                   )""",
                (uid, current_hash),
            )
            cur = await db.execute(
                "DELETE FROM api_sessions WHERE telegram_id=? AND token_hash<>?",
                (uid, current_hash),
            )
            revoked = int(cur.rowcount)
            await db.commit()
        return {"status": "revoked", "revoked_sessions": revoked}

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

    async def media_message_fields(db: Any, media_id: str | None) -> dict[str, str | None]:
        if not media_id:
            return {"media_type": None, "media_name": None}
        cur = await db.execute(
            "SELECT mime_type,original_name FROM media_assets WHERE id=?",
            (media_id,),
        )
        media = await cur.fetchone()
        if media is None:
            raise HTTPException(status_code=404, detail="Вложение не найдено")
        return {
            "media_type": str(media[0]),
            "media_name": str(media[1] or "document"),
        }

    async def default_media_message_body(db: Any, media_id: str) -> str:
        fields = await media_message_fields(db, media_id)
        if str(fields["media_type"] or "").startswith("image/"):
            return "Изображение"
        return "Документ: " + str(fields["media_name"] or "document")

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
                       (id,owner_telegram_id,storage_name,mime_type,size_bytes,created_at,original_name)
                       VALUES(?,?,?,?,?,?,?)""",
                    (media_id, uid, storage_name, mime_type, len(normalized), now, "image" + extension),
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

    @router.post("/api/media/documents", status_code=201)
    async def upload_document(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        declared_type = str(request.headers.get("content-type", "")).split(";", 1)[0].strip().lower()
        allowed_types = {
            "application/pdf", "text/plain", "text/csv", "application/zip",
            "video/mp4", "video/webm", "video/quicktime", "video/x-matroska",
            "audio/mpeg", "audio/mp4", "audio/ogg", "audio/wav",
            "application/octet-stream",
        }
        if declared_type not in allowed_types:
            raise HTTPException(
                status_code=415,
                detail="Поддерживаются PDF, TXT, CSV, ZIP, MP4, WebM, MOV, MKV, MP3, M4A, OGG и WAV",
            )
        declared_length = request.headers.get("content-length")
        if declared_length:
            try:
                if int(declared_length) > MAX_DOCUMENT_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Размер вложения превышает 25 МБ")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Некорректный Content-Length") from exc

        incoming = bytearray()
        async for chunk in request.stream():
            if len(incoming) + len(chunk) > MAX_DOCUMENT_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Размер вложения превышает 25 МБ")
            incoming.extend(chunk)
        if not incoming:
            raise HTTPException(status_code=400, detail="Файл документа пуст")

        raw_filename = request.headers.get("x-filename", "document")
        try:
            filename = unquote(raw_filename, errors="strict")
            normalized, mime_type, extension, safe_name = await asyncio.to_thread(
                _normalize_uploaded_document, bytes(incoming), filename
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise HTTPException(status_code=415, detail=str(exc)) from exc
        if declared_type not in {mime_type, "application/octet-stream"}:
            raise HTTPException(status_code=415, detail="Заголовок Content-Type не совпадает с документом")

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
                    raise HTTPException(status_code=413, detail="Достигнут лимит хранилища файлов аккаунта")
                if int(quota["recent_uploads"] or 0) >= MAX_USER_IMAGE_UPLOADS_PER_HOUR:
                    await db.rollback()
                    raise HTTPException(status_code=429, detail="Слишком много загрузок. Повторите позже.")

                await asyncio.to_thread(file_path.write_bytes, normalized)
                await db.execute(
                    """INSERT INTO media_assets
                       (id,owner_telegram_id,storage_name,mime_type,size_bytes,created_at,original_name)
                       VALUES(?,?,?,?,?,?,?)""",
                    (media_id, uid, storage_name, mime_type, len(normalized), now, safe_name),
                )
                await db.commit()
        except Exception:
            await asyncio.to_thread(file_path.unlink, missing_ok=True)
            raise
        return {
            "id": media_id,
            "mime_type": mime_type,
            "name": safe_name,
            "size_bytes": len(normalized),
            "url": f"/api/media/{media_id}",
        }

    @router.get("/api/media/shared")
    async def list_shared_media(
        scope: str = Query(...),
        peer_id: int = Query(..., gt=0),
        kind: str | None = Query(default=None),
        before_id: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=100),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        if kind not in (None, "image", "video", "audio", "document"):
            raise HTTPException(status_code=400, detail="kind: image, video, audio, document или без фильтра")
        mime_clause = ""
        if kind == "image":
            mime_clause = "AND lower(a.mime_type) LIKE 'image/%'"
        elif kind == "video":
            mime_clause = "AND lower(a.mime_type) LIKE 'video/%'"
        elif kind == "audio":
            mime_clause = "AND lower(a.mime_type) LIKE 'audio/%'"
        elif kind == "document":
            mime_clause = """AND lower(a.mime_type) NOT LIKE 'image/%'
                             AND lower(a.mime_type) NOT LIKE 'video/%'
                             AND lower(a.mime_type) NOT LIKE 'audio/%'"""

        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            # Keep authorization and the media query in the same read transaction.
            await db.execute("BEGIN")
            if scope == "dm":
                cur = await db.execute("SELECT is_banned FROM accounts WHERE telegram_id=?", (peer_id,))
                target = await cur.fetchone()
                if target is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Собеседник не найден")
                if target[0]:
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Аккаунт собеседника недоступен")
                cur = await db.execute(
                    f"""SELECT m.id AS message_id,m.sender_telegram_id AS sender_id,
                               m.recipient_telegram_id AS recipient_id,m.body,m.media_id,
                               a.mime_type AS media_type,a.original_name AS media_name,m.created_at
                        FROM messages m JOIN media_assets a ON a.id=m.media_id
                        WHERE ((m.sender_telegram_id=? AND m.recipient_telegram_id=?) OR
                               (m.sender_telegram_id=? AND m.recipient_telegram_id=?))
                          AND NOT EXISTS (
                              SELECT 1 FROM message_hidden_for hidden
                              WHERE hidden.message_id=m.id AND hidden.telegram_id=?
                          )
                          AND m.media_id IS NOT NULL AND (?=0 OR m.id<?)
                          {mime_clause}
                        ORDER BY m.id DESC LIMIT ?""",
                    (uid, peer_id, peer_id, uid, uid, before_id, before_id, limit),
                )
            elif scope == "group":
                await require_group_member(db, peer_id, uid)
                cur = await db.execute(
                    f"""SELECT m.id AS message_id,m.sender_telegram_id AS sender_id,
                               m.body,m.media_id,a.mime_type AS media_type,
                               a.original_name AS media_name,m.created_at
                        FROM group_messages m JOIN media_assets a ON a.id=m.media_id
                        WHERE m.group_id=? AND m.media_id IS NOT NULL
                          AND (?=0 OR m.id<?) {mime_clause}
                        ORDER BY m.id DESC LIMIT ?""",
                    (peer_id, before_id, before_id, limit),
                )
            else:
                cur = await db.execute(
                    """SELECT ch.is_public,ch.owner_telegram_id,
                              EXISTS(SELECT 1 FROM channel_admins ca
                                     WHERE ca.channel_id=ch.id AND ca.telegram_id=?),
                              EXISTS(SELECT 1 FROM channel_members cm
                                     WHERE cm.channel_id=ch.id AND cm.telegram_id=?)
                       FROM channels ch WHERE ch.id=?""",
                    (uid, uid, peer_id),
                )
                access = await cur.fetchone()
                if access is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Канал не найден")
                is_public, owner_id, is_admin, is_member = access
                if not bool(is_public) and int(owner_id) != uid and not bool(is_admin) and not bool(is_member):
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Нет доступа к приватному каналу")
                cur = await db.execute(
                    f"""SELECT m.id AS message_id,m.author_telegram_id AS sender_id,
                               m.body,m.media_id,a.mime_type AS media_type,
                               a.original_name AS media_name,m.created_at
                        FROM channel_messages m JOIN media_assets a ON a.id=m.media_id
                        WHERE m.channel_id=? AND m.media_id IS NOT NULL
                          AND (?=0 OR m.id<?) {mime_clause}
                        ORDER BY m.id DESC LIMIT ?""",
                    (peer_id, before_id, before_id, limit),
                )
            rows = [dict(row) for row in await cur.fetchall()]
            await db.commit()
        for row in rows:
            row["url"] = f"/api/media/{row['media_id']}"
        return {
            "scope": scope,
            "peer_id": peer_id,
            "kind": kind or "all",
            "media": rows,
            "count": len(rows),
            "has_more": len(rows) == limit,
            "next_before_id": int(rows[-1]["message_id"]) if rows else 0,
        }

    @router.get("/api/media/{media_id}")
    async def download_media(
        media_id: str,
        request: Request,
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
                       (sender_telegram_id=? OR recipient_telegram_id=?)
                         AND NOT EXISTS (
                             SELECT 1 FROM message_hidden_for hidden
                             WHERE hidden.message_id=messages.id AND hidden.telegram_id=?
                         )
                       LIMIT 1""",
                    (media_id, uid, uid, uid),
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
                cur = await db.execute("SELECT 1 FROM accounts WHERE avatar_media_id=? LIMIT 1", (media_id,))
                allowed = await cur.fetchone() is not None
            if not allowed:
                raise HTTPException(status_code=404, detail="Изображение не найдено")

        file_path = media_storage_dir() / str(media["storage_name"])
        try:
            file_size = (await asyncio.to_thread(file_path.stat)).st_size
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Файл изображения отсутствует на сервере") from exc

        mime_type = str(media["mime_type"])
        original_name = str(media["original_name"] or "document")
        content_disposition = (
            "inline"
            if mime_type.startswith(("image/", "video/", "audio/"))
            else "attachment; filename=\"" + re.sub(r"[^A-Za-z0-9._-]", "_", original_name)
                 + "\"; filename*=UTF-8''" + quote(original_name, safe="")
        )
        response_headers = {
            "Accept-Ranges": "bytes",
            "Cache-Control": "private, max-age=3600",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": content_disposition,
        }

        range_header = request.headers.get("range", "").strip()
        if range_header.lower().startswith("bytes="):
            match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header, flags=re.IGNORECASE)
            if match is None or (not match.group(1) and not match.group(2)):
                return Response(
                    status_code=416,
                    headers={**response_headers, "Content-Range": f"bytes */{file_size}"},
                )

            first, last = match.groups()
            if len(first) > 20 or len(last) > 20:
                return Response(
                    status_code=416,
                    headers={**response_headers, "Content-Range": f"bytes */{file_size}"},
                )
            if not first:
                suffix_length = int(last)
                if suffix_length <= 0 or file_size <= 0:
                    return Response(
                        status_code=416,
                        headers={**response_headers, "Content-Range": f"bytes */{file_size}"},
                    )
                start_byte = max(0, file_size - suffix_length)
                end_byte = file_size - 1
            else:
                start_byte = int(first)
                end_byte = int(last) if last else file_size - 1
                if start_byte >= file_size or end_byte < start_byte:
                    return Response(
                        status_code=416,
                        headers={**response_headers, "Content-Range": f"bytes */{file_size}"},
                    )
                end_byte = min(end_byte, file_size - 1)

            byte_count = end_byte - start_byte + 1

            def read_media_range() -> bytes:
                with file_path.open("rb") as media_file:
                    media_file.seek(start_byte)
                    return media_file.read(byte_count)

            content = await asyncio.to_thread(read_media_range)
            return Response(
                content=content,
                status_code=206,
                media_type=mime_type,
                headers={
                    **response_headers,
                    "Content-Range": f"bytes {start_byte}-{end_byte}/{file_size}",
                },
            )

        try:
            content = await asyncio.to_thread(file_path.read_bytes)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Файл изображения отсутствует на сервере") from exc
        return Response(
            content=content,
            media_type=mime_type,
            headers=response_headers,
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
                """SELECT ch.id,
                          CASE WHEN ch.is_public=1 THEN ch.username ELSE '' END AS username,
                          ch.title,ch.owner_telegram_id,ch.is_public,
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

    async def can_view_channel(channel_id: int, telegram_id: int) -> bool:
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                """SELECT 1 FROM channels ch
                   WHERE ch.id=? AND (
                       ch.is_public=1 OR ch.owner_telegram_id=?
                       OR EXISTS(SELECT 1 FROM channel_admins ca
                                 WHERE ca.channel_id=ch.id AND ca.telegram_id=?)
                       OR EXISTS(SELECT 1 FROM channel_members cm
                                 WHERE cm.channel_id=ch.id AND cm.telegram_id=?)
                   )""",
                (channel_id, telegram_id, telegram_id, telegram_id),
            )
            return await cur.fetchone() is not None

    async def require_channel_access(channel_id: int, telegram_id: int) -> None:
        await channel_row(channel_id)
        if not await can_view_channel(channel_id, telegram_id):
            raise HTTPException(status_code=403, detail="Это приватный канал. Нужна ссылка-приглашение.")

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

    async def require_cloud_draft_access(scope: str, peer_id: int, telegram_id: int) -> None:
        if scope == "dm":
            async with aiosqlite.connect(db_path()) as db:
                cur = await db.execute(
                    "SELECT is_banned FROM accounts WHERE telegram_id=?", (peer_id,)
                )
                peer = await cur.fetchone()
                if peer is None:
                    raise HTTPException(status_code=404, detail="Собеседник не найден")
                if peer[0]:
                    raise HTTPException(status_code=403, detail="Аккаунт собеседника недоступен")
                if peer_id != telegram_id:
                    cur = await db.execute(
                        """SELECT 1 FROM blocked_users
                           WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                              OR (owner_telegram_id=? AND blocked_telegram_id=?) LIMIT 1""",
                        (telegram_id, peer_id, peer_id, telegram_id),
                    )
                    if await cur.fetchone():
                        raise HTTPException(status_code=403, detail="Нельзя работать с черновиком: пользователь в чёрном списке")
        elif scope == "group":
            async with aiosqlite.connect(db_path()) as db:
                await require_group_member(db, peer_id, telegram_id)
        elif scope == "channel":
            await require_channel_access(peer_id, telegram_id)

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
            "push_notifications": True,
            "push_delivery_ready": _firebase_service_account() is not None,
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
                "profiles", "contact_notes", "common_groups", "mutual_contacts", "direct_messages", "saved_messages", "pinned_messages", "typing_indicators", "incremental_messages",
                "channels", "private_channels", "channel_invites",
                "incremental_channel_posts", "idempotent_writes",
                "session_refresh", "session_management", "cloud_drafts", "gifts", "gift_inventory", "gift_transfer",
                "gift_auctions", "auction_bids", "telegram_gift_catalog",
                "telegram_gift_sticker_proxy", "groups", "group_members", "group_messages", "group_invites", "group_join_requests", "group_slow_mode",
                "image_uploads", "document_uploads", "message_media", "shared_media", "private_media_downloads",
                "long_poll_messages", "push_notifications",
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
                session_hash = _token_hash(token)
                async with aiosqlite.connect(db_path()) as db:
                    await db.execute("DELETE FROM push_devices WHERE session_token_hash=?", (session_hash,))
                    await db.execute("DELETE FROM api_sessions WHERE token_hash=?", (session_hash,))
                    await db.commit()
        return {"status": "logged_out"}

    @router.get("/api/me")
    async def get_me(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        result = _public_account(user, include_phone=True)
        result["is_admin"] = is_admin_user(user)
        return result

    @router.put("/api/me/avatar")
    async def set_avatar(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        media_id = str(payload.get("media_id") or "").strip()
        if not re.fullmatch(r"[a-f0-9]{32}", media_id):
            raise HTTPException(status_code=400, detail="Некорректный идентификатор изображения")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT mime_type FROM media_assets WHERE id=? AND owner_telegram_id=?", (media_id, uid)
            )
            media = await cur.fetchone()
            if media is None or not str(media["mime_type"]).startswith("image/"):
                raise HTTPException(status_code=404, detail="Изображение не найдено")
            await db.execute(
                "UPDATE accounts SET avatar_media_id=?,updated_at=? WHERE telegram_id=?",
                (media_id, int(time.time()), uid),
            )
            await db.commit()
        return {"avatar_media_id": media_id}

    @router.delete("/api/me/avatar")
    async def remove_avatar(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute(
                "UPDATE accounts SET avatar_media_id='',updated_at=? WHERE telegram_id=?",
                (int(time.time()), int(user["telegram_id"])),
            )
            await db.commit()
        return {"avatar_media_id": ""}

    @router.put("/api/me")
    @router.patch("/api/me")
    async def update_me(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        if not payload or not ({"username", "display_name", "bio"} & payload.keys()):
            raise HTTPException(status_code=400, detail="Нет полей для изменения")
        username = user["username"]
        display_name = user["display_name"]
        bio = _bio_of(user)
        if "bio" in payload:
            if not isinstance(payload["bio"], str) or len(payload["bio"].strip()) > 140:
                raise HTTPException(status_code=400, detail="О себе: не более 140 символов")
            bio = payload["bio"].strip()
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
                "UPDATE accounts SET username=?,display_name=?,bio=?,updated_at=? WHERE telegram_id=?",
                (username, display_name, bio, int(time.time()), int(user["telegram_id"])),
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
                """SELECT id,serial_number,gift_id,telegram_gift_id,gift_name,acquired_at,
                          upgrade_level,attributes_json,
                          EXISTS(SELECT 1 FROM gift_market_listings l
                                 WHERE l.serial_number=user_gifts.serial_number
                                   AND l.status='active') AS is_listed,
                          EXISTS(SELECT 1 FROM gift_collectible_auctions a
                                 WHERE a.serial_number=user_gifts.serial_number
                                   AND a.status='active') AS is_auctioned
                   FROM user_gifts WHERE owner_telegram_id=? ORDER BY id DESC""",
                (int(user["telegram_id"]),),
            )
            rows = await cur.fetchall()
        gifts = []
        for row in rows:
            item = dict(row)
            try:
                item["attributes"] = json.loads(item.pop("attributes_json") or "{}")
            except (TypeError, ValueError):
                item["attributes"] = {}
            gifts.append(item)
        return {"gifts": gifts}

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
                    """SELECT telegram_id AS id,username,display_name,avatar_media_id FROM accounts
                       WHERE telegram_id=? LIMIT 30""",
                    (int(q),),
                )
            else:
                cur = await db.execute(
                    """SELECT telegram_id AS id,username,display_name,avatar_media_id FROM accounts
                       WHERE username LIKE ? OR display_name LIKE ?
                       ORDER BY telegram_id DESC LIMIT 30""",
                    (f"%{q}%", f"%{q}%"),
                )
            rows = await cur.fetchall()
        return {"users": [dict(row) for row in rows]}

    @router.get("/api/contacts")
    async def list_contacts(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT a.telegram_id AS id,a.username,a.display_name,a.avatar_media_id,a.bio,c.created_at,
                          COALESCE(n.note,'') AS note
                   FROM contacts c JOIN accounts a ON a.telegram_id=c.contact_telegram_id
                   LEFT JOIN contact_notes n
                     ON n.owner_telegram_id=c.owner_telegram_id AND n.contact_telegram_id=c.contact_telegram_id
                   WHERE c.owner_telegram_id=? AND a.is_banned=0
                   ORDER BY lower(a.display_name),lower(a.username),a.telegram_id""",
                (uid,),
            )
            rows = await cur.fetchall()
        return {"contacts": [dict(row) for row in rows], "count": len(rows)}

    @router.post("/api/contacts", status_code=201)
    async def add_contact(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        value = payload.get("user_id")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise HTTPException(status_code=400, detail="Укажите корректный ID пользователя")
        if value == uid:
            raise HTTPException(status_code=400, detail="Нельзя добавить себя в контакты")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT telegram_id AS id,username,display_name,avatar_media_id,bio FROM accounts WHERE telegram_id=? AND is_banned=0",
                (value,),
            )
            contact = await cur.fetchone()
            if contact is None:
                raise HTTPException(status_code=404, detail="Пользователь не найден")
            cur = await db.execute(
                """INSERT OR IGNORE INTO contacts(owner_telegram_id,contact_telegram_id,created_at)
                   VALUES(?,?,?)""",
                (uid, value, now),
            )
            added = cur.rowcount == 1
            await db.commit()
        return {
            "status": "added" if added else "already_exists",
            "contact": dict(contact),
        }

    @router.delete("/api/contacts/{user_id}")
    async def remove_contact(
        user_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            owner_id = int(user["telegram_id"])
            cur = await db.execute(
                "DELETE FROM contacts WHERE owner_telegram_id=? AND contact_telegram_id=?",
                (owner_id, user_id),
            )
            if cur.rowcount != 1:
                raise HTTPException(status_code=404, detail="Контакт не найден")
            await db.execute(
                "DELETE FROM contact_notes WHERE owner_telegram_id=? AND contact_telegram_id=?",
                (owner_id, user_id),
            )
            await db.commit()
        return {"status": "removed", "user_id": user_id}

    @router.put("/api/contacts/{user_id}/note")
    async def update_contact_note(
        user_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        note = payload.get("note")
        if not isinstance(note, str) or len(note.strip()) > 500:
            raise HTTPException(status_code=400, detail="Заметка должна содержать не более 500 символов")
        note = note.strip()
        owner_id = int(user["telegram_id"])
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT 1 FROM contacts WHERE owner_telegram_id=? AND contact_telegram_id=?",
                (owner_id, user_id),
            )
            if await cur.fetchone() is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сначала добавьте пользователя в контакты")
            if note:
                await db.execute(
                    """INSERT INTO contact_notes(owner_telegram_id,contact_telegram_id,note,updated_at)
                       VALUES(?,?,?,?)
                       ON CONFLICT(owner_telegram_id,contact_telegram_id) DO UPDATE SET
                           note=excluded.note,updated_at=excluded.updated_at""",
                    (owner_id, user_id, note, now),
                )
            else:
                await db.execute(
                    "DELETE FROM contact_notes WHERE owner_telegram_id=? AND contact_telegram_id=?",
                    (owner_id, user_id),
                )
            await db.commit()
        return {"user_id": user_id, "note": note, "updated_at": now if note else None}

    @router.get("/api/blocks")
    async def list_blocked_users(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT a.telegram_id AS id,a.username,a.display_name,a.avatar_media_id,b.created_at
                   FROM blocked_users b JOIN accounts a ON a.telegram_id=b.blocked_telegram_id
                   WHERE b.owner_telegram_id=?
                   ORDER BY b.created_at DESC,b.blocked_telegram_id""",
                (uid,),
            )
            rows = await cur.fetchall()
        return {"blocked_users": [dict(row) for row in rows], "count": len(rows)}

    @router.post("/api/blocks", status_code=201)
    async def block_user(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        target_id = payload.get("user_id")
        if isinstance(target_id, bool) or not isinstance(target_id, int) or target_id <= 0:
            raise HTTPException(status_code=400, detail="Укажите корректный ID пользователя")
        if target_id == uid:
            raise HTTPException(status_code=400, detail="Нельзя заблокировать себя")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT telegram_id AS id,username,display_name,avatar_media_id
                   FROM accounts WHERE telegram_id=? AND is_banned=0""",
                (target_id,),
            )
            target = await cur.fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="Пользователь не найден")
            cur = await db.execute(
                """INSERT OR IGNORE INTO blocked_users(owner_telegram_id,blocked_telegram_id,created_at)
                   VALUES(?,?,?)""",
                (uid, target_id, int(time.time())),
            )
            added = cur.rowcount == 1
            await db.commit()
        return {
            "status": "blocked" if added else "already_blocked",
            "user": dict(target),
        }

    @router.delete("/api/blocks/{user_id}")
    async def unblock_user(
        user_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "DELETE FROM blocked_users WHERE owner_telegram_id=? AND blocked_telegram_id=?",
                (int(user["telegram_id"]), user_id),
            )
            if cur.rowcount != 1:
                raise HTTPException(status_code=404, detail="Пользователь не найден в чёрном списке")
            await db.commit()
        return {"status": "unblocked", "user_id": user_id}

    @router.get("/api/users/{user_id}")
    async def get_user_profile(
        user_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        viewer = await current_user(authorization)
        viewer_id = int(viewer["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT telegram_id AS id,username,display_name,avatar_media_id,bio,created_at
                   FROM accounts WHERE telegram_id=? AND is_banned=0""",
                (user_id,),
            )
            row = await cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Пользователь не найден")
            cur = await db.execute(
                """SELECT id,serial_number,gift_id,telegram_gift_id,gift_name,acquired_at,
                          upgrade_level,attributes_json,
                          EXISTS(SELECT 1 FROM gift_market_listings l
                                 WHERE l.serial_number=user_gifts.serial_number
                                   AND l.status='active') AS is_listed,
                          EXISTS(SELECT 1 FROM gift_collectible_auctions a
                                 WHERE a.serial_number=user_gifts.serial_number
                                   AND a.status='active') AS is_auctioned
                   FROM user_gifts
                   WHERE owner_telegram_id=?
                   ORDER BY id DESC LIMIT 50""",
                (user_id,),
            )
            gifts = [dict(item) for item in await cur.fetchall()]
            cur = await db.execute(
                """SELECT g.id,g.username,g.title,
                          (SELECT COUNT(*) FROM group_members count_members
                           WHERE count_members.group_id=g.id) AS member_count
                   FROM group_members viewer_member
                   JOIN group_members target_member
                     ON target_member.group_id=viewer_member.group_id
                   JOIN chat_groups g ON g.id=viewer_member.group_id
                   WHERE viewer_member.telegram_id=? AND target_member.telegram_id=?
                   ORDER BY g.id DESC LIMIT 50""",
                (viewer_id, user_id),
            )
            common_groups = [dict(item) for item in await cur.fetchall()]
            cur = await db.execute(
                """SELECT a.telegram_id AS id,a.username,a.display_name,a.avatar_media_id
                   FROM contacts viewer_contact
                   JOIN contacts target_contact
                     ON target_contact.contact_telegram_id=viewer_contact.contact_telegram_id
                    AND target_contact.owner_telegram_id=?
                   JOIN accounts a ON a.telegram_id=viewer_contact.contact_telegram_id
                   WHERE viewer_contact.owner_telegram_id=? AND a.is_banned=0
                   ORDER BY lower(a.display_name),lower(a.username),a.telegram_id
                   LIMIT 50""",
                (user_id, viewer_id),
            )
            common_contacts = [dict(item) for item in await cur.fetchall()]
        profile = dict(row)
        for gift in gifts:
            try:
                gift["attributes"] = json.loads(gift.pop("attributes_json") or "{}")
            except (TypeError, ValueError):
                gift["attributes"] = {}
        profile["gifts"] = gifts
        profile["common_groups"] = common_groups
        profile["common_contacts"] = common_contacts
        return profile

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

    def is_admin_user(user: Any) -> bool:
        return admin_id is not None and int(user["telegram_id"]) == int(admin_id)

    async def gift_prices() -> dict[str, dict[str, int]]:
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT gift_id,price_stars,supply,sold FROM telegram_gift_prices")
            rows = await cur.fetchall()
        return {
            str(row["gift_id"]): {
                "price_stars": int(row["price_stars"]),
                "supply": int(row["supply"]),
                "sold": int(row["sold"]),
            }
            for row in rows
        }

    @router.post("/api/telegram/gifts/{gift_id}/purchase", status_code=201)
    async def purchase_telegram_gift(
        gift_id: str,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", gift_id):
            raise HTTPException(status_code=400, detail="Некорректный Telegram Gift ID")
        recipient = payload.get("recipient_id")
        if recipient is not None and (isinstance(recipient, bool) or not isinstance(recipient, int) or recipient <= 0):
            raise HTTPException(status_code=400, detail="Некорректный получатель")
        key = (idempotency_key or "").strip()
        if key and (len(key) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", key)):
            raise HTTPException(status_code=400, detail="Некорректный Idempotency-Key")
        canonical = json.dumps(
            {"gift_id": gift_id, "payload": payload},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        request_hash = hashlib.sha256(
            ("/api/telegram/gifts/purchase\n" + canonical).encode("utf-8")
        ).hexdigest()
        await ensure_telegram_gifts_fresh()  # the catalog must exist before a title can be looked up
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            if key:
                cur = await db.execute(
                    """SELECT request_hash,response_json FROM api_idempotency_records
                       WHERE telegram_id=? AND scope='telegram_gift_purchase'
                         AND idempotency_key=? AND created_at>=?""",
                    (uid, key, now - 7 * 86400),
                )
                prior = await cur.fetchone()
                if prior:
                    await db.rollback()
                    if not hmac.compare_digest(str(prior["request_hash"]), request_hash):
                        raise HTTPException(
                            status_code=409,
                            detail="Idempotency-Key уже использован для другого запроса",
                        )
                    return json.loads(prior["response_json"])
            cur = await db.execute(
                "SELECT price_stars,supply,sold FROM telegram_gift_prices WHERE gift_id=?", (gift_id,)
            )
            priced = await cur.fetchone()
            if not priced or int(priced["price_stars"]) <= 0 or int(priced["supply"]) - int(priced["sold"]) <= 0:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Подарок недоступен для покупки")
            title = await telegram_gift_title(db, gift_id)
            if not title:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Подарок больше недоступен в Telegram")
            price = int(priced["price_stars"])
            cur = await db.execute("SELECT stars,is_banned FROM accounts WHERE telegram_id=?", (uid,))
            account = await cur.fetchone()
            if not account or account["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Аккаунт недоступен")
            owner = uid
            if recipient is not None and int(recipient) != uid:
                cur = await db.execute("SELECT is_banned FROM accounts WHERE telegram_id=?", (int(recipient),))
                target = await cur.fetchone()
                if not target or target["is_banned"]:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Получатель не найден")
                owner = int(recipient)
            cur = await db.execute(
                "UPDATE accounts SET stars=stars-?,updated_at=? WHERE telegram_id=? AND stars>=?",
                (price, now, uid, price),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Stars")
            cur = await db.execute(
                "UPDATE telegram_gift_prices SET sold=sold+1 WHERE gift_id=? AND sold<supply", (gift_id,)
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Подарок закончился")
            serial = "WG-" + secrets.token_hex(6).upper()
            await db.execute(
                """INSERT INTO user_gifts
                   (serial_number,gift_id,telegram_gift_id,gift_name,owner_telegram_id,acquired_at)
                   VALUES(?,NULL,?,?,?,?)""",
                (serial, gift_id, title, owner, now),
            )
            balance = int(account["stars"]) - price
            await db.execute(
                """INSERT INTO economy_transactions(telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                   VALUES(?,'stars',?,?,?,NULL,?)""",
                (uid, -price, balance, f"telegram_gift:{gift_id}", now),
            )
            await db.execute(
                """INSERT INTO gift_transactions(event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                   VALUES('purchase',?,?,NULL,?,?)""",
                (serial, title, uid, now),
            )
            # Telegram-style purchase receipt in the buyer's Saved Messages.
            # It is committed atomically with the balance debit and inventory item.
            cur = await db.execute(
                """INSERT INTO messages
                   (sender_telegram_id,recipient_telegram_id,body,created_at)
                   VALUES(?,?,?,?)""",
                (uid, uid, f"Вы приобрели коллекционный подарок «{title}»", now),
            )
            saved_message_id = int(cur.lastrowid)
            await db.execute(
                """INSERT INTO message_gifts
                   (message_id,serial_number,gift_name,telegram_gift_id,upgrade_level,attributes_json)
                   VALUES(?,?,?,?,0,'{}')""",
                (saved_message_id, serial, title, gift_id),
            )
            await record_event(
                db, "dm", saved_message_id, "new_message", uid,
                user_a=uid, user_b=uid,
            )
            if owner != uid:
                await db.execute(
                    """INSERT INTO gift_transactions(event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                       VALUES('transfer',?,?,?,?,?)""",
                    (serial, title, uid, owner, now),
                )
            result = {
                "status": "purchased",
                "gift": {
                    "serial_number": serial,
                    "telegram_gift_id": gift_id,
                    "gift_name": title,
                    "owner_id": owner,
                },
                "price_stars": price,
                "stars": balance,
            }
            if key:
                await db.execute(
                    """INSERT INTO api_idempotency_records
                       (telegram_id,scope,idempotency_key,request_hash,response_json,created_at)
                       VALUES(?,'telegram_gift_purchase',?,?,?,?)""",
                    (uid, key, request_hash, json.dumps(result, ensure_ascii=False, separators=(",", ":")), now),
                )
            await db.commit()
        return result

    async def telegram_gift_title(db: Any, gift_id: str) -> str:
        cur = await db.execute("SELECT source FROM telegram_gift_sync_state WHERE id=1")
        state = await cur.fetchone()
        source = str(state[0]) if state else "telegram_bot_api"
        table = "telegram_mtproto_gift_catalog" if source == "telegram_mtproto" else "telegram_gift_catalog"
        cur = await db.execute(
            f"SELECT title FROM {table} WHERE gift_id=?",
            (gift_id,),
        )
        row = await cur.fetchone()
        return str(row[0]) if row else ""

    @router.get("/api/telegram/gifts")
    async def telegram_gift_catalog(
        authorization: str | None = Header(default=None),
        all: int = 0,
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        show_all = bool(all)
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
                       ORDER BY is_available DESC, position ASC"""
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
                       ORDER BY is_available DESC, position ASC"""
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

        prices = await gift_prices()
        for gift in gifts:
            priced = prices.get(str(gift["id"]), {"price_stars": 0, "supply": 0, "sold": 0})
            gift["telegram_star_count"] = gift["star_count"]
            gift["price_stars"] = priced["price_stars"]
            gift["supply"] = priced["supply"]
            gift["sold"] = priced["sold"]
            gift["remaining"] = max(priced["supply"] - priced["sold"], 0)
            gift["for_sale"] = priced["price_stars"] > 0 and gift["remaining"] > 0
        if not show_all:
            # Nothing is for sale until the administrator sets a price and a stock for the gift.
            # The app asks for everything (all=1) to be able to draw the gifts a user already owns.
            gifts = [gift for gift in gifts if gift["for_sale"]]

        synced_at = int(state["last_synced_at"])
        return {
            "source": source,
            "scope": "telegram_full_mtproto_catalog" if source == "telegram_mtproto" else "gifts_available_to_authbot",
            "currency": "stars",
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
                       FROM telegram_gift_catalog WHERE gift_id=?""",
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
                "SELECT 1 FROM gift_market_listings WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала снимите подарок с продажи")
            cur = await db.execute(
                "SELECT 1 FROM gift_collectible_auctions WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала отмените аукцион подарка")
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

    async def settle_due_collectible_auctions(db: Any, now: int) -> int:
        cur = await db.execute(
            """SELECT id,serial_number,seller_telegram_id,current_bid_grams,
                      highest_bidder_telegram_id
               FROM gift_collectible_auctions
               WHERE status='active' AND ends_at<=?
               ORDER BY ends_at,id""",
            (now,),
        )
        due = await cur.fetchall()
        settled = 0
        for auction in due:
            auction_id = int(auction["id"])
            serial = str(auction["serial_number"])
            seller_id = int(auction["seller_telegram_id"])
            bidder_value = auction["highest_bidder_telegram_id"]
            bid = int(auction["current_bid_grams"])
            if bidder_value is None or bid <= 0:
                await db.execute(
                    "UPDATE gift_collectible_auctions SET status='ended',settled_at=? WHERE id=? AND status='active'",
                    (now, auction_id),
                )
                settled += 1
                continue

            bidder_id = int(bidder_value)
            cur = await db.execute(
                "SELECT id,gift_name FROM user_gifts WHERE serial_number=? AND owner_telegram_id=?",
                (serial, seller_id),
            )
            gift = await cur.fetchone()
            cur = await db.execute(
                "SELECT grams,is_banned FROM accounts WHERE telegram_id=?",
                (seller_id,),
            )
            seller = await cur.fetchone()
            cur = await db.execute(
                "SELECT grams,is_banned FROM accounts WHERE telegram_id=?",
                (bidder_id,),
            )
            bidder = await cur.fetchone()

            if gift is None or seller is None or bidder is None or seller["is_banned"] or bidder["is_banned"]:
                if bidder is not None:
                    refunded_balance = int(bidder["grams"]) + bid
                    await db.execute(
                        "UPDATE accounts SET grams=?,updated_at=? WHERE telegram_id=?",
                        (refunded_balance, now, bidder_id),
                    )
                    await db.execute(
                        """INSERT INTO economy_transactions
                           (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                           VALUES(?,'grams',?,?,?,NULL,?)""",
                        (bidder_id, bid, refunded_balance, f"gift_auction_refund:{auction_id}", now),
                    )
                await db.execute(
                    "UPDATE gift_collectible_auctions SET status='cancelled',settled_at=? WHERE id=? AND status='active'",
                    (now, auction_id),
                )
                settled += 1
                continue

            cur = await db.execute(
                "UPDATE user_gifts SET owner_telegram_id=? WHERE id=? AND owner_telegram_id=?",
                (bidder_id, int(gift["id"]), seller_id),
            )
            if cur.rowcount != 1:
                refunded_balance = int(bidder["grams"]) + bid
                await db.execute(
                    "UPDATE accounts SET grams=?,updated_at=? WHERE telegram_id=?",
                    (refunded_balance, now, bidder_id),
                )
                await db.execute(
                    """INSERT INTO economy_transactions
                       (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                       VALUES(?,'grams',?,?,?,NULL,?)""",
                    (bidder_id, bid, refunded_balance, f"gift_auction_refund:{auction_id}", now),
                )
                await db.execute(
                    "UPDATE gift_collectible_auctions SET status='cancelled',settled_at=? WHERE id=? AND status='active'",
                    (now, auction_id),
                )
                settled += 1
                continue

            seller_balance = int(seller["grams"]) + bid
            await db.execute(
                "UPDATE accounts SET grams=?,updated_at=? WHERE telegram_id=?",
                (seller_balance, now, seller_id),
            )
            await db.execute(
                """INSERT INTO economy_transactions
                   (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                   VALUES(?,'grams',?,?,?,NULL,?)""",
                (seller_id, bid, seller_balance, f"gift_auction_sale:{auction_id}", now),
            )
            await db.execute(
                """INSERT INTO gift_transactions
                   (event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                   VALUES('auction_sale',?,?,?,?,?)""",
                (serial, str(gift["gift_name"]), seller_id, bidder_id, now),
            )
            await db.execute(
                "UPDATE gift_collectible_auctions SET status='sold',settled_at=? WHERE id=? AND status='active'",
                (now, auction_id),
            )
            settled += 1
        return settled

    async def process_due_collectible_auctions() -> int:
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            settled = await settle_due_collectible_auctions(db, now)
            await db.commit()
        return settled

    @router.get("/api/gift-auctions")
    async def list_collectible_gift_auctions(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        viewer = await current_user(authorization)
        viewer_id = int(viewer["telegram_id"])
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            settled = await settle_due_collectible_auctions(db, now)
            cur = await db.execute(
                """SELECT a.id AS auction_id,a.serial_number,a.seller_telegram_id,
                          a.starting_price_grams,a.current_bid_grams,
                          a.highest_bidder_telegram_id,a.starts_at,a.ends_at,
                          g.gift_name,g.telegram_gift_id,g.upgrade_level,g.attributes_json,
                          seller.username AS seller_username,seller.display_name AS seller_display_name,
                          (SELECT COUNT(*) FROM gift_collectible_auction_bids b
                           WHERE b.auction_id=a.id) AS bid_count,
                          CASE WHEN a.current_bid_grams=0 THEN a.starting_price_grams
                               ELSE a.current_bid_grams+1 END AS minimum_bid_grams
                   FROM gift_collectible_auctions a
                   JOIN user_gifts g ON g.serial_number=a.serial_number
                   JOIN accounts seller ON seller.telegram_id=a.seller_telegram_id
                   WHERE a.status='active'
                   ORDER BY a.ends_at ASC,a.id ASC LIMIT 100"""
            )
            rows = await cur.fetchall()
            await db.commit()
        auctions = []
        for row in rows:
            item = dict(row)
            try:
                item["attributes"] = json.loads(item.pop("attributes_json") or "{}")
            except (TypeError, ValueError):
                item["attributes"] = {}
            item["is_own_auction"] = int(item["seller_telegram_id"]) == viewer_id
            auctions.append(item)
        return {"auctions": auctions, "count": len(auctions), "settled_count": settled, "currency": "grams"}

    @router.post("/api/gifts/{serial_number}/auction", status_code=201)
    async def create_collectible_gift_auction(
        serial_number: str,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        serial = serial_number.strip().upper()
        if not GIFT_SERIAL_RE.fullmatch(serial):
            raise HTTPException(status_code=400, detail="Некорректный серийный номер подарка")
        raw_start = payload.get("starting_price_grams")
        raw_duration = payload.get("duration_seconds", 86400)
        if isinstance(raw_start, bool) or isinstance(raw_duration, bool):
            raise HTTPException(status_code=400, detail="Цена и срок аукциона должны быть целыми числами")
        try:
            starting_price = int(raw_start)
            duration = int(raw_duration)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Укажите стартовую цену и срок аукциона")
        if not 1 <= starting_price <= 1_000_000_000:
            raise HTTPException(status_code=400, detail="Стартовая цена должна быть от 1 до 1000000000 Gram")
        if duration not in (3600, 21600, 86400, 259200, 604800):
            raise HTTPException(status_code=400, detail="Срок аукциона: 1, 6, 24, 72 или 168 часов")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            await settle_due_collectible_auctions(db, now)
            cur = await db.execute(
                "SELECT id,gift_name,upgrade_level,attributes_json FROM user_gifts WHERE serial_number=? AND owner_telegram_id=?",
                (serial, uid),
            )
            gift = await cur.fetchone()
            if gift is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Подарок не найден в вашем инвентаре")
            try:
                gift_attributes = json.loads(str(gift["attributes_json"] or "{}"))
            except (TypeError, ValueError):
                gift_attributes = {}
            if (
                int(gift["upgrade_level"] or 0) < 1
                or not _has_collectible_traits(gift_attributes)
            ):
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала улучшите подарок до коллекционного")
            cur = await db.execute(
                "SELECT 1 FROM gift_market_listings WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала снимите подарок с фиксированной продажи")
            cur = await db.execute(
                "SELECT 1 FROM gift_collectible_auctions WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Подарок уже выставлен на аукцион")
            ends_at = now + duration
            cur = await db.execute(
                """INSERT INTO gift_collectible_auctions
                   (serial_number,seller_telegram_id,starting_price_grams,current_bid_grams,
                    highest_bidder_telegram_id,status,starts_at,ends_at,created_at)
                   VALUES(?,?,?,0,NULL,'active',?,?,?)""",
                (serial, uid, starting_price, now, ends_at, now),
            )
            auction_id = int(cur.lastrowid)
            await db.commit()
        return {
            "status": "created",
            "auction_id": auction_id,
            "serial_number": serial,
            "gift_name": str(gift["gift_name"]),
            "starting_price_grams": starting_price,
            "current_bid_grams": 0,
            "minimum_bid_grams": starting_price,
            "starts_at": now,
            "ends_at": ends_at,
            "currency": "grams",
        }

    @router.delete("/api/gifts/{serial_number}/auction")
    async def cancel_collectible_gift_auction(
        serial_number: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        serial = serial_number.strip().upper()
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT id,current_bid_grams,highest_bidder_telegram_id
                   FROM gift_collectible_auctions
                   WHERE serial_number=? AND seller_telegram_id=? AND status='active'""",
                (serial, uid),
            )
            auction = await cur.fetchone()
            if auction is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Активный аукцион не найден")
            if auction["highest_bidder_telegram_id"] is not None or int(auction["current_bid_grams"]) > 0:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Нельзя отменить аукцион после первой ставки")
            await db.execute(
                "UPDATE gift_collectible_auctions SET status='cancelled',settled_at=? WHERE id=? AND status='active'",
                (now, int(auction["id"])),
            )
            await db.commit()
        return {"status": "cancelled", "serial_number": serial, "auction_id": int(auction["id"])}

    @router.post("/api/gift-auctions/{auction_id}/bid", status_code=201)
    async def place_collectible_gift_auction_bid(
        auction_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if auction_id <= 0:
            raise HTTPException(status_code=400, detail="Некорректный ID аукциона")
        raw_amount = payload.get("amount_grams")
        if isinstance(raw_amount, bool):
            raise HTTPException(status_code=400, detail="Ставка должна быть целым числом Gram")
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError):
            amount = 0
        if not 1 <= amount <= 1_000_000_000:
            raise HTTPException(status_code=400, detail="Ставка должна быть от 1 до 1000000000 Gram")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            await settle_due_collectible_auctions(db, now)
            cur = await db.execute(
                """SELECT id,serial_number,seller_telegram_id,starting_price_grams,
                          current_bid_grams,highest_bidder_telegram_id,ends_at
                   FROM gift_collectible_auctions WHERE id=? AND status='active'""",
                (auction_id,),
            )
            auction = await cur.fetchone()
            if auction is None or int(auction["ends_at"]) <= now:
                # Keep any due-auction settlement performed above.
                await db.commit()
                raise HTTPException(status_code=409, detail="Аукцион уже завершён или недоступен")
            seller_id = int(auction["seller_telegram_id"])
            if uid == seller_id:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Нельзя делать ставку на собственный подарок")
            current_bid = int(auction["current_bid_grams"])
            previous_bidder_value = auction["highest_bidder_telegram_id"]
            previous_bidder = int(previous_bidder_value) if previous_bidder_value is not None else None
            minimum = int(auction["starting_price_grams"]) if current_bid == 0 else current_bid + 1
            if amount < minimum:
                await db.rollback()
                raise HTTPException(status_code=409, detail=f"Минимальная следующая ставка: {minimum} Gram")
            cur = await db.execute(
                "SELECT grams,is_banned FROM accounts WHERE telegram_id=?",
                (uid,),
            )
            bidder = await cur.fetchone()
            if bidder is None or bidder["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Аккаунт недоступен")
            available = int(bidder["grams"]) + (current_bid if previous_bidder == uid else 0)
            if available < amount:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Gram для ставки")
            if previous_bidder is not None and current_bid > 0:
                cur = await db.execute(
                    "SELECT grams FROM accounts WHERE telegram_id=?",
                    (previous_bidder,),
                )
                previous_account = await cur.fetchone()
                if previous_account is not None:
                    refund_balance = int(previous_account["grams"]) + current_bid
                    await db.execute(
                        "UPDATE accounts SET grams=?,updated_at=? WHERE telegram_id=?",
                        (refund_balance, now, previous_bidder),
                    )
                    await db.execute(
                        """INSERT INTO economy_transactions
                           (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                           VALUES(?,'grams',?,?,?,NULL,?)""",
                        (previous_bidder, current_bid, refund_balance,
                         f"gift_auction_outbid_refund:{auction_id}", now),
                    )
            cur = await db.execute("SELECT grams FROM accounts WHERE telegram_id=?", (uid,))
            current_account = await cur.fetchone()
            new_balance = int(current_account["grams"]) - amount
            if new_balance < 0:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Gram для ставки")
            await db.execute(
                "UPDATE accounts SET grams=?,updated_at=? WHERE telegram_id=?",
                (new_balance, now, uid),
            )
            await db.execute(
                """INSERT INTO economy_transactions
                   (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                   VALUES(?,'grams',?,?,?,NULL,?)""",
                (uid, -amount, new_balance, f"gift_auction_bid:{auction_id}", now),
            )
            await db.execute(
                """INSERT INTO gift_collectible_auction_bids
                   (auction_id,bidder_telegram_id,amount_grams,created_at)
                   VALUES(?,?,?,?)""",
                (auction_id, uid, amount, now),
            )
            await db.execute(
                """UPDATE gift_collectible_auctions
                   SET current_bid_grams=?,highest_bidder_telegram_id=?
                   WHERE id=? AND status='active'""",
                (amount, uid, auction_id),
            )
            await db.commit()
        return {
            "status": "accepted",
            "auction_id": auction_id,
            "serial_number": str(auction["serial_number"]),
            "bid_grams": amount,
            "minimum_next_bid_grams": amount + 1,
            "grams_balance": new_balance,
            "ends_at": int(auction["ends_at"]),
        }

    @router.get("/api/gift-market")
    async def list_gift_market(
        limit: int = Query(default=50, ge=1, le=100),
        before_id: int = Query(default=0, ge=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        viewer = await current_user(authorization)
        viewer_id = int(viewer["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT l.id AS listing_id,l.serial_number,l.price_grams,l.created_at,
                          g.gift_id,g.telegram_gift_id,g.gift_name,g.upgrade_level,g.attributes_json,
                          a.telegram_id AS seller_id,a.username AS seller_username,
                          a.display_name AS seller_display_name
                   FROM gift_market_listings l
                   JOIN user_gifts g ON g.serial_number=l.serial_number
                   JOIN accounts a ON a.telegram_id=l.seller_telegram_id
                   WHERE l.status='active' AND l.seller_telegram_id<>?
                     AND (?=0 OR l.id<?)
                   ORDER BY l.id DESC LIMIT ?""",
                (viewer_id, before_id, before_id, limit),
            )
            rows = await cur.fetchall()
        items = []
        for row in rows:
            item = dict(row)
            try:
                item["attributes"] = json.loads(item.pop("attributes_json") or "{}")
            except (TypeError, ValueError):
                item["attributes"] = {}
            items.append(item)
        return {"currency": "grams", "listings": items, "count": len(items)}

    @router.post("/api/gifts/{serial_number}/list", status_code=201)
    async def create_gift_listing(
        serial_number: str,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        serial = serial_number.strip().upper()
        if not GIFT_SERIAL_RE.fullmatch(serial):
            raise HTTPException(status_code=400, detail="Некорректный серийный номер подарка")
        raw_price = payload.get("price_grams")
        if isinstance(raw_price, bool):
            raise HTTPException(status_code=400, detail="Цена должна быть целым числом Gram")
        try:
            price = int(raw_price)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Укажите цену в Gram")
        if not 1 <= price <= 1_000_000_000:
            raise HTTPException(status_code=400, detail="Цена должна быть от 1 до 1000000000 Gram")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT id,gift_name FROM user_gifts WHERE serial_number=? AND owner_telegram_id=?",
                (serial, uid),
            )
            gift = await cur.fetchone()
            if gift is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Подарок не найден в вашем инвентаре")
            cur = await db.execute(
                "SELECT id,status FROM gift_market_listings WHERE serial_number=?",
                (serial,),
            )
            previous_listing = await cur.fetchone()
            if previous_listing and str(previous_listing["status"]) == "active":
                await db.rollback()
                raise HTTPException(status_code=409, detail="Подарок уже выставлен на продажу")
            cur = await db.execute(
                "SELECT 1 FROM gift_collectible_auctions WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала отмените аукцион подарка")
            if previous_listing:
                listing_id = int(previous_listing["id"])
                await db.execute(
                    """UPDATE gift_market_listings
                       SET seller_telegram_id=?,price_grams=?,status='active',
                           buyer_telegram_id=NULL,created_at=?,sold_at=NULL
                       WHERE id=?""",
                    (uid, price, now, listing_id),
                )
            else:
                cur = await db.execute(
                    """INSERT INTO gift_market_listings
                       (serial_number,seller_telegram_id,price_grams,status,created_at)
                       VALUES(?,?,?,'active',?)""",
                    (serial, uid, price, now),
                )
                listing_id = int(cur.lastrowid)
            await db.commit()
        return {
            "status": "listed",
            "listing_id": listing_id,
            "serial_number": serial,
            "gift_name": str(gift["gift_name"]),
            "price_grams": price,
            "currency": "grams",
        }

    @router.delete("/api/gifts/{serial_number}/list")
    async def cancel_gift_listing(
        serial_number: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        serial = serial_number.strip().upper()
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """UPDATE gift_market_listings SET status='cancelled'
                   WHERE serial_number=? AND seller_telegram_id=? AND status='active'""",
                (serial, uid),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Активное объявление не найдено")
            await db.commit()
        return {"status": "cancelled", "serial_number": serial}

    @router.post("/api/gift-market/{listing_id}/purchase", status_code=201)
    async def purchase_market_gift(
        listing_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        buyer_id = int(user["telegram_id"])
        if listing_id <= 0:
            raise HTTPException(status_code=400, detail="Некорректный ID объявления")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT l.id,l.serial_number,l.seller_telegram_id,l.price_grams,
                          g.id AS gift_instance_id,g.gift_name
                   FROM gift_market_listings l
                   JOIN user_gifts g ON g.serial_number=l.serial_number
                   WHERE l.id=? AND l.status='active'
                     AND g.owner_telegram_id=l.seller_telegram_id""",
                (listing_id,),
            )
            listing = await cur.fetchone()
            if listing is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Объявление недоступно")
            seller_id = int(listing["seller_telegram_id"])
            price = int(listing["price_grams"])
            serial = str(listing["serial_number"])
            if buyer_id == seller_id:
                await db.rollback()
                raise HTTPException(status_code=400, detail="Нельзя купить собственный подарок")
            cur = await db.execute(
                "SELECT grams,is_banned FROM accounts WHERE telegram_id=?",
                (buyer_id,),
            )
            buyer = await cur.fetchone()
            cur = await db.execute(
                "SELECT grams,is_banned FROM accounts WHERE telegram_id=?",
                (seller_id,),
            )
            seller = await cur.fetchone()
            if not buyer or buyer["is_banned"] or not seller or seller["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Один из аккаунтов недоступен")
            if int(buyer["grams"]) < price:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Gram")
            buyer_balance = int(buyer["grams"]) - price
            seller_balance = int(seller["grams"]) + price
            cur = await db.execute(
                "UPDATE gift_market_listings SET status='sold',buyer_telegram_id=?,sold_at=? WHERE id=? AND status='active'",
                (buyer_id, now, listing_id),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Объявление уже куплено")
            cur = await db.execute(
                "UPDATE user_gifts SET owner_telegram_id=? WHERE id=? AND owner_telegram_id=?",
                (buyer_id, int(listing["gift_instance_id"]), seller_id),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Владение подарком уже изменилось")
            await db.execute(
                "UPDATE accounts SET grams=?,updated_at=? WHERE telegram_id=?",
                (buyer_balance, now, buyer_id),
            )
            await db.execute(
                "UPDATE accounts SET grams=?,updated_at=? WHERE telegram_id=?",
                (seller_balance, now, seller_id),
            )
            await db.executemany(
                """INSERT INTO economy_transactions
                   (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                   VALUES(?,'grams',?,?,?,NULL,?)""",
                [
                    (buyer_id, -price, buyer_balance, f"gift_market_purchase:{listing_id}", now),
                    (seller_id, price, seller_balance, f"gift_market_sale:{listing_id}", now),
                ],
            )
            await db.execute(
                """INSERT INTO gift_transactions
                   (event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                   VALUES('market_sale',?,?,?,?,?)""",
                (serial, str(listing["gift_name"]), seller_id, buyer_id, now),
            )
            await db.commit()
        return {
            "status": "purchased",
            "listing_id": listing_id,
            "serial_number": serial,
            "gift_name": str(listing["gift_name"]),
            "seller_id": seller_id,
            "buyer_id": buyer_id,
            "price_grams": price,
            "grams_balance": buyer_balance,
        }

    @router.post("/api/gifts/{serial_number}/upgrade")
    async def upgrade_gift(
        serial_number: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        serial = serial_number.strip().upper()
        if not GIFT_SERIAL_RE.fullmatch(serial):
            raise HTTPException(status_code=400, detail="Некорректный серийный номер подарка")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT id,gift_name,telegram_gift_id,upgrade_level,attributes_json
                   FROM user_gifts WHERE serial_number=? AND owner_telegram_id=?""",
                (serial, uid),
            )
            gift = await cur.fetchone()
            if gift is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Подарок не найден в вашем инвентаре")
            cur = await db.execute(
                "SELECT 1 FROM gift_market_listings WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала снимите подарок с продажи")
            cur = await db.execute(
                "SELECT 1 FROM gift_collectible_auctions WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала отмените аукцион подарка")
            if not str(gift["telegram_gift_id"] or ""):
                await db.rollback()
                raise HTTPException(status_code=409, detail="Этот подарок нельзя улучшить")
            cur = await db.execute("SELECT source FROM telegram_gift_sync_state WHERE id=1")
            state = await cur.fetchone()
            source = str(state[0]) if state else "telegram_bot_api"
            if source == "telegram_mtproto":
                cur = await db.execute(
                    "SELECT upgrade_stars FROM telegram_mtproto_gift_catalog WHERE gift_id=? AND is_available=1",
                    (str(gift["telegram_gift_id"]),),
                )
            else:
                cur = await db.execute(
                    "SELECT upgrade_star_count FROM telegram_gift_catalog WHERE gift_id=? AND is_available=1",
                    (str(gift["telegram_gift_id"]),),
                )
            catalog = await cur.fetchone()
            if catalog is None or catalog[0] is None or int(catalog[0]) <= 0:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Для этого подарка нет доступного улучшения")
            price = int(catalog[0])
            cur = await db.execute(
                "SELECT stars,is_banned FROM accounts WHERE telegram_id=?",
                (uid,),
            )
            account = await cur.fetchone()
            if not account or account["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Аккаунт недоступен")
            if int(account["stars"]) < price:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Недостаточно Stars")
            new_balance = int(account["stars"]) - price
            new_level = int(gift["upgrade_level"]) + 1
            try:
                attributes = json.loads(str(gift["attributes_json"] or "{}"))
            except (TypeError, ValueError):
                attributes = {}
            if not isinstance(attributes, dict):
                attributes = {}
            attributes.update({
                "upgrade_level": new_level,
                "last_upgraded_at": now,
                "upgrade_source": "waysgram_internal",
            })
            if not _has_collectible_traits(attributes):
                # Traits are generated once on the first successful upgrade and
                # remain unchanged on subsequent upgrades, transfers and sales.
                attributes["collectible_traits"] = _generate_collectible_traits()
            await db.execute(
                "UPDATE accounts SET stars=?,updated_at=? WHERE telegram_id=?",
                (new_balance, now, uid),
            )
            await db.execute(
                "UPDATE user_gifts SET upgrade_level=?,attributes_json=? WHERE id=? AND owner_telegram_id=?",
                (new_level, json.dumps(attributes, ensure_ascii=False, separators=(",", ":")),
                 int(gift["id"]), uid),
            )
            await db.execute(
                """INSERT INTO economy_transactions
                   (telegram_id,asset,amount,balance_after,reason,admin_id,created_at)
                   VALUES(?,'stars',?,?,?,NULL,?)""",
                (uid, -price, new_balance, f"gift_upgrade:{serial}:{new_level}", now),
            )
            await db.execute(
                """INSERT INTO gift_transactions
                   (event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                   VALUES('upgrade',?,?,?, ?,?)""",
                (serial, str(gift["gift_name"]), uid, uid, now),
            )
            await db.commit()
        return {
            "status": "upgraded",
            "serial_number": serial,
            "gift_name": str(gift["gift_name"]),
            "upgrade_level": new_level,
            "price_stars": price,
            "stars_balance": new_balance,
            "attributes": attributes,
        }

    @router.get("/api/channels")
    async def list_channels(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ch.id,
                          CASE WHEN ch.is_public=1 THEN ch.username ELSE '' END AS username,
                          ch.title,ch.owner_telegram_id,ch.is_public,
                          owner.username AS owner_username,
                          COALESCE((SELECT rm.last_read_id FROM read_markers rm
                                    WHERE rm.telegram_id=? AND rm.scope='channel' AND rm.peer_id=ch.id),0) AS last_read_id,
                          (SELECT COUNT(*) FROM channel_messages z
                           WHERE z.channel_id=ch.id AND z.author_telegram_id<>?
                             AND z.id>COALESCE((SELECT rm.last_read_id FROM read_markers rm
                                                WHERE rm.telegram_id=? AND rm.scope='channel'
                                                  AND rm.peer_id=ch.id),0)) AS unread_count
                   FROM channels ch LEFT JOIN accounts owner
                     ON owner.telegram_id=ch.owner_telegram_id
                   WHERE ch.is_public=1 OR ch.owner_telegram_id=?
                      OR EXISTS(SELECT 1 FROM channel_admins ca
                                WHERE ca.channel_id=ch.id AND ca.telegram_id=?)
                      OR EXISTS(SELECT 1 FROM channel_members cm
                                WHERE cm.channel_id=ch.id AND cm.telegram_id=?)
                   ORDER BY ch.id DESC""",
                (uid, uid, uid, uid, uid, uid),
            )
            rows = await cur.fetchall()
        return {"channels": [dict(row) for row in rows]}

    @router.post("/api/channels", status_code=201)
    async def create_channel(
        payload: dict[str, Any],
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        title = payload.get("title")
        username = str(payload.get("username", "")).strip().lstrip("@").lower()
        is_public = payload.get("is_public", True)
        if not isinstance(is_public, bool):
            raise HTTPException(status_code=400, detail="is_public должен быть true или false")
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 80:
            raise HTTPException(status_code=400, detail="Название канала должно содержать 1–80 символов")
        if is_public and not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", username):
            raise HTTPException(status_code=400, detail="Публичному каналу нужен username: латиница, цифры и _, первый символ — буква")
        if not is_public:
            username = "private_" + secrets.token_hex(16)
        invite_token = secrets.token_urlsafe(32) if not is_public else None
        now = int(time.time())
        owner_id = int(user["telegram_id"])
        try:
            async with aiosqlite.connect(db_path()) as db:
                await db.execute("BEGIN IMMEDIATE")
                cur = await db.execute(
                    """INSERT INTO channels
                       (username,title,owner_telegram_id,created_at,is_public,invite_token)
                       VALUES(?,?,?,?,?,?)""",
                    (username, title.strip(), owner_id, now, int(is_public), invite_token),
                )
                channel_id = int(cur.lastrowid)
                await db.execute(
                    "INSERT INTO channel_members(channel_id,telegram_id,joined_at) VALUES(?,?,?)",
                    (channel_id, owner_id, now),
                )
                await db.commit()
        except aiosqlite.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username канала уже занят") from exc
        result = {
            "id": channel_id,
            "username": username if is_public else "",
            "title": title.strip(),
            "owner_telegram_id": owner_id,
            "is_public": is_public,
        }
        if invite_token:
            result["invite_link"] = _external_api_base_url(request) + f"/api/channels/invites/{invite_token}"
        return result

    @router.get("/api/channels/invites/{invite_token}", name="preview_channel_invite")
    async def preview_channel_invite(invite_token: str) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", invite_token):
            raise HTTPException(status_code=404, detail="Приглашение не найдено или отозвано")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ch.id,ch.title,ch.is_public,ch.created_at,
                          owner.username AS owner_username
                   FROM channels ch LEFT JOIN accounts owner
                     ON owner.telegram_id=ch.owner_telegram_id
                   WHERE ch.invite_token=? AND ch.is_public=0""",
                (invite_token,),
            )
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Приглашение не найдено или отозвано")
        return {
            "channel_id": int(row["id"]),
            "title": str(row["title"]),
            "is_public": False,
            "owner_username": str(row["owner_username"] or ""),
        }

    @router.post("/api/channels/join", status_code=200)
    async def join_private_channel(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        invite_value = str(payload.get("invite_link") or payload.get("invite_token") or "").strip()
        match = re.fullmatch(r"[A-Za-z0-9_-]{20,128}", invite_value)
        if match:
            invite_token = invite_value
        else:
            match = re.search(r"/api/channels/invites/([A-Za-z0-9_-]{20,128})(?:[?#].*)?$", invite_value)
            if not match:
                raise HTTPException(status_code=400, detail="Вставьте полную ссылку WaysGram или код приглашения")
            invite_token = match.group(1)
        uid = int(user["telegram_id"])
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT id,title FROM channels
                   WHERE invite_token=? AND is_public=0""",
                (invite_token,),
            )
            channel = await cur.fetchone()
            if channel is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Приглашение недействительно или уже отозвано")
            await db.execute(
                "INSERT OR IGNORE INTO channel_members(channel_id,telegram_id,joined_at) VALUES(?,?,?)",
                (int(channel[0]), uid, now),
            )
            await db.commit()
        return {"joined": True, "id": int(channel[0]), "title": str(channel[1]), "is_public": False}

    @router.get("/api/channels/{channel_id}")
    async def get_channel(
        channel_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        await require_channel_access(channel_id, int(user["telegram_id"]))
        return await channel_row(channel_id)

    @router.patch("/api/channels/{channel_id}")
    async def update_channel(
        channel_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        channel = await channel_row(channel_id)
        if int(channel["owner_telegram_id"]) != int(user["telegram_id"]):
            raise HTTPException(status_code=403, detail="Изменять канал может только владелец")
        if not payload or not ({"title", "username"} & payload.keys()):
            raise HTTPException(status_code=400, detail="Нет полей для изменения")
        is_public = bool(channel.get("is_public", 1))
        if not is_public and "username" in payload:
            raise HTTPException(status_code=400, detail="У приватного канала нельзя изменить публичный username")

        title = str(channel["title"])
        username = str(channel["username"])
        if "title" in payload:
            new_title = payload["title"]
            if not isinstance(new_title, str) or not 1 <= len(new_title.strip()) <= 80:
                raise HTTPException(status_code=400, detail="Название канала должно содержать 1–80 символов")
            title = new_title.strip()
        if "username" in payload:
            new_username = str(payload["username"] or "").strip().lstrip("@").lower()
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", new_username):
                raise HTTPException(status_code=400, detail="Username канала: латиница, цифры и _, первый символ — буква")
            username = new_username
        try:
            async with aiosqlite.connect(db_path()) as db:
                if is_public:
                    await db.execute(
                        "UPDATE channels SET username=?,title=? WHERE id=?",
                        (username, title, channel_id),
                    )
                else:
                    # channel_row intentionally hides private usernames; never write that redacted value
                    # back into the database when changing a private channel's title.
                    await db.execute("UPDATE channels SET title=? WHERE id=?", (title, channel_id))
                await db.commit()
        except aiosqlite.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username канала уже занят") from exc
        return {
            "id": channel_id,
            "username": username if is_public else "",
            "title": title,
            "owner_telegram_id": int(channel["owner_telegram_id"]),
            "is_public": is_public,
        }

    @router.get("/api/channels/{channel_id}/admins")
    async def list_channel_admins(
        channel_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        channel = await channel_row(channel_id)
        uid = int(user["telegram_id"])
        await require_channel_access(channel_id, uid)
        owner_id = int(channel["owner_telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT ca.telegram_id,a.username,a.display_name,a.avatar_media_id,ca.created_at
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

    async def attach_my_reactions(items: list[dict[str, Any]], scope: str, chat_id: int, user_id: int) -> None:
        message_ids = [int(item["id"]) for item in items if item.get("id") is not None]
        if not message_ids:
            return
        placeholders = ",".join("?" for _ in message_ids)
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                f"SELECT message_id,reaction FROM message_reactions WHERE scope=? AND chat_id=? AND user_telegram_id=? AND message_id IN ({placeholders}) ORDER BY created_at,reaction",
                (scope, chat_id, user_id, *message_ids),
            )
            rows = await cur.fetchall()
        mine: dict[int, list[str]] = {}
        for message_id, reaction in rows:
            mine.setdefault(int(message_id), []).append(str(reaction))
        for item in items:
            item["my_reactions"] = mine.get(int(item["id"]), [])
    @router.get("/api/channels/{channel_id}/messages")
    async def list_channel_messages(
        channel_id: int,
        after_id: int = Query(default=0, ge=0),
        wait_seconds: int = Query(default=0, ge=0, le=20),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        await require_channel_access(channel_id, int(user["telegram_id"]))
        deadline = time.monotonic() + (wait_seconds if after_id else 0)
        rows = []
        while True:
            await channel_row(channel_id)
            async with aiosqlite.connect(db_path()) as db:
                db.row_factory = aiosqlite.Row
                if after_id:
                    cur = await db.execute(
                        """SELECT id,channel_id,author_telegram_id AS author_id,body,media_id,media_album_id,media_album_index,media_album_count,edited_at,reply_to_id,created_at,
                                  (SELECT body FROM channel_messages AS replied WHERE replied.id=channel_messages.reply_to_id) AS reply_to_body,
                                  (SELECT author_telegram_id FROM channel_messages AS replied WHERE replied.id=channel_messages.reply_to_id) AS reply_to_sender_id,
                                  (SELECT group_concat(reaction || ':' || reaction_count, ',')
                                     FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                                           WHERE scope='channel' AND chat_id=channel_messages.channel_id
                                             AND message_id=channel_messages.id GROUP BY reaction)) AS reaction_summary,
                                  (SELECT mime_type FROM media_assets WHERE id=channel_messages.media_id) AS media_type,
                                  (SELECT original_name FROM media_assets WHERE id=channel_messages.media_id) AS media_name
                           FROM channel_messages WHERE channel_id=? AND id>?
                           ORDER BY id ASC LIMIT 100""",
                        (channel_id, after_id),
                    )
                else:
                    cur = await db.execute(
                        """SELECT id,channel_id,author_telegram_id AS author_id,body,media_id,media_album_id,media_album_index,media_album_count,edited_at,reply_to_id,created_at,
                                  (SELECT body FROM channel_messages AS replied WHERE replied.id=channel_messages.reply_to_id) AS reply_to_body,
                                  (SELECT author_telegram_id FROM channel_messages AS replied WHERE replied.id=channel_messages.reply_to_id) AS reply_to_sender_id,
                                  (SELECT group_concat(reaction || ':' || reaction_count, ',')
                                     FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                                           WHERE scope='channel' AND chat_id=channel_messages.channel_id
                                             AND message_id=channel_messages.id GROUP BY reaction)) AS reaction_summary,
                                  (SELECT mime_type FROM media_assets WHERE id=channel_messages.media_id) AS media_type,
                                  (SELECT original_name FROM media_assets WHERE id=channel_messages.media_id) AS media_name
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
        await attach_my_reactions(items, "channel", channel_id, int(user["telegram_id"]))
        return {"messages": items}

    def parse_reply_id(payload: dict[str, Any]) -> int | None:
        value = payload.get("reply_to_id")
        if value is None or value == 0:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HTTPException(status_code=400, detail="Некорректный reply_to_id")
        return value

    async def require_reply_target(db: Any, sql: str, params: tuple[Any, ...]) -> None:
        cur = await db.execute(sql, params)
        if await cur.fetchone() is None:
            await db.rollback()
            raise HTTPException(status_code=404, detail="Сообщение, на которое вы отвечаете, не найдено")

    @router.get("/api/channels/{channel_id}/messages/search")
    async def search_channel_messages(
        channel_id: int,
        q: str = Query(min_length=1, max_length=128),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        await require_channel_access(channel_id, int(user["telegram_id"]))
        term = q.strip()
        if not term:
            raise HTTPException(status_code=400, detail="Введите текст для поиска")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await channel_row(channel_id)
            cur = await db.execute(
                """SELECT id,channel_id,author_telegram_id AS author_id,body,media_id,media_album_id,media_album_index,media_album_count,edited_at,reply_to_id,created_at,
                          (SELECT body FROM channel_messages AS replied WHERE replied.id=channel_messages.reply_to_id) AS reply_to_body,
                                  (SELECT author_telegram_id FROM channel_messages AS replied WHERE replied.id=channel_messages.reply_to_id) AS reply_to_sender_id,
                                  (SELECT group_concat(reaction || ':' || reaction_count, ',')
                                     FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                                           WHERE scope='channel' AND chat_id=channel_messages.channel_id
                                             AND message_id=channel_messages.id GROUP BY reaction)) AS reaction_summary,
                                  (SELECT mime_type FROM media_assets WHERE id=channel_messages.media_id) AS media_type,
                          (SELECT original_name FROM media_assets WHERE id=channel_messages.media_id) AS media_name
                   FROM channel_messages
                   WHERE channel_id=? AND body LIKE ? COLLATE NOCASE
                   ORDER BY id DESC LIMIT 100""",
                (channel_id, f"%{term}%"),
            )
            rows = await cur.fetchall()
        items = [dict(row) for row in rows]
        items.reverse()
        await attach_my_reactions(items, "channel", channel_id, int(user["telegram_id"]))
        return {"query": term, "messages": items, "count": len(items), "has_more": len(items) == 100}

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
        body = _message_body(body_value) if body_value.strip() or not media_id else ""
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
            if not body:
                body = _message_body(await default_media_message_body(db, media_id))
            media_fields = await media_message_fields(db, media_id)
            reply_to_id = parse_reply_id(payload)
            if reply_to_id:
                await require_reply_target(
                    db, "SELECT 1 FROM channel_messages WHERE id=? AND channel_id=?", (reply_to_id, channel_id)
                )
            cur = await db.execute(
                "SELECT COUNT(*) FROM channel_messages WHERE author_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= CHANNEL_POSTS_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит публикаций")
            cur = await db.execute(
                """INSERT INTO channel_messages
                   (channel_id,author_telegram_id,body,media_id,reply_to_id,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (channel_id, uid, body, media_id, reply_to_id, now),
            )
            message_id = int(cur.lastrowid)
            await record_event(
                db, "channel", message_id, "new_message", uid, chat_id=channel_id,
            )
            result = {"id": message_id, "status": "published", "channel_id": channel_id, "author_id": uid, "body": body, "media_id": media_id, "reply_to_id": reply_to_id, **media_fields, "created_at": now}
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "SELECT telegram_id FROM channel_members WHERE channel_id=? AND telegram_id<>?",
                (channel_id, uid),
            )
            channel_recipients = [int(row[0]) for row in await cur.fetchall()]
        await deliver_push_notifications(
            channel_recipients,
            str(user.get("display_name") or user.get("username") or "Новая публикация"),
            body,
            {"scope": "channel", "chat_id": str(channel_id), "message_id": str(message_id)},
        )
        return result

    @router.post("/api/channels/{channel_id}/messages/album", status_code=201)
    async def create_channel_message_album(
        channel_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if not await can_manage_channel(channel_id, uid):
            raise HTTPException(status_code=403, detail="Публиковать в канале может только владелец или администратор")

        raw_media_ids = payload.get("media_ids")
        if not isinstance(raw_media_ids, list) or not 2 <= len(raw_media_ids) <= 10:
            raise HTTPException(status_code=400, detail="Альбом должен содержать от 2 до 10 файлов")
        media_ids: list[str] = []
        for raw_id in raw_media_ids:
            media_id = str(raw_id or "").strip()
            if not re.fullmatch(r"[a-f0-9]{32}", media_id):
                raise HTTPException(status_code=400, detail="Некорректный ID вложения в альбоме")
            media_ids.append(media_id)
        if len(set(media_ids)) != len(media_ids):
            raise HTTPException(status_code=400, detail="Альбом не должен содержать повторяющиеся файлы")

        body_value = str(payload.get("body") or "")
        body = _message_body(body_value) if body_value.strip() else "Медиаальбом"
        silent = payload.get("silent", False)
        if not isinstance(silent, bool):
            raise HTTPException(status_code=400, detail="silent должен быть логическим значением")

        now = int(time.time())
        scope = f"/api/channels/{channel_id}/messages/album"
        descriptor = idempotency_descriptor(scope, payload, idempotency_key)
        album_id = secrets.token_hex(16)
        created_messages: list[dict[str, Any]] = []

        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, scope, descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous

            checked_media: list[tuple[str, dict[str, str | None]]] = []
            for media_id in media_ids:
                owned_id = await require_owned_media(db, media_id, uid)
                fields = await media_message_fields(db, owned_id)
                media_type = str(fields.get("media_type") or "").lower()
                if not (media_type.startswith("image/") or media_type.startswith("video/")):
                    await db.rollback()
                    raise HTTPException(
                        status_code=415,
                        detail="В медиаальбом можно добавлять только фотографии и видео",
                    )
                checked_media.append((media_id, fields))

            reply_to_id = parse_reply_id(payload)
            if reply_to_id:
                await require_reply_target(
                    db,
                    "SELECT 1 FROM channel_messages WHERE id=? AND channel_id=?",
                    (reply_to_id, channel_id),
                )

            cur = await db.execute(
                "SELECT COUNT(*) FROM channel_messages WHERE author_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            sent_recently = int((await cur.fetchone())[0])
            if sent_recently + len(checked_media) > CHANNEL_POSTS_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит публикаций для медиаальбома")

            for index, (media_id, media_fields) in enumerate(checked_media):
                item_body = body if index == 0 else ""
                cur = await db.execute(
                    """INSERT INTO channel_messages
                       (channel_id,author_telegram_id,body,media_id,reply_to_id,
                        media_album_id,media_album_index,media_album_count,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        channel_id, uid, item_body, media_id, reply_to_id,
                        album_id, index, len(checked_media), now,
                    ),
                )
                message_id = int(cur.lastrowid)
                await record_event(db, "channel", message_id, "new_message", uid, chat_id=channel_id)
                created_messages.append({
                    "id": message_id,
                    "channel_id": channel_id,
                    "author_id": uid,
                    "body": item_body,
                    "media_id": media_id,
                    "reply_to_id": reply_to_id,
                    "media_album_id": album_id,
                    "media_album_index": index,
                    "media_album_count": len(checked_media),
                    **media_fields,
                    "created_at": now,
                })

            result = {
                "status": "published",
                "album_id": album_id,
                "channel_id": channel_id,
                "count": len(created_messages),
                "first_message_id": created_messages[0]["id"],
                "last_message_id": created_messages[-1]["id"],
                "messages": created_messages,
            }
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()

        if not silent:
            async with aiosqlite.connect(db_path()) as db:
                cur = await db.execute(
                    "SELECT telegram_id FROM channel_members WHERE channel_id=? AND telegram_id<>?",
                    (channel_id, uid),
                )
                recipients = [int(row[0]) for row in await cur.fetchall()]
            await deliver_push_notifications(
                recipients,
                str(user.get("display_name") or user.get("username") or "Новая публикация"),
                f"Медиаальбом · {len(created_messages)} вложений",
                {
                    "scope": "channel",
                    "chat_id": str(channel_id),
                    "message_id": str(created_messages[-1]["id"]),
                    "media_album_id": album_id,
                },
            )
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
            joined_at = int(time.time())
            await db.execute(
                "INSERT OR IGNORE INTO channel_admins(channel_id,telegram_id,created_at) VALUES(?,?,?)",
                (channel_id, target_id, joined_at),
            )
            await db.execute(
                "INSERT OR IGNORE INTO channel_members(channel_id,telegram_id,joined_at) VALUES(?,?,?)",
                (channel_id, target_id, joined_at),
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
            await db.execute("DELETE FROM channel_members WHERE channel_id=?", (channel_id,))
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

        params: tuple[Any, ...] = (uid, peer, peer, uid, uid)
        base = """
            SELECT id,sender_telegram_id AS sender_id,
                   recipient_telegram_id AS recipient_id,body,media_id,edited_at,reply_to_id,created_at,
                   media_album_id,media_album_index,media_album_count,
                   forwarded_from_telegram_id,forwarded_from_message_id,
                   (SELECT display_name FROM accounts WHERE telegram_id=messages.forwarded_from_telegram_id) AS forwarded_from_display_name,
                   (SELECT body FROM messages AS replied WHERE replied.id=messages.reply_to_id) AS reply_to_body,
                   (SELECT sender_telegram_id FROM messages AS replied WHERE replied.id=messages.reply_to_id) AS reply_to_sender_id,
                   (SELECT group_concat(reaction || ':' || reaction_count, ',')
                      FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                            WHERE scope='dm' AND chat_id=0 AND message_id=messages.id GROUP BY reaction)) AS reaction_summary,
                   (SELECT mime_type FROM media_assets WHERE id=messages.media_id) AS media_type,
                   (SELECT original_name FROM media_assets WHERE id=messages.media_id) AS media_name,
                   gift_attachment.serial_number AS gift_serial_number,
                   gift_attachment.gift_name AS gift_name,
                   gift_attachment.telegram_gift_id AS gift_telegram_gift_id,
                   gift_attachment.upgrade_level AS gift_upgrade_level,
                   gift_attachment.attributes_json AS gift_attributes_json
            FROM messages
            LEFT JOIN message_gifts gift_attachment ON gift_attachment.message_id=messages.id
            WHERE
            ((sender_telegram_id=? AND recipient_telegram_id=?) OR
             (sender_telegram_id=? AND recipient_telegram_id=?))
              AND NOT EXISTS (
                  SELECT 1 FROM message_hidden_for hidden
                  WHERE hidden.message_id=messages.id AND hidden.telegram_id=?
              )
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
        for item in items:
            raw_attributes = item.pop("gift_attributes_json", None)
            try:
                attributes = json.loads(raw_attributes or "{}") if raw_attributes else {}
            except (TypeError, ValueError):
                attributes = {}
            item["gift_attributes"] = attributes if isinstance(attributes, dict) else {}
        await attach_my_reactions(items, "dm", 0, uid)
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                """SELECT
                     COALESCE((SELECT last_read_id FROM read_markers WHERE telegram_id=? AND scope='dm' AND peer_id=?),0),
                     COALESCE((SELECT last_read_id FROM read_markers WHERE telegram_id=? AND scope='dm' AND peer_id=?),0)""",
                (uid, peer, peer, uid),
            )
            my_read_id, peer_read_id = await cur.fetchone()
        return {
            "my_read_id": int(my_read_id),
            "peer_read_id": int(peer_read_id),
            "messages": items,
            "count": len(items),
            "next_before_id": items[0]["id"] if items else 0,
            "next_after_id": items[-1]["id"] if items else 0,
        }

    @router.get("/api/messages/export")
    async def export_direct_messages(
        peer: int = Query(alias="with", gt=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT username,display_name FROM accounts WHERE telegram_id=?",
                (peer,),
            )
            peer_row = await cur.fetchone()
            if peer_row is None:
                raise HTTPException(status_code=404, detail="Собеседник не найден")
            cur = await db.execute(
                """SELECT m.id,m.sender_telegram_id AS sender_id,
                          m.recipient_telegram_id AS recipient_id,m.body,m.created_at,
                          m.edited_at,m.media_id,media.original_name AS media_name,
                          gift.serial_number AS gift_serial_number,
                          gift.gift_name AS gift_name,
                          COALESCE(sender.display_name,sender.username,'Пользователь') AS sender_name
                   FROM messages m
                   LEFT JOIN media_assets media ON media.id=m.media_id
                   LEFT JOIN message_gifts gift ON gift.message_id=m.id
                   LEFT JOIN accounts sender ON sender.telegram_id=m.sender_telegram_id
                   WHERE ((m.sender_telegram_id=? AND m.recipient_telegram_id=?) OR
                          (m.sender_telegram_id=? AND m.recipient_telegram_id=?))
                     AND NOT EXISTS (
                         SELECT 1 FROM message_hidden_for hidden
                         WHERE hidden.message_id=m.id AND hidden.telegram_id=?
                     )
                   ORDER BY m.id DESC LIMIT 1000""",
                (uid, peer, peer, uid, uid),
            )
            rows = [dict(row) for row in await cur.fetchall()]
        rows.reverse()
        peer_name = str(peer_row["display_name"] or peer_row["username"] or peer)
        output = [
            f"WaysGram — экспорт переписки: {peer_name}",
            "Время указано в UTC.",
            "",
        ]
        truncated = len(rows) == 1000
        for row in rows:
            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC",
                time.gmtime(int(row["created_at"])),
            )
            sender_name = str(row["sender_name"] or "Пользователь")
            body = str(row["body"] or "")
            line = f"[{timestamp}] {sender_name}: {body}"
            if row["media_name"]:
                line += f" [Вложение: {str(row['media_name'])[:160]}]"
            if row["gift_serial_number"]:
                line += (
                    f" [Подарок: {str(row['gift_name'] or 'WaysGram')}"
                    f" · {str(row['gift_serial_number'])}]"
                )
            if row["edited_at"]:
                line += " [изменено]"
            if sum(len(part) for part in output) + len(line) + 1 > 200_000:
                truncated = True
                break
            output.append(line)
        return {
            "peer_id": peer,
            "peer_name": peer_name,
            "count": min(len(rows), max(0, len(output) - 3)),
            "truncated": truncated,
            "text": "\n".join(output),
        }

    @router.get("/api/messages/search")
    async def search_messages(
        peer: int = Query(alias="with", gt=0),
        q: str = Query(min_length=1, max_length=128),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        term = q.strip()
        if not term:
            raise HTTPException(status_code=400, detail="Введите текст для поиска")
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (peer,))
            if not await cur.fetchone():
                raise HTTPException(status_code=404, detail="Собеседник не найден")
            cur = await db.execute(
                """SELECT id,sender_telegram_id AS sender_id,
                          recipient_telegram_id AS recipient_id,body,media_id,edited_at,reply_to_id,created_at,
                          forwarded_from_telegram_id,forwarded_from_message_id,
                          (SELECT display_name FROM accounts WHERE telegram_id=messages.forwarded_from_telegram_id) AS forwarded_from_display_name,
                   (SELECT body FROM messages AS replied WHERE replied.id=messages.reply_to_id) AS reply_to_body,
                   (SELECT sender_telegram_id FROM messages AS replied WHERE replied.id=messages.reply_to_id) AS reply_to_sender_id,
                   (SELECT group_concat(reaction || ':' || reaction_count, ',')
                      FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                            WHERE scope='dm' AND chat_id=0 AND message_id=messages.id GROUP BY reaction)) AS reaction_summary,
                          (SELECT mime_type FROM media_assets WHERE id=messages.media_id) AS media_type,
                          (SELECT original_name FROM media_assets WHERE id=messages.media_id) AS media_name
                   FROM messages
                   WHERE ((sender_telegram_id=? AND recipient_telegram_id=?) OR
                          (sender_telegram_id=? AND recipient_telegram_id=?))
                     AND NOT EXISTS (
                         SELECT 1 FROM message_hidden_for hidden
                         WHERE hidden.message_id=messages.id AND hidden.telegram_id=?
                     )
                     AND body LIKE ? COLLATE NOCASE
                   ORDER BY id DESC LIMIT 100""",
                (uid, peer, peer, uid, uid, f"%{term}%"),
            )
            rows = await cur.fetchall()
        items = [dict(row) for row in rows]
        items.reverse()
        await attach_my_reactions(items, "dm", 0, uid)
        return {"query": term, "messages": items, "count": len(items), "has_more": len(items) == 100}

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
        if recipient_id <= 0:
            raise HTTPException(status_code=400, detail="Укажите корректного получателя")
        media_id = str(payload.get("media_id") or "").strip() or None
        body_value = str(payload.get("body") or "")
        body = _message_body(body_value) if body_value.strip() or not media_id else ""
        silent = payload.get("silent", False)
        if not isinstance(silent, bool):
            raise HTTPException(status_code=400, detail="silent должен быть логическим значением")
        now = int(time.time())
        descriptor = idempotency_descriptor("/api/messages", payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, "/api/messages", descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            media_id = await require_owned_media(db, media_id, uid)
            if not body:
                body = _message_body(await default_media_message_body(db, media_id))
            media_fields = await media_message_fields(db, media_id)
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
                """SELECT 1 FROM blocked_users
                   WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                      OR (owner_telegram_id=? AND blocked_telegram_id=?)
                   LIMIT 1""",
                (uid, recipient_id, recipient_id, uid),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=403, detail="Нельзя отправить сообщение: пользователь находится в чёрном списке")
            reply_to_id = parse_reply_id(payload)
            if reply_to_id:
                await require_reply_target(
                    db,
                    """SELECT 1 FROM messages WHERE id=? AND
                       ((sender_telegram_id=? AND recipient_telegram_id=?) OR (sender_telegram_id=? AND recipient_telegram_id=?))""",
                    (reply_to_id, uid, recipient_id, recipient_id, uid),
                )
            cur = await db.execute(
                "SELECT COUNT(*) FROM messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит отправки сообщений")
            cur = await db.execute(
                """INSERT INTO messages
                   (sender_telegram_id,recipient_telegram_id,body,media_id,reply_to_id,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (uid, recipient_id, body, media_id, reply_to_id, now),
            )
            message_id = int(cur.lastrowid)
            await record_event(
                db, "dm", message_id, "new_message", uid,
                user_a=uid, user_b=recipient_id,
            )
            result = {
                "id": message_id,
                "status": "sent",
                "sender_id": uid,
                "recipient_id": recipient_id,
                "body": body,
                "media_id": media_id,
                "reply_to_id": reply_to_id,
                **media_fields,
                "created_at": now,
            }
            await idempotency_store(db, uid, "/api/messages", descriptor, result, now)
            await db.commit()
        if not silent:
            await deliver_push_notifications(
                [recipient_id],
                str(user.get("display_name") or user.get("username") or "Новое сообщение"),
                body,
                {"scope": "dm", "chat_id": str(uid), "message_id": str(message_id)},
            )
        return result


    @router.post("/api/messages/album", status_code=201)
    async def send_message_album(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Create a photo/video album as one atomic send and one push notification."""
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            recipient_id = int(payload.get("recipient_id", payload.get("to", 0)))
        except (TypeError, ValueError):
            recipient_id = 0
        if recipient_id <= 0:
            raise HTTPException(status_code=400, detail="Укажите корректного получателя")

        raw_media_ids = payload.get("media_ids")
        if not isinstance(raw_media_ids, list) or not 2 <= len(raw_media_ids) <= 10:
            raise HTTPException(status_code=400, detail="Альбом должен содержать от 2 до 10 файлов")
        media_ids: list[str] = []
        for raw_id in raw_media_ids:
            media_id = str(raw_id or "").strip()
            if not re.fullmatch(r"[a-f0-9]{32}", media_id):
                raise HTTPException(status_code=400, detail="Некорректный ID вложения в альбоме")
            media_ids.append(media_id)
        if len(set(media_ids)) != len(media_ids):
            raise HTTPException(status_code=400, detail="Альбом не должен содержать повторяющиеся файлы")

        body_value = str(payload.get("body") or "")
        body = _message_body(body_value) if body_value.strip() else "Медиаальбом"
        silent = payload.get("silent", False)
        if not isinstance(silent, bool):
            raise HTTPException(status_code=400, detail="silent должен быть логическим значением")
        now = int(time.time())
        scope = "/api/messages/album"
        descriptor = idempotency_descriptor(scope, payload, idempotency_key)
        album_id = secrets.token_hex(16)
        created_messages: list[dict[str, Any]] = []

        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, scope, descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous

            recipient_cur = await db.execute(
                "SELECT is_banned FROM accounts WHERE telegram_id=?",
                (recipient_id,),
            )
            recipient = await recipient_cur.fetchone()
            if recipient is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Получатель не найден")
            if recipient["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Получатель заблокирован")
            blocked_cur = await db.execute(
                """SELECT 1 FROM blocked_users
                   WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                      OR (owner_telegram_id=? AND blocked_telegram_id=?)
                   LIMIT 1""",
                (uid, recipient_id, recipient_id, uid),
            )
            if await blocked_cur.fetchone():
                await db.rollback()
                raise HTTPException(
                    status_code=403,
                    detail="Нельзя отправить альбом: пользователь находится в чёрном списке",
                )

            reply_to_id = parse_reply_id(payload)
            if reply_to_id:
                await require_reply_target(
                    db,
                    """SELECT 1 FROM messages WHERE id=? AND
                       ((sender_telegram_id=? AND recipient_telegram_id=?) OR
                        (sender_telegram_id=? AND recipient_telegram_id=?))""",
                    (reply_to_id, uid, recipient_id, recipient_id, uid),
                )

            checked_media: list[tuple[str, dict[str, str | None]]] = []
            for media_id in media_ids:
                owned_id = await require_owned_media(db, media_id, uid)
                fields = await media_message_fields(db, owned_id)
                media_type = str(fields.get("media_type") or "").lower()
                if not (media_type.startswith("image/") or media_type.startswith("video/")):
                    await db.rollback()
                    raise HTTPException(
                        status_code=415,
                        detail="В медиаальбом можно добавлять только фотографии и видео",
                    )
                checked_media.append((media_id, fields))

            rate_cur = await db.execute(
                "SELECT COUNT(*) FROM messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            sent_recently = int((await rate_cur.fetchone())[0])
            if sent_recently + len(checked_media) > DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(
                    status_code=429,
                    detail="Превышен лимит отправки сообщений для медиаальбома",
                )

            for index, (media_id, media_fields) in enumerate(checked_media):
                item_body = body if index == 0 else ""
                cur = await db.execute(
                    """INSERT INTO messages
                       (sender_telegram_id,recipient_telegram_id,body,media_id,reply_to_id,
                        media_album_id,media_album_index,media_album_count,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        uid, recipient_id, item_body, media_id, reply_to_id,
                        album_id, index, len(checked_media), now,
                    ),
                )
                message_id = int(cur.lastrowid)
                await record_event(
                    db, "dm", message_id, "new_message", uid,
                    user_a=uid, user_b=recipient_id,
                )
                created_messages.append({
                    "id": message_id,
                    "sender_id": uid,
                    "recipient_id": recipient_id,
                    "body": item_body,
                    "media_id": media_id,
                    "reply_to_id": reply_to_id,
                    "media_album_id": album_id,
                    "media_album_index": index,
                    "media_album_count": len(checked_media),
                    **media_fields,
                    "created_at": now,
                })

            result = {
                "status": "sent",
                "album_id": album_id,
                "count": len(created_messages),
                "first_message_id": created_messages[0]["id"],
                "last_message_id": created_messages[-1]["id"],
                "messages": created_messages,
            }
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()

        if not silent:
            await deliver_push_notifications(
                [recipient_id],
                str(user.get("display_name") or user.get("username") or "Новое сообщение"),
                f"Медиаальбом · {len(created_messages)} вложения",
                {
                    "scope": "dm",
                    "chat_id": str(uid),
                    "message_id": str(created_messages[-1]["id"]),
                    "media_album_id": album_id,
                },
            )
        return result


    @router.post("/api/messages/schedule", status_code=201)
    async def schedule_direct_message(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            recipient_id = int(payload.get("recipient_id", 0))
        except (TypeError, ValueError):
            recipient_id = 0
        if recipient_id <= 0:
            raise HTTPException(status_code=400, detail="Укажите корректного получателя")
        body_value = payload.get("body")
        if not isinstance(body_value, str):
            raise HTTPException(status_code=400, detail="Укажите текст сообщения")
        body = _message_body(body_value)
        scheduled_at = payload.get("scheduled_at")
        if isinstance(scheduled_at, bool) or not isinstance(scheduled_at, int):
            raise HTTPException(status_code=400, detail="scheduled_at должен быть Unix timestamp")
        repeat_interval = payload.get("repeat_interval_seconds", 0)
        if (
            isinstance(repeat_interval, bool)
            or not isinstance(repeat_interval, int)
            or repeat_interval not in (0, 86400, 604800)
        ):
            raise HTTPException(
                status_code=400,
                detail="repeat_interval_seconds: 0, 86400 или 604800",
            )
        silent = payload.get("silent", False)
        if not isinstance(silent, bool):
            raise HTTPException(status_code=400, detail="silent должен быть логическим значением")
        time_zone = payload.get("time_zone", "UTC")
        if not isinstance(time_zone, str) or not time_zone.strip() or len(time_zone) > 64:
            raise HTTPException(status_code=400, detail="time_zone должен содержать IANA-идентификатор часового пояса")
        time_zone = time_zone.strip()
        try:
            ZoneInfo(time_zone)
        except (ZoneInfoNotFoundError, ValueError):
            raise HTTPException(status_code=400, detail="Неизвестный часовой пояс")
        now = int(time.time())
        if scheduled_at < now + 10:
            raise HTTPException(status_code=400, detail="Отправка должна быть запланирована минимум через 10 секунд")
        if scheduled_at > now + 30 * 24 * 60 * 60:
            raise HTTPException(status_code=400, detail="Нельзя запланировать отправку более чем на 30 дней")
        scope = "/api/messages/schedule"
        descriptor = idempotency_descriptor(scope, payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, scope, descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            cur = await db.execute(
                "SELECT is_banned FROM accounts WHERE telegram_id=?",
                (recipient_id,),
            )
            recipient = await cur.fetchone()
            if recipient is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Получатель не найден")
            if recipient[0]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Получатель заблокирован")
            if recipient_id != uid:
                cur = await db.execute(
                    """SELECT 1 FROM blocked_users
                       WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                          OR (owner_telegram_id=? AND blocked_telegram_id=?)
                       LIMIT 1""",
                    (uid, recipient_id, recipient_id, uid),
                )
                if await cur.fetchone():
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Нельзя запланировать сообщение: пользователь находится в чёрном списке")
            cur = await db.execute(
                """INSERT INTO scheduled_messages
                   (sender_telegram_id,recipient_telegram_id,body,scheduled_at,
                    repeat_interval_seconds,created_at,silent,time_zone)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (uid, recipient_id, body, scheduled_at, repeat_interval, now, int(silent), time_zone),
            )
            scheduled_id = int(cur.lastrowid)
            result = {
                "id": scheduled_id,
                "status": "pending",
                "sender_id": uid,
                "recipient_id": recipient_id,
                "body": body,
                "scheduled_at": scheduled_at,
                "repeat_interval_seconds": repeat_interval,
                "silent": silent,
                "time_zone": time_zone,
                "created_at": now,
            }
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()
        return result

    @router.get("/api/messages/scheduled")
    async def list_scheduled_messages(
        peer: int = Query(alias="with", gt=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                "SELECT 1 FROM accounts WHERE telegram_id=?",
                (peer,),
            )
            if await cur.fetchone() is None:
                raise HTTPException(status_code=404, detail="Собеседник не найден")
            cur = await db.execute(
                """SELECT id,recipient_telegram_id AS recipient_id,body,scheduled_at,
                          repeat_interval_seconds,created_at,silent,time_zone,status,message_id,error
                   FROM scheduled_messages
                   WHERE sender_telegram_id=? AND recipient_telegram_id=?
                     AND status IN ('pending','failed')
                   ORDER BY scheduled_at ASC,id ASC LIMIT 100""",
                (uid, peer),
            )
            rows = [dict(row) for row in await cur.fetchall()]
        return {"scheduled_messages": rows, "count": len(rows)}

    @router.delete("/api/messages/scheduled/{scheduled_id}")
    async def cancel_scheduled_message(
        scheduled_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """UPDATE scheduled_messages SET status='cancelled'
                   WHERE id=? AND sender_telegram_id=? AND status='pending'""",
                (scheduled_id, uid),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Отложенное сообщение не найдено или уже обработано")
            await db.commit()
        return {"id": scheduled_id, "status": "cancelled"}


    @router.post("/api/messages/gift", status_code=201)
    async def send_gift_message(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        """Transfer a WaysGram-owned gift and persist its collectible snapshot in a DM."""
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            recipient_id = int(payload.get("recipient_id", 0))
        except (TypeError, ValueError):
            recipient_id = 0
        serial = str(payload.get("serial_number") or "").strip().upper()
        if recipient_id <= 0 or not GIFT_SERIAL_RE.fullmatch(serial):
            raise HTTPException(status_code=400, detail="Укажите получателя и корректный серийный номер подарка")
        if recipient_id == uid:
            raise HTTPException(status_code=400, detail="Нельзя отправить подарок самому себе")
        caption_value = str(payload.get("body") or "").strip()
        body = _message_body(caption_value) if caption_value else "Подарок WaysGram"
        now = int(time.time())
        scope = "/api/messages/gift"
        descriptor = idempotency_descriptor(scope, payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, scope, descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            cur = await db.execute(
                "SELECT is_banned FROM accounts WHERE telegram_id=?",
                (recipient_id,),
            )
            recipient = await cur.fetchone()
            if recipient is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Получатель не найден")
            if recipient["is_banned"]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Получатель заблокирован")
            cur = await db.execute(
                """SELECT 1 FROM blocked_users
                   WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                      OR (owner_telegram_id=? AND blocked_telegram_id=?)
                   LIMIT 1""",
                (uid, recipient_id, recipient_id, uid),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=403, detail="Нельзя отправить подарок: пользователь находится в чёрном списке")
            cur = await db.execute(
                """SELECT id,gift_name,telegram_gift_id,upgrade_level,attributes_json
                   FROM user_gifts WHERE serial_number=? AND owner_telegram_id=?""",
                (serial, uid),
            )
            gift = await cur.fetchone()
            if gift is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Подарок не найден в вашем инвентаре")
            cur = await db.execute(
                "SELECT 1 FROM gift_market_listings WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала снимите подарок с продажи")
            cur = await db.execute(
                "SELECT 1 FROM gift_collectible_auctions WHERE serial_number=? AND status='active'",
                (serial,),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=409, detail="Сначала отмените аукцион подарка")
            cur = await db.execute(
                "SELECT COUNT(*) FROM messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит отправки сообщений")
            try:
                attributes = json.loads(str(gift["attributes_json"] or "{}"))
            except (TypeError, ValueError):
                attributes = {}
            if not isinstance(attributes, dict):
                attributes = {}
            attributes_json = json.dumps(attributes, ensure_ascii=False, separators=(",", ":"))
            cur = await db.execute(
                "UPDATE user_gifts SET owner_telegram_id=? WHERE id=? AND owner_telegram_id=?",
                (recipient_id, int(gift["id"]), uid),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Владение подарком уже изменилось")
            cur = await db.execute(
                """INSERT INTO messages
                   (sender_telegram_id,recipient_telegram_id,body,created_at)
                   VALUES(?,?,?,?)""",
                (uid, recipient_id, body, now),
            )
            message_id = int(cur.lastrowid)
            gift_name = str(gift["gift_name"])
            telegram_gift_id = str(gift["telegram_gift_id"] or "")
            upgrade_level = int(gift["upgrade_level"] or 0)
            await db.execute(
                """INSERT INTO message_gifts
                   (message_id,serial_number,gift_name,telegram_gift_id,upgrade_level,attributes_json)
                   VALUES(?,?,?,?,?,?)""",
                (message_id, serial, gift_name, telegram_gift_id, upgrade_level, attributes_json),
            )
            await db.execute(
                """INSERT INTO gift_transactions
                   (event_type,serial_number,gift_name,from_telegram_id,to_telegram_id,created_at)
                   VALUES('chat_send',?,?,?,?,?)""",
                (serial, gift_name, uid, recipient_id, now),
            )
            await record_event(
                db, "dm", message_id, "new_message", uid,
                user_a=uid, user_b=recipient_id,
            )
            result = {
                "id": message_id,
                "status": "sent",
                "type": "gift",
                "sender_id": uid,
                "recipient_id": recipient_id,
                "body": body,
                "gift_serial_number": serial,
                "gift_name": gift_name,
                "gift_telegram_gift_id": telegram_gift_id,
                "gift_upgrade_level": upgrade_level,
                "gift_attributes": attributes,
                "created_at": now,
            }
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()
        await deliver_push_notifications(
            [recipient_id],
            str(user.get("display_name") or user.get("username") or "Новый подарок"),
            f"Подарок WaysGram: {gift_name}",
            {"scope": "dm", "chat_id": str(uid), "message_id": str(message_id), "type": "gift"},
        )
        return result

    @router.post("/api/messages/{message_id}/forward", status_code=201)
    async def forward_message(
        message_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            recipient_id = int(payload.get("recipient_id", 0))
        except (TypeError, ValueError):
            recipient_id = 0
        if recipient_id <= 0:
            raise HTTPException(status_code=400, detail="Укажите корректного получателя")
        now = int(time.time())
        scope = f"/api/messages/{message_id}/forward"
        descriptor = idempotency_descriptor(scope, payload, idempotency_key)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            previous = await idempotency_lookup(db, uid, scope, descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous
            cur = await db.execute(
                """SELECT m.id,m.sender_telegram_id,m.recipient_telegram_id,m.body,m.media_id,
                          m.forwarded_from_telegram_id,m.forwarded_from_message_id,
                          COALESCE(a.display_name,a.username,'Пользователь') AS original_sender_name
                   FROM messages m
                   LEFT JOIN accounts a
                     ON a.telegram_id=COALESCE(m.forwarded_from_telegram_id,m.sender_telegram_id)
                   WHERE m.id=? AND (m.sender_telegram_id=? OR m.recipient_telegram_id=?)""",
                (message_id, uid, uid),
            )
            source = await cur.fetchone()
            if source is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Исходное сообщение не найдено")
            cur = await db.execute(
                "SELECT is_banned FROM accounts WHERE telegram_id=?", (recipient_id,)
            )
            target = await cur.fetchone()
            if target is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Получатель не найден")
            if target[0]:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Получатель заблокирован")
            cur = await db.execute(
                """SELECT 1 FROM blocked_users
                   WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                      OR (owner_telegram_id=? AND blocked_telegram_id=?)
                   LIMIT 1""",
                (uid, recipient_id, recipient_id, uid),
            )
            if await cur.fetchone():
                await db.rollback()
                raise HTTPException(status_code=403, detail="Нельзя переслать сообщение: пользователь находится в чёрном списке")
            cur = await db.execute(
                "SELECT COUNT(*) FROM messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит отправки сообщений")
            forwarded_from_id = (
                int(source["forwarded_from_telegram_id"])
                if source["forwarded_from_telegram_id"] is not None
                else int(source["sender_telegram_id"])
            )
            forwarded_from_message_id = (
                int(source["forwarded_from_message_id"])
                if source["forwarded_from_message_id"] is not None
                else int(source["id"])
            )
            cur = await db.execute(
                """INSERT INTO messages
                   (sender_telegram_id,recipient_telegram_id,body,media_id,reply_to_id,created_at,
                    forwarded_from_telegram_id,forwarded_from_message_id)
                   VALUES(?,?,?,?,NULL,?,?,?)""",
                (
                    uid, recipient_id, str(source["body"]), source["media_id"], now,
                    forwarded_from_id, forwarded_from_message_id,
                ),
            )
            new_message_id = int(cur.lastrowid)
            await record_event(
                db, "dm", new_message_id, "new_message", uid,
                user_a=uid, user_b=recipient_id,
            )
            media_fields = await media_message_fields(db, source["media_id"])
            result = {
                "id": new_message_id,
                "status": "forwarded",
                "sender_id": uid,
                "recipient_id": recipient_id,
                "body": str(source["body"]),
                "media_id": source["media_id"],
                "forwarded_from_telegram_id": forwarded_from_id,
                "forwarded_from_message_id": forwarded_from_message_id,
                "forwarded_from_display_name": str(source["original_sender_name"] or "Пользователь"),
                **media_fields,
                "created_at": now,
            }
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()
        await deliver_push_notifications(
            [recipient_id],
            str(user.get("display_name") or user.get("username") or "Новое сообщение"),
            str(source["body"]),
            {"scope": "dm", "chat_id": str(uid), "message_id": str(new_message_id)},
        )
        return result

    async def record_event(
        db: Any, scope: str, message_id: int, kind: str, actor_id: int,
        chat_id: int = 0, user_a: int = 0, user_b: int = 0,
    ) -> None:
        await db.execute(
            """INSERT INTO message_events(scope,chat_id,user_a,user_b,message_id,kind,actor_id,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (scope, chat_id, user_a, user_b, message_id, kind, actor_id, int(time.time())),
        )

    async def process_due_scheduled_messages() -> None:
        now = int(time.time())
        notifications: list[tuple[int, int, str, str, int]] = []
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT id,sender_telegram_id,recipient_telegram_id,body,silent,
                          scheduled_at,repeat_interval_seconds,time_zone
                   FROM scheduled_messages
                   WHERE status='pending' AND scheduled_at<=?
                   ORDER BY scheduled_at ASC,id ASC LIMIT 100""",
                (now,),
            )
            due = await cur.fetchall()
            for scheduled in due:
                scheduled_id, sender_id, recipient_id, body, silent, scheduled_at, repeat_interval, time_zone = scheduled
                cur = await db.execute(
                    "SELECT is_banned FROM accounts WHERE telegram_id=?",
                    (sender_id,),
                )
                sender = await cur.fetchone()
                cur = await db.execute(
                    "SELECT is_banned FROM accounts WHERE telegram_id=?",
                    (recipient_id,),
                )
                recipient = await cur.fetchone()
                failure = ""
                if sender is None or sender[0]:
                    failure = "Аккаунт отправителя недоступен"
                elif recipient is None or recipient[0]:
                    failure = "Получатель недоступен"
                elif int(sender_id) != int(recipient_id):
                    cur = await db.execute(
                        """SELECT 1 FROM blocked_users
                           WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                              OR (owner_telegram_id=? AND blocked_telegram_id=?)
                           LIMIT 1""",
                        (sender_id, recipient_id, recipient_id, sender_id),
                    )
                    if await cur.fetchone():
                        failure = "Пользователь находится в чёрном списке"
                cur = await db.execute(
                    "SELECT COUNT(*) FROM messages WHERE sender_telegram_id=? AND created_at>?",
                    (sender_id, now - 60),
                )
                if not failure and int((await cur.fetchone())[0]) >= DM_MESSAGES_PER_MINUTE:
                    continue
                if failure:
                    await db.execute(
                        "UPDATE scheduled_messages SET status='failed',error=? WHERE id=? AND status='pending'",
                        (failure, scheduled_id),
                    )
                    continue
                cur = await db.execute(
                    """INSERT INTO messages(sender_telegram_id,recipient_telegram_id,body,created_at)
                       VALUES(?,?,?,?)""",
                    (sender_id, recipient_id, body, now),
                )
                message_id = int(cur.lastrowid)
                await record_event(
                    db, "dm", message_id, "new_message", int(sender_id),
                    user_a=int(sender_id), user_b=int(recipient_id),
                )
                if int(repeat_interval) > 0:
                    next_scheduled_at = _next_recurring_scheduled_timestamp(
                        int(scheduled_at), now, int(repeat_interval), str(time_zone or "UTC")
                    )
                    await db.execute(
                        """UPDATE scheduled_messages
                           SET scheduled_at=?,created_at=?,message_id=?,error=''
                           WHERE id=? AND status='pending'""",
                        (next_scheduled_at, now, message_id, scheduled_id),
                    )
                else:
                    await db.execute(
                        """UPDATE scheduled_messages
                           SET status='sent',message_id=?,error=''
                           WHERE id=? AND status='pending'""",
                        (message_id, scheduled_id),
                    )
                if not bool(silent):
                    notifications.append((
                        int(recipient_id), int(sender_id),
                        str(body), str(scheduled_id), message_id,
                    ))
            await db.commit()
        for recipient_id, sender_id, body, scheduled_id, message_id in notifications:
            await deliver_push_notifications(
                [recipient_id],
                "Отложенное сообщение",
                body,
                {
                    "scope": "dm",
                    "chat_id": str(sender_id),
                    "message_id": str(message_id),
                    "scheduled_message_id": scheduled_id,
                },
            )

    scheduled_worker_task: asyncio.Task | None = None

    async def scheduled_message_worker() -> None:
        last_auction_settlement = 0
        while True:
            try:
                await process_due_scheduled_messages()
                now = int(time.time())
                if now - last_auction_settlement >= 5:
                    await process_due_collectible_auctions()
                    last_auction_settlement = now
            except Exception as exc:
                LOGGER.warning(
                    "Scheduled message or collectible auction processing failed (%s)",
                    type(exc).__name__,
                )
            await asyncio.sleep(1.0)

    @router.on_event("startup")
    async def start_scheduled_message_worker() -> None:
        nonlocal scheduled_worker_task
        if scheduled_worker_task is None or scheduled_worker_task.done():
            scheduled_worker_task = asyncio.create_task(scheduled_message_worker())

    @router.on_event("shutdown")
    async def stop_scheduled_message_worker() -> None:
        nonlocal scheduled_worker_task
        if scheduled_worker_task is not None:
            scheduled_worker_task.cancel()
            await asyncio.gather(scheduled_worker_task, return_exceptions=True)
            scheduled_worker_task = None

    def edited_body(payload: dict[str, Any]) -> str:
        value = payload.get("body")
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(status_code=400, detail="Текст сообщения не может быть пустым")
        return _message_body(value)

    async def toggle_message_reaction(
        scope: str,
        chat_id: int,
        message_id: int,
        user_id: int,
        reaction: str,
    ) -> dict[str, Any]:
        allowed = {"👍", "❤️", "😂", "😮", "😢", "🎉", "🙏"}
        if reaction not in allowed:
            raise HTTPException(status_code=400, detail="Недопустимая реакция")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            event_user_a = 0
            event_user_b = 0
            if scope == "dm":
                cur = await db.execute(
                    """SELECT sender_telegram_id,recipient_telegram_id
                       FROM messages WHERE id=?""",
                    (message_id,),
                )
                message = await cur.fetchone()
                if message is None or user_id not in (int(message[0]), int(message[1])):
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Сообщение не найдено")
                event_user_a = int(message[0])
                event_user_b = int(message[1])
            elif scope == "group":
                await require_group_member(db, chat_id, user_id)
                cur = await db.execute(
                    "SELECT 1 FROM group_messages WHERE id=? AND group_id=?",
                    (message_id, chat_id),
                )
                if await cur.fetchone() is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Сообщение не найдено")
            elif scope == "channel":
                cur = await db.execute(
                    "SELECT 1 FROM channel_messages WHERE id=? AND channel_id=?",
                    (message_id, chat_id),
                )
                if await cur.fetchone() is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Публикация не найдена")
            cur = await db.execute(
                """SELECT 1 FROM message_reactions
                   WHERE scope=? AND chat_id=? AND message_id=?
                     AND user_telegram_id=? AND reaction=?""",
                (scope, chat_id, message_id, user_id, reaction),
            )
            exists = await cur.fetchone() is not None
            if exists:
                await db.execute(
                    """DELETE FROM message_reactions
                       WHERE scope=? AND chat_id=? AND message_id=?
                         AND user_telegram_id=? AND reaction=?""",
                    (scope, chat_id, message_id, user_id, reaction),
                )
                status = "removed"
            else:
                cur = await db.execute(
                    """SELECT COUNT(*) FROM message_reactions
                       WHERE scope=? AND chat_id=? AND message_id=? AND user_telegram_id=?""",
                    (scope, chat_id, message_id, user_id),
                )
                if int((await cur.fetchone())[0]) >= 3:
                    await db.rollback()
                    raise HTTPException(status_code=409, detail="Можно поставить не более трёх разных реакций")
                await db.execute(
                    """INSERT INTO message_reactions
                       (scope,chat_id,message_id,user_telegram_id,reaction,created_at)
                       VALUES(?,?,?,?,?,?)""",
                    (scope, chat_id, message_id, user_id, reaction, now),
                )
                status = "added"
            cur = await db.execute(
                """SELECT reaction,COUNT(*) AS count FROM message_reactions
                   WHERE scope=? AND chat_id=? AND message_id=?
                   GROUP BY reaction ORDER BY MIN(created_at),reaction""",
                (scope, chat_id, message_id),
            )
            summary = [{"reaction": str(row[0]), "count": int(row[1])} for row in await cur.fetchall()]
            cur = await db.execute(
                """SELECT reaction FROM message_reactions
                   WHERE scope=? AND chat_id=? AND message_id=? AND user_telegram_id=?
                   ORDER BY created_at,reaction""",
                (scope, chat_id, message_id, user_id),
            )
            mine = [str(row[0]) for row in await cur.fetchall()]
            await record_event(
                db,
                scope,
                message_id,
                "reaction",
                user_id,
                chat_id=chat_id,
                user_a=event_user_a,
                user_b=event_user_b,
            )
            await db.commit()
        return {
            "status": status,
            "scope": scope,
            "chat_id": chat_id,
            "message_id": message_id,
            "reactions": summary,
            "my_reactions": mine,
        }

    async def change_pinned_message(
        scope: str, chat_id: int, message_id: int, user_id: int, pin: bool
    ) -> dict[str, Any]:
        if scope not in ("dm", "group", "channel") or chat_id <= 0 or message_id <= 0:
            raise HTTPException(status_code=400, detail="Некорректные параметры закрепления")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            event_user_a = 0
            event_user_b = 0
            if scope == "dm":
                cur = await db.execute(
                    """SELECT sender_telegram_id,recipient_telegram_id FROM messages
                       WHERE id=? AND ((sender_telegram_id=? AND recipient_telegram_id=?)
                                      OR (sender_telegram_id=? AND recipient_telegram_id=?))""",
                    (message_id, user_id, chat_id, chat_id, user_id),
                )
                message = await cur.fetchone()
                if message is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Сообщение не найдено в этой переписке")
                event_user_a = int(message["sender_telegram_id"])
                event_user_b = int(message["recipient_telegram_id"])
            elif scope == "group":
                membership = await require_group_member(db, chat_id, user_id)
                if membership["role"] not in ("owner", "admin"):
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Закреплять сообщения могут только администраторы группы")
                cur = await db.execute(
                    "SELECT 1 FROM group_messages WHERE id=? AND group_id=?", (message_id, chat_id)
                )
                if await cur.fetchone() is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Сообщение группы не найдено")
            else:
                cur = await db.execute(
                    """SELECT ch.owner_telegram_id,
                              EXISTS(SELECT 1 FROM channel_admins ca
                                     WHERE ca.channel_id=ch.id AND ca.telegram_id=?) AS is_admin
                       FROM channels ch WHERE ch.id=?""",
                    (user_id, chat_id),
                )
                channel = await cur.fetchone()
                if channel is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Канал не найден")
                if int(channel["owner_telegram_id"]) != user_id and not bool(channel["is_admin"]):
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Закреплять публикации могут только администраторы канала")
                cur = await db.execute(
                    "SELECT 1 FROM channel_messages WHERE id=? AND channel_id=?", (message_id, chat_id)
                )
                if await cur.fetchone() is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Публикация не найдена")
            stored_chat_id = chat_id if scope != "dm" else 0
            if pin:
                cur = await db.execute(
                    """INSERT OR IGNORE INTO pinned_messages(scope,chat_id,message_id,pinned_by,created_at)
                       VALUES(?,?,?,?,?)""",
                    (scope, stored_chat_id, message_id, user_id, now),
                )
                status = "pinned" if cur.rowcount == 1 else "already_pinned"
                event_kind = "pin" if cur.rowcount == 1 else ""
            else:
                cur = await db.execute(
                    "DELETE FROM pinned_messages WHERE scope=? AND chat_id=? AND message_id=?",
                    (scope, stored_chat_id, message_id),
                )
                status = "unpinned" if cur.rowcount == 1 else "not_pinned"
                event_kind = "unpin" if cur.rowcount == 1 else ""
            if event_kind:
                await record_event(
                    db, scope, message_id, event_kind, user_id,
                    chat_id=stored_chat_id, user_a=event_user_a, user_b=event_user_b,
                )
            await db.commit()
        return {"status": status, "scope": scope, "peer_id": chat_id, "message_id": message_id}

    @router.get("/api/pins")
    async def list_pinned_messages(
        scope: str = Query(...),
        peer_id: int = Query(..., gt=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        if scope == "dm":
            async with aiosqlite.connect(db_path()) as db:
                cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (peer_id,))
                if await cur.fetchone() is None:
                    raise HTTPException(status_code=404, detail="Собеседник не найден")
        elif scope == "group":
            async with aiosqlite.connect(db_path()) as db:
                await require_group_member(db, peer_id, uid)
        else:
            await require_channel_access(peer_id, uid)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            if scope == "dm":
                cur = await db.execute(
                    """SELECT p.message_id,p.pinned_by,p.created_at AS pinned_at,
                              m.body,m.created_at,m.sender_telegram_id AS sender_id,
                              m.recipient_telegram_id AS recipient_id
                       FROM pinned_messages p JOIN messages m ON m.id=p.message_id
                       WHERE p.scope='dm' AND p.chat_id=0 AND
                         ((m.sender_telegram_id=? AND m.recipient_telegram_id=?) OR
                          (m.sender_telegram_id=? AND m.recipient_telegram_id=?))
                         AND NOT EXISTS (
                             SELECT 1 FROM message_hidden_for hidden
                             WHERE hidden.message_id=m.id AND hidden.telegram_id=?
                         )
                       ORDER BY p.created_at DESC,p.message_id DESC LIMIT 100""",
                    (uid, peer_id, peer_id, uid, uid),
                )
            elif scope == "group":
                cur = await db.execute(
                    """SELECT p.message_id,p.pinned_by,p.created_at AS pinned_at,
                              m.body,m.created_at,m.sender_telegram_id AS sender_id
                       FROM pinned_messages p JOIN group_messages m ON m.id=p.message_id
                       WHERE p.scope='group' AND p.chat_id=? AND m.group_id=p.chat_id
                       ORDER BY p.created_at DESC,p.message_id DESC LIMIT 100""",
                    (peer_id,),
                )
            else:
                cur = await db.execute(
                    """SELECT p.message_id,p.pinned_by,p.created_at AS pinned_at,
                              m.body,m.created_at,m.author_telegram_id AS sender_id
                       FROM pinned_messages p JOIN channel_messages m ON m.id=p.message_id
                       WHERE p.scope='channel' AND p.chat_id=? AND m.channel_id=p.chat_id
                       ORDER BY p.created_at DESC,p.message_id DESC LIMIT 100""",
                    (peer_id,),
                )
            rows = [dict(row) for row in await cur.fetchall()]
        return {"scope": scope, "peer_id": peer_id, "pinned_messages": rows, "count": len(rows)}

    @router.post("/api/pins")
    async def pin_message(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        scope = payload.get("scope")
        peer_id = payload.get("peer_id")
        message_id = payload.get("message_id")
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in (peer_id, message_id)):
            raise HTTPException(status_code=400, detail="peer_id и message_id должны быть положительными целыми числами")
        return await change_pinned_message(str(scope), peer_id, message_id, int(user["telegram_id"]), True)

    @router.delete("/api/pins")
    async def unpin_message(
        scope: str = Query(...),
        peer_id: int = Query(..., gt=0),
        message_id: int = Query(..., gt=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        return await change_pinned_message(scope, peer_id, message_id, int(user["telegram_id"]), False)

    @router.post("/api/messages/{message_id}/reactions")
    async def react_to_direct_message(
        message_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        return await toggle_message_reaction(
            "dm", 0, message_id, int(user["telegram_id"]), str(payload.get("reaction") or "")
        )

    @router.post("/api/groups/{group_id}/messages/{message_id}/reactions")
    async def react_to_group_message(
        group_id: int,
        message_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        return await toggle_message_reaction(
            "group", group_id, message_id, int(user["telegram_id"]), str(payload.get("reaction") or "")
        )

    @router.post("/api/channels/{channel_id}/messages/{message_id}/reactions")
    async def react_to_channel_message(
        channel_id: int,
        message_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        await require_channel_access(channel_id, int(user["telegram_id"]))
        return await toggle_message_reaction(
            "channel", channel_id, message_id, int(user["telegram_id"]), str(payload.get("reaction") or "")
        )

    @router.delete("/api/conversations/{peer_id}/messages")
    async def clear_direct_message_history(
        peer_id: int,
        delete_for: str = Query(default="me", alias="for"),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if peer_id <= 0:
            raise HTTPException(status_code=400, detail="Укажите корректного собеседника")
        if delete_for != "me":
            raise HTTPException(status_code=400, detail="Очистка истории поддерживает только for=me")
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT 1 FROM accounts WHERE telegram_id=?",
                (peer_id,),
            )
            if await cur.fetchone() is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Собеседник не найден")
            cur = await db.execute(
                """SELECT COUNT(*),COALESCE(MAX(id),0) FROM messages
                   WHERE ((sender_telegram_id=? AND recipient_telegram_id=?) OR
                          (sender_telegram_id=? AND recipient_telegram_id=?))
                     AND NOT EXISTS (
                         SELECT 1 FROM message_hidden_for hidden
                         WHERE hidden.message_id=messages.id AND hidden.telegram_id=?
                     )""",
                (uid, peer_id, peer_id, uid, uid),
            )
            count, latest_message_id = await cur.fetchone()
            now = int(time.time())
            if int(count) > 0:
                await db.execute(
                    """INSERT OR IGNORE INTO message_hidden_for(message_id,telegram_id,hidden_at)
                       SELECT id,?,? FROM messages
                       WHERE ((sender_telegram_id=? AND recipient_telegram_id=?) OR
                              (sender_telegram_id=? AND recipient_telegram_id=?))""",
                    (uid, now, uid, peer_id, peer_id, uid),
                )
                await record_event(
                    db, "dm", int(latest_message_id), "clear_for_me", uid,
                    user_a=uid, user_b=peer_id,
                )
            await db.commit()
        return {
            "status": "cleared_for_me",
            "peer_id": peer_id,
            "deleted_count": int(count),
        }

    @router.put("/api/messages/{message_id}")
    @router.patch("/api/messages/{message_id}")
    async def edit_message(
        message_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        body = edited_body(payload)
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT sender_telegram_id,recipient_telegram_id FROM messages WHERE id=?", (message_id,)
            )
            row = await cur.fetchone()
            if row is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сообщение не найдено")
            if int(row[0]) != uid:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Изменять можно только свои сообщения")
            await db.execute("UPDATE messages SET body=?,edited_at=? WHERE id=?", (body, now, message_id))
            await record_event(db, "dm", message_id, "edit", uid, user_a=int(row[0]), user_b=int(row[1]))
            await db.commit()
        return {"id": message_id, "body": body, "edited_at": now}

    @router.delete("/api/messages/{message_id}")
    async def delete_message(
        message_id: int,
        delete_for: str = Query(default="all", alias="for"),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if delete_for not in ("me", "all"):
            raise HTTPException(status_code=400, detail="for должен быть me или all")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT sender_telegram_id,recipient_telegram_id FROM messages WHERE id=?",
                (message_id,),
            )
            row = await cur.fetchone()
            if row is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сообщение не найдено")
            sender_id, recipient_id = int(row[0]), int(row[1])
            if uid not in (sender_id, recipient_id):
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сообщение не найдено")
            if delete_for == "me":
                await db.execute(
                    """INSERT OR IGNORE INTO message_hidden_for(message_id,telegram_id,hidden_at)
                       VALUES(?,?,?)""",
                    (message_id, uid, now),
                )
                await record_event(
                    db, "dm", message_id, "delete_for_me", uid,
                    user_a=sender_id, user_b=recipient_id,
                )
                await db.commit()
                return {"id": message_id, "status": "hidden_for_me"}
            if sender_id != uid:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Удалять для всех можно только свои сообщения")
            await db.execute("DELETE FROM messages WHERE id=?", (message_id,))
            await record_event(
                db, "dm", message_id, "delete", uid,
                user_a=sender_id, user_b=recipient_id,
            )
            await db.commit()
        return {"id": message_id, "status": "deleted_for_all"}

    @router.put("/api/groups/{group_id}/messages/{message_id}")
    @router.patch("/api/groups/{group_id}/messages/{message_id}")
    async def edit_group_message(
        group_id: int,
        message_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        body = edited_body(payload)
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            await require_group_member(db, group_id, uid)
            cur = await db.execute(
                "SELECT sender_telegram_id FROM group_messages WHERE id=? AND group_id=?", (message_id, group_id)
            )
            row = await cur.fetchone()
            if row is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сообщение не найдено")
            if int(row[0]) != uid:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Изменять можно только свои сообщения")
            await db.execute("UPDATE group_messages SET body=?,edited_at=? WHERE id=?", (body, now, message_id))
            await record_event(db, "group", message_id, "edit", uid, chat_id=group_id)
            await db.commit()
        return {"id": message_id, "body": body, "edited_at": now}

    @router.delete("/api/groups/{group_id}/messages/{message_id}")
    async def delete_group_message(
        group_id: int,
        message_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            member = await require_group_member(db, group_id, uid)
            cur = await db.execute(
                "SELECT sender_telegram_id FROM group_messages WHERE id=? AND group_id=?", (message_id, group_id)
            )
            row = await cur.fetchone()
            if row is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сообщение не найдено")
            if int(row[0]) != uid and member["role"] not in ("owner", "admin"):
                await db.rollback()
                raise HTTPException(status_code=403, detail="Удалять чужие сообщения могут только администраторы")
            await db.execute("DELETE FROM group_messages WHERE id=?", (message_id,))
            await record_event(db, "group", message_id, "delete", uid, chat_id=group_id)
            await db.commit()
        return {"id": message_id, "status": "deleted"}

    @router.delete("/api/group-messages/{message_id}")
    async def delete_group_message_by_id(
        message_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Same as deleting inside a group, for clients that only know the message id."""
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute("SELECT group_id FROM group_messages WHERE id=?", (message_id,))
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Сообщение не найдено")
        return await delete_group_message(int(row[0]), message_id, authorization)

    @router.put("/api/channels/{channel_id}/messages/{message_id}")
    @router.patch("/api/channels/{channel_id}/messages/{message_id}")
    async def edit_channel_message(
        channel_id: int,
        message_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if not await can_manage_channel(channel_id, uid):
            raise HTTPException(status_code=403, detail="Менять публикации может только владелец или администратор")
        body = edited_body(payload)
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT 1 FROM channel_messages WHERE id=? AND channel_id=?", (message_id, channel_id)
            )
            if await cur.fetchone() is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сообщение не найдено")
            await db.execute("UPDATE channel_messages SET body=?,edited_at=? WHERE id=?", (body, now, message_id))
            await record_event(db, "channel", message_id, "edit", uid, chat_id=channel_id)
            await db.commit()
        return {"id": message_id, "body": body, "edited_at": now}

    @router.delete("/api/channels/{channel_id}/messages/{message_id}")
    async def delete_channel_message(
        channel_id: int,
        message_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if not await can_manage_channel(channel_id, uid):
            raise HTTPException(status_code=403, detail="Удалять публикации может только владелец или администратор")
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT 1 FROM channel_messages WHERE id=? AND channel_id=?", (message_id, channel_id)
            )
            if await cur.fetchone() is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Сообщение не найдено")
            await db.execute("DELETE FROM channel_messages WHERE id=?", (message_id,))
            await record_event(db, "channel", message_id, "delete", uid, chat_id=channel_id)
            await db.commit()
        return {"id": message_id, "status": "deleted"}

    @router.put("/api/read")
    async def mark_read(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        scope = str(payload.get("scope") or "")
        peer_id = payload.get("peer_id")
        last_read_id = payload.get("last_read_id")
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        for value in (peer_id, last_read_id):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise HTTPException(status_code=400, detail="peer_id и last_read_id должны быть целыми числами")
        if not peer_id:
            raise HTTPException(status_code=400, detail="Укажите peer_id")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            if scope == "group":
                await require_group_member(db, int(peer_id), uid)
            elif scope == "channel":
                cur = await db.execute(
                    """SELECT ch.is_public,ch.owner_telegram_id,
                              EXISTS(SELECT 1 FROM channel_admins ca
                                     WHERE ca.channel_id=ch.id AND ca.telegram_id=?),
                              EXISTS(SELECT 1 FROM channel_members cm
                                     WHERE cm.channel_id=ch.id AND cm.telegram_id=?)
                       FROM channels ch WHERE ch.id=?""",
                    (uid, uid, int(peer_id)),
                )
                channel_access = await cur.fetchone()
                if channel_access is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Канал не найден")
                is_public, owner_id, is_admin, is_member = channel_access
                if not bool(is_public) and int(owner_id) != uid and not bool(is_admin) and not bool(is_member):
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Нет доступа к приватному каналу")
            else:
                cur = await db.execute("SELECT 1 FROM accounts WHERE telegram_id=?", (int(peer_id),))
                if await cur.fetchone() is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Собеседник не найден")
            cur = await db.execute(
                "SELECT last_read_id FROM read_markers WHERE telegram_id=? AND scope=? AND peer_id=?",
                (uid, scope, int(peer_id)),
            )
            row = await cur.fetchone()
            current = int(row[0]) if row else 0
            value = max(current, int(last_read_id))  # the marker never moves back
            await db.execute(
                """INSERT INTO read_markers(telegram_id,scope,peer_id,last_read_id,updated_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(telegram_id,scope,peer_id) DO UPDATE SET last_read_id=excluded.last_read_id,
                       updated_at=excluded.updated_at""",
                (uid, scope, int(peer_id), value, now),
            )
            if scope == "dm" and int(peer_id) != uid and value > current:
                await record_event(db, "dm", value, "read", uid, user_a=uid, user_b=int(peer_id))
            await db.commit()
        return {"last_read_id": value}

    @router.get("/api/drafts")
    async def get_cloud_draft(
        scope: str = Query(...),
        peer_id: int = Query(..., gt=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        uid = int(user["telegram_id"])
        await require_cloud_draft_access(scope, peer_id, uid)
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT scope,peer_id,body,updated_at FROM cloud_drafts
                   WHERE owner_telegram_id=? AND scope=? AND peer_id=?""",
                (uid, scope, peer_id),
            )
            row = await cur.fetchone()
        return {"draft": dict(row) if row is not None else None}

    @router.put("/api/drafts")
    async def save_cloud_draft(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        scope = payload.get("scope")
        peer_id = payload.get("peer_id")
        body = payload.get("body")
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        if isinstance(peer_id, bool) or not isinstance(peer_id, int) or peer_id <= 0:
            raise HTTPException(status_code=400, detail="peer_id должен быть положительным целым числом")
        if not isinstance(body, str) or not body.strip() or len(body) > MAX_MESSAGE_LENGTH:
            raise HTTPException(status_code=400, detail=f"Черновик должен содержать 1–{MAX_MESSAGE_LENGTH} символов")
        uid = int(user["telegram_id"])
        await require_cloud_draft_access(str(scope), peer_id, uid)
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute(
                """INSERT INTO cloud_drafts(owner_telegram_id,scope,peer_id,body,updated_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(owner_telegram_id,scope,peer_id) DO UPDATE SET
                       body=excluded.body,updated_at=excluded.updated_at""",
                (uid, str(scope), peer_id, body, now),
            )
            await db.commit()
        return {"scope": str(scope), "peer_id": peer_id, "body": body, "updated_at": now}

    @router.delete("/api/drafts")
    async def delete_cloud_draft(
        scope: str = Query(...),
        peer_id: int = Query(..., gt=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        if scope not in ("dm", "group", "channel"):
            raise HTTPException(status_code=400, detail="scope: dm, group или channel")
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "DELETE FROM cloud_drafts WHERE owner_telegram_id=? AND scope=? AND peer_id=?",
                (uid, scope, peer_id),
            )
            deleted = cur.rowcount == 1
            await db.commit()
        return {"status": "deleted" if deleted else "not_found", "scope": scope, "peer_id": peer_id}

    @router.put("/api/typing")
    async def update_typing_indicator(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        scope = payload.get("scope")
        peer_id = payload.get("peer_id")
        is_typing = payload.get("is_typing", True)
        if scope not in ("dm", "group"):
            raise HTTPException(status_code=400, detail="scope: dm или group")
        if isinstance(peer_id, bool) or not isinstance(peer_id, int) or peer_id <= 0:
            raise HTTPException(status_code=400, detail="peer_id должен быть положительным целым числом")
        if not isinstance(is_typing, bool):
            raise HTTPException(status_code=400, detail="is_typing должен быть логическим значением")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            if scope == "dm":
                if peer_id == uid:
                    await db.rollback()
                    raise HTTPException(status_code=400, detail="Индикатор набора не нужен для избранного")
                cur = await db.execute(
                    "SELECT is_banned FROM accounts WHERE telegram_id=?", (peer_id,)
                )
                target = await cur.fetchone()
                if target is None:
                    await db.rollback()
                    raise HTTPException(status_code=404, detail="Собеседник не найден")
                if target[0]:
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Аккаунт собеседника недоступен")
                cur = await db.execute(
                    """SELECT 1 FROM blocked_users
                       WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                          OR (owner_telegram_id=? AND blocked_telegram_id=?) LIMIT 1""",
                    (uid, peer_id, peer_id, uid),
                )
                if await cur.fetchone():
                    await db.rollback()
                    raise HTTPException(status_code=403, detail="Индикатор недоступен для этого диалога")
                chat_id = peer_id
            else:
                await require_group_member(db, peer_id, uid)
                chat_id = peer_id
            await db.execute("DELETE FROM typing_indicators WHERE expires_at<=?", (now,))
            if is_typing:
                expires_at = now + 8
                await db.execute(
                    """INSERT INTO typing_indicators(scope,chat_id,user_telegram_id,updated_at,expires_at)
                       VALUES(?,?,?,?,?)
                       ON CONFLICT(scope,chat_id,user_telegram_id) DO UPDATE SET
                           updated_at=excluded.updated_at,expires_at=excluded.expires_at""",
                    (scope, chat_id, uid, now, expires_at),
                )
            else:
                expires_at = 0
                await db.execute(
                    "DELETE FROM typing_indicators WHERE scope=? AND chat_id=? AND user_telegram_id=?",
                    (scope, chat_id, uid),
                )
            await db.commit()
        return {
            "scope": scope,
            "peer_id": peer_id,
            "is_typing": is_typing,
            "expires_at": expires_at if is_typing else None,
        }

    @router.get("/api/typing")
    async def get_typing_indicators(
        scope: str = Query(...),
        peer_id: int = Query(..., gt=0),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        if scope not in ("dm", "group"):
            raise HTTPException(status_code=400, detail="scope: dm или group")
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("DELETE FROM typing_indicators WHERE expires_at<=?", (now,))
            if scope == "dm":
                if peer_id == uid:
                    raise HTTPException(status_code=400, detail="Для избранного индикатор набора не используется")
                cur = await db.execute(
                    "SELECT is_banned FROM accounts WHERE telegram_id=?", (peer_id,)
                )
                target = await cur.fetchone()
                if target is None:
                    raise HTTPException(status_code=404, detail="Собеседник не найден")
                if target[0]:
                    raise HTTPException(status_code=403, detail="Аккаунт собеседника недоступен")
                cur = await db.execute(
                    """SELECT 1 FROM blocked_users
                       WHERE (owner_telegram_id=? AND blocked_telegram_id=?)
                          OR (owner_telegram_id=? AND blocked_telegram_id=?) LIMIT 1""",
                    (uid, peer_id, peer_id, uid),
                )
                if await cur.fetchone():
                    raise HTTPException(status_code=403, detail="Индикатор недоступен для этого диалога")
                cur = await db.execute(
                    """SELECT a.telegram_id AS id,a.username,a.display_name,ti.updated_at
                       FROM typing_indicators ti JOIN accounts a ON a.telegram_id=ti.user_telegram_id
                       WHERE ti.scope='dm' AND ti.chat_id=? AND ti.user_telegram_id=?
                         AND ti.expires_at>? AND a.is_banned=0""",
                    (uid, peer_id, now),
                )
            else:
                await require_group_member(db, peer_id, uid)
                cur = await db.execute(
                    """SELECT a.telegram_id AS id,a.username,a.display_name,ti.updated_at
                       FROM typing_indicators ti JOIN accounts a ON a.telegram_id=ti.user_telegram_id
                       JOIN group_members gm ON gm.telegram_id=ti.user_telegram_id AND gm.group_id=ti.chat_id
                       WHERE ti.scope='group' AND ti.chat_id=? AND ti.user_telegram_id<>?
                         AND ti.expires_at>? AND a.is_banned=0
                       ORDER BY ti.updated_at DESC LIMIT 50""",
                    (peer_id, uid, now),
                )
            rows = [dict(row) for row in await cur.fetchall()]
            await db.commit()
        return {"scope": scope, "peer_id": peer_id, "typing_users": rows, "count": len(rows)}

    @router.get("/api/events")
    async def message_changes(
        after_id: int | None = Query(default=None, ge=0),
        wait_seconds: int = Query(default=0, ge=0, le=20),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Return message changes, optionally waiting briefly for a new visible event."""
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        deadline = time.monotonic() + (wait_seconds if after_id is not None else 0)
        rows: list[dict[str, Any]] = []
        latest = 0
        while True:
            async with aiosqlite.connect(db_path()) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute("SELECT COALESCE(MAX(id),0) FROM message_events")
                latest = int((await cur.fetchone())[0])
                if after_id is None:
                    return {"events": [], "latest_id": latest}
                cur = await db.execute(
                    """SELECT id,scope,chat_id,user_a,user_b,message_id,kind,actor_id,created_at
                       FROM message_events
                       WHERE id>? AND (
                           (kind IN ('delete_for_me','clear_for_me') AND actor_id=?)
                           OR (kind NOT IN ('delete_for_me','clear_for_me') AND actor_id<>?)
                       ) AND (
                           (scope='dm' AND (user_a=? OR user_b=?))
                           OR (scope='group' AND chat_id IN (SELECT group_id FROM group_members WHERE telegram_id=?))
                           OR (scope='channel' AND chat_id IN (
                               SELECT ch.id FROM channels ch
                               WHERE ch.is_public=1 OR ch.owner_telegram_id=?
                                  OR EXISTS(SELECT 1 FROM channel_admins ca
                                            WHERE ca.channel_id=ch.id AND ca.telegram_id=?)
                                  OR EXISTS(SELECT 1 FROM channel_members cm
                                            WHERE cm.channel_id=ch.id AND cm.telegram_id=?)
                           )))
                       ORDER BY id ASC LIMIT 200""",
                    (after_id, uid, uid, uid, uid, uid, uid, uid, uid),
                )
                rows = [dict(row) for row in await cur.fetchall()]
            if rows or time.monotonic() >= deadline:
                break
            await asyncio.sleep(min(0.5, max(0.05, deadline - time.monotonic())))
        cursor = rows[-1]["id"] if len(rows) >= 200 else latest
        return {"events": rows, "latest_id": cursor}

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
                    WHERE (sender_telegram_id=? OR recipient_telegram_id=?)
                      AND NOT EXISTS (
                          SELECT 1 FROM message_hidden_for hidden
                          WHERE hidden.message_id=messages.id AND hidden.telegram_id=?
                      )
                    GROUP BY peer_id
                )
                SELECT peer.telegram_id AS id,peer.username,peer.display_name,peer.avatar_media_id,
                       message.body AS last_message,message.created_at,
                       message.id AS last_message_id,
                       message.sender_telegram_id AS last_sender_id,
                       COALESCE((SELECT rm.last_read_id FROM read_markers rm
                                 WHERE rm.telegram_id=? AND rm.scope='dm' AND rm.peer_id=peer.telegram_id),0) AS my_read_id,
                       COALESCE((SELECT rm.last_read_id FROM read_markers rm
                                 WHERE rm.telegram_id=peer.telegram_id AND rm.scope='dm' AND rm.peer_id=?),0) AS peer_read_id,
                       (SELECT COUNT(*) FROM messages um
                        WHERE um.sender_telegram_id=peer.telegram_id AND um.recipient_telegram_id=?
                          AND um.sender_telegram_id<>um.recipient_telegram_id
                          AND NOT EXISTS (
                              SELECT 1 FROM message_hidden_for hidden
                              WHERE hidden.message_id=um.id AND hidden.telegram_id=?
                          )
                          AND um.id>COALESCE((SELECT rm.last_read_id FROM read_markers rm
                                              WHERE rm.telegram_id=? AND rm.scope='dm'
                                                AND rm.peer_id=peer.telegram_id),0)) AS unread_count
                FROM recent
                JOIN accounts AS peer ON peer.telegram_id=recent.peer_id
                JOIN messages AS message ON message.id=recent.last_message_id
                ORDER BY message.id DESC LIMIT 100""",
                (uid, uid, uid, uid, uid, uid, uid, uid, uid),
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
                          (SELECT COUNT(*) FROM group_messages x WHERE x.group_id=g.id) AS message_count,
                          COALESCE((SELECT rm.last_read_id FROM read_markers rm
                                    WHERE rm.telegram_id=? AND rm.scope='group' AND rm.peer_id=g.id),0) AS last_read_id,
                          (SELECT COUNT(*) FROM group_messages y
                           WHERE y.group_id=g.id AND y.sender_telegram_id<>?
                             AND y.id>COALESCE((SELECT rm.last_read_id FROM read_markers rm
                                                WHERE rm.telegram_id=? AND rm.scope='group'
                                                  AND rm.peer_id=g.id),0)) AS unread_count
                   FROM group_members gm
                   JOIN chat_groups g ON g.id=gm.group_id
                   WHERE gm.telegram_id=?
                   ORDER BY g.id DESC LIMIT 100""",
                (uid, uid, uid, uid),
            )
            rows = await cur.fetchall()
        return {"groups": [dict(row) for row in rows]}

    @router.post("/api/groups", status_code=201)
    async def create_group(
        payload: dict[str, Any],        authorization: str | None = Header(default=None),
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
                          g.slow_mode_seconds,
                          (SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id) AS member_count
                   FROM chat_groups g WHERE g.id=?""",
                (group_id,),
            )
            group = await cur.fetchone()
            cur = await db.execute(
                """SELECT gm.telegram_id,gm.role,gm.joined_at,a.username,a.display_name,a.avatar_media_id
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

    @router.put("/api/groups/{group_id}/slow-mode")
    async def update_group_slow_mode(
        group_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        seconds = payload.get("seconds")
        allowed_intervals = {0, 5, 10, 15, 30, 60, 120, 300}
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds not in allowed_intervals:
            raise HTTPException(
                status_code=400,
                detail="seconds должен быть одним из значений: 0, 5, 10, 15, 30, 60, 120, 300",
            )
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            member = await require_group_member(db, group_id, uid)
            if member["role"] not in ("owner", "admin"):
                await db.rollback()
                raise HTTPException(status_code=403, detail="Настраивать медленный режим могут только администраторы группы")
            await db.execute(
                "UPDATE chat_groups SET slow_mode_seconds=? WHERE id=?",
                (seconds, group_id),
            )
            await db.commit()
        return {"group_id": group_id, "slow_mode_seconds": seconds}

    @router.post("/api/groups/{group_id}/invites", status_code=201)
    async def create_group_invite(
        group_id: int,
        payload: dict[str, Any],
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        try:
            expires_hours = int(payload.get("expires_in_hours", 168))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="expires_in_hours должен быть целым числом")
        if expires_hours < 1 or expires_hours > 24 * 365:
            raise HTTPException(status_code=400, detail="Срок приглашения должен быть от 1 часа до 1 года")
        require_approval = payload.get("require_approval", False)
        if not isinstance(require_approval, bool):
            raise HTTPException(status_code=400, detail="require_approval должен быть логическим значением")
        raw_max_uses = payload.get("max_uses")
        max_uses = None
        if raw_max_uses is not None:
            if isinstance(raw_max_uses, bool) or not isinstance(raw_max_uses, int):
                raise HTTPException(status_code=400, detail="max_uses должен быть целым числом")
            if raw_max_uses < 1 or raw_max_uses > 10000:
                raise HTTPException(status_code=400, detail="Лимит вступлений должен быть от 1 до 10000")
            max_uses = raw_max_uses
        now = int(time.time())
        expires_at = now + expires_hours * 3600
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            member = await require_group_member(db, group_id, uid)
            if member["role"] not in ("owner", "admin"):
                await db.rollback()
                raise HTTPException(status_code=403, detail="Создавать приглашения могут только администраторы группы")
            await db.execute(
                """INSERT INTO group_invites
                   (token_hash,group_id,created_by,created_at,expires_at,max_uses,uses,require_approval,revoked_at)
                   VALUES(?,?,?,?,?,?,0,?,NULL)""",
                (token_hash, group_id, uid, now, expires_at, max_uses, int(require_approval)),
            )
            cur = await db.execute("SELECT title FROM chat_groups WHERE id=?", (group_id,))
            group = await cur.fetchone()
            await db.commit()
        return {
            "group_id": group_id,
            "title": str(group[0]),
            "invite_link": _external_api_base_url(request) + f"/api/groups/invites/{token}",
            "expires_at": expires_at,
            "max_uses": max_uses,
            "uses": 0,
            "require_approval": require_approval,
        }

    @router.get("/api/groups/invites/{invite_token}")
    async def preview_group_invite(invite_token: str) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", invite_token):
            raise HTTPException(status_code=404, detail="Приглашение не найдено или отозвано")
        token_hash = hashlib.sha256(invite_token.encode("utf-8")).hexdigest()
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT gi.group_id,gi.created_at,gi.expires_at,gi.max_uses,gi.uses,
                          gi.require_approval,g.title,g.username,
                          (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id=g.id) AS member_count
                   FROM group_invites gi JOIN chat_groups g ON g.id=gi.group_id
                   WHERE gi.token_hash=? AND gi.revoked_at IS NULL
                     AND (gi.expires_at IS NULL OR gi.expires_at>?)
                     AND (gi.max_uses IS NULL OR gi.uses<gi.max_uses)""",
                (token_hash, now),
            )
            invite = await cur.fetchone()
        if invite is None:
            raise HTTPException(status_code=404, detail="Приглашение недействительно, истекло или отозвано")
        return {
            "group_id": int(invite["group_id"]),
            "title": str(invite["title"]),
            "username": str(invite["username"] or ""),
            "member_count": int(invite["member_count"]),
            "created_at": int(invite["created_at"]),
            "expires_at": int(invite["expires_at"]) if invite["expires_at"] is not None else None,
            "max_uses": int(invite["max_uses"]) if invite["max_uses"] is not None else None,
            "uses": int(invite["uses"]),
            "require_approval": bool(invite["require_approval"]),
        }

    @router.post("/api/groups/join")
    async def join_group_by_invite(
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        invite_value = str(payload.get("invite_link") or payload.get("invite_token") or "").strip()
        match = re.fullmatch(r"[A-Za-z0-9_-]{20,128}", invite_value)
        if match:
            invite_token = invite_value
        else:
            match = re.search(r"/api/groups/invites/([A-Za-z0-9_-]{20,128})(?:[?#].*)?$", invite_value)
            if not match:
                raise HTTPException(status_code=400, detail="Вставьте полную ссылку WaysGram или код приглашения")
            invite_token = match.group(1)
        token_hash = hashlib.sha256(invite_token.encode("utf-8")).hexdigest()
        uid = int(user["telegram_id"])
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                """SELECT gi.group_id,gi.expires_at,gi.max_uses,gi.uses,g.title,gi.require_approval
                   FROM group_invites gi JOIN chat_groups g ON g.id=gi.group_id
                   WHERE gi.token_hash=? AND gi.revoked_at IS NULL""",
                (token_hash,),
            )
            invite = await cur.fetchone()
            if invite is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Приглашение недействительно или отозвано")
            group_id = int(invite[0])
            cur = await db.execute(
                "SELECT 1 FROM group_members WHERE group_id=? AND telegram_id=?",
                (group_id, uid),
            )
            already_member = await cur.fetchone() is not None
            if invite[1] is not None and int(invite[1]) <= now:
                await db.rollback()
                raise HTTPException(status_code=410, detail="Срок приглашения истёк")
            if not already_member and invite[2] is not None and int(invite[3]) >= int(invite[2]):
                await db.rollback()
                raise HTTPException(status_code=410, detail="Лимит вступлений по приглашению исчерпан")
            joined = False
            join_requested = False
            if not already_member:
                if bool(invite[5]):
                    cur = await db.execute(
                        """INSERT INTO group_join_requests
                           (group_id,telegram_id,invite_token_hash,requested_at,status,reviewed_by,reviewed_at)
                           VALUES(?,?,?,?,'pending',NULL,NULL)
                           ON CONFLICT(group_id,telegram_id) DO UPDATE SET
                               invite_token_hash=excluded.invite_token_hash,
                               requested_at=excluded.requested_at,
                               status='pending',reviewed_by=NULL,reviewed_at=NULL
                           WHERE group_join_requests.status<>'pending'""",
                        (group_id, uid, token_hash, now),
                    )
                    join_requested = cur.rowcount == 1
                    if not join_requested:
                        cur = await db.execute(
                            "SELECT 1 FROM group_join_requests WHERE group_id=? AND telegram_id=? AND status='pending'",
                            (group_id, uid),
                        )
                        join_requested = await cur.fetchone() is not None
                else:
                    cur = await db.execute(
                        """INSERT OR IGNORE INTO group_members(group_id,telegram_id,role,joined_at)
                           VALUES(?,?,'member',?)""",
                        (group_id, uid, now),
                    )
                    joined = cur.rowcount == 1
                    if joined:
                        await db.execute(
                            "UPDATE group_invites SET uses=uses+1 WHERE token_hash=?",
                            (token_hash,),
                        )
            await db.commit()
        return {
            "joined": joined,
            "join_requested": join_requested,
            "already_member": already_member,
            "id": group_id,
            "title": str(invite[4]),
        }

    @router.get("/api/groups/{group_id}/join-requests")
    async def list_group_join_requests(
        group_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            member = await require_group_member(db, group_id, uid)
            if member["role"] not in ("owner", "admin"):
                raise HTTPException(status_code=403, detail="Просматривать заявки могут только администраторы группы")
            cur = await db.execute(
                """SELECT r.telegram_id,r.requested_at,a.username,a.display_name,a.avatar_media_id
                   FROM group_join_requests r
                   JOIN accounts a ON a.telegram_id=r.telegram_id
                   WHERE r.group_id=? AND r.status='pending' AND a.is_banned=0
                   ORDER BY r.requested_at,r.telegram_id LIMIT 200""",
                (group_id,),
            )
            rows = [dict(row) for row in await cur.fetchall()]
        return {"group_id": group_id, "requests": rows, "count": len(rows)}

    @router.post("/api/groups/{group_id}/join-requests/{telegram_id}/approve")
    async def approve_group_join_request(
        group_id: int,
        telegram_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            member = await require_group_member(db, group_id, uid)
            if member["role"] not in ("owner", "admin"):
                await db.rollback()
                raise HTTPException(status_code=403, detail="Одобрять заявки могут только администраторы группы")
            cur = await db.execute(
                """SELECT invite_token_hash FROM group_join_requests
                   WHERE group_id=? AND telegram_id=? AND status='pending'""",
                (group_id, telegram_id),
            )
            request_row = await cur.fetchone()
            if request_row is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Ожидающая заявка не найдена")
            cur = await db.execute(
                "SELECT is_banned FROM accounts WHERE telegram_id=?",
                (telegram_id,),
            )
            account = await cur.fetchone()
            if account is None or account[0]:
                await db.rollback()
                raise HTTPException(status_code=404, detail="Аккаунт пользователя не найден или заблокирован")
            invite_hash = str(request_row["invite_token_hash"])
            cur = await db.execute(
                "SELECT max_uses,uses FROM group_invites WHERE token_hash=? AND group_id=?",
                (invite_hash, group_id),
            )
            invite = await cur.fetchone()
            if invite is None:
                await db.rollback()
                raise HTTPException(status_code=409, detail="Исходное приглашение больше не существует")
            if invite[0] is not None and int(invite[1]) >= int(invite[0]):
                await db.rollback()
                raise HTTPException(status_code=409, detail="Лимит вступлений по приглашению исчерпан")
            cur = await db.execute(
                """INSERT OR IGNORE INTO group_members(group_id,telegram_id,role,joined_at)
                   VALUES(?,?,'member',?)""",
                (group_id, telegram_id, now),
            )
            joined = cur.rowcount == 1
            if joined:
                await db.execute(
                    "UPDATE group_invites SET uses=uses+1 WHERE token_hash=?",
                    (invite_hash,),
                )
            await db.execute(
                """UPDATE group_join_requests SET status='approved',reviewed_by=?,reviewed_at=?
                   WHERE group_id=? AND telegram_id=? AND status='pending'""",
                (uid, now, group_id, telegram_id),
            )
            await db.commit()
        return {"approved": True, "joined": joined, "group_id": group_id, "telegram_id": telegram_id}

    @router.post("/api/groups/{group_id}/join-requests/{telegram_id}/decline")
    async def decline_group_join_request(
        group_id: int,
        telegram_id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            member = await require_group_member(db, group_id, uid)
            if member["role"] not in ("owner", "admin"):
                await db.rollback()
                raise HTTPException(status_code=403, detail="Отклонять заявки могут только администраторы группы")
            cur = await db.execute(
                """UPDATE group_join_requests SET status='declined',reviewed_by=?,reviewed_at=?
                   WHERE group_id=? AND telegram_id=? AND status='pending'""",
                (uid, now, group_id, telegram_id),
            )
            await db.commit()
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Ожидающая заявка не найдена")
        return {"declined": True, "group_id": group_id, "telegram_id": telegram_id}

    @router.delete("/api/groups/{group_id}/invites/{invite_token}")
    async def revoke_group_invite(
        group_id: int,
        invite_token: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", invite_token):
            raise HTTPException(status_code=404, detail="Приглашение не найдено")
        token_hash = hashlib.sha256(invite_token.encode("utf-8")).hexdigest()
        uid = int(user["telegram_id"])
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            member = await require_group_member(db, group_id, uid)
            if member["role"] not in ("owner", "admin"):
                await db.rollback()
                raise HTTPException(status_code=403, detail="Отзывать приглашения могут только администраторы группы")
            cur = await db.execute(
                """UPDATE group_invites SET revoked_at=?
                   WHERE token_hash=? AND group_id=? AND revoked_at IS NULL""",
                (now, token_hash, group_id),
            )
            await db.commit()
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="Активное приглашение не найдено")
        return {"status": "revoked", "group_id": group_id}

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
                        """SELECT id,group_id,sender_telegram_id AS sender_id,body,media_id,media_album_id,media_album_index,media_album_count,edited_at,reply_to_id,created_at,
                                  (SELECT body FROM group_messages AS replied WHERE replied.id=group_messages.reply_to_id) AS reply_to_body,
                                  (SELECT sender_telegram_id FROM group_messages AS replied WHERE replied.id=group_messages.reply_to_id) AS reply_to_sender_id,
                                  (SELECT group_concat(reaction || ':' || reaction_count, ',')
                                     FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                                           WHERE scope='group' AND chat_id=group_messages.group_id
                                             AND message_id=group_messages.id GROUP BY reaction)) AS reaction_summary,
                                  (SELECT mime_type FROM media_assets WHERE id=group_messages.media_id) AS media_type,
                                  (SELECT original_name FROM media_assets WHERE id=group_messages.media_id) AS media_name
                           FROM group_messages WHERE group_id=? AND id>? ORDER BY id ASC LIMIT 100""",
                        (group_id, after_id),
                    )
                else:
                    cur = await db.execute(
                        """SELECT id,group_id,sender_telegram_id AS sender_id,body,media_id,media_album_id,media_album_index,media_album_count,edited_at,reply_to_id,created_at,
                                  (SELECT body FROM group_messages AS replied WHERE replied.id=group_messages.reply_to_id) AS reply_to_body,
                                  (SELECT sender_telegram_id FROM group_messages AS replied WHERE replied.id=group_messages.reply_to_id) AS reply_to_sender_id,
                                  (SELECT group_concat(reaction || ':' || reaction_count, ',')
                                     FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                                           WHERE scope='group' AND chat_id=group_messages.group_id
                                             AND message_id=group_messages.id GROUP BY reaction)) AS reaction_summary,
                                  (SELECT mime_type FROM media_assets WHERE id=group_messages.media_id) AS media_type,
                                  (SELECT original_name FROM media_assets WHERE id=group_messages.media_id) AS media_name
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
        await attach_my_reactions(items, "group", group_id, uid)
        return {"messages": items, "next_after_id": items[-1]["id"] if items else 0}

    @router.get("/api/groups/{group_id}/messages/search")
    async def search_group_messages(
        group_id: int,
        q: str = Query(min_length=1, max_length=128),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        term = q.strip()
        if not term:
            raise HTTPException(status_code=400, detail="Введите текст для поиска")
        async with aiosqlite.connect(db_path()) as db:
            await require_group_member(db, group_id, int(user["telegram_id"]))
            db.row_factory = aiosqlite.Row
            cur = await db.execute(
                """SELECT id,group_id,sender_telegram_id AS sender_id,body,media_id,media_album_id,media_album_index,media_album_count,edited_at,reply_to_id,created_at,
                          (SELECT body FROM group_messages AS replied WHERE replied.id=group_messages.reply_to_id) AS reply_to_body,
                                  (SELECT sender_telegram_id FROM group_messages AS replied WHERE replied.id=group_messages.reply_to_id) AS reply_to_sender_id,
                                  (SELECT group_concat(reaction || ':' || reaction_count, ',')
                                     FROM (SELECT reaction,COUNT(*) AS reaction_count FROM message_reactions
                                           WHERE scope='group' AND chat_id=group_messages.group_id
                                             AND message_id=group_messages.id GROUP BY reaction)) AS reaction_summary,
                                  (SELECT mime_type FROM media_assets WHERE id=group_messages.media_id) AS media_type,
                          (SELECT original_name FROM media_assets WHERE id=group_messages.media_id) AS media_name
                   FROM group_messages
                   WHERE group_id=? AND body LIKE ? COLLATE NOCASE
                   ORDER BY id DESC LIMIT 100""",
                (group_id, f"%{term}%"),
            )
            rows = await cur.fetchall()
        items = [dict(row) for row in rows]
        items.reverse()
        await attach_my_reactions(items, "group", group_id, int(user["telegram_id"]))
        return {"query": term, "messages": items, "count": len(items), "has_more": len(items) == 100}

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
        body = _message_body(body_value) if body_value.strip() or not media_id else ""
        now = int(time.time())
        async with aiosqlite.connect(db_path()) as db:
            await db.execute("BEGIN IMMEDIATE")
            membership = await require_group_member(db, group_id, uid)
            cur = await db.execute(
                "SELECT slow_mode_seconds FROM chat_groups WHERE id=?",
                (group_id,),
            )
            group_settings = await cur.fetchone()
            slow_mode_seconds = int(group_settings[0]) if group_settings else 0
            if slow_mode_seconds > 0 and membership["role"] not in ("owner", "admin"):
                cur = await db.execute(
                    """SELECT created_at FROM group_messages
                       WHERE group_id=? AND sender_telegram_id=?
                       ORDER BY id DESC LIMIT 1""",
                    (group_id, uid),
                )
                previous_message = await cur.fetchone()
                if previous_message is not None:
                    elapsed = max(0, now - int(previous_message[0]))
                    remaining = slow_mode_seconds - elapsed
                    if remaining > 0:
                        await db.rollback()
                        raise HTTPException(
                            status_code=429,
                            detail=f"Медленный режим: подождите ещё {remaining} сек.",
                            headers={"Retry-After": str(remaining)},
                        )
            media_id = await require_owned_media(db, media_id, uid)
            if not body:
                body = _message_body(await default_media_message_body(db, media_id))
            media_fields = await media_message_fields(db, media_id)
            reply_to_id = parse_reply_id(payload)
            if reply_to_id:
                await require_reply_target(
                    db, "SELECT 1 FROM group_messages WHERE id=? AND group_id=?", (reply_to_id, group_id)
                )
            cur = await db.execute(
                "SELECT COUNT(*) FROM group_messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            if int((await cur.fetchone())[0]) >= DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит отправки сообщений")
            cur = await db.execute(
                """INSERT INTO group_messages
                   (group_id,sender_telegram_id,body,media_id,reply_to_id,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (group_id, uid, body, media_id, reply_to_id, now),
            )
            message_id = int(cur.lastrowid)
            await record_event(
                db, "group", message_id, "new_message", uid, chat_id=group_id,
            )
            await db.commit()
        async with aiosqlite.connect(db_path()) as db:
            cur = await db.execute(
                "SELECT telegram_id FROM group_members WHERE group_id=? AND telegram_id<>?",
                (group_id, uid),
            )
            group_recipients = [int(row[0]) for row in await cur.fetchall()]
        await deliver_push_notifications(
            group_recipients,
            str(user.get("display_name") or user.get("username") or "Новое сообщение"),
            body,
            {"scope": "group", "chat_id": str(group_id), "message_id": str(message_id)},
        )
        return {
            "id": message_id,
            "group_id": group_id,
            "sender_id": uid,
            "body": body,
            "media_id": media_id,
            "reply_to_id": reply_to_id,
            **media_fields,
            "created_at": now,
        }

    @router.post("/api/groups/{group_id}/messages/album", status_code=201)
    async def send_group_message_album(
        group_id: int,
        payload: dict[str, Any],
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        user = await current_user(authorization)
        uid = int(user["telegram_id"])
        raw_media_ids = payload.get("media_ids")
        if not isinstance(raw_media_ids, list) or not 2 <= len(raw_media_ids) <= 10:
            raise HTTPException(status_code=400, detail="Альбом должен содержать от 2 до 10 файлов")
        media_ids: list[str] = []
        for raw_id in raw_media_ids:
            media_id = str(raw_id or "").strip()
            if not re.fullmatch(r"[a-f0-9]{32}", media_id):
                raise HTTPException(status_code=400, detail="Некорректный ID вложения в альбоме")
            media_ids.append(media_id)
        if len(set(media_ids)) != len(media_ids):
            raise HTTPException(status_code=400, detail="Альбом не должен содержать повторяющиеся файлы")

        body_value = str(payload.get("body") or "")
        body = _message_body(body_value) if body_value.strip() else "Медиаальбом"
        silent = payload.get("silent", False)
        if not isinstance(silent, bool):
            raise HTTPException(status_code=400, detail="silent должен быть логическим значением")

        now = int(time.time())
        scope = f"/api/groups/{group_id}/messages/album"
        descriptor = idempotency_descriptor(scope, payload, idempotency_key)
        album_id = secrets.token_hex(16)
        created_messages: list[dict[str, Any]] = []

        async with aiosqlite.connect(db_path()) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("BEGIN IMMEDIATE")
            membership = await require_group_member(db, group_id, uid)
            previous = await idempotency_lookup(db, uid, scope, descriptor, now)
            if previous is not None:
                await db.rollback()
                return previous

            cur = await db.execute("SELECT slow_mode_seconds FROM chat_groups WHERE id=?", (group_id,))
            group_settings = await cur.fetchone()
            slow_mode_seconds = int(group_settings[0]) if group_settings else 0
            if slow_mode_seconds > 0 and membership["role"] not in ("owner", "admin"):
                cur = await db.execute(
                    """SELECT created_at FROM group_messages
                       WHERE group_id=? AND sender_telegram_id=?
                       ORDER BY id DESC LIMIT 1""",
                    (group_id, uid),
                )
                previous_message = await cur.fetchone()
                if previous_message is not None:
                    elapsed = max(0, now - int(previous_message[0]))
                    remaining = slow_mode_seconds - elapsed
                    if remaining > 0:
                        await db.rollback()
                        raise HTTPException(
                            status_code=429,
                            detail=f"Медленный режим: подождите ещё {remaining} сек.",
                            headers={"Retry-After": str(remaining)},
                        )

            checked_media: list[tuple[str, dict[str, str | None]]] = []
            for media_id in media_ids:
                owned_id = await require_owned_media(db, media_id, uid)
                fields = await media_message_fields(db, owned_id)
                media_type = str(fields.get("media_type") or "").lower()
                if not (media_type.startswith("image/") or media_type.startswith("video/")):
                    await db.rollback()
                    raise HTTPException(
                        status_code=415,
                        detail="В медиаальбом можно добавлять только фотографии и видео",
                    )
                checked_media.append((media_id, fields))

            reply_to_id = parse_reply_id(payload)
            if reply_to_id:
                await require_reply_target(
                    db,
                    "SELECT 1 FROM group_messages WHERE id=? AND group_id=?",
                    (reply_to_id, group_id),
                )

            cur = await db.execute(
                "SELECT COUNT(*) FROM group_messages WHERE sender_telegram_id=? AND created_at>?",
                (uid, now - 60),
            )
            sent_recently = int((await cur.fetchone())[0])
            if sent_recently + len(checked_media) > DM_MESSAGES_PER_MINUTE:
                await db.rollback()
                raise HTTPException(status_code=429, detail="Превышен лимит отправки сообщений для медиаальбома")

            for index, (media_id, media_fields) in enumerate(checked_media):
                item_body = body if index == 0 else ""
                cur = await db.execute(
                    """INSERT INTO group_messages
                       (group_id,sender_telegram_id,body,media_id,reply_to_id,
                        media_album_id,media_album_index,media_album_count,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        group_id, uid, item_body, media_id, reply_to_id,
                        album_id, index, len(checked_media), now,
                    ),
                )
                message_id = int(cur.lastrowid)
                await record_event(db, "group", message_id, "new_message", uid, chat_id=group_id)
                created_messages.append({
                    "id": message_id,
                    "group_id": group_id,
                    "sender_id": uid,
                    "body": item_body,
                    "media_id": media_id,
                    "reply_to_id": reply_to_id,
                    "media_album_id": album_id,
                    "media_album_index": index,
                    "media_album_count": len(checked_media),
                    **media_fields,
                    "created_at": now,
                })

            result = {
                "status": "sent",
                "album_id": album_id,
                "group_id": group_id,
                "count": len(created_messages),
                "first_message_id": created_messages[0]["id"],
                "last_message_id": created_messages[-1]["id"],
                "messages": created_messages,
            }
            await idempotency_store(db, uid, scope, descriptor, result, now)
            await db.commit()

        if not silent:
            async with aiosqlite.connect(db_path()) as db:
                cur = await db.execute(
                    "SELECT telegram_id FROM group_members WHERE group_id=? AND telegram_id<>?",
                    (group_id, uid),
                )
                recipients = [int(row[0]) for row in await cur.fetchall()]
            await deliver_push_notifications(
                recipients,
                str(user.get("display_name") or user.get("username") or "Новое сообщение"),
                f"Медиаальбом · {len(created_messages)} вложений",
                {
                    "scope": "group",
                    "chat_id": str(group_id),
                    "message_id": str(created_messages[-1]["id"]),
                    "media_album_id": album_id,
                },
            )
        return result

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