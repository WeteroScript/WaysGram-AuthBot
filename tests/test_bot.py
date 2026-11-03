from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

import bot as bot_module
from messenger_api import init_messenger_storage


class FakeBot:
    def __init__(self) -> None:
        self.messages: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str) -> None:
        self.messages.append((chat_id, text))


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bot_module.Store:
    instance = bot_module.Store(tmp_path / "waysgram.sqlite3")
    monkeypatch.setattr(bot_module, "DATABASE_PATH", instance.path)
    instance.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    asyncio.run(instance.init())
    asyncio.run(bot_module.init_admin_storage())
    monkeypatch.setattr(bot_module, "store", instance)
    return instance


def run(coro):
    return asyncio.run(coro)


def test_virtual_number_is_unique_and_persistent(store: bot_module.Store) -> None:
    run(store.upsert_user(101, 101))
    run(store.upsert_user(202, 202))
    run(store.set_verified(101, True))
    run(store.set_verified(202, True))

    first = run(store.allocate_number(101))
    second = run(store.allocate_number(202))

    assert len(first) == 12
    assert first.startswith("+1")
    assert first[1:].isdigit()
    assert first != second
    assert run(store.allocate_number(101)) == first
    assert run(store.resolve_number(first))["telegram_id"] == 101


def test_otp_is_encrypted_and_consumed_once(store: bot_module.Store, tmp_path: Path) -> None:
    run(store.upsert_user(303, 303))
    run(store.set_verified(303, True))
    number = run(store.allocate_number(303))

    assert run(store.save_code(number, "482601", 300)) is True

    with sqlite3.connect(store.path) as conn:
        stored_code, encrypted = conn.execute(
            "SELECT code, encrypted FROM auth_codes WHERE number=?", (number,)
        ).fetchone()

    assert encrypted == 1
    assert stored_code != "482601"
    assert run(store.latest_code(number))[0] == "482601"
    assert run(store.verify_code(number, "482601")) is True
    assert run(store.verify_code(number, "482601")) is False


def test_otp_request_cooldown_and_attempt_limit(store: bot_module.Store) -> None:
    run(store.upsert_user(404, 404))
    run(store.set_verified(404, True))
    number = run(store.allocate_number(404))

    assert run(store.save_code(number, "100001", 300)) is True
    assert run(store.save_code(number, "100002", 300)) is False

    # Exercise the five-attempt limit without waiting for the cooldown.
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE numbers SET last_code_requested_at=? WHERE number=?",
            (int(time.time()) - 31, number),
        )
    assert run(store.save_code(number, "100002", 300)) is True
    for _ in range(5):
        assert run(store.verify_code(number, "999999")) is False
    assert run(store.verify_code(number, "100002")) is False


def test_internal_api_requires_secret_and_delivers_otp(store: bot_module.Store, monkeypatch) -> None:
    run(store.upsert_user(505, 505))
    number = run(store.allocate_number(505))
    fake_bot = FakeBot()
    monkeypatch.setattr(bot_module, "bot", fake_bot)
    monkeypatch.setattr(bot_module, "INTERNAL_API_TOKEN", "test-internal-secret")

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=bot_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            denied = await client.post(
                "/internal/v1/auth-code/request", json={"number": number}
            )
            assert denied.status_code == 401

            unverified = await client.post(
                "/internal/v1/auth-code/request",
                json={"number": number},
                headers={"X-Internal-Token": "test-internal-secret"},
            )
            assert unverified.status_code == 403

            await client.post(
                "/internal/v1/number/resolve",
                json={"number": number},
                headers={"X-Internal-Token": "test-internal-secret"},
            )

            await store.set_verified(505, True)
            requested = await client.post(
                "/internal/v1/auth-code/request",
                json={"number": number},
                headers={"X-Internal-Token": "test-internal-secret"},
            )
            assert requested.status_code == 200
            assert requested.json() == {"status": "delivered"}
            assert len(fake_bot.messages) == 1
            assert "Get code" in fake_bot.messages[0][1]

            code, _remaining = await store.latest_code(number)
            assert code not in requested.text

            verified = await client.post(
                "/internal/v1/auth-code/verify",
                json={"number": number, "code": code},
                headers={"X-Internal-Token": "test-internal-secret"},
            )
            assert verified.status_code == 200
            assert verified.json() == {"valid": True}

            replay = await client.post(
                "/internal/v1/auth-code/verify",
                json={"number": number, "code": code},
                headers={"X-Internal-Token": "test-internal-secret"},
            )
            assert replay.json() == {"valid": False}

    run(scenario())


def test_legacy_plaintext_codes_are_encrypted_during_migration(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    now = int(time.time())
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE users (
                telegram_id INTEGER PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                language TEXT,
                verified INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE numbers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL UNIQUE,
                number TEXT NOT NULL UNIQUE,
                provider_ref TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_code_requested_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE auth_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                number TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT INTO users VALUES(606, 606, 'en', 1, ?)", (now,)
        )
        conn.execute(
            "INSERT INTO numbers(telegram_id, number, provider_ref, created_at) VALUES(606, '+11234567890', 'internal', ?)",
            (now,),
        )
        conn.execute(
            "INSERT INTO auth_codes(number, code, expires_at, attempts, created_at) VALUES('+11234567890', '761204', ?, 0, ?)",
            (now + 300, now),
        )

    instance = bot_module.Store(path)
    instance.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(instance.init())

    with sqlite3.connect(path) as conn:
        stored_code, encrypted = conn.execute(
            "SELECT code, encrypted FROM auth_codes"
        ).fetchone()

    assert encrypted == 1
    assert stored_code != "761204"
    assert run(instance.latest_code("+11234567890"))[0] == "761204"


def test_settings_keyboard_contains_arrow_back_button() -> None:
    keyboard = bot_module.language_keyboard(include_back=True)
    arrow_buttons = [
        button
        for row in keyboard.inline_keyboard
        for button in row
        if button.text == "->"
    ]
    assert len(arrow_buttons) == 1
    assert arrow_buttons[0].callback_data == "nav:menu"


def test_admin_account_storage_and_suspension(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "admin.sqlite3"
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    instance = bot_module.Store(path)
    instance.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(instance.init())
    run(instance.upsert_user(707, 707))
    run(instance.set_verified(707, True))
    number = run(instance.allocate_number(707))
    run(bot_module.init_admin_storage())
    assert run(bot_module.account_is_banned(707)) is False
    with sqlite3.connect(path) as conn:
        saved = conn.execute("SELECT virtual_number FROM accounts WHERE telegram_id=707").fetchone()
    assert saved == (number,)

    with sqlite3.connect(bot_module.DATABASE_PATH) as conn:
        conn.execute("UPDATE accounts SET is_banned=1 WHERE telegram_id=707")

    assert run(bot_module.account_is_banned(707)) is True


class FakeAdminMessage:
    def __init__(self, text: str = "") -> None:
        self.from_user = SimpleNamespace(id=bot_module.ADMIN_ID)
        self.text = text
        self.responses: list[tuple[str, object]] = []

    async def answer(self, text: str, reply_markup=None) -> None:
        self.responses.append((text, reply_markup))


class FakeAdminCallback:
    def __init__(self, data: str) -> None:
        self.from_user = SimpleNamespace(id=bot_module.ADMIN_ID)
        self.data = data
        self.message = FakeAdminMessage()
        self.answered = False

    async def answer(self, *args, **kwargs) -> None:
        self.answered = True


def test_admin_can_edit_gift_catalog_and_moderate_channels(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "admin_actions.sqlite3"
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    instance = bot_module.Store(path)
    instance.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(instance.init())
    run(bot_module.init_admin_storage())
    run(init_messenger_storage(path))
    run(instance.upsert_user(bot_module.ADMIN_ID, bot_module.ADMIN_ID))
    run(instance.set_verified(bot_module.ADMIN_ID, True))
    number = run(instance.allocate_number(bot_module.ADMIN_ID))
    run(bot_module.ensure_account(bot_module.ADMIN_ID, number, "admin", "Admin"))
    run(instance.upsert_user(90099, 90099))
    run(instance.set_verified(90099, True))
    moderator_number = run(instance.allocate_number(90099))
    run(bot_module.ensure_account(90099, moderator_number, "moderator", "Moderator"))

    now = int(time.time())
    with sqlite3.connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO gift_catalog(name,price_grams,supply,created_at) VALUES('Test Gift',5,2,?)",
            (now,),
        )
        gift_id = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO channels(username,title,owner_telegram_id,created_at) VALUES('moderated','Moderated',?,?)",
            (bot_module.ADMIN_ID, now),
        )
        channel_id = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO channel_admins(channel_id,telegram_id,created_at) VALUES(?,?,?)",
            (channel_id, 90099, now),
        )
        conn.execute(
            "INSERT INTO channel_messages(channel_id,author_telegram_id,body,created_at) VALUES(?,?,?,?)",
            (channel_id, bot_module.ADMIN_ID, "old post", now),
        )

    bot_module.ADMIN_INPUT[bot_module.ADMIN_ID] = ("edit_gift_supply", gift_id)
    edit_message = FakeAdminMessage("9")
    run(bot_module.admin_text_input(edit_message))
    assert edit_message.responses
    with sqlite3.connect(path) as conn:
        supply = conn.execute("SELECT supply FROM gift_catalog WHERE id=?", (gift_id,)).fetchone()[0]
    assert supply == 9

    grant_callback = FakeAdminCallback(f"wgadm:grantgift:{bot_module.ADMIN_ID}:{gift_id}")
    run(bot_module.admin_callback(grant_callback))
    assert grant_callback.answered
    with sqlite3.connect(path) as conn:
        serial = conn.execute(
            "SELECT serial_number FROM user_gifts WHERE owner_telegram_id=?",
            (bot_module.ADMIN_ID,),
        ).fetchone()[0]
    assert len(serial) == 15
    assert serial.startswith("WG-")

    remove_admin_callback = FakeAdminCallback(f"wgadm:channeladminremove:{channel_id}:90099")
    run(bot_module.admin_callback(remove_admin_callback))
    assert remove_admin_callback.answered
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT 1 FROM channel_admins WHERE channel_id=? AND telegram_id=90099",
            (channel_id,),
        ).fetchone() is None

    callback = FakeAdminCallback(f"wgadm:channeldelete:{channel_id}")
    run(bot_module.admin_callback(callback))
    assert callback.answered
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT 1 FROM channels WHERE id=?", (channel_id,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM channel_messages WHERE channel_id=?", (channel_id,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM channel_admins WHERE channel_id=?", (channel_id,)).fetchone() is None
        log = conn.execute(
            "SELECT action FROM admin_logs WHERE target=? ORDER BY id DESC LIMIT 1",
            (str(channel_id),),
        ).fetchone()
    assert log == ("channel_delete",)

def test_new_account_receives_one_time_welcome_balances(
    store: bot_module.Store,
) -> None:
    user_id = 880001
    number = "+15550000001"

    run(bot_module.ensure_account(user_id, number, "starter", "Starter User"))

    with sqlite3.connect(store.path) as conn:
        stars, grams = conn.execute(
            "SELECT stars, grams FROM accounts WHERE telegram_id=?", (user_id,)
        ).fetchone()
        grants = conn.execute(
            "SELECT asset, amount, reason FROM economy_transactions "
            "WHERE telegram_id=? AND reason='welcome_bonus' ORDER BY asset",
            (user_id,),
        ).fetchall()

    assert (stars, grams) == (5000, 15)
    assert grants == [
        ("grams", 15, "welcome_bonus"),
        ("stars", 5000, "welcome_bonus"),
    ]

    # A repeated number/account sync must not issue the welcome balance twice.
    with sqlite3.connect(store.path) as conn:
        conn.execute(
            "UPDATE accounts SET stars=4900, grams=14 WHERE telegram_id=?",
            (user_id,),
        )
    run(bot_module.ensure_account(user_id, number, "starter", "Starter User"))

    with sqlite3.connect(store.path) as conn:
        stars, grams = conn.execute(
            "SELECT stars, grams FROM accounts WHERE telegram_id=?", (user_id,)
        ).fetchone()
        grant_count = conn.execute(
            "SELECT COUNT(*) FROM economy_transactions "
            "WHERE telegram_id=? AND reason='welcome_bonus'",
            (user_id,),
        ).fetchone()[0]

    assert (stars, grams) == (4900, 14)
    assert grant_count == 2



def _signed_telesrv_otp(number: str, delivery_id: str, code: str, secret: str):
    expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {
        "version": "1",
        "delivery_id": delivery_id,
        "purpose": "login_sms",
        "channel": "sms",
        "recipient": number[1:],
        "code": code,
        "expires_at": expiry.isoformat().replace("+00:00", "Z"),
        "expires_in": 300,
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + raw,
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": delivery_id,
        "X-Telesrv-Timestamp": timestamp,
        "X-Telesrv-Signature": signature,
    }
    return raw, headers


def test_telesrv_webhook_delivers_server_generated_code_idempotently(
    store: bot_module.Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = 950001
    run(store.upsert_user(user_id, user_id))
    run(store.set_verified(user_id, True))
    number = run(store.allocate_number(user_id))
    secret = "test-telesrv-webhook-secret"
    monkeypatch.setattr(bot_module, "TELESRV_OTP_WEBHOOK_SECRET", secret)

    class MessageBot(FakeBot):
        async def send_message(self, chat_id: int, text: str):
            await super().send_message(chat_id, text)
            return SimpleNamespace(message_id=len(self.messages))

    fake_bot = MessageBot()
    monkeypatch.setattr(bot_module, "bot", fake_bot)
    raw, headers = _signed_telesrv_otp(number, "delivery_950001", "482913", secret)

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=bot_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            delivered = await client.post(
                "/internal/v1/telesrv/otp",
                content=raw,
                headers=headers,
            )
            assert delivered.status_code == 200
            assert delivered.json() == {"accepted": True, "message_id": "1"}
            assert len(fake_bot.messages) == 1
            assert "482913" not in delivered.text
            assert "482913" not in fake_bot.messages[0][1]

            saved_code, seconds_left = await store.latest_code(number)
            assert saved_code == "482913"
            assert seconds_left > 0

            replay = await client.post(
                "/internal/v1/telesrv/otp",
                content=raw,
                headers=headers,
            )
            assert replay.status_code == 200
            assert replay.json() == delivered.json()
            assert len(fake_bot.messages) == 1

            changed_raw, changed_headers = _signed_telesrv_otp(
                number, "delivery_950001", "112233", secret
            )
            conflict = await client.post(
                "/internal/v1/telesrv/otp",
                content=changed_raw,
                headers=changed_headers,
            )
            assert conflict.status_code == 409
            assert conflict.json()["error_code"] == "IDEMPOTENCY_CONFLICT"
            assert (await store.latest_code(number))[0] == "482913"

    run(scenario())


def test_telesrv_webhook_rejects_invalid_signature_and_unverified_number(
    store: bot_module.Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = 950002
    run(store.upsert_user(user_id, user_id))
    number = run(store.allocate_number(user_id))
    secret = "another-test-secret"
    monkeypatch.setattr(bot_module, "TELESRV_OTP_WEBHOOK_SECRET", secret)
    fake_bot = FakeBot()
    monkeypatch.setattr(bot_module, "bot", fake_bot)
    raw, headers = _signed_telesrv_otp(number, "delivery_950002", "123456", secret)

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=bot_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            invalid = dict(headers)
            invalid["X-Telesrv-Signature"] = "sha256=" + ("0" * 64)
            denied = await client.post(
                "/internal/v1/telesrv/otp", content=raw, headers=invalid
            )
            assert denied.status_code == 401

            unverified = await client.post(
                "/internal/v1/telesrv/otp", content=raw, headers=headers
            )
            assert unverified.status_code == 403
            assert fake_bot.messages == []
            assert await store.latest_code(number) is None

    run(scenario())
