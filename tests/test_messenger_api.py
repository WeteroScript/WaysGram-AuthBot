from __future__ import annotations

import asyncio
from io import BytesIO
import hashlib
import sqlite3
import db_split
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from PIL import Image

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bot as bot_module
import messenger_api
from messenger_api import build_messenger_router, init_messenger_storage
from telegram_mtproto import TelegramMTProtoGiftCatalog


class FakeBot:
    def __init__(self) -> None:
        self.token = "test-telegram-bot-token"
        self.messages: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str) -> None:
        self.messages.append((chat_id, text))


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def api_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    auth_store = bot_module.Store(path)
    auth_store.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(auth_store.init())
    run(bot_module.init_admin_storage())
    run(init_messenger_storage(path))
    fake_bot = FakeBot()
    app = FastAPI()
    app.include_router(
        build_messenger_router(
            path,
            auth_store,
            lambda: fake_bot,
            bot_module.account_is_banned,
        )
    )
    return path, auth_store, fake_bot, app


def add_account(api_env, telegram_id: int, username: str = "") -> str:
    path, auth_store, _fake_bot, _app = api_env
    run(auth_store.upsert_user(telegram_id, telegram_id))
    run(auth_store.set_verified(telegram_id, True))
    number = run(auth_store.allocate_number(telegram_id))
    run(bot_module.ensure_account(telegram_id, number, username, f"User {telegram_id}"))
    return number


def add_session(path: Path, telegram_id: int, token: str) -> None:
    now = int(time.time())
    with db_split.sqlite_connect(path) as db:
        db.execute(
            "INSERT INTO api_sessions(token_hash,telegram_id,expires_at,created_at) VALUES(?,?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), telegram_id, now + 3600, now),
        )


async def client_for(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_authbot_code_login_creates_hashed_api_session(api_env) -> None:
    path, auth_store, fake_bot, app = api_env
    number = add_account(api_env, 81001, "alpha")
    add_account(api_env, 81002, "occupied")
    assert run(bot_module.health())["status"] == "online"

    async def scenario() -> None:
        async with await client_for(app) as client:
            denied = await client.get("/api/me")
            assert denied.status_code == 401

            requested = await client.post("/api/auth/request-code", json={"phone": number})
            assert requested.status_code == 200
            assert requested.json()["delivery"] == "AuthWaysGram_bot"
            assert len(fake_bot.messages) == 1
            assert fake_bot.messages[0][0] == 81001

            code, _remaining = await auth_store.latest_code(number)
            verified = await client.post(
                "/api/auth/verify-code",
                json={"phone": number, "code": code},
            )
            assert verified.status_code == 200
            payload = verified.json()
            token = payload["token"]
            assert payload["user"]["id"] == 81001
            assert payload["user"]["phone"] == number

            profile = await client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
            assert profile.status_code == 200
            assert profile.json()["username"] == "alpha"

            rename = await client.patch(
                "/api/me",
                headers={"Authorization": f"Bearer {token}"},
                json={"display_name": "Alpha Updated"},
            )
            assert rename.status_code == 200
            assert rename.json()["display_name"] == "Alpha Updated"

            updated_profile = await client.put(
                "/api/me",
                headers={"Authorization": f"Bearer {token}"},
                json={"display_name": "Alpha via PUT", "bio": "WaysGram profile"},
            )
            assert updated_profile.status_code == 200
            assert updated_profile.json()["display_name"] == "Alpha via PUT"
            assert updated_profile.json()["bio"] == "WaysGram profile"

            duplicate = await client.patch(
                "/api/me",
                headers={"Authorization": f"Bearer {token}"},
                json={"username": "occupied"},
            )
            assert duplicate.status_code == 409

            refreshed = await client.post(
                "/api/auth/refresh",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert refreshed.status_code == 200

            with db_split.sqlite_connect(path) as db:
                saved_hash = db.execute("SELECT token_hash FROM api_sessions").fetchone()[0]
            assert saved_hash == hashlib.sha256(token.encode()).hexdigest()
            assert saved_hash != token

            logged_out = await client.post(
                "/api/auth/logout",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert logged_out.status_code == 200
            expired = await client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
            assert expired.status_code == 401

    run(scenario())


def test_new_account_gets_system_welcome_and_balance_notifications(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    run(bot_module.ensure_system_account())
    user_id = 81234
    number = add_account(api_env, user_id, "newbie")
    add_session(path, user_id, "system-welcome-session")

    with db_split.sqlite_connect(path) as db:
        system_account = db.execute(
            "SELECT virtual_number,username,display_name FROM accounts WHERE telegram_id=?",
            (bot_module.SYSTEM_ACCOUNT_ID,),
        ).fetchone()
        welcome = db.execute(
            """SELECT sender_telegram_id,recipient_telegram_id,body FROM messages
               WHERE sender_telegram_id=? AND recipient_telegram_id=?""",
            (bot_module.SYSTEM_ACCOUNT_ID, user_id),
        ).fetchall()

    assert system_account == ("+4277", "waysgram", "WaysGram")
    assert len(welcome) == 1
    assert welcome[0][0:2] == (bot_module.SYSTEM_ACCOUNT_ID, user_id)
    assert welcome[0][2].startswith("Привет 👋")
    assert "Добро пожаловать в WaysGram!" in welcome[0][2]
    assert "—" not in welcome[0][2]

    class FakeAdminMessage:
        def __init__(self, text: str):
            self.text = text
            self.from_user = SimpleNamespace(id=bot_module.ADMIN_ID)

        async def answer(self, *_args, **_kwargs):
            return None

    async def apply_credit(asset: str, amount: int) -> None:
        bot_module.ADMIN_INPUT[bot_module.ADMIN_ID] = ("credit", (asset, user_id))
        await bot_module.admin_text_input(FakeAdminMessage(str(amount)))

    try:
        run(apply_credit("stars", 125))
        run(apply_credit("grams", 7))
    finally:
        bot_module.ADMIN_INPUT.pop(bot_module.ADMIN_ID, None)

    with db_split.sqlite_connect(path) as db:
        notices = db.execute(
            """SELECT body FROM messages WHERE sender_telegram_id=? AND recipient_telegram_id=?
               ORDER BY id ASC""",
            (bot_module.SYSTEM_ACCOUNT_ID, user_id),
        ).fetchall()
        balances = db.execute(
            "SELECT stars,grams FROM accounts WHERE telegram_id=?",
            (user_id,),
        ).fetchone()

    assert len(notices) == 3
    assert "Начислено: +125 Stars" in notices[1][0]
    assert "Текущий баланс: 5125 Stars" in notices[1][0]
    assert "Начислено: +7 Gram" in notices[2][0]
    assert "Текущий баланс: 22 Gram" in notices[2][0]
    assert balances == (5125, 22)

    async def scenario() -> None:
        async with await client_for(app) as client:
            response = await client.get(
                "/api/conversations",
                headers={"Authorization": "Bearer system-welcome-session"},
            )
            assert response.status_code == 200
            conversations = response.json()["conversations"]
            system_chat = next(item for item in conversations if item["id"] == bot_module.SYSTEM_ACCOUNT_ID)
            assert system_chat["display_name"] == "WaysGram"
            assert system_chat["last_message"].startswith("Баланс пополнен!")

    run(scenario())

    run(bot_module.ensure_account(user_id, number, "newbie", "User 81234"))
    with db_split.sqlite_connect(path) as db:
        count = db.execute(
            "SELECT COUNT(*) FROM messages WHERE sender_telegram_id=? AND recipient_telegram_id=?",
            (bot_module.SYSTEM_ACCOUNT_ID, user_id),
        ).fetchone()[0]
    assert count == 3


def test_direct_message_long_poll_returns_new_message(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89201, "longpoll_sender")
    add_account(api_env, 89202, "longpoll_recipient")
    add_account(api_env, 89203, "longpoll_outsider")
    add_session(path, 89201, "longpoll-sender-session")
    add_session(path, 89202, "longpoll-recipient-session")
    add_session(path, 89203, "longpoll-outsider-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer longpoll-sender-session"}
            recipient = {"Authorization": "Bearer longpoll-recipient-session"}
            outsider = {"Authorization": "Bearer longpoll-outsider-session"}

            initial = await client.post(
                "/api/messages",
                headers=sender,
                json={"recipient_id": 89202, "body": "initial"},
            )
            assert initial.status_code == 201
            initial_id = initial.json()["id"]

            sender_conversations = await client.get("/api/conversations", headers=sender)
            assert sender_conversations.status_code == 200
            assert sender_conversations.json()["conversations"][0]["unread_count"] == 0
            assert (await client.get("/api/events?after_id=0", headers=sender)).json()["events"] == []
            assert (await client.get("/api/events?after_id=0", headers=outsider)).json()["events"] == []

            initial_conversations = await client.get("/api/conversations", headers=recipient)
            assert initial_conversations.status_code == 200
            assert initial_conversations.json()["conversations"][0]["unread_count"] == 1

            event_cursor_response = await client.get("/api/events", headers=recipient)
            assert event_cursor_response.status_code == 200
            event_cursor = event_cursor_response.json()["latest_id"]
            pending_events = asyncio.create_task(
                client.get(
                    f"/api/events?after_id={event_cursor}&wait_seconds=20",
                    headers=recipient,
                )
            )
            pending = asyncio.create_task(
                client.get(
                    f"/api/messages?with=89201&after_id={initial_id}&wait_seconds=5",
                    headers=recipient,
                )
            )
            await asyncio.sleep(0.2)
            next_message = await client.post(
                "/api/messages",
                headers=sender,
                json={"recipient_id": 89202, "body": "arrived during long poll"},
            )
            assert next_message.status_code == 201

            response = await asyncio.wait_for(pending, timeout=3)
            assert response.status_code == 200
            messages = response.json()["messages"]
            assert len(messages) == 1
            assert messages[0]["id"] == next_message.json()["id"]
            assert messages[0]["body"] == "arrived during long poll"

            event_response = await asyncio.wait_for(pending_events, timeout=3)
            assert event_response.status_code == 200
            assert any(
                event["kind"] == "new_message"
                and event["scope"] == "dm"
                and event["message_id"] == next_message.json()["id"]
                for event in event_response.json()["events"]
            )
            refreshed_conversations = await client.get("/api/conversations", headers=recipient)
            assert refreshed_conversations.json()["conversations"][0]["unread_count"] == 2
            assert (await client.get(
                f"/api/events?after_id={event_cursor}", headers=sender
            )).json()["events"] == []
            assert (await client.get(
                f"/api/events?after_id={event_cursor}", headers=outsider
            )).json()["events"] == []

            invalid_wait = await client.get(
                f"/api/messages?with=89201&after_id={next_message.json()['id']}&wait_seconds=21",
                headers=recipient,
            )
            assert invalid_wait.status_code == 422

    run(scenario())



 
 
 



def test_mentions_and_hashtag_search_support_chat_links(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89401, "link_sender")
    add_account(api_env, 89402, "find_me")
    add_session(path, 89401, "chat-links-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            headers = {"Authorization": "Bearer chat-links-session"}
            mention = await client.get("/api/users?q=%40find_me", headers=headers)
            assert mention.status_code == 200
            assert any(user["username"] == "find_me" for user in mention.json()["users"])

            sent = await client.post(
                "/api/messages",
                headers=headers,
                json={"recipient_id": 89402, "body": "Hello @find_me #featurecheck"},
            )
            assert sent.status_code == 201

            hashtag = await client.get(
                "/api/messages/search?with=89402&q=%23featurecheck",
                headers=headers,
            )
            assert hashtag.status_code == 200
            assert hashtag.json()["count"] == 1
            assert hashtag.json()["messages"][0]["id"] == sent.json()["id"]

    run(scenario())


def test_message_waits_until_recipient_becomes_online(api_env) -> None:
    _path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89501, "online_sender")
    add_account(api_env, 89502, "online_recipient")
    add_session(_path, 89501, "online-sender-session")
    add_session(_path, 89502, "online-recipient-session")

    async def scenario() -> None:
        for startup_handler in app.router.on_startup:
            await startup_handler()
        try:
            async with await client_for(app) as client:
                sender = {"Authorization": "Bearer online-sender-session"}
                recipient = {"Authorization": "Bearer online-recipient-session"}
                headers = {**sender, "Idempotency-Key": "wait-online-message-key-01"}

                queued = await client.post(
                    "/api/messages/when-online",
                    headers=headers,
                    json={"recipient_id": 89502, "body": "send when I appear online"},
                )
                assert queued.status_code == 201
                assert queued.json()["status"] == "pending"
                assert queued.json()["trigger"] == "when_online"

                with db_split.sqlite_connect(_path) as db:
                    before_online_count = db.execute(
                        """SELECT COUNT(*) FROM messages
                           WHERE sender_telegram_id=? AND recipient_telegram_id=?""",
                        (89501, 89502),
                    ).fetchone()[0]
                assert before_online_count == 0

                # This authenticated request is the recipient's first online activity.
                profile = await client.get("/api/me", headers=recipient)
                assert profile.status_code == 200

                history = None
                for _ in range(12):
                    await asyncio.sleep(0.25)
                    response = await client.get("/api/messages?with=89501", headers=recipient)
                    assert response.status_code == 200
                    messages = response.json()["messages"]
                    if messages:
                        history = messages
                        break
                assert history is not None and len(history) == 1
                assert history[0]["body"] == "send when I appear online"
                assert history[0]["sender_id"] == 89501

                repeated = await client.post(
                    "/api/messages/when-online",
                    headers=headers,
                    json={"recipient_id": 89502, "body": "send when I appear online"},
                )
                assert repeated.status_code == 201
                assert repeated.json()["id"] == queued.json()["id"]

                pending = await client.post(
                    "/api/messages/when-online",
                    headers={**sender, "Idempotency-Key": "cancel-online-message-key"},
                    json={"recipient_id": 89502, "body": "cancel this online message"},
                )
                assert pending.status_code == 201
                cancelled = await client.delete(
                    f"/api/messages/when-online/{pending.json()['id']}",
                    headers=sender,
                )
                assert cancelled.status_code == 200
                assert cancelled.json()["status"] == "cancelled"
        finally:
            for shutdown_handler in reversed(app.router.on_shutdown):
                await shutdown_handler()

    run(scenario())


def test_recurring_scheduled_messages_keep_local_time_across_dst() -> None:
    zone_name = "Europe/Amsterdam"
    zone = ZoneInfo(zone_name)

    before_spring_dst = datetime(2026, 3, 28, 9, 15, tzinfo=zone)
    next_day = messenger_api._next_recurring_scheduled_timestamp(
        int(before_spring_dst.timestamp()),
        int(before_spring_dst.timestamp()) + 60,
        86400,
        zone_name,
    )
    spring_local = datetime.fromtimestamp(next_day, zone)
    assert (spring_local.month, spring_local.day, spring_local.hour, spring_local.minute) == (
        3, 29, 9, 15
    )
    assert spring_local.utcoffset() != before_spring_dst.utcoffset()

    before_autumn_dst = datetime(2026, 10, 24, 9, 15, tzinfo=zone)
    next_week = messenger_api._next_recurring_scheduled_timestamp(
        int(before_autumn_dst.timestamp()),
        int(before_autumn_dst.timestamp()) + 60,
        604800,
        zone_name,
    )
    autumn_local = datetime.fromtimestamp(next_week, zone)
    assert (autumn_local.month, autumn_local.day, autumn_local.hour, autumn_local.minute) == (
        10, 31, 9, 15
    )
    assert autumn_local.utcoffset() != before_autumn_dst.utcoffset()


def test_scheduled_messages_store_and_validate_iana_time_zone(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89301, "timezone_sender")
    add_account(api_env, 89302, "timezone_recipient")
    add_session(path, 89301, "timezone-sender-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            headers = {"Authorization": "Bearer timezone-sender-session"}
            scheduled = await client.post(
                "/api/messages/schedule",
                headers=headers,
                json={
                    "recipient_id": 89302,
                    "body": "timezone reminder",
                    "scheduled_at": int(time.time()) + 60,
                    "repeat_interval_seconds": 86400,
                    "time_zone": "Europe/Amsterdam",
                },
            )
            assert scheduled.status_code == 201
            assert scheduled.json()["time_zone"] == "Europe/Amsterdam"

            listing = await client.get(
                "/api/messages/scheduled?with=89302",
                headers=headers,
            )
            assert listing.status_code == 200
            assert listing.json()["scheduled_messages"][0]["time_zone"] == "Europe/Amsterdam"

            invalid = await client.post(
                "/api/messages/schedule",
                headers=headers,
                json={
                    "recipient_id": 89302,
                    "body": "invalid timezone",
                    "scheduled_at": int(time.time()) + 60,
                    "repeat_interval_seconds": 0,
                    "time_zone": "Mars/Olympus_Mons",
                },
            )
            assert invalid.status_code == 400

            old_client = await client.post(
                "/api/messages/schedule",
                headers=headers,
                json={
                    "recipient_id": 89302,
                    "body": "legacy client timezone",
                    "scheduled_at": int(time.time()) + 60,
                    "repeat_interval_seconds": 0,
                },
            )
            assert old_client.status_code == 201
            assert old_client.json()["time_zone"] == "UTC"

    run(scenario())


def test_scheduled_direct_messages_send_once_and_can_be_cancelled(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89201, "schedule_sender")
    add_account(api_env, 89202, "schedule_recipient")
    add_session(path, 89201, "schedule-sender-session")
    add_session(path, 89202, "schedule-recipient-session")

    async def scenario() -> None:
        await app.router._startup()
        try:
            async with await client_for(app) as client:
                sender = {"Authorization": "Bearer schedule-sender-session"}
                due_at = int(time.time()) + 60
                headers = {
                    **sender,
                    "Idempotency-Key": "scheduled-message-test-001",
                }
                payload = {
                    "recipient_id": 89202,
                    "body": "**scheduled** message",
                    "scheduled_at": due_at,
                    "silent": True,
                }
                scheduled = await client.post(
                    "/api/messages/schedule",
                    headers=headers,
                    json=payload,
                )
                replay = await client.post(
                    "/api/messages/schedule",
                    headers=headers,
                    json=payload,
                )
                assert scheduled.status_code == 201
                assert scheduled.json()["status"] == "pending"
                assert replay.json()["id"] == scheduled.json()["id"]

                scheduled_id = scheduled.json()["id"]
                listing = await client.get(
                    "/api/messages/scheduled?with=89202",
                    headers=sender,
                )
                assert listing.status_code == 200
                assert listing.json()["count"] == 1
                assert listing.json()["scheduled_messages"][0]["id"] == scheduled_id

                with db_split.sqlite_connect(path) as db:
                    db.execute(
                        "UPDATE scheduled_messages SET scheduled_at=? WHERE id=?",
                        (int(time.time()) - 1, scheduled_id),
                    )
                    db.commit()

                deadline = time.monotonic() + 4
                history = None
                while time.monotonic() < deadline:
                    history = await client.get(
                        "/api/messages?with=89202",
                        headers=sender,
                    )
                    if history.status_code == 200 and history.json()["messages"]:
                        break
                    await asyncio.sleep(0.1)
                assert history is not None and history.status_code == 200
                assert [item["body"] for item in history.json()["messages"]] == [
                    "**scheduled** message"
                ]

                listing_after_send = await client.get(
                    "/api/messages/scheduled?with=89202",
                    headers=sender,
                )
                assert listing_after_send.json()["count"] == 0

                second = await client.post(
                    "/api/messages/schedule",
                    headers=sender,
                    json={
                        "recipient_id": 89202,
                        "body": "cancel me",
                        "scheduled_at": int(time.time()) + 60,
                    },
                )
                assert second.status_code == 201
                cancelled = await client.delete(
                    f"/api/messages/scheduled/{second.json()['id']}",
                    headers=sender,
                )
                assert cancelled.status_code == 200
                assert cancelled.json()["status"] == "cancelled"

                with db_split.sqlite_connect(path) as db:
                    db.execute(
                        "UPDATE scheduled_messages SET scheduled_at=? WHERE id=?",
                        (int(time.time()) - 1, second.json()["id"]),
                    )
                    db.commit()

                await asyncio.sleep(1.2)
                after_cancel = await client.get(
                    "/api/messages?with=89202",
                    headers=sender,
                )
                assert [item["body"] for item in after_cancel.json()["messages"]] == [
                    "**scheduled** message"
                ]

                recurring = await client.post(
                    "/api/messages/schedule",
                    headers=sender,
                    json={
                        "recipient_id": 89202,
                        "body": "daily reminder",
                        "scheduled_at": int(time.time()) + 60,
                        "repeat_interval_seconds": 86400,
                        "silent": True,
                    },
                )
                assert recurring.status_code == 201
                assert recurring.json()["repeat_interval_seconds"] == 86400
                with db_split.sqlite_connect(path) as db:
                    db.execute(
                        "UPDATE scheduled_messages SET scheduled_at=? WHERE id=?",
                        (int(time.time()) - 1, recurring.json()["id"]),
                    )
                    db.commit()

                deadline = time.monotonic() + 4
                recurring_history = None
                while time.monotonic() < deadline:
                    recurring_history = await client.get(
                        "/api/messages?with=89202",
                        headers=sender,
                    )
                    if recurring_history.status_code == 200 and len(
                        recurring_history.json()["messages"]
                    ) >= 2:
                        break
                    await asyncio.sleep(0.1)
                assert recurring_history is not None
                assert [item["body"] for item in recurring_history.json()["messages"]] == [
                    "**scheduled** message", "daily reminder"
                ]

                recurring_list = await client.get(
                    "/api/messages/scheduled?with=89202",
                    headers=sender,
                )
                assert recurring_list.status_code == 200
                assert recurring_list.json()["count"] == 1
                recurring_item = recurring_list.json()["scheduled_messages"][0]
                assert recurring_item["id"] == recurring.json()["id"]
                assert recurring_item["status"] == "pending"
                assert recurring_item["repeat_interval_seconds"] == 86400
                assert recurring_item["scheduled_at"] >= int(time.time()) + 86390

                recurring_cancel = await client.delete(
                    f"/api/messages/scheduled/{recurring.json()['id']}",
                    headers=sender,
                )
                assert recurring_cancel.status_code == 200
                with db_split.sqlite_connect(path) as db:
                    db.execute(
                        "UPDATE scheduled_messages SET scheduled_at=? WHERE id=?",
                        (int(time.time()) - 1, recurring.json()["id"]),
                    )
                    db.commit()
                await asyncio.sleep(1.2)
                final_history = await client.get(
                    "/api/messages?with=89202",
                    headers=sender,
                )
                assert len(final_history.json()["messages"]) == 2

                invalid_repeat = await client.post(
                    "/api/messages/schedule",
                    headers=sender,
                    json={
                        "recipient_id": 89202,
                        "body": "invalid repeat",
                        "scheduled_at": int(time.time()) + 60,
                        "repeat_interval_seconds": 3600,
                    },
                )
                assert invalid_repeat.status_code == 400

                too_soon = await client.post(
                    "/api/messages/schedule",
                    headers=sender,
                    json={
                        "recipient_id": 89202,
                        "body": "too soon",
                        "scheduled_at": int(time.time()) + 2,
                    },
                )
                assert too_soon.status_code == 400

                too_far = await client.post(
                    "/api/messages/schedule",
                    headers=sender,
                    json={
                        "recipient_id": 89202,
                        "body": "too far",
                        "scheduled_at": int(time.time()) + 31 * 24 * 60 * 60,
                    },
                )
                assert too_far.status_code == 400
        finally:
            await app.router._shutdown()

    run(scenario())


def test_direct_message_forward_preserves_origin_and_is_idempotent(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89301, "forward_original")
    add_account(api_env, 89302, "forward_sender")
    add_account(api_env, 89303, "forward_recipient")
    add_account(api_env, 89304, "forward_outsider")
    for user_id, token in (
        (89301, "forward-original-session"),
        (89302, "forward-sender-session"),
        (89303, "forward-recipient-session"),
        (89304, "forward-outsider-session"),
    ):
        add_session(path, user_id, token)

    async def scenario() -> None:
        async with await client_for(app) as client:
            original_sender = {"Authorization": "Bearer forward-original-session"}
            forward_sender = {"Authorization": "Bearer forward-sender-session"}
            recipient = {"Authorization": "Bearer forward-recipient-session"}
            outsider = {"Authorization": "Bearer forward-outsider-session"}

            original = await client.post(
                "/api/messages",
                headers=original_sender,
                json={"recipient_id": 89302, "body": "message to forward"},
            )
            assert original.status_code == 201
            message_id = original.json()["id"]

            forward_headers = {**forward_sender, "Idempotency-Key": "forward-once-key-0001"}
            forwarded = await client.post(
                f"/api/messages/{message_id}/forward",
                headers=forward_headers,
                json={"recipient_id": 89303},
            )
            assert forwarded.status_code == 201
            payload = forwarded.json()
            assert payload["body"] == "message to forward"
            assert payload["forwarded_from_telegram_id"] == 89301
            assert payload["forwarded_from_message_id"] == message_id

            repeated = await client.post(
                f"/api/messages/{message_id}/forward",
                headers=forward_headers,
                json={"recipient_id": 89303},
            )
            assert repeated.status_code == 201
            assert repeated.json()["id"] == payload["id"]

            denied = await client.post(
                f"/api/messages/{message_id}/forward",
                headers=outsider,
                json={"recipient_id": 89303},
            )
            assert denied.status_code == 404

            history = await client.get("/api/messages?with=89302", headers=recipient)
            assert history.status_code == 200
            forwarded_message = history.json()["messages"][-1]
            assert forwarded_message["id"] == payload["id"]
            assert forwarded_message["forwarded_from_telegram_id"] == 89301

    run(scenario())


def test_direct_messages_preserve_telegram_html_formatting(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89101, "format_sender")
    add_account(api_env, 89102, "format_recipient")
    add_session(path, 89101, "format-sender-session")
    add_session(path, 89102, "format-recipient-session")

    body = (
        "<b>bold</b> <i>italic</i> <u>underlined</u> "
        "<s>struck</s> <tg-spoiler>spoiler</tg-spoiler> <code>monospace</code> "
        "<blockquote>quoted text</blockquote> "
        "<pre>code block</pre> https://example.com/test"
    )

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer format-sender-session"}
            sent = await client.post(
                "/api/messages",
                headers=sender,
                json={"recipient_id": 89102, "body": body},
            )
            assert sent.status_code == 201
            assert sent.json()["body"] == body

            history = await client.get("/api/messages?with=89102", headers=sender)
            assert history.status_code == 200
            assert history.json()["messages"][0]["body"] == body

            exported = await client.get("/api/messages/export?with=89102", headers=sender)
            assert exported.status_code == 200
            assert body in exported.json()["text"]

    run(scenario())

def test_direct_message_export_respects_private_visibility(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89001, "export_sender")
    add_account(api_env, 89002, "export_recipient")
    add_session(path, 89001, "export-sender-session")
    add_session(path, 89002, "export-recipient-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer export-sender-session"}
            recipient = {"Authorization": "Bearer export-recipient-session"}

            first = await client.post(
                "/api/messages", headers=sender,
                json={"recipient_id": 89002, "body": "visible sender message"},
            )
            second = await client.post(
                "/api/messages", headers=recipient,
                json={"recipient_id": 89001, "body": "hidden reply for sender"},
            )
            assert first.status_code == second.status_code == 201

            hidden = await client.delete(
                f"/api/messages/{second.json()['id']}?for=me",
                headers=sender,
            )
            assert hidden.status_code == 200

            sender_export = await client.get(
                "/api/messages/export?with=89002", headers=sender
            )
            recipient_export = await client.get(
                "/api/messages/export?with=89001", headers=recipient
            )
            assert sender_export.status_code == recipient_export.status_code == 200
            assert sender_export.json()["count"] == 1
            assert "visible sender message" in sender_export.json()["text"]
            assert "hidden reply for sender" not in sender_export.json()["text"]
            assert recipient_export.json()["count"] == 2
            assert "hidden reply for sender" in recipient_export.json()["text"]

            missing = await client.get(
                "/api/messages/export?with=89999", headers=sender
            )
            assert missing.status_code == 404

    run(scenario())


def test_clear_direct_message_history_only_hides_messages_for_current_account(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 88901, "clear_sender")
    add_account(api_env, 88902, "clear_recipient")
    add_session(path, 88901, "clear-sender-session")
    add_session(path, 88902, "clear-recipient-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer clear-sender-session"}
            recipient = {"Authorization": "Bearer clear-recipient-session"}

            first = await client.post(
                "/api/messages", headers=sender,
                json={"recipient_id": 88902, "body": "first message"},
            )
            second = await client.post(
                "/api/messages", headers=recipient,
                json={"recipient_id": 88901, "body": "second message"},
            )
            assert first.status_code == second.status_code == 201

            recipient_cursor = await client.get("/api/events", headers=recipient)
            sender_cursor = await client.get("/api/events", headers=sender)
            assert recipient_cursor.status_code == sender_cursor.status_code == 200

            cleared = await client.delete(
                "/api/conversations/88901/messages?for=me",
                headers=recipient,
            )
            assert cleared.status_code == 200
            assert cleared.json()["status"] == "cleared_for_me"
            assert cleared.json()["deleted_count"] == 2

            recipient_history = await client.get("/api/messages?with=88901", headers=recipient)
            sender_history = await client.get("/api/messages?with=88902", headers=sender)
            assert recipient_history.status_code == sender_history.status_code == 200
            assert recipient_history.json()["messages"] == []
            assert [item["body"] for item in sender_history.json()["messages"]] == [
                "first message", "second message"
            ]

            recipient_events = await client.get(
                f"/api/events?after_id={recipient_cursor.json()['latest_id']}",
                headers=recipient,
            )
            sender_events = await client.get(
                f"/api/events?after_id={sender_cursor.json()['latest_id']}",
                headers=sender,
            )
            assert any(event["kind"] == "clear_for_me"
                       for event in recipient_events.json()["events"])
            assert sender_events.json()["events"] == []

            cleared_again = await client.delete(
                "/api/conversations/88901/messages?for=me",
                headers=recipient,
            )
            assert cleared_again.status_code == 200
            assert cleared_again.json()["deleted_count"] == 0

            denied = await client.delete(
                "/api/conversations/88901/messages?for=all",
                headers=recipient,
            )
            assert denied.status_code == 400

    run(scenario())


def test_direct_message_delete_for_me_is_private_and_consistent(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 88801, "delete_sender")
    add_account(api_env, 88802, "delete_recipient")
    add_account(api_env, 88803, "delete_outsider")
    add_session(path, 88801, "delete-sender-session")
    add_session(path, 88802, "delete-recipient-session")
    add_session(path, 88803, "delete-outsider-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer delete-sender-session"}
            recipient = {"Authorization": "Bearer delete-recipient-session"}
            outsider = {"Authorization": "Bearer delete-outsider-session"}

            sent = await client.post(
                "/api/messages",
                headers=sender,
                json={"recipient_id": 88802, "body": "private deletion check"},
            )
            assert sent.status_code == 201
            message_id = sent.json()["id"]

            pinned = await client.post(
                "/api/pins",
                headers=recipient,
                json={"scope": "dm", "peer_id": 88801, "message_id": message_id},
            )
            assert pinned.status_code == 200

            recipient_event_cursor = await client.get("/api/events", headers=recipient)
            sender_event_cursor = await client.get("/api/events", headers=sender)
            assert recipient_event_cursor.status_code == sender_event_cursor.status_code == 200

            hidden = await client.delete(
                f"/api/messages/{message_id}?for=me",
                headers=recipient,
            )
            assert hidden.status_code == 200
            assert hidden.json()["status"] == "hidden_for_me"

            recipient_events = await client.get(
                f"/api/events?after_id={recipient_event_cursor.json()['latest_id']}",
                headers=recipient,
            )
            sender_events = await client.get(
                f"/api/events?after_id={sender_event_cursor.json()['latest_id']}",
                headers=sender,
            )
            assert recipient_events.status_code == sender_events.status_code == 200
            assert any(event["kind"] == "delete_for_me"
                       for event in recipient_events.json()["events"])
            assert sender_events.json()["events"] == []

            recipient_history = await client.get("/api/messages?with=88801", headers=recipient)
            assert recipient_history.status_code == 200
            assert recipient_history.json()["messages"] == []

            recipient_search = await client.get(
                "/api/messages/search?with=88801&q=private",
                headers=recipient,
            )
            assert recipient_search.status_code == 200
            assert recipient_search.json()["messages"] == []

            recipient_conversations = await client.get("/api/conversations", headers=recipient)
            assert recipient_conversations.status_code == 200
            assert recipient_conversations.json()["conversations"] == []

            recipient_pins = await client.get(
                "/api/pins?scope=dm&peer_id=88801",
                headers=recipient,
            )
            assert recipient_pins.status_code == 200
            assert recipient_pins.json()["pinned_messages"] == []

            sender_history = await client.get("/api/messages?with=88802", headers=sender)
            assert sender_history.status_code == 200
            assert [item["body"] for item in sender_history.json()["messages"]] == [
                "private deletion check"
            ]

            sender_pins = await client.get(
                "/api/pins?scope=dm&peer_id=88802",
                headers=sender,
            )
            assert sender_pins.status_code == 200
            assert len(sender_pins.json()["pinned_messages"]) == 1

            outsider_delete = await client.delete(
                f"/api/messages/{message_id}?for=me",
                headers=outsider,
            )
            assert outsider_delete.status_code == 404

            forbidden_delete_all = await client.delete(
                f"/api/messages/{message_id}?for=all",
                headers=recipient,
            )
            assert forbidden_delete_all.status_code == 403

            invalid_mode = await client.delete(
                f"/api/messages/{message_id}?for=everyone",
                headers=recipient,
            )
            assert invalid_mode.status_code == 400

            delete_all = await client.delete(
                f"/api/messages/{message_id}?for=all",
                headers=sender,
            )
            assert delete_all.status_code == 200
            assert delete_all.json()["status"] == "deleted_for_all"

            sender_after_all = await client.get("/api/messages?with=88802", headers=sender)
            assert sender_after_all.status_code == 200
            assert sender_after_all.json()["messages"] == []

    run(scenario())


def test_silent_direct_messages_skip_push_delivery(api_env, monkeypatch) -> None:
    _path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 88701, "silent_sender")
    add_account(api_env, 88702, "silent_recipient")
    add_session(_path, 88701, "silent-sender-session")
    add_session(_path, 88702, "silent-recipient-session")

    push_credential_checks: list[bool] = []

    def capture_push_setup():
        push_credential_checks.append(True)
        return None

    # deliver_push_notifications is a router-local helper. Observe its first
    # module-level dependency instead of trying to patch the closed-over helper.
    monkeypatch.setattr(messenger_api, "_firebase_service_account", capture_push_setup)

    async def scenario() -> None:
        async with await client_for(app) as client:
            headers = {"Authorization": "Bearer silent-sender-session"}
            silent = await client.post(
                "/api/messages",
                headers=headers,
                json={"recipient_id": 88702, "body": "quiet message", "silent": True},
            )
            assert silent.status_code == 201
            assert silent.json()["body"] == "quiet message"
            assert push_credential_checks == []

            normal = await client.post(
                "/api/messages",
                headers=headers,
                json={"recipient_id": 88702, "body": "normal message"},
            )
            assert normal.status_code == 201
            assert len(push_credential_checks) == 1

            invalid = await client.post(
                "/api/messages",
                headers=headers,
                json={"recipient_id": 88702, "body": "invalid flag", "silent": "true"},
            )
            assert invalid.status_code == 400

    run(scenario())


def test_direct_messages_and_channel_permissions(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 82001, "sender")
    add_account(api_env, 82002, "recipient")
    add_account(api_env, 82003, "occupied")
    add_session(path, 82001, "sender-session")
    add_session(path, 82002, "recipient-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer sender-session"}
            recipient = {"Authorization": "Bearer recipient-session"}

            dm_headers = {**sender, "Idempotency-Key": "direct-message-order-0001"}
            sent = await client.post(
                "/api/messages",
                headers=dm_headers,
                json={"recipient_id": 82002, "body": "test message"},
            )
            replay = await client.post(
                "/api/messages",
                headers=dm_headers,
                json={"recipient_id": 82002, "body": "test message"},
            )
            assert sent.status_code == 201
            assert sent.json()["status"] == "sent"
            assert sent.json()["sender_id"] == 82001
            assert replay.json()["id"] == sent.json()["id"]

            changed_replay = await client.post(
                "/api/messages",
                headers=dm_headers,
                json={"recipient_id": 82002, "body": "different body"},
            )
            assert changed_replay.status_code == 409

            history = await client.get(
                "/api/messages?with=82002",
                headers=sender,
            )
            assert history.status_code == 200
            assert len(history.json()["messages"]) == 1
            assert history.json()["messages"][0]["body"] == "test message"

            second = await client.post(
                "/api/messages",
                headers={**sender, "Idempotency-Key": "direct-message-order-0002"},
                json={"recipient_id": 82002, "body": "second message"},
            )
            assert second.status_code == 201

            after_cursor = await client.get(
                f"/api/messages?with=82002&after_id={sent.json()['id']}",
                headers=sender,
            )
            assert [m["body"] for m in after_cursor.json()["messages"]] == ["second message"]

            before_cursor = await client.get(
                f"/api/messages?with=82002&before_id={second.json()['id']}",
                headers=sender,
            )
            assert [m["body"] for m in before_cursor.json()["messages"]] == ["test message"]

            invalid_cursors = await client.get(
                f"/api/messages?with=82002&after_id={sent.json()['id']}&before_id={second.json()['id']}",
                headers=sender,
            )
            assert invalid_cursors.status_code == 400

            conversations = await client.get("/api/conversations", headers=sender)
            assert conversations.status_code == 200
            latest_conversation = conversations.json()["conversations"][0]
            assert latest_conversation["id"] == 82002
            assert latest_conversation["last_sender_id"] == 82001
            assert latest_conversation["last_message"] == "second message"

            created = await client.post(
                "/api/channels",
                headers=sender,
                json={"username": "alpha_news", "title": "Alpha News"},
            )
            assert created.status_code == 201
            channel_id = created.json()["id"]

            initial_admins = await client.get(
                f"/api/channels/{channel_id}/admins",
                headers=sender,
            )
            assert initial_admins.status_code == 200
            assert initial_admins.json()["my_role"] == "owner"
            assert initial_admins.json()["admins"] == []

            channel_headers = {**sender, "Idempotency-Key": "channel-post-order-0001"}
            post = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=channel_headers,
                json={"body": "first post"},
            )
            post_replay = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=channel_headers,
                json={"body": "first post"},
            )
            assert post.status_code == 201
            assert post.json()["status"] == "published"
            assert post_replay.json()["id"] == post.json()["id"]

            forbidden = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=recipient,
                json={"body": "unauthorized post"},
            )
            assert forbidden.status_code == 403

            appointed = await client.post(
                f"/api/channels/{channel_id}/admins",
                headers=sender,
                json={"telegram_id": 82002},
            )
            assert appointed.status_code == 201

            listed_admins = await client.get(
                f"/api/channels/{channel_id}/admins",
                headers=recipient,
            )
            assert listed_admins.status_code == 200
            assert listed_admins.json()["my_role"] == "admin"
            assert listed_admins.json()["admins"][0]["telegram_id"] == 82002
            assert listed_admins.json()["admins"][0]["username"] == "recipient"

            admin_post = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=recipient,
                json={"body": "admin post"},
            )
            assert admin_post.status_code == 201

            denied_owner_action = await client.post(
                f"/api/channels/{channel_id}/admins",
                headers=recipient,
                json={"telegram_id": 82003},
            )
            assert denied_owner_action.status_code == 403

            removed = await client.delete(
                f"/api/channels/{channel_id}/admins/82002",
                headers=sender,
            )
            assert removed.status_code == 200

            admins_after_removal = await client.get(
                f"/api/channels/{channel_id}/admins",
                headers=sender,
            )
            assert admins_after_removal.status_code == 200
            assert admins_after_removal.json()["admins"] == []

            forbidden_again = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=recipient,
                json={"body": "after removal"},
            )
            assert forbidden_again.status_code == 403

            channel_history = await client.get(
                f"/api/channels/{channel_id}/messages",
                headers=recipient,
            )
            assert channel_history.status_code == 200
            assert len(channel_history.json()["messages"]) == 2
            assert channel_history.json()["messages"][0]["body"] == "first post"
            assert channel_history.json()["messages"][1]["body"] == "admin post"

            denied_delete = await client.delete(
                f"/api/channels/{channel_id}",
                headers=recipient,
            )
            assert denied_delete.status_code == 404
            owner_delete = await client.delete(
                f"/api/channels/{channel_id}",
                headers=sender,
            )
            assert owner_delete.status_code == 200
            remaining = await client.get(
                f"/api/channels/{channel_id}/messages",
                headers=sender,
            )
            assert remaining.status_code == 404

    run(scenario())


def test_image_upload_direct_message_and_private_download(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89001, "image_sender")
    add_account(api_env, 89002, "image_recipient")
    add_account(api_env, 89003, "image_intruder")
    add_session(path, 89001, "image-sender-session")
    add_session(path, 89002, "image-recipient-session")
    add_session(path, 89003, "image-intruder-session")

    image_buffer = BytesIO()
    Image.new("RGB", (4, 3), (30, 100, 180)).save(image_buffer, format="PNG")
    image_bytes = image_buffer.getvalue()

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer image-sender-session"}
            recipient = {"Authorization": "Bearer image-recipient-session"}
            intruder = {"Authorization": "Bearer image-intruder-session"}

            invalid = await client.post(
                "/api/media/images",
                headers={**sender, "Content-Type": "image/png"},
                content=b"not an image",
            )
            assert invalid.status_code == 415

            uploaded = await client.post(
                "/api/media/images",
                headers={**sender, "Content-Type": "image/png"},
                content=image_bytes,
            )
            assert uploaded.status_code == 201
            media = uploaded.json()
            assert len(media["id"]) == 32
            assert media["mime_type"] == "image/png"
            assert media["size_bytes"] > 0

            wrong_owner = await client.post(
                "/api/messages",
                headers=recipient,
                json={"recipient_id": 89001, "media_id": media["id"]},
            )
            assert wrong_owner.status_code == 404

            sent = await client.post(
                "/api/messages",
                headers=sender,
                json={"recipient_id": 89002, "media_id": media["id"]},
            )
            assert sent.status_code == 201
            assert sent.json()["body"] == "Изображение"
            assert sent.json()["media_id"] == media["id"]

            history = await client.get("/api/messages?with=89001", headers=recipient)
            assert history.status_code == 200
            assert history.json()["messages"][0]["media_id"] == media["id"]

            downloaded = await client.get(media["url"], headers=recipient)
            assert downloaded.status_code == 200
            assert downloaded.headers["content-type"].startswith("image/png")
            with Image.open(BytesIO(downloaded.content)) as normalized_image:
                assert normalized_image.size == (4, 3)
                assert normalized_image.convert("RGB").getpixel((0, 0)) == (30, 100, 180)

            denied = await client.get(media["url"], headers=intruder)
            assert denied.status_code == 404

    run(scenario())


def test_image_attachments_in_group_and_channel_messages(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89101, "media_owner")
    add_account(api_env, 89102, "media_member")
    add_account(api_env, 89103, "media_observer")
    add_session(path, 89101, "media-owner-session")
    add_session(path, 89102, "media-member-session")
    add_session(path, 89103, "media-observer-session")

    image_buffer = BytesIO()
    Image.new("RGB", (5, 4), (80, 140, 40)).save(image_buffer, format="JPEG")
    image_bytes = image_buffer.getvalue()

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer media-owner-session"}
            member = {"Authorization": "Bearer media-member-session"}
            observer = {"Authorization": "Bearer media-observer-session"}

            uploaded = await client.post(
                "/api/media/images",
                headers={**owner, "Content-Type": "image/jpeg"},
                content=image_bytes,
            )
            assert uploaded.status_code == 201
            media_id = uploaded.json()["id"]
            media_url = uploaded.json()["url"]

            group = await client.post(
                "/api/groups",
                headers=owner,
                json={"title": "Image group", "username": "image_group"},
            )
            assert group.status_code == 201
            group_id = group.json()["id"]
            joined = await client.post(
                f"/api/groups/{group_id}/members",
                headers=owner,
                json={"telegram_id": 89102},
            )
            assert joined.status_code == 201

            group_post = await client.post(
                f"/api/groups/{group_id}/messages",
                headers=owner,
                json={"media_id": media_id},
            )
            assert group_post.status_code == 201
            group_history = await client.get(
                f"/api/groups/{group_id}/messages",
                headers=member,
            )
            assert group_history.status_code == 200
            assert group_history.json()["messages"][0]["media_id"] == media_id

            member_download = await client.get(media_url, headers=member)
            assert member_download.status_code == 200
            with Image.open(BytesIO(member_download.content)) as decoded:
                assert decoded.size == (5, 4)

            group_denied = await client.get(media_url, headers=observer)
            assert group_denied.status_code == 404

            channel = await client.post(
                "/api/channels",
                headers=owner,
                json={"username": "image_channel", "title": "Image channel"},
            )
            assert channel.status_code == 201
            channel_id = channel.json()["id"]
            channel_post = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=owner,
                json={"media_id": media_id},
            )
            assert channel_post.status_code == 201
            channel_history = await client.get(
                f"/api/channels/{channel_id}/messages",
                headers=observer,
            )
            assert channel_history.status_code == 200
            assert channel_history.json()["messages"][0]["media_id"] == media_id
            channel_download = await client.get(media_url, headers=observer)
            assert channel_download.status_code == 200

    run(scenario())




def test_document_upload_attachment_and_private_download(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89201, "document_sender")
    add_account(api_env, 89202, "document_recipient")
    add_account(api_env, 89203, "document_intruder")
    add_session(path, 89201, "document-sender-session")
    add_session(path, 89202, "document-recipient-session")
    add_session(path, 89203, "document-intruder-session")

    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    text_bytes = "WaysGram document\nsecond line\n".encode("utf-8")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer document-sender-session"}
            recipient = {"Authorization": "Bearer document-recipient-session"}
            intruder = {"Authorization": "Bearer document-intruder-session"}

            rejected_type = await client.post(
                "/api/media/documents",
                headers={**sender, "Content-Type": "application/octet-stream", "X-Filename": "payload.exe"},
                content=b"MZ\\x00fake executable",
            )
            assert rejected_type.status_code == 415

            rejected_pdf = await client.post(
                "/api/media/documents",
                headers={**sender, "Content-Type": "application/pdf", "X-Filename": "fake.pdf"},
                content=b"not a PDF document",
            )
            assert rejected_pdf.status_code == 415

            uploaded = await client.post(
                "/api/media/documents",
                headers={**sender, "Content-Type": "application/pdf", "X-Filename": "project%20notes.pdf"},
                content=pdf_bytes,
            )
            assert uploaded.status_code == 201
            media = uploaded.json()
            assert media["mime_type"] == "application/pdf"
            assert media["name"] == "project notes.pdf"
            assert media["size_bytes"] == len(pdf_bytes)

            sent = await client.post(
                "/api/messages",
                headers=sender,
                json={"recipient_id": 89202, "media_id": media["id"]},
            )
            assert sent.status_code == 201
            assert sent.json()["body"] == "Документ: project notes.pdf"
            assert sent.json()["media_id"] == media["id"]
            assert sent.json()["media_type"] == "application/pdf"
            assert sent.json()["media_name"] == "project notes.pdf"

            history = await client.get("/api/messages?with=89201", headers=recipient)
            assert history.status_code == 200
            assert history.json()["messages"][0]["media_id"] == media["id"]
            assert history.json()["messages"][0]["media_type"] == "application/pdf"
            assert history.json()["messages"][0]["media_name"] == "project notes.pdf"

            downloaded = await client.get(media["url"], headers=recipient)
            assert downloaded.status_code == 200
            assert downloaded.headers["content-type"].startswith("application/pdf")
            assert downloaded.headers["content-disposition"].startswith("attachment;")
            assert "filename*=UTF-8''project%20notes.pdf" in downloaded.headers["content-disposition"]
            assert downloaded.content == pdf_bytes

            denied = await client.get(media["url"], headers=intruder)
            assert denied.status_code == 404

            text_upload = await client.post(
                "/api/media/documents",
                headers={**sender, "Content-Type": "text/plain", "X-Filename": "summary.txt"},
                content=text_bytes,
            )
            assert text_upload.status_code == 201
            assert text_upload.json()["mime_type"] == "text/plain"
            text_download = await client.get(text_upload.json()["url"], headers=sender)
            assert text_download.status_code == 200
            assert text_download.headers["content-disposition"].startswith("attachment;")
            assert text_download.content == text_bytes

            archive_fixtures = [
                ("backup.rar", "application/vnd.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 32),
                ("backup.7z", "application/x-7z-compressed", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32),
                ("backup.tar", "application/x-tar", b"\x00" * 257 + b"ustar" + b"\x00" * 250),
                ("backup.gz", "application/gzip", b"\x1f\x8b\x08" + b"\x00" * 20),
                ("backup.bz2", "application/x-bzip2", b"BZh9" + b"\x00" * 20),
                ("backup.xz", "application/x-xz", b"\xfd7zXZ\x00" + b"\x00" * 20),
                ("backup.tar.gz", "application/gzip", b"\x1f\x8b\x08" + b"\x00" * 20),
            ]
            for archive_name, mime_type, archive_bytes in archive_fixtures:
                archive_upload = await client.post(
                    "/api/media/documents",
                    headers={
                        **sender,
                        "Content-Type": mime_type,
                        "X-Filename": archive_name,
                    },
                    content=archive_bytes,
                )
                assert archive_upload.status_code == 201, archive_name
                archive_media = archive_upload.json()
                assert archive_media["mime_type"] == mime_type
                assert archive_media["name"] == archive_name
                archive_download = await client.get(archive_media["url"], headers=sender)
                assert archive_download.status_code == 200, archive_name
                assert archive_download.content == archive_bytes, archive_name

            invalid_rar = await client.post(
                "/api/media/documents",
                headers={**sender, "Content-Type": "application/vnd.rar", "X-Filename": "broken.rar"},
                content=b"not a RAR archive",
            )
            assert invalid_rar.status_code == 415

    run(scenario())

def test_uncompressed_image_attachment_preserves_original_bytes(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89301, "uncompressed_sender")
    add_account(api_env, 89302, "uncompressed_intruder")
    add_session(path, 89301, "uncompressed-sender-session")
    add_session(path, 89302, "uncompressed-intruder-session")

    fixtures = []
    for extension, image_format, mime_type in (
        (".jpg", "JPEG", "image/jpeg"),
        (".png", "PNG", "image/png"),
        (".webp", "WEBP", "image/webp"),
    ):
        buffer = BytesIO()
        Image.new("RGB", (7, 5), (17, 81, 149)).save(buffer, format=image_format)
        fixtures.append((f"original{extension}", mime_type, buffer.getvalue()))

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer uncompressed-sender-session"}
            intruder = {"Authorization": "Bearer uncompressed-intruder-session"}

            for filename, mime_type, original_bytes in fixtures:
                uploaded = await client.post(
                    "/api/media/documents",
                    headers={
                        **sender,
                        "Content-Type": mime_type,
                        "X-Filename": filename,
                    },
                    content=original_bytes,
                )
                assert uploaded.status_code == 201, filename
                media = uploaded.json()
                assert media["mime_type"] == mime_type
                assert media["size_bytes"] == len(original_bytes)
                downloaded = await client.get(media["url"], headers=sender)
                assert downloaded.status_code == 200
                assert downloaded.content == original_bytes

            rejected = await client.post(
                "/api/media/documents",
                headers={
                    **sender,
                    "Content-Type": "image/jpeg",
                    "X-Filename": "broken.jpg",
                },
                content=b"not an image",
            )
            assert rejected.status_code == 415

            denied = await client.get(media["url"], headers=intruder)
            assert denied.status_code == 404

    run(scenario())


def test_gift_purchase_is_idempotent_and_transfer_updates_inventory(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 83001, "buyer")
    add_account(api_env, 83002, "receiver")
    add_session(path, 83001, "buyer-session")
    add_session(path, 83002, "receiver-session")
    with db_split.sqlite_connect(path) as db:
        db.execute("UPDATE accounts SET grams=100 WHERE telegram_id=83001")
        db.execute(
            "INSERT INTO gift_catalog(name,price_grams,supply,created_at) VALUES('Test Gift',50,1,?)",
            (int(time.time()),),
        )

    async def scenario() -> None:
        async with await client_for(app) as client:
            buyer = {"Authorization": "Bearer buyer-session"}
            receiver = {"Authorization": "Bearer receiver-session"}
            headers = {**buyer, "Idempotency-Key": "gift-purchase-order-0001"}

            first = await client.post(
                "/api/gifts/1/purchase",
                headers=headers,
                json={},
            )
            second = await client.post(
                "/api/gifts/1/purchase",
                headers=headers,
                json={},
            )
            assert first.status_code == 201
            assert second.status_code == 201
            assert first.json()["gift"]["serial_number"] == second.json()["gift"]["serial_number"]
            assert first.json()["grams_balance"] == 50

            wallet = await client.get("/api/me/wallet", headers=buyer)
            assert wallet.json()["grams"] == 50

            serial = first.json()["gift"]["serial_number"]
            transfer_headers = {**buyer, "Idempotency-Key": "gift-transfer-order-0001"}
            transfer_body = {"serial_number": serial, "recipient": "receiver"}
            transferred = await client.post(
                "/api/gifts/transfer",
                headers=transfer_headers,
                json=transfer_body,
            )
            transfer_replay = await client.post(
                "/api/gifts/transfer",
                headers=transfer_headers,
                json=transfer_body,
            )
            assert transferred.status_code == 200
            assert transfer_replay.json() == transferred.json()
            assert transferred.json()["to_user_id"] == 83002
            assert transferred.json()["to_username"] == "receiver"

            buyer_inventory = await client.get("/api/me/gifts", headers=buyer)
            receiver_inventory = await client.get("/api/me/gifts", headers=receiver)
            assert buyer_inventory.json()["gifts"] == []
            assert receiver_inventory.json()["gifts"][0]["serial_number"] == serial
            history = await client.get("/api/me/gifts/transactions", headers=buyer)
            assert history.status_code == 200
            assert history.json()["transactions"][0]["to_username"] == "receiver"

            with db_split.sqlite_connect(path) as db:
                supply = db.execute("SELECT supply FROM gift_catalog WHERE id=1").fetchone()[0]
                transaction_count = db.execute("SELECT COUNT(*) FROM economy_transactions WHERE reason='gift_purchase:1'").fetchone()[0]
                gift_history_count = db.execute("SELECT COUNT(*) FROM gift_transactions WHERE serial_number=?", (serial,)).fetchone()[0]
            assert supply == 0
            assert transaction_count == 1
            assert gift_history_count == 2

    run(scenario())



def test_system_gift_auction_refunds_outbid_user_and_settles_winner(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 84001, "first_bidder")
    add_account(api_env, 84002, "second_bidder")
    add_session(path, 84001, "first-bidder-session")
    add_session(path, 84002, "second-bidder-session")
    now = int(time.time())
    with db_split.sqlite_connect(path) as db:
        db.execute("UPDATE accounts SET stars=200 WHERE telegram_id IN (84001,84002)")
        db.execute(
            "INSERT INTO gift_catalog(name,price_grams,supply,created_at) VALUES('Auction Gift',40,0,?)",
            (now,),
        )
        db.execute(
            """INSERT INTO gift_auctions
               (gift_id,gift_name,starting_bid,current_bid,status,starts_at,ends_at,created_by,created_at)
               VALUES(1,'Auction Gift',50,0,'active',?,?,999,?)""",
            (now - 1, now + 3600, now),
        )

    async def scenario() -> None:
        async with await client_for(app) as client:
            first = {"Authorization": "Bearer first-bidder-session"}
            second = {"Authorization": "Bearer second-bidder-session"}

            first_bid = await client.post(
                "/api/auctions/1/bid",
                headers=first,
                json={"amount": 50},
            )
            assert first_bid.status_code == 201
            assert first_bid.json()["stars_balance"] == 150

            second_bid = await client.post(
                "/api/auctions/1/bid",
                headers=second,
                json={"amount": 80},
            )
            assert second_bid.status_code == 201
            assert second_bid.json()["stars_balance"] == 120

            too_low = await client.post(
                "/api/auctions/1/bid",
                headers=first,
                json={"amount": 80},
            )
            assert too_low.status_code == 409
            assert "Минимальная следующая ставка" in too_low.json()["detail"]

            with db_split.sqlite_connect(path) as db:
                first_balance = db.execute(
                    "SELECT stars FROM accounts WHERE telegram_id=84001"
                ).fetchone()[0]
                second_balance = db.execute(
                    "SELECT stars FROM accounts WHERE telegram_id=84002"
                ).fetchone()[0]
            assert first_balance == 200
            assert second_balance == 120

            # A new high bid refunds the previous leader and escrows only the current bid.
            third_bid = await client.post(
                "/api/auctions/1/bid",
                headers=first,
                json={"amount": 100},
            )
            assert third_bid.status_code == 201
            assert third_bid.json()["stars_balance"] == 100

            with db_split.sqlite_connect(path) as db:
                db.execute(
                    "UPDATE gift_auctions SET ends_at=? WHERE id=1",
                    (int(time.time()) - 1,),
                )

            auctions = await client.get("/api/auctions", headers=first)
            assert auctions.status_code == 200
            assert auctions.json()["auctions"][0]["status"] == "ended"

            with db_split.sqlite_connect(path) as db:
                first_balance = db.execute(
                    "SELECT stars FROM accounts WHERE telegram_id=84001"
                ).fetchone()[0]
                second_balance = db.execute(
                    "SELECT stars FROM accounts WHERE telegram_id=84002"
                ).fetchone()[0]
                winner = db.execute(
                    "SELECT owner_telegram_id,gift_name FROM user_gifts"
                ).fetchone()
                auction_status = db.execute(
                    "SELECT status FROM gift_auctions WHERE id=1"
                ).fetchone()[0]
            assert first_balance == 100
            assert second_balance == 200
            assert winner == (84001, "Auction Gift")
            assert auction_status == "ended"

    run(scenario())


def test_group_and_channel_long_poll_return_incremental_messages(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89301, "timeline_owner")
    add_account(api_env, 89302, "timeline_member")
    add_session(path, 89301, "timeline-owner-session")
    add_session(path, 89302, "timeline-member-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer timeline-owner-session"}
            member = {"Authorization": "Bearer timeline-member-session"}

            group = await client.post(
                "/api/groups",
                headers=owner,
                json={"title": "Long poll group", "username": "longpoll_group"},
            )
            assert group.status_code == 201
            group_id = group.json()["id"]
            joined = await client.post(
                f"/api/groups/{group_id}/members",
                headers=owner,
                json={"telegram_id": 89302},
            )
            assert joined.status_code == 201

            group_initial = await client.post(
                f"/api/groups/{group_id}/messages",
                headers=owner,
                json={"body": "group initial"},
            )
            assert group_initial.status_code == 201
            group_event_cursor_response = await client.get("/api/events", headers=member)
            assert group_event_cursor_response.status_code == 200
            group_event_cursor = group_event_cursor_response.json()["latest_id"]
            group_events_pending = asyncio.create_task(
                client.get(
                    f"/api/events?after_id={group_event_cursor}&wait_seconds=20",
                    headers=member,
                )
            )
            group_pending = asyncio.create_task(
                client.get(
                    f"/api/groups/{group_id}/messages?after_id={group_initial.json()['id']}&wait_seconds=5",
                    headers=member,
                )
            )
            await asyncio.sleep(0.2)
            group_next = await client.post(
                f"/api/groups/{group_id}/messages",
                headers=owner,
                json={"body": "group arrived"},
            )
            group_response = await asyncio.wait_for(group_pending, timeout=3)
            assert group_response.status_code == 200
            assert [item["body"] for item in group_response.json()["messages"]] == ["group arrived"]
            assert group_next.status_code == 201
            group_event_response = await asyncio.wait_for(group_events_pending, timeout=3)
            assert any(
                event["kind"] == "new_message"
                and event["scope"] == "group"
                and event["chat_id"] == group_id
                for event in group_event_response.json()["events"]
            )
            group_rows = await client.get("/api/groups", headers=member)
            assert group_rows.json()["groups"][0]["unread_count"] == 2

            channel = await client.post(
                "/api/channels",
                headers=owner,
                json={"username": "longpoll_channel", "title": "Long poll channel"},
            )
            assert channel.status_code == 201
            channel_id = channel.json()["id"]

            channel_initial = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=owner,
                json={"body": "channel initial"},
            )
            assert channel_initial.status_code == 201
            channel_event_cursor_response = await client.get("/api/events", headers=member)
            assert channel_event_cursor_response.status_code == 200
            channel_event_cursor = channel_event_cursor_response.json()["latest_id"]
            channel_events_pending = asyncio.create_task(
                client.get(
                    f"/api/events?after_id={channel_event_cursor}&wait_seconds=20",
                    headers=member,
                )
            )
            channel_pending = asyncio.create_task(
                client.get(
                    f"/api/channels/{channel_id}/messages?after_id={channel_initial.json()['id']}&wait_seconds=5",
                    headers=member,
                )
            )
            await asyncio.sleep(0.2)
            channel_next = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=owner,
                json={"body": "channel arrived"},
            )
            channel_response = await asyncio.wait_for(channel_pending, timeout=3)
            assert channel_response.status_code == 200
            assert [item["body"] for item in channel_response.json()["messages"]] == ["channel arrived"]
            assert channel_next.status_code == 201
            channel_event_response = await asyncio.wait_for(channel_events_pending, timeout=3)
            assert any(
                event["kind"] == "new_message"
                and event["scope"] == "channel"
                and event["chat_id"] == channel_id
                for event in channel_event_response.json()["events"]
            )
            channel_rows = await client.get("/api/channels", headers=member)
            channel_item = next(
                item for item in channel_rows.json()["channels"]
                if item["id"] == channel_id
            )
            assert channel_item["unread_count"] == 2

    run(scenario())


def test_group_creation_roles_membership_and_messages(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 85001, "group_owner")
    add_account(api_env, 85002, "group_admin")
    add_account(api_env, 85003, "group_guest")
    add_session(path, 85001, "group-owner-session")
    add_session(path, 85002, "group-admin-session")
    add_session(path, 85003, "group-guest-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer group-owner-session"}
            admin = {"Authorization": "Bearer group-admin-session"}
            guest = {"Authorization": "Bearer group-guest-session"}

            created = await client.post(
                "/api/groups",
                headers=owner,
                json={"title": "WaysGram Test Group", "username": "waysgram_test", "description": "Group API test"},
            )
            assert created.status_code == 201
            group_id = created.json()["id"]

            denied = await client.get(f"/api/groups/{group_id}", headers=guest)
            assert denied.status_code == 403

            joined = await client.post(
                f"/api/groups/{group_id}/members",
                headers=owner,
                json={"username": "group_admin"},
            )
            assert joined.status_code == 201
            assert joined.json()["joined"] is True

            promoted = await client.post(
                f"/api/groups/{group_id}/admins",
                headers=owner,
                json={"telegram_id": 85002},
            )
            assert promoted.status_code == 201
            assert promoted.json()["role"] == "admin"

            guest_joined = await client.post(
                f"/api/groups/{group_id}/members",
                headers=admin,
                json={"telegram_id": 85003},
            )
            assert guest_joined.status_code == 201

            post = await client.post(
                f"/api/groups/{group_id}/messages",
                headers=guest,
                json={"body": "Group message"},
            )
            assert post.status_code == 201
            history = await client.get(
                f"/api/groups/{group_id}/messages",
                headers=owner,
            )
            assert history.status_code == 200
            assert history.json()["messages"][0]["body"] == "Group message"

            member_list = await client.get(f"/api/groups/{group_id}", headers=owner)
            assert member_list.status_code == 200
            assert member_list.json()["my_telegram_id"] == 85001
            assert member_list.json()["my_role"] == "owner"
            roles = {row["telegram_id"]: row["role"] for row in member_list.json()["members"]}
            assert roles == {85001: "owner", 85002: "admin", 85003: "member"}

            left = await client.delete(
                f"/api/groups/{group_id}/members/85003",
                headers=guest,
            )
            assert left.status_code == 200
            denied_after_leave = await client.post(
                f"/api/groups/{group_id}/messages",
                headers=guest,
                json={"body": "Cannot post after leaving"},
            )
            assert denied_after_leave.status_code == 403

    run(scenario())


def test_group_and_channel_photo_video_albums_are_atomic_and_idempotent(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89301, "album_owner")
    add_account(api_env, 89302, "album_member")
    add_account(api_env, 89303, "album_outsider")
    add_session(path, 89301, "album-owner-session")
    add_session(path, 89302, "album-member-session")
    add_session(path, 89303, "album-outsider-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer album-owner-session"}
            member = {"Authorization": "Bearer album-member-session"}
            outsider = {"Authorization": "Bearer album-outsider-session"}

            uploaded_ids: list[str] = []
            uploaded_urls: list[str] = []
            image_buffer = BytesIO()
            Image.new("RGB", (6, 5), (20, 80, 140)).save(image_buffer, format="JPEG")
            uploaded_image = await client.post(
                "/api/media/images",
                headers={**owner, "Content-Type": "image/jpeg"},
                content=image_buffer.getvalue(),
            )
            assert uploaded_image.status_code == 201
            uploaded_ids.append(uploaded_image.json()["id"])
            uploaded_urls.append(uploaded_image.json()["url"])

            # Minimal ISO BMFF header exercises the MP4 upload and album MIME path.
            video_bytes = b"\x00\x00\x00\x18ftypisom" + (b"\x00" * 8)
            uploaded_video = await client.post(
                "/api/media/documents",
                headers={
                    **owner,
                    "Content-Type": "video/mp4",
                    "X-Filename": "album-clip.mp4",
                },
                content=video_bytes,
            )
            assert uploaded_video.status_code == 201
            assert uploaded_video.json()["mime_type"] == "video/mp4"
            uploaded_ids.append(uploaded_video.json()["id"])
            uploaded_urls.append(uploaded_video.json()["url"])

            group = await client.post(
                "/api/groups",
                headers=owner,
                json={"title": "Album group", "username": "album_group"},
            )
            assert group.status_code == 201
            group_id = group.json()["id"]
            joined = await client.post(
                f"/api/groups/{group_id}/members",
                headers=owner,
                json={"telegram_id": 89302},
            )
            assert joined.status_code == 201

            group_headers = {**owner, "Idempotency-Key": "group-album-test-0001"}
            group_payload = {"media_ids": uploaded_ids, "body": "Group album caption"}
            group_album = await client.post(
                f"/api/groups/{group_id}/messages/album",
                headers=group_headers,
                json=group_payload,
            )
            assert group_album.status_code == 201
            group_replay = await client.post(
                f"/api/groups/{group_id}/messages/album",
                headers=group_headers,
                json=group_payload,
            )
            assert group_replay.status_code == 201
            assert group_replay.json()["first_message_id"] == group_album.json()["first_message_id"]
            assert group_replay.json()["album_id"] == group_album.json()["album_id"]

            group_items = group_album.json()["messages"]
            assert [item["media_id"] for item in group_items] == uploaded_ids
            assert [item["media_type"] for item in group_items] == ["image/jpeg", "video/mp4"]
            assert [item["media_album_index"] for item in group_items] == [0, 1]
            assert all(item["media_album_count"] == 2 for item in group_items)
            assert group_items[0]["media_album_id"] == group_items[1]["media_album_id"]
            assert group_items[0]["body"] == "Group album caption"
            assert group_items[1]["body"] == ""

            group_history = await client.get(
                f"/api/groups/{group_id}/messages",
                headers=member,
            )
            assert group_history.status_code == 200
            assert [item["media_album_index"] for item in group_history.json()["messages"]] == [0, 1]
            member_download = await client.get(uploaded_urls[0], headers=member)
            assert member_download.status_code == 200
            member_video_range = await client.get(
                uploaded_urls[1],
                headers={**member, "Range": "bytes=0-7"},
            )
            assert member_video_range.status_code == 206
            assert member_video_range.content == video_bytes[:8]
            assert member_video_range.headers["content-range"] == f"bytes 0-7/{len(video_bytes)}"
            invalid_video_range = await client.get(
                uploaded_urls[1],
                headers={**member, "Range": f"bytes={len(video_bytes)}-"},
            )
            assert invalid_video_range.status_code == 416
            assert invalid_video_range.headers["content-range"] == f"bytes */{len(video_bytes)}"
            outsider_post = await client.post(
                f"/api/groups/{group_id}/messages/album",
                headers=outsider,
                json={"media_ids": uploaded_ids},
            )
            assert outsider_post.status_code == 403
            outsider_download = await client.get(uploaded_urls[0], headers=outsider)
            assert outsider_download.status_code == 404

            channel = await client.post(
                "/api/channels",
                headers=owner,
                json={"username": "album_channel", "title": "Album channel"},
            )
            assert channel.status_code == 201
            channel_id = channel.json()["id"]

            channel_headers = {**owner, "Idempotency-Key": "channel-album-test-0001"}
            channel_payload = {"media_ids": uploaded_ids, "body": "Channel album caption"}
            channel_album = await client.post(
                f"/api/channels/{channel_id}/messages/album",
                headers=channel_headers,
                json=channel_payload,
            )
            assert channel_album.status_code == 201
            channel_replay = await client.post(
                f"/api/channels/{channel_id}/messages/album",
                headers=channel_headers,
                json=channel_payload,
            )
            assert channel_replay.status_code == 201
            assert channel_replay.json()["first_message_id"] == channel_album.json()["first_message_id"]
            channel_items = channel_album.json()["messages"]
            assert [item["media_id"] for item in channel_items] == uploaded_ids
            assert [item["media_type"] for item in channel_items] == ["image/jpeg", "video/mp4"]
            assert [item["media_album_index"] for item in channel_items] == [0, 1]
            assert all(item["media_album_count"] == 2 for item in channel_items)
            assert channel_items[0]["media_album_id"] == channel_items[1]["media_album_id"]
            assert channel_items[0]["body"] == "Channel album caption"
            assert channel_items[1]["body"] == ""

            forbidden_channel_post = await client.post(
                f"/api/channels/{channel_id}/messages/album",
                headers=member,
                json={"media_ids": uploaded_ids},
            )
            assert forbidden_channel_post.status_code == 403
            channel_history = await client.get(
                f"/api/channels/{channel_id}/messages",
                headers=outsider,
            )
            assert channel_history.status_code == 200
            assert [item["media_album_index"] for item in channel_history.json()["messages"]] == [0, 1]
            public_download = await client.get(uploaded_urls[1], headers=outsider)
            assert public_download.status_code == 200

    run(scenario())


def test_internal_botfather_create_commands_and_message_runtime(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 86001, "bot_owner")
    add_account(api_env, 86002, "bot_user")
    add_session(path, 86001, "bot-owner-session")
    add_session(path, 86002, "bot-user-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer bot-owner-session"}
            user = {"Authorization": "Bearer bot-user-session"}

            created = await client.post(
                "/api/bots",
                headers=owner,
                json={
                    "name": "WaysGram Helper",
                    "username": "waysgram_helper_bot",
                    "about": "A test bot",                    "description": "Internal bot API test",
                },
            )
            assert created.status_code == 201
            bot_data = created.json()
            bot_id = bot_data["id"]
            token = bot_data["token"]
            assert token.startswith("wgbot_")

            owned = await client.get("/api/bots", headers=owner)
            assert owned.status_code == 200
            assert owned.json()["bots"][0]["username"] == "waysgram_helper_bot"
            assert "token" not in owned.json()["bots"][0]

            commands = await client.put(
                f"/api/bots/{bot_id}/commands",
                headers=owner,
                json={"commands": [
                    {"command": "start", "description": "Start the bot"},
                    {"command": "help", "description": "Show help"},
                ]},
            )
            assert commands.status_code == 200
            assert len(commands.json()["commands"]) == 2

            public = await client.get(
                "/api/bots/by-username/waysgram_helper_bot",
                headers=user,
            )
            assert public.status_code == 200
            assert public.json()["id"] == bot_id

            incoming = await client.post(
                f"/api/bots/{bot_id}/messages",
                headers=user,
                json={"body": "/start"},
            )
            assert incoming.status_code == 201

            bot_headers = {"Authorization": f"Bearer {token}"}
            updates = await client.get("/api/bot-api/getUpdates?offset=0", headers=bot_headers)
            assert updates.status_code == 200
            assert updates.json()["result"][0]["text"] == "/start"
            assert updates.json()["result"][0]["chat_id"] == 86002

            sent = await client.post(
                "/api/bot-api/sendMessage",
                headers=bot_headers,
                json={"chat_id": 86002, "text": "Hello from the internal bot"},
            )
            assert sent.status_code == 200
            assert sent.json()["ok"] is True

            history = await client.get(
                f"/api/bots/{bot_id}/messages",
                headers=user,
            )
            assert [message["sender"] for message in history.json()["messages"]] == ["user", "bot"]
            assert history.json()["messages"][1]["body"] == "Hello from the internal bot"

            reset = await client.post(
                f"/api/bots/{bot_id}/token/reset",
                headers=owner,
            )
            assert reset.status_code == 200
            old_token = await client.get("/api/bot-api/getUpdates", headers=bot_headers)
            assert old_token.status_code == 401
            new_headers = {"Authorization": f"Bearer {reset.json()['token']}"}
            new_token = await client.get("/api/bot-api/getUpdates", headers=new_headers)
            assert new_token.status_code == 200

            revoked = await client.delete(f"/api/bots/{bot_id}", headers=owner)
            assert revoked.status_code == 200
            revoked_token = await client.get("/api/bot-api/getUpdates", headers=new_headers)
            assert revoked_token.status_code == 401

    run(scenario())


def test_telegram_gift_catalog_sync_and_sticker_proxy(api_env, monkeypatch) -> None:
    path, _auth_store, fake_bot, app = api_env
    add_account(api_env, 87001, "telegram_gift_user")
    add_session(path, 87001, "telegram-gift-session")

    remote_gifts = [
        {
            "id": "gift_123",
            "sticker": {
                "file_id": "telegram-file-id",
                "file_unique_id": "telegram-unique-id",
                "type": "regular",
                "width": 512,
                "height": 512,
                "is_animated": False,
                "is_video": False,
                "emoji": "🎁",
                "set_name": "TelegramGifts",
                "mime_type": "image/webp",
            },
            "star_count": 25,
            "upgrade_star_count": 100,
            "is_premium": True,
            "has_colors": True,
            "total_count": 5000,
            "remaining_count": 4500,
            "personal_total_count": 100,
            "personal_remaining_count": 90,
            "unique_gift_variant_count": 12,
            "background": {"center_color": 123, "edge_color": 456, "text_color": 789},
        }
    ]
    fetch_calls: list[str] = []

    async def fake_fetch_telegram_gifts(bot):
        fetch_calls.append(bot.token)
        return remote_gifts

    async def fake_fetch_telegram_sticker(bot, file_id: str, preferred_mime: str = ""):
        assert bot.token == "test-telegram-bot-token"
        assert file_id == "telegram-file-id"
        assert preferred_mime == "image/webp"
        return b"fake-webp-sticker", "image/webp"

    monkeypatch.setattr(messenger_api, "fetch_telegram_gifts", fake_fetch_telegram_gifts)
    monkeypatch.setattr(messenger_api, "fetch_telegram_sticker", fake_fetch_telegram_sticker)

    async def scenario() -> None:
        async with await client_for(app) as client:
            auth = {"Authorization": "Bearer telegram-gift-session"}
            catalog = await client.get("/api/telegram/gifts", headers=auth)
            assert catalog.status_code == 200
            payload = catalog.json()
            assert payload["source"] == "telegram_bot_api"
            assert payload["scope"] == "gifts_available_to_authbot"
            assert payload["currency"] == "stars"
            # The storefront is sale-filtered, but the Android catalog must be able
            # to display every Telegram gift even before a WaysGram price is assigned.
            assert payload["count"] == 0
            full_catalog = await client.get("/api/telegram/gifts?all=1", headers=auth)
            assert full_catalog.status_code == 200
            assert full_catalog.json()["count"] == 1
            assert full_catalog.json()["gifts"][0]["id"] == "gift_123"
            assert full_catalog.json()["gifts"][0]["for_sale"] is False
            with db_split.sqlite_connect(path) as db:
                db.execute(
                    "INSERT INTO telegram_gift_prices(gift_id,price_stars,supply,sold,updated_at) VALUES('gift_123',40,3,0,1)"
                )
            catalog = await client.get("/api/telegram/gifts", headers=auth)
            payload = catalog.json()
            assert payload["count"] == 1

            gift = payload["gifts"][0]
            assert gift["price_stars"] == 40
            assert gift["remaining"] == 3
            assert gift["telegram_star_count"] == 25
            assert gift["id"] == "gift_123"
            assert gift["title"] == "🎁"
            assert gift["star_count"] == 25
            assert gift["upgrade_star_count"] == 100
            assert gift["is_premium"] is True
            assert gift["is_limited"] is True
            assert gift["remaining_count"] == 4500
            assert gift["sticker"]["mime_type"] == "image/webp"
            assert gift["sticker"]["url"] == "/api/telegram/gifts/gift_123/sticker"

            sticker = await client.get(gift["sticker"]["url"], headers=auth)
            assert sticker.status_code == 200
            assert sticker.content == b"fake-webp-sticker"
            assert sticker.headers["content-type"].startswith("image/webp")
            assert "private" in sticker.headers["cache-control"]

            # A second request inside the one-minute cache interval must not call Telegram again.
            second = await client.get("/api/telegram/gifts", headers=auth)
            assert second.status_code == 200
            assert len(fetch_calls) == 1

            with db_split.sqlite_connect(path) as db:
                row = db.execute(
                    "SELECT gift_id,star_count,sticker_file_id,is_available "
                    "FROM telegram_gift_catalog"
                ).fetchone()
                sync_count = db.execute(
                    "SELECT gift_count FROM telegram_gift_sync_state WHERE id=1"
                ).fetchone()[0]
            assert row == ("gift_123", 25, "telegram-file-id", 1)
            assert sync_count == 1

            # Telegram gift records remain a separate catalog and are not purchasable
            # through the internal Gram gift endpoint.
            internal_catalog = await client.get("/api/gifts", headers=auth)
            assert internal_catalog.status_code == 200
            assert internal_catalog.json()["gifts"] == []

    run(scenario())


def test_mtproto_gift_catalog_api_and_sticker_proxy(api_env) -> None:
    path, auth_store, fake_bot, _old_app = api_env
    add_account(api_env, 88001, "mtproto_catalog_user")
    add_session(path, 88001, "mtproto-catalog-session")

    class FakeMTProtoClient:
        def __init__(self):
            self.document = SimpleNamespace(
                id=9901,
                dc_id=2,
                size=512,
                mime_type="image/webp",
                attributes=[],
            )
            self.gift = SimpleNamespace(
                id=987654321,
                title="MTProto Gift",
                sticker=self.document,
                stars=42,
                limited=True,
                sold_out=False,
                birthday=True,
                require_premium=True,
                limited_per_user=True,
                peer_color_available=True,
                auction=True,
                availability_remains=7,
                availability_total=25,
                availability_resale=3,
                convert_stars=8,
                first_sale_date=1700000000,
                last_sale_date=1700000100,
                upgrade_stars=150,
                resell_min_stars=45,
                released_by=None,
                per_user_total=2,
                per_user_remains=1,
                locked_until_date=1700000200,
                auction_slug="mtproto-auction",
                gifts_per_round=10,
                auction_start_date=1700000300,
                upgrade_variants=5,
                background=None,
            )

        async def __call__(self, request):
            return SimpleNamespace(gifts=[self.gift])

        async def download_media(self, document, file=bytes):
            assert document is self.document
            return b"mtproto-gift-sticker"

    mtproto_client = FakeMTProtoClient()
    provider = TelegramMTProtoGiftCatalog(mtproto_client)
    run(provider.sync(path))

    app = FastAPI()
    app.include_router(
        build_messenger_router(
            path,
            auth_store,
            lambda: fake_bot,
            bot_module.account_is_banned,
            lambda: provider,
        )
    )

    async def scenario() -> None:
        async with await client_for(app) as client:
            auth = {"Authorization": "Bearer mtproto-catalog-session"}
            catalog = await client.get("/api/telegram/gifts", headers=auth)
            assert catalog.status_code == 200
            payload = catalog.json()
            assert payload["source"] == "telegram_mtproto"
            assert payload["scope"] == "telegram_full_mtproto_catalog"
            assert payload["currency"] == "stars"
            assert payload["count"] == 0  # hidden until the administrator prices it
            with db_split.sqlite_connect(path) as db:
                db.execute(
                    "INSERT INTO telegram_gift_prices(gift_id,price_stars,supply,sold,updated_at) VALUES('987654321',60,5,0,1)"
                )
            payload = (await client.get("/api/telegram/gifts", headers=auth)).json()
            assert payload["count"] == 1

            gift = payload["gifts"][0]
            assert gift["id"] == "987654321"
            assert gift["title"] == "MTProto Gift"
            assert gift["star_count"] == 42
            assert gift["auction"] is True
            assert gift["sold_out"] is False
            assert gift["require_premium"] is True
            assert gift["total_count"] == 25
            assert gift["remaining_count"] == 7
            assert gift["sticker"]["mime_type"] == "image/webp"

            sticker = await client.get(gift["sticker"]["url"], headers=auth)
            assert sticker.status_code == 200
            assert sticker.content == b"mtproto-gift-sticker"
            assert sticker.headers["content-type"].startswith("image/webp")

    run(scenario())

def test_legacy_admin_gift_serials_are_migrated(api_env) -> None:
    path, _auth_store, _fake_bot, _app = api_env
    now = int(time.time())
    with db_split.sqlite_connect(path) as db:
        cur = db.execute(
            "INSERT INTO gift_catalog(name,price_grams,supply,created_at) VALUES('Legacy Gift',0,0,?)",
            (now,),
        )
        gift_id = int(cur.lastrowid)
        db.execute(
            """INSERT INTO user_gifts(serial_number,gift_id,gift_name,owner_telegram_id,acquired_at)
               VALUES('WG-ABCDEF12',?,?,84001,?)""",
            (gift_id, "Legacy Gift", now),
        )
        db.execute(
            """INSERT INTO gift_transactions(event_type,serial_number,gift_name,
                      from_telegram_id,to_telegram_id,created_at)
               VALUES('admin_grant','WG-ABCDEF12','Legacy Gift',NULL,84001,?)""",
            (now,),
        )

    run(init_messenger_storage(path))
    with db_split.sqlite_connect(path) as db:
        serial = db.execute(
            "SELECT serial_number FROM user_gifts WHERE gift_id=?",
            (gift_id,),
        ).fetchone()[0]
        history_serial = db.execute(
            "SELECT serial_number FROM gift_transactions WHERE gift_name='Legacy Gift'"
        ).fetchone()[0]
    assert len(serial) == 15
    assert serial.startswith("WG-")
    assert all(char in "0123456789ABCDEF" for char in serial[3:])
    assert history_serial == serial


def test_channel_owner_can_change_title_and_username(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 83001, "chowner")
    add_account(api_env, 83002, "chother")
    add_session(path, 83001, "chowner-session")
    add_session(path, 83002, "chother-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer chowner-session"}
            other = {"Authorization": "Bearer chother-session"}
            created = await client.post("/api/channels", headers=owner, json={"title": "First", "username": "first_chan"})
            taken = await client.post("/api/channels", headers=other, json={"title": "Taken", "username": "taken_chan"})
            assert created.status_code == 201 and taken.status_code == 201
            channel_id = created.json()["id"]

            changed = await client.patch(
                f"/api/channels/{channel_id}", headers=owner, json={"title": "Renamed", "username": "renamed_chan"}
            )
            assert changed.status_code == 200
            assert changed.json()["title"] == "Renamed"
            assert changed.json()["username"] == "renamed_chan"

            assert (await client.patch(f"/api/channels/{channel_id}", headers=other, json={"title": "Nope"})).status_code == 403
            assert (await client.patch(f"/api/channels/{channel_id}", headers=owner, json={"username": "taken_chan"})).status_code == 409
            assert (await client.patch(f"/api/channels/{channel_id}", headers=owner, json={"username": "1bad"})).status_code == 400
            assert (await client.patch(f"/api/channels/{channel_id}", headers=owner, json={})).status_code == 400

    run(scenario())


def test_private_channels_hide_content_until_invite_join(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 82101, "private_owner")
    add_account(api_env, 82102, "private_guest")
    add_session(path, 82101, "private-owner-session")
    add_session(path, 82102, "private-guest-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer private-owner-session"}
            guest = {"Authorization": "Bearer private-guest-session"}
            created = await client.post(
                "/api/channels",
                headers=owner,
                json={"title": "Private Room", "is_public": False},
            )
            assert created.status_code == 201
            private = created.json()
            assert private["is_public"] is False
            assert private["username"] == ""
            assert private["invite_link"].startswith("http://test/api/channels/invites/")
            channel_id = private["id"]

            private_post = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=owner,
                json={"body": "Private event payload"},
            )
            assert private_post.status_code == 201
            private_event = await client.delete(
                f"/api/channels/{channel_id}/messages/{private_post.json()['id']}",
                headers=owner,
            )
            assert private_event.status_code == 200

            events_before_join = await client.get("/api/events?after_id=0", headers=guest)
            assert events_before_join.status_code == 200
            assert not any(
                event.get("scope") == "channel" and event.get("chat_id") == channel_id
                for event in events_before_join.json()["events"]
            )

            preview = await client.get(private["invite_link"])
            assert preview.status_code == 200
            assert preview.json()["channel_id"] == channel_id
            assert preview.json()["is_public"] is False

            hidden = await client.get("/api/channels", headers=guest)
            assert hidden.status_code == 200
            assert all(item["id"] != channel_id for item in hidden.json()["channels"])

            denied_details = await client.get(f"/api/channels/{channel_id}", headers=guest)
            denied_messages = await client.get(
                f"/api/channels/{channel_id}/messages",
                headers=guest,
            )
            assert denied_details.status_code == 403
            assert denied_messages.status_code == 403
            denied_read_marker = await client.put(
                "/api/read",
                headers=guest,
                json={"scope": "channel", "peer_id": channel_id, "last_read_id": 0},
            )
            assert denied_read_marker.status_code == 403

            joined = await client.post(
                "/api/channels/join",
                headers=guest,
                json={"invite_link": private["invite_link"]},
            )
            assert joined.status_code == 200
            assert joined.json()["joined"] is True
            assert joined.json()["id"] == channel_id

            events_after_join = await client.get("/api/events?after_id=0", headers=guest)
            assert events_after_join.status_code == 200
            assert any(
                event.get("scope") == "channel" and event.get("chat_id") == channel_id
                for event in events_after_join.json()["events"]
            )

            visible = await client.get("/api/channels", headers=guest)
            assert any(item["id"] == channel_id and item["is_public"] == 0
                       for item in visible.json()["channels"])
            details = await client.get(f"/api/channels/{channel_id}", headers=guest)
            history = await client.get(f"/api/channels/{channel_id}/messages", headers=guest)
            assert details.status_code == 200
            assert details.json()["is_public"] == 0
            assert history.status_code == 200
            allowed_read_marker = await client.put(
                "/api/read",
                headers=guest,
                json={"scope": "channel", "peer_id": channel_id, "last_read_id": 0},
            )
            assert allowed_read_marker.status_code == 200

            invalid = await client.post(
                "/api/channels/join",
                headers=guest,
                json={"invite_token": "not-a-valid-invite"},
            )
            assert invalid.status_code == 400

    run(scenario())



def test_private_channel_title_updates_preserve_internal_usernames(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 82111, "private_edit_owner")
    add_session(path, 82111, "private-edit-owner-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer private-edit-owner-session"}
            first = await client.post(
                "/api/channels",
                headers=owner,
                json={"title": "Private One", "is_public": False},
            )
            second = await client.post(
                "/api/channels",
                headers=owner,
                json={"title": "Private Two", "is_public": False},
            )
            assert first.status_code == 201
            assert second.status_code == 201

            first_id = first.json()["id"]
            second_id = second.json()["id"]
            renamed_first = await client.patch(
                f"/api/channels/{first_id}",
                headers=owner,
                json={"title": "Private One Renamed"},
            )
            renamed_second = await client.patch(
                f"/api/channels/{second_id}",
                headers=owner,
                json={"title": "Private Two Renamed"},
            )
            assert renamed_first.status_code == 200
            assert renamed_second.status_code == 200
            assert renamed_first.json()["username"] == ""
            assert renamed_second.json()["username"] == ""
            assert renamed_first.json()["is_public"] is False
            assert renamed_second.json()["is_public"] is False

            rejected = await client.patch(
                f"/api/channels/{first_id}",
                headers=owner,
                json={"username": "should_not_be_public"},
            )
            assert rejected.status_code == 400

    run(scenario())



def test_video_audio_and_zip_uploads_are_validated_and_private(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89211, "media_sender")
    add_account(api_env, 89212, "media_recipient")
    add_account(api_env, 89213, "media_intruder")
    add_session(path, 89211, "media-sender-session")
    add_session(path, 89212, "media-recipient-session")
    add_session(path, 89213, "media-intruder-session")

    fixtures = (
        ("video/mp4", "clip.mp4", b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00", "video/mp4", "inline"),
        ("audio/mpeg", "voice.mp3", b"ID3\x04\x00\x00\x00\x00\x00\x00\xff\xfb", "audio/mpeg", "inline"),
        ("audio/mp4", "voice.m4a", b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00", "audio/mp4", "inline"),
        ("application/zip", "bundle.zip", b"PK\x03\x04\x14\x00\x00\x00\x00\x00", "application/zip", "attachment"),
    )

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer media-sender-session"}
            recipient = {"Authorization": "Bearer media-recipient-session"}
            intruder = {"Authorization": "Bearer media-intruder-session"}

            invalid_video = await client.post(
                "/api/media/documents",
                headers={**sender, "Content-Type": "video/mp4", "X-Filename": "fake.mp4"},
                content=b"not a video",
            )
            assert invalid_video.status_code == 415

            for index, (declared_type, filename, payload, expected_type, disposition) in enumerate(fixtures):
                uploaded = await client.post(
                    "/api/media/documents",
                    headers={
                        **sender,
                        "Content-Type": declared_type,
                        "X-Filename": filename,
                    },
                    content=payload,
                )
                assert uploaded.status_code == 201
                media = uploaded.json()
                assert media["mime_type"] == expected_type

                sent = await client.post(
                    "/api/messages",
                    headers=sender,
                    json={
                        "recipient_id": 89212,
                        "body": "media attachment " + str(index),
                        "media_id": media["id"],
                    },
                )
                assert sent.status_code == 201
                assert sent.json()["media_type"] == expected_type

                downloaded = await client.get(media["url"], headers=recipient)
                assert downloaded.status_code == 200
                assert downloaded.headers["content-type"].startswith(expected_type)
                actual_disposition = downloaded.headers.get("content-disposition", "")
                assert actual_disposition == disposition or actual_disposition.startswith(disposition + ";")
                assert downloaded.content == payload

                forbidden = await client.get(media["url"], headers=intruder)
                assert forbidden.status_code == 404

    run(scenario())


def test_video_note_upload_is_persisted_and_exposed_in_dm_history(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89401, "video_note_sender")
    add_account(api_env, 89402, "video_note_recipient")
    add_session(path, 89401, "video-note-sender-session")
    add_session(path, 89402, "video-note-recipient-session")

    video_bytes = b"\x00\x00\x00\x18ftypisom" + (b"\x00" * 32)

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer video-note-sender-session"}
            recipient = {"Authorization": "Bearer video-note-recipient-session"}

            uploaded = await client.post(
                "/api/media/documents",
                headers={
                    **sender,
                    "Content-Type": "video/mp4",
                    "X-Filename": "round-video.mp4",
                    "X-Media-Kind": "video_note",
                },
                content=video_bytes,
            )
            assert uploaded.status_code == 201
            media = uploaded.json()
            assert media["mime_type"] == "video/mp4"
            assert media["media_kind"] == "video_note"

            sent = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89402,
                    "body": "Видеосообщение",
                    "media_id": media["id"],
                },
            )
            assert sent.status_code == 201
            assert sent.json()["media_kind"] == "video_note"

            history = await client.get("/api/messages?with=89401", headers=recipient)
            assert history.status_code == 200
            assert history.json()["messages"][-1]["media_kind"] == "video_note"

            search = await client.get(
                "/api/messages/search?with=89401&q=Видеосообщение",
                headers=recipient,
            )
            assert search.status_code == 200
            assert search.json()["messages"][-1]["media_kind"] == "video_note"

            downloaded = await client.get(media["url"], headers=recipient)
            assert downloaded.status_code == 200
            assert downloaded.content == video_bytes

            invalid_kind = await client.post(
                "/api/media/documents",
                headers={
                    **sender,
                    "Content-Type": "video/mp4",
                    "X-Filename": "ordinary-video.mp4",
                    "X-Media-Kind": "not_a_real_kind",
                },
                content=video_bytes,
            )
            assert invalid_kind.status_code == 400

            invalid_format = await client.post(
                "/api/media/documents",
                headers={
                    **sender,
                    "Content-Type": "audio/mp4",
                    "X-Filename": "audio.m4a",
                    "X-Media-Kind": "video_note",
                },
                content=b"\x00\x00\x00\x18ftypM4A " + (b"\x00" * 16),
            )
            assert invalid_format.status_code == 415

    run(scenario())


def test_direct_messages_support_structured_contact_cards(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89501, "contact_sender")
    add_account(api_env, 89502, "contact_recipient")
    add_session(path, 89501, "contact-sender-session")
    add_session(path, 89502, "contact-recipient-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer contact-sender-session"}
            recipient = {"Authorization": "Bearer contact-recipient-session"}
            payload = {
                "recipient_id": 89502,
                "contact": {
                    "name": "Sample Contact",
                    "phone": "+31 6 12345678",
                    "email": "sample@example.com",
                },
            }
            sent = await client.post("/api/messages", headers=sender, json=payload)
            assert sent.status_code == 201
            assert sent.json()["body"] == "Контакт: Sample Contact"
            assert sent.json()["contact"] == {
                "name": "Sample Contact",
                "phone": "+31 6 12345678",
                "email": "sample@example.com",
            }

            history = await client.get("/api/messages?with=89501", headers=recipient)
            assert history.status_code == 200
            message = history.json()["messages"][-1]
            assert message["contact_name"] == "Sample Contact"
            assert message["contact_phone"] == "+31 6 12345678"
            assert message["contact_email"] == "sample@example.com"

            search = await client.get(
                "/api/messages/search?with=89501&q=Sample%20Contact",
                headers=recipient,
            )
            assert search.status_code == 200
            assert search.json()["messages"][-1]["contact_phone"] == "+31 6 12345678"

            bad_phone = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89502,
                    "contact": {"name": "Bad Contact", "phone": "not a phone"},
                },
            )
            assert bad_phone.status_code == 400

            bad_email = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89502,
                    "contact": {
                        "name": "Bad Contact",
                        "phone": "+31 6 12345678",
                        "email": "invalid-email",
                    },
                },
            )
            assert bad_email.status_code == 400

            mixed = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89502,
                    "media_id": "f" * 32,
                    "contact": {"name": "Bad Contact", "phone": "+31 6 12345678"},
                },
            )
            assert mixed.status_code == 400

    run(scenario())


def test_direct_messages_support_explicit_location_sharing(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89601, "location_sender")
    add_account(api_env, 89602, "location_recipient")
    add_session(path, 89601, "location-sender-session")
    add_session(path, 89602, "location-recipient-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer location-sender-session"}
            recipient = {"Authorization": "Bearer location-recipient-session"}
            sent = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89602,
                    "location": {
                        "latitude": 51.5074,
                        "longitude": -0.1278,
                        "label": "London",
                    },
                },
            )
            assert sent.status_code == 201
            assert sent.json()["body"] == "London"
            assert sent.json()["location"] == {
                "latitude": 51.5074,
                "longitude": -0.1278,
                "label": "London",
            }

            history = await client.get("/api/messages?with=89601", headers=recipient)
            assert history.status_code == 200
            message = history.json()["messages"][-1]
            assert message["location_latitude"] == 51.5074
            assert message["location_longitude"] == -0.1278
            assert message["location_label"] == "London"

            search = await client.get(
                "/api/messages/search?with=89601&q=London",
                headers=recipient,
            )
            assert search.status_code == 200
            assert search.json()["messages"][-1]["location_latitude"] == 51.5074

            invalid_latitude = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89602,
                    "location": {"latitude": 91, "longitude": 0},
                },
            )
            assert invalid_latitude.status_code == 400

            invalid_longitude = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89602,
                    "location": {"latitude": 0, "longitude": 181},
                },
            )
            assert invalid_longitude.status_code == 400

            invalid_nan = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89602,
                    "location": {"latitude": "NaN", "longitude": 0},
                },
            )
            assert invalid_nan.status_code == 400

            invalid_boolean = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89602,
                    "location": {"latitude": True, "longitude": 0},
                },
            )
            assert invalid_boolean.status_code == 400

            mixed = await client.post(
                "/api/messages",
                headers=sender,
                json={
                    "recipient_id": 89602,
                    "body": "Location with contact",
                    "location": {"latitude": 0, "longitude": 0},
                    "contact": {"name": "Sample", "phone": "+31 6 12345678"},
                },
            )
            assert mixed.status_code == 400

    run(scenario())


def test_saved_messages_support_self_chat_without_unread_count(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    user_id = 82301
    add_account(api_env, user_id, "saved_user")
    add_session(path, user_id, "saved-messages-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            headers = {"Authorization": "Bearer saved-messages-session"}
            sent = await client.post(
                "/api/messages",
                headers=headers,
                json={"recipient_id": user_id, "body": "Note to myself"},
            )
            assert sent.status_code == 201
            assert sent.json()["sender_id"] == user_id
            assert sent.json()["recipient_id"] == user_id

            history = await client.get(
                f"/api/messages?with={user_id}",
                headers=headers,
            )
            assert history.status_code == 200
            assert [item["body"] for item in history.json()["messages"]] == ["Note to myself"]

            conversations = await client.get("/api/conversations", headers=headers)
            assert conversations.status_code == 200
            saved = next(item for item in conversations.json()["conversations"] if item["id"] == user_id)
            assert saved["last_message"] == "Note to myself"
            assert saved["unread_count"] == 0

    run(scenario())


def test_private_channel_invite_uses_configured_public_api_base_url(api_env, monkeypatch) -> None:
    _path, _auth_store, _fake_bot, app = api_env
    user_id = 82121
    add_account(api_env, user_id, "invite_host_owner")
    add_session(_path, user_id, "invite-host-owner-session")
    monkeypatch.setenv("PUBLIC_API_BASE_URL", "https://bot-1793554244-6434-weterochina.bothost.tech")

    async def scenario() -> None:
        async with await client_for(app) as client:
            response = await client.post(
                "/api/channels",
                headers={"Authorization": "Bearer invite-host-owner-session"},
                json={"title": "Invite Host Test", "is_public": False},
            )
            assert response.status_code == 201
            invite_link = response.json()["invite_link"]
            assert invite_link.startswith(
                "https://bot-1793554244-6434-weterochina.bothost.tech/api/channels/invites/"
            )
            assert "http://test" not in invite_link

    run(scenario())

def test_message_reactions_cover_direct_group_channel_access_and_limits(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89401, "reaction_owner")
    add_account(api_env, 89402, "reaction_peer")
    add_account(api_env, 89403, "reaction_outsider")
    add_session(path, 89401, "reaction-owner-session")
    add_session(path, 89402, "reaction-peer-session")
    add_session(path, 89403, "reaction-outsider-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer reaction-owner-session"}
            peer = {"Authorization": "Bearer reaction-peer-session"}
            outsider = {"Authorization": "Bearer reaction-outsider-session"}

            direct = await client.post(
                "/api/messages",
                headers=owner,
                json={"recipient_id": 89402, "body": "react to this direct message"},
            )
            assert direct.status_code == 201
            direct_id = direct.json()["id"]
            direct_path = f"/api/messages/{direct_id}/reactions"
            event_cursor_response = await client.get("/api/events", headers=owner)
            assert event_cursor_response.status_code == 200
            direct_event_cursor = event_cursor_response.json()["latest_id"]

            invalid = await client.post(direct_path, headers=peer, json={"reaction": "🔥"})
            assert invalid.status_code == 400

            hidden = await client.post(direct_path, headers=outsider, json={"reaction": "👍"})
            assert hidden.status_code == 404

            pending_events_started = time.monotonic()
            pending_events = asyncio.create_task(
                client.get(
                    f"/api/events?after_id={direct_event_cursor}&wait_seconds=20",
                    headers=owner,
                )
            )
            await asyncio.sleep(0.05)

            first = await client.post(direct_path, headers=peer, json={"reaction": "👍"})
            assert first.status_code == 200
            delivered_events = await asyncio.wait_for(pending_events, timeout=3.0)
            assert delivered_events.status_code == 200
            assert time.monotonic() - pending_events_started < 3.0
            assert any(
                event["kind"] == "reaction"
                and event["scope"] == "dm"
                and event["message_id"] == direct_id
                for event in delivered_events.json()["events"]
            )

            second = await client.post(direct_path, headers=peer, json={"reaction": "❤️"})
            third = await client.post(direct_path, headers=peer, json={"reaction": "😂"})
            assert first.status_code == second.status_code == third.status_code == 200
            assert first.json()["status"] == "added"
            assert first.json()["my_reactions"] == ["👍"]
            assert {item["reaction"] for item in third.json()["reactions"]} == {"👍", "❤️", "😂"}

            over_limit = await client.post(direct_path, headers=peer, json={"reaction": "😮"})
            assert over_limit.status_code == 409

            removed = await client.post(direct_path, headers=peer, json={"reaction": "👍"})
            assert removed.status_code == 200
            assert removed.json()["status"] == "removed"
            assert "👍" not in removed.json()["my_reactions"]

            after_remove = await client.post(direct_path, headers=peer, json={"reaction": "😮"})
            assert after_remove.status_code == 200
            direct_events = await client.get(
                f"/api/events?after_id={direct_event_cursor}",
                headers=owner,
            )
            assert direct_events.status_code == 200
            assert any(
                event["kind"] == "reaction"
                and event["scope"] == "dm"
                and event["message_id"] == direct_id
                for event in direct_events.json()["events"]
            )
            event_cursor = direct_events.json()["latest_id"]
            direct_history = await client.get("/api/messages?with=89402", headers=owner)
            assert direct_history.status_code == 200
            direct_summary = direct_history.json()["messages"][0]["reaction_summary"]
            assert direct_history.json()["messages"][0]["my_reactions"] == []
            peer_direct_history = await client.get("/api/messages?with=89401", headers=peer)
            assert peer_direct_history.status_code == 200
            assert peer_direct_history.json()["messages"][0]["my_reactions"] == ["❤️", "😂", "😮"]
            assert "❤️:1" in direct_summary
            assert "😂:1" in direct_summary
            assert "😮:1" in direct_summary
            assert "👍" not in direct_summary

            group = await client.post(
                "/api/groups",
                headers=owner,
                json={"title": "Reaction group", "username": "reaction_group"},
            )
            assert group.status_code == 201
            group_id = group.json()["id"]
            joined = await client.post(
                f"/api/groups/{group_id}/members",
                headers=owner,
                json={"telegram_id": 89402},
            )
            assert joined.status_code == 201

            group_message = await client.post(
                f"/api/groups/{group_id}/messages",
                headers=owner,
                json={"body": "react to the group message"},
            )
            assert group_message.status_code == 201
            group_id_message = group_message.json()["id"]
            group_reaction_path = (
                f"/api/groups/{group_id}/messages/{group_id_message}/reactions"
            )
            group_reaction = await client.post(
                group_reaction_path,
                headers=peer,
                json={"reaction": "🎉"},
            )
            assert group_reaction.status_code == 200
            assert group_reaction.json()["reactions"] == [{"reaction": "🎉", "count": 1}]
            group_events = await client.get(
                f"/api/events?after_id={event_cursor}",
                headers=owner,
            )
            assert group_events.status_code == 200
            assert any(
                event["kind"] == "reaction"
                and event["scope"] == "group"
                and event["chat_id"] == group_id
                and event["message_id"] == group_id_message
                for event in group_events.json()["events"]
            )
            event_cursor = group_events.json()["latest_id"]

            denied_group_reaction = await client.post(
                group_reaction_path,
                headers=outsider,
                json={"reaction": "🙏"},
            )
            assert denied_group_reaction.status_code == 403

            group_history = await client.get(
                f"/api/groups/{group_id}/messages",
                headers=owner,
            )
            assert group_history.status_code == 200
            assert group_history.json()["messages"][0]["reaction_summary"] == "🎉:1"
            assert group_history.json()["messages"][0]["my_reactions"] == []
            peer_group_history = await client.get(f"/api/groups/{group_id}/messages", headers=peer)
            assert peer_group_history.status_code == 200
            assert peer_group_history.json()["messages"][0]["my_reactions"] == ["🎉"]

            channel = await client.post(
                "/api/channels",
                headers=owner,
                json={"username": "reaction_channel", "title": "Reaction channel"},
            )
            assert channel.status_code == 201
            channel_id = channel.json()["id"]
            channel_message = await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=owner,
                json={"body": "react to the channel post"},
            )
            assert channel_message.status_code == 201
            channel_reaction = await client.post(
                f"/api/channels/{channel_id}/messages/{channel_message.json()['id']}/reactions",
                headers=peer,
                json={"reaction": "🙏"},
            )
            assert channel_reaction.status_code == 200
            assert channel_reaction.json()["reactions"] == [{"reaction": "🙏", "count": 1}]
            channel_events = await client.get(
                f"/api/events?after_id={event_cursor}",
                headers=owner,
            )
            assert channel_events.status_code == 200
            assert any(
                event["kind"] == "reaction"
                and event["scope"] == "channel"
                and event["chat_id"] == channel_id
                and event["message_id"] == channel_message.json()["id"]
                for event in channel_events.json()["events"]
            )

            channel_history = await client.get(
                f"/api/channels/{channel_id}/messages",
                headers=owner,
            )
            assert channel_history.status_code == 200
            assert channel_history.json()["messages"][0]["reaction_summary"] == "🙏:1"
            assert channel_history.json()["messages"][0]["my_reactions"] == []
            peer_channel_history = await client.get(
                f"/api/channels/{channel_id}/messages", headers=peer
            )
            assert peer_channel_history.status_code == 200
            assert peer_channel_history.json()["messages"][0]["my_reactions"] == ["🙏"]

    run(scenario())

def test_profile_avatar_upload_set_remove_and_owner_isolation(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89501, "avatar_owner")
    add_account(api_env, 89502, "avatar_other")
    add_session(path, 89501, "avatar-owner-session")
    add_session(path, 89502, "avatar-other-session")

    image_buffer = BytesIO()
    Image.new("RGB", (4, 3), (80, 120, 180)).save(image_buffer, format="PNG")
    image_bytes = image_buffer.getvalue()

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer avatar-owner-session"}
            other = {"Authorization": "Bearer avatar-other-session"}

            uploaded = await client.post(
                "/api/media/images",
                headers={**owner, "Content-Type": "image/png"},
                content=image_bytes,
            )
            assert uploaded.status_code == 201
            media_id = uploaded.json()["id"]

            foreign_assignment = await client.put(
                "/api/me/avatar",
                headers=other,
                json={"media_id": media_id},
            )
            assert foreign_assignment.status_code == 404

            assigned = await client.put(
                "/api/me/avatar",
                headers=owner,
                json={"media_id": media_id},
            )
            assert assigned.status_code == 200
            assert assigned.json()["avatar_media_id"] == media_id

            profile = await client.get("/api/me", headers=owner)
            assert profile.status_code == 200
            assert profile.json()["avatar_media_id"] == media_id

            removed = await client.delete("/api/me/avatar", headers=owner)
            assert removed.status_code == 200
            assert removed.json()["avatar_media_id"] == ""

            refreshed = await client.get("/api/me", headers=owner)
            assert refreshed.status_code == 200
            assert refreshed.json()["avatar_media_id"] == ""

    run(scenario())


def test_cloud_drafts_sync_and_enforce_chat_access(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 95101, "draft_owner")
    add_account(api_env, 95102, "draft_member")
    add_account(api_env, 95103, "draft_outsider")
    add_session(path, 95101, "draft-owner-session")
    add_session(path, 95102, "draft-member-session")
    add_session(path, 95103, "draft-outsider-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer draft-owner-session"}
            member = {"Authorization": "Bearer draft-member-session"}
            outsider = {"Authorization": "Bearer draft-outsider-session"}

            # DM drafts are private to the account that created them, even when
            # both participants can access the conversation itself.
            saved_dm = await client.put(
                "/api/drafts", headers=owner,
                json={"scope": "dm", "peer_id": 95102, "body": "private DM draft"},
            )
            assert saved_dm.status_code == 200
            own_dm = await client.get(
                "/api/drafts", headers=owner, params={"scope": "dm", "peer_id": 95102},
            )
            assert own_dm.json()["draft"]["body"] == "private DM draft"
            other_dm = await client.get(
                "/api/drafts", headers=member, params={"scope": "dm", "peer_id": 95101},
            )
            assert other_dm.status_code == 200 and other_dm.json()["draft"] is None

            # Group drafts require current membership and remain per-user.
            created_group = await client.post(
                "/api/groups", headers=owner,
                json={"title": "Draft Group", "username": "draft_group", "description": ""},
            )
            assert created_group.status_code == 201
            group_id = created_group.json()["id"]
            joined = await client.post(
                f"/api/groups/{group_id}/members", headers=owner,
                json={"username": "draft_member"},
            )
            assert joined.status_code == 201
            saved_group = await client.put(
                "/api/drafts", headers=owner,
                json={"scope": "group", "peer_id": group_id, "body": "owner group draft"},
            )
            assert saved_group.status_code == 200
            member_group = await client.get(
                "/api/drafts", headers=member, params={"scope": "group", "peer_id": group_id},
            )
            assert member_group.status_code == 200 and member_group.json()["draft"] is None
            assert (await client.get(
                "/api/drafts", headers=outsider, params={"scope": "group", "peer_id": group_id},
            )).status_code == 403

            # Private channel drafts are inaccessible before invite join.
            created_channel = await client.post(
                "/api/channels", headers=owner,
                json={"title": "Draft Channel", "is_public": False},
            )
            assert created_channel.status_code == 201
            channel_id = created_channel.json()["id"]
            invite_link = created_channel.json()["invite_link"]
            saved_channel = await client.put(
                "/api/drafts", headers=owner,
                json={"scope": "channel", "peer_id": channel_id, "body": "owner channel draft"},
            )
            assert saved_channel.status_code == 200
            denied_channel = await client.get(
                "/api/drafts", headers=member, params={"scope": "channel", "peer_id": channel_id},
            )
            assert denied_channel.status_code == 403
            joined_channel = await client.post(
                "/api/channels/join", headers=member, json={"invite_link": invite_link},
            )
            assert joined_channel.status_code == 200
            member_channel = await client.get(
                "/api/drafts", headers=member, params={"scope": "channel", "peer_id": channel_id},
            )
            assert member_channel.status_code == 200 and member_channel.json()["draft"] is None

            # Draft size and scope are validated; clearing is idempotent.
            too_large = await client.put(
                "/api/drafts", headers=owner,
                json={"scope": "dm", "peer_id": 95102, "body": "x" * 4001},
            )
            assert too_large.status_code == 400
            deleted = await client.delete(
                "/api/drafts", headers=owner, params={"scope": "dm", "peer_id": 95102},
            )
            assert deleted.status_code == 200 and deleted.json()["status"] == "deleted"
            missing = await client.delete(
                "/api/drafts", headers=owner, params={"scope": "dm", "peer_id": 95102},
            )
            assert missing.status_code == 200 and missing.json()["status"] == "not_found"
            assert (await client.get(
                "/api/drafts", headers=owner, params={"scope": "dm", "peer_id": 95102},
            )).json()["draft"] is None

    run(scenario())


def test_contact_notes_are_private_and_removed_with_contact(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 95201, "note_owner")
    add_account(api_env, 95202, "note_contact")
    add_session(path, 95201, "note-owner-session")
    add_session(path, 95202, "note-contact-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer note-owner-session"}
            contact = {"Authorization": "Bearer note-contact-session"}
            added = await client.post("/api/contacts", headers=owner, json={"user_id": 95202})
            assert added.status_code == 201
            saved = await client.put(
                "/api/contacts/95202/note", headers=owner,
                json={"note": "Met through the WaysGram project"},
            )
            assert saved.status_code == 200
            owner_list = await client.get("/api/contacts", headers=owner)
            assert owner_list.status_code == 200
            assert owner_list.json()["contacts"][0]["note"] == "Met through the WaysGram project"

            # The other account has a separate contact record and cannot read this note.
            reverse_added = await client.post("/api/contacts", headers=contact, json={"user_id": 95201})
            assert reverse_added.status_code == 201
            reverse_list = await client.get("/api/contacts", headers=contact)
            assert reverse_list.status_code == 200
            assert reverse_list.json()["contacts"][0]["note"] == ""

            invalid = await client.put(
                "/api/contacts/95202/note", headers=owner, json={"note": "x" * 501},
            )
            assert invalid.status_code == 400
            removed = await client.delete("/api/contacts/95202", headers=owner)
            assert removed.status_code == 200
            readded = await client.post("/api/contacts", headers=owner, json={"user_id": 95202})
            assert readded.status_code == 201
            cleared = await client.get("/api/contacts", headers=owner)
            assert cleared.json()["contacts"][0]["note"] == ""

            not_a_contact = await client.put(
                "/api/contacts/95202/note", headers=contact, json={"note": "Not permitted"},
            )
            assert not_a_contact.status_code == 404

    run(scenario())



def test_pinned_messages_cover_direct_group_and_channel_permissions(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 95301, "pin_owner")
    add_account(api_env, 95302, "pin_peer")
    add_account(api_env, 95303, "pin_admin")
    add_account(api_env, 95304, "pin_member")
    add_account(api_env, 95305, "pin_outsider")
    for user_id, token in [
        (95301, "pin-owner-session"),
        (95302, "pin-peer-session"),
        (95303, "pin-admin-session"),
        (95304, "pin-member-session"),
        (95305, "pin-outsider-session"),
    ]:
        add_session(path, user_id, token)

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer pin-owner-session"}
            peer = {"Authorization": "Bearer pin-peer-session"}
            admin = {"Authorization": "Bearer pin-admin-session"}
            member = {"Authorization": "Bearer pin-member-session"}
            outsider = {"Authorization": "Bearer pin-outsider-session"}

            # Direct messages: either participant can pin and unpin, outsiders cannot.
            direct = await client.post(
                "/api/messages", headers=owner,
                json={"recipient_id": 95302, "body": "Pin this direct message"},
            )
            assert direct.status_code == 201
            direct_id = direct.json()["id"]
            pinned_dm = await client.post(
                "/api/pins", headers=peer,
                json={"scope": "dm", "peer_id": 95301, "message_id": direct_id},
            )
            assert pinned_dm.status_code == 200 and pinned_dm.json()["status"] == "pinned"
            duplicate_dm = await client.post(
                "/api/pins", headers=owner,
                json={"scope": "dm", "peer_id": 95302, "message_id": direct_id},
            )
            assert duplicate_dm.status_code == 200 and duplicate_dm.json()["status"] == "already_pinned"
            listed_dm = await client.get(
                "/api/pins", headers=owner, params={"scope": "dm", "peer_id": 95302},
            )
            assert listed_dm.status_code == 200
            assert listed_dm.json()["pinned_messages"][0]["body"] == "Pin this direct message"
            denied_dm = await client.post(
                "/api/pins", headers=outsider,
                json={"scope": "dm", "peer_id": 95301, "message_id": direct_id},
            )
            assert denied_dm.status_code == 404
            unpinned_dm = await client.delete(
                "/api/pins", headers=owner,
                params={"scope": "dm", "peer_id": 95302, "message_id": direct_id},
            )
            assert unpinned_dm.status_code == 200 and unpinned_dm.json()["status"] == "unpinned"

            # Groups: only owners and admins can pin; all members can read the pin list.
            created_group = await client.post(
                "/api/groups", headers=owner,
                json={"title": "Pinned Group", "username": "pinned_group", "description": ""},
            )
            assert created_group.status_code == 201
            group_id = created_group.json()["id"]
            for username in ("pin_admin", "pin_member"):
                joined = await client.post(
                    f"/api/groups/{group_id}/members", headers=owner,
                    json={"username": username},
                )
                assert joined.status_code == 201
            promoted = await client.post(
                f"/api/groups/{group_id}/admins", headers=owner,
                json={"telegram_id": 95303},
            )
            assert promoted.status_code == 201
            group_post = await client.post(
                f"/api/groups/{group_id}/messages", headers=member,
                json={"body": "Pin this group message"},
            )
            assert group_post.status_code == 201
            group_message_id = group_post.json()["id"]
            denied_group = await client.post(
                "/api/pins", headers=member,
                json={"scope": "group", "peer_id": group_id, "message_id": group_message_id},
            )
            assert denied_group.status_code == 403
            pinned_group = await client.post(
                "/api/pins", headers=admin,
                json={"scope": "group", "peer_id": group_id, "message_id": group_message_id},
            )
            assert pinned_group.status_code == 200
            listed_group = await client.get(
                "/api/pins", headers=member, params={"scope": "group", "peer_id": group_id},
            )
            assert listed_group.status_code == 200
            assert listed_group.json()["count"] == 1
            denied_group_list = await client.get(
                "/api/pins", headers=outsider, params={"scope": "group", "peer_id": group_id},
            )
            assert denied_group_list.status_code == 403

            # Channels: viewers can read pins, while only channel admins can change them.
            created_channel = await client.post(
                "/api/channels", headers=owner,
                json={"title": "Pinned Channel", "username": "pinned_channel"},
            )
            assert created_channel.status_code == 201
            channel_id = created_channel.json()["id"]
            channel_post = await client.post(
                f"/api/channels/{channel_id}/messages", headers=owner,
                json={"body": "Pin this channel post"},
            )
            assert channel_post.status_code == 201
            channel_message_id = channel_post.json()["id"]
            appointed = await client.post(
                f"/api/channels/{channel_id}/admins", headers=owner,
                json={"telegram_id": 95303},
            )
            assert appointed.status_code == 201
            denied_channel = await client.post(
                "/api/pins", headers=member,
                json={"scope": "channel", "peer_id": channel_id, "message_id": channel_message_id},
            )
            assert denied_channel.status_code == 403
            pinned_channel = await client.post(
                "/api/pins", headers=admin,
                json={"scope": "channel", "peer_id": channel_id, "message_id": channel_message_id},
            )
            assert pinned_channel.status_code == 200
            listed_channel = await client.get(
                "/api/pins", headers=outsider,
                params={"scope": "channel", "peer_id": channel_id},
            )
            assert listed_channel.status_code == 200
            assert listed_channel.json()["pinned_messages"][0]["body"] == "Pin this channel post"
            removed_channel_pin = await client.delete(
                "/api/pins", headers=owner,
                params={"scope": "channel", "peer_id": channel_id, "message_id": channel_message_id},
            )
            assert removed_channel_pin.status_code == 200

    run(scenario())



def test_typing_indicators_expire_and_respect_chat_membership(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 95401, "typing_owner")
    add_account(api_env, 95402, "typing_peer")
    add_account(api_env, 95403, "typing_outsider")
    add_session(path, 95401, "typing-owner-session")
    add_session(path, 95402, "typing-peer-session")
    add_session(path, 95403, "typing-outsider-session")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer typing-owner-session"}
            peer = {"Authorization": "Bearer typing-peer-session"}
            outsider = {"Authorization": "Bearer typing-outsider-session"}

            started = await client.put(
                "/api/typing", headers=peer,
                json={"scope": "dm", "peer_id": 95401, "is_typing": True},
            )
            assert started.status_code == 200
            assert started.json()["expires_at"] > 0
            visible = await client.get(
                "/api/typing", headers=owner,
                params={"scope": "dm", "peer_id": 95402},
            )
            assert visible.status_code == 200
            assert [item["id"] for item in visible.json()["typing_users"]] == [95402]
            assert "phone" not in str(visible.json())

            # The typing state is directional: the sender does not see their own indicator.
            own = await client.get(
                "/api/typing", headers=peer,
                params={"scope": "dm", "peer_id": 95401},
            )
            assert own.status_code == 200 and own.json()["count"] == 0

            stopped = await client.put(
                "/api/typing", headers=peer,
                json={"scope": "dm", "peer_id": 95401, "is_typing": False},
            )
            assert stopped.status_code == 200 and stopped.json()["expires_at"] is None
            cleared = await client.get(
                "/api/typing", headers=owner,
                params={"scope": "dm", "peer_id": 95402},
            )
            assert cleared.status_code == 200 and cleared.json()["count"] == 0

            invalid = await client.put(
                "/api/typing", headers=peer,
                json={"scope": "dm", "peer_id": 95401, "is_typing": "yes"},
            )
            assert invalid.status_code == 400

            # Blocking either direction prevents typing state from being shared.
            blocked = await client.post("/api/blocks", headers=owner, json={"user_id": 95402})
            assert blocked.status_code == 201
            denied_dm = await client.put(
                "/api/typing", headers=peer,
                json={"scope": "dm", "peer_id": 95401, "is_typing": True},
            )
            assert denied_dm.status_code == 403
            await client.delete("/api/blocks/95402", headers=owner)

            # Group typing is visible only to current members.
            created = await client.post(
                "/api/groups", headers=owner,
                json={"title": "Typing Group", "username": "typing_group", "description": ""},
            )
            assert created.status_code == 201
            group_id = created.json()["id"]
            joined = await client.post(
                f"/api/groups/{group_id}/members", headers=owner,
                json={"username": "typing_peer"},
            )
            assert joined.status_code == 201
            group_started = await client.put(
                "/api/typing", headers=peer,
                json={"scope": "group", "peer_id": group_id, "is_typing": True},
            )
            assert group_started.status_code == 200
            group_visible = await client.get(
                "/api/typing", headers=owner,
                params={"scope": "group", "peer_id": group_id},
            )
            assert group_visible.status_code == 200
            assert [item["id"] for item in group_visible.json()["typing_users"]] == [95402]
            denied_group = await client.get(
                "/api/typing", headers=outsider,
                params={"scope": "group", "peer_id": group_id},
            )
            assert denied_group.status_code == 403

            # Expired state is removed and never shown as current activity.
            with db_split.sqlite_connect(path) as db:
                db.execute(
                    "UPDATE typing_indicators SET expires_at=? WHERE scope='group' AND chat_id=?",
                    (int(time.time()) - 1, group_id),
                )
            expired = await client.get(
                "/api/typing", headers=owner,
                params={"scope": "group", "peer_id": group_id},
            )
            assert expired.status_code == 200 and expired.json()["count"] == 0

    run(scenario())



def test_public_profile_shows_only_mutual_contacts_and_common_groups(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    for user_id, username in [
        (95501, "common_viewer"),
        (95502, "common_profile"),
        (95503, "common_person"),
        (95504, "viewer_only"),
        (95505, "target_only"),
    ]:
        add_account(api_env, user_id, username)
    for user_id, token in [
        (95501, "common-viewer-session"),
        (95502, "common-profile-session"),
    ]:
        add_session(path, user_id, token)

    async def scenario() -> None:
        async with await client_for(app) as client:
            viewer = {"Authorization": "Bearer common-viewer-session"}
            target = {"Authorization": "Bearer common-profile-session"}

            # One private group is shared; the other groups are deliberately not.
            shared_group = await client.post(
                "/api/groups", headers=viewer,
                json={"title": "Shared Group", "username": "shared_group", "description": ""},
            )
            assert shared_group.status_code == 201
            shared_id = shared_group.json()["id"]
            joined = await client.post(
                f"/api/groups/{shared_id}/members", headers=viewer,
                json={"telegram_id": 95502},
            )
            assert joined.status_code == 201

            viewer_group = await client.post(
                "/api/groups", headers=viewer,
                json={"title": "Viewer Only", "username": "viewer_only_group", "description": ""},
            )
            assert viewer_group.status_code == 201
            target_group = await client.post(
                "/api/groups", headers=target,
                json={"title": "Target Only", "username": "target_only_group", "description": ""},
            )
            assert target_group.status_code == 201

            # Mutual contacts are the intersection of the two private contact lists.
            for user_id in (95503, 95504):
                added = await client.post("/api/contacts", headers=viewer, json={"user_id": user_id})
                assert added.status_code == 201
            for user_id in (95503, 95505):
                added = await client.post("/api/contacts", headers=target, json={"user_id": user_id})
                assert added.status_code == 201

            response = await client.get("/api/users/95502", headers=viewer)
            assert response.status_code == 200
            profile = response.json()
            assert [group["id"] for group in profile["common_groups"]] == [shared_id]
            assert [contact["id"] for contact in profile["common_contacts"]] == [95503]
            assert "phone" not in profile
            assert "stars" not in profile
            assert "token" not in str(profile)

    run(scenario())



def test_shared_media_history_filters_and_enforces_access(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 95601, "shared_owner")
    add_account(api_env, 95602, "shared_peer")
    add_account(api_env, 95603, "shared_outsider")
    add_session(path, 95601, "shared-owner-session")
    add_session(path, 95602, "shared-peer-session")
    add_session(path, 95603, "shared-outsider-session")

    image_buffer = BytesIO()
    Image.new("RGB", (4, 4), (40, 90, 160)).save(image_buffer, format="PNG")
    image_bytes = image_buffer.getvalue()

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer shared-owner-session"}
            peer = {"Authorization": "Bearer shared-peer-session"}
            outsider = {"Authorization": "Bearer shared-outsider-session"}

            first_upload = await client.post(
                "/api/media/images", headers={**owner, "Content-Type": "image/png"}, content=image_bytes,
            )
            second_upload = await client.post(
                "/api/media/images", headers={**peer, "Content-Type": "image/png"}, content=image_bytes,
            )
            assert first_upload.status_code == second_upload.status_code == 201
            first_media_id = first_upload.json()["id"]
            second_media_id = second_upload.json()["id"]

            first_message = await client.post(
                "/api/messages", headers=owner,
                json={"recipient_id": 95602, "media_id": first_media_id},
            )
            second_message = await client.post(
                "/api/messages", headers=peer,
                json={"recipient_id": 95601, "media_id": second_media_id},
            )
            assert first_message.status_code == second_message.status_code == 201

            first_page = await client.get(
                "/api/media/shared", headers=owner,
                params={"scope": "dm", "peer_id": 95602, "kind": "image", "limit": 1},
            )
            assert first_page.status_code == 200
            assert first_page.json()["count"] == 1
            assert first_page.json()["has_more"] is True
            assert first_page.json()["media"][0]["media_type"] == "image/png"
            assert first_page.json()["media"][0]["url"].startswith("/api/media/")
            second_page = await client.get(
                "/api/media/shared", headers=owner,
                params={
                    "scope": "dm", "peer_id": 95602,
                    "kind": "image", "before_id": first_page.json()["next_before_id"],
                },
            )
            assert second_page.status_code == 200
            assert second_page.json()["count"] == 1
            assert second_page.json()["has_more"] is False
            assert first_page.json()["media"][0]["message_id"] > second_page.json()["media"][0]["message_id"]

            document_filter = await client.get(
                "/api/media/shared", headers=owner,
                params={"scope": "dm", "peer_id": 95602, "kind": "document"},
            )
            assert document_filter.status_code == 200 and document_filter.json()["count"] == 0
            outsider_dm = await client.get(
                "/api/media/shared", headers=outsider,
                params={"scope": "dm", "peer_id": 95601},
            )
            assert outsider_dm.status_code == 200 and outsider_dm.json()["count"] == 0

            # Group media is visible to members but not outsiders.
            group = await client.post(
                "/api/groups", headers=owner,
                json={"title": "Shared Media Group", "username": "shared_media_group"},
            )
            assert group.status_code == 201
            group_id = group.json()["id"]
            joined = await client.post(
                f"/api/groups/{group_id}/members", headers=owner,
                json={"telegram_id": 95602},
            )
            assert joined.status_code == 201
            group_post = await client.post(
                f"/api/groups/{group_id}/messages", headers=owner,
                json={"media_id": first_media_id},
            )
            assert group_post.status_code == 201
            group_media = await client.get(
                "/api/media/shared", headers=peer,
                params={"scope": "group", "peer_id": group_id},
            )
            assert group_media.status_code == 200 and group_media.json()["count"] == 1
            group_denied = await client.get(
                "/api/media/shared", headers=outsider,
                params={"scope": "group", "peer_id": group_id},
            )
            assert group_denied.status_code == 403

            # Private-channel media requires invite membership.
            channel = await client.post(
                "/api/channels", headers=owner,
                json={"title": "Private Shared Media", "is_public": False},
            )
            assert channel.status_code == 201
            channel_id = channel.json()["id"]
            channel_post = await client.post(
                f"/api/channels/{channel_id}/messages", headers=owner,
                json={"media_id": first_media_id},
            )
            assert channel_post.status_code == 201
            channel_denied = await client.get(
                "/api/media/shared", headers=peer,
                params={"scope": "channel", "peer_id": channel_id},
            )
            assert channel_denied.status_code == 403
            joined_channel = await client.post(
                "/api/channels/join", headers=peer,
                json={"invite_link": channel.json()["invite_link"]},
            )
            assert joined_channel.status_code == 200
            channel_media = await client.get(
                "/api/media/shared", headers=peer,
                params={"scope": "channel", "peer_id": channel_id, "kind": "image"},
            )
            assert channel_media.status_code == 200 and channel_media.json()["count"] == 1

    run(scenario())



def test_group_invites_enforce_expiry_usage_limits_and_admin_permissions(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    for user_id, username in [
        (95701, "invite_owner"),
        (95702, "invite_admin"),
        (95703, "invite_member"),
        (95704, "invite_guest"),
    ]:
        add_account(api_env, user_id, username)
        add_session(path, user_id, f"group-invite-session-{user_id}")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer group-invite-session-95701"}
            admin = {"Authorization": "Bearer group-invite-session-95702"}
            member = {"Authorization": "Bearer group-invite-session-95703"}
            guest = {"Authorization": "Bearer group-invite-session-95704"}

            created = await client.post(
                "/api/groups", headers=owner,
                json={"title": "Invite Group", "username": "invite_group", "description": ""},
            )
            assert created.status_code == 201
            group_id = created.json()["id"]

            joined_admin = await client.post(
                f"/api/groups/{group_id}/members", headers=owner,
                json={"telegram_id": 95702},
            )
            assert joined_admin.status_code == 201
            promoted = await client.post(
                f"/api/groups/{group_id}/admins", headers=owner,
                json={"telegram_id": 95702},
            )
            assert promoted.status_code == 201

            denied_member_create = await client.post(
                f"/api/groups/{group_id}/invites", headers=member,
                json={"expires_in_hours": 24},
            )
            assert denied_member_create.status_code == 403

            invalid_limit = await client.post(
                f"/api/groups/{group_id}/invites", headers=admin,
                json={"expires_in_hours": 24, "max_uses": 0},
            )
            assert invalid_limit.status_code == 400

            invite = await client.post(
                f"/api/groups/{group_id}/invites", headers=admin,
                json={"expires_in_hours": 24, "max_uses": 1},
            )
            assert invite.status_code == 201
            invite_link = invite.json()["invite_link"]
            assert invite_link.startswith("/api/groups/invites/") is False
            token = invite_link.rsplit("/", 1)[-1]
            assert len(token) >= 20

            with db_split.sqlite_connect(path) as db:
                stored_hash = db.execute(
                    "SELECT token_hash FROM group_invites WHERE group_id=?",
                    (group_id,),
                ).fetchone()[0]
                assert stored_hash != token
                assert stored_hash == hashlib.sha256(token.encode()).hexdigest()

            preview = await client.get(invite_link)
            assert preview.status_code == 200
            assert preview.json()["group_id"] == group_id
            assert preview.json()["title"] == "Invite Group"

            joined = await client.post(
                "/api/groups/join", headers=guest,
                json={"invite_link": invite_link},
            )
            assert joined.status_code == 200
            assert joined.json()["joined"] is True
            assert joined.json()["already_member"] is False

            repeated = await client.post(
                "/api/groups/join", headers=guest,
                json={"invite_token": token},
            )
            assert repeated.status_code == 200
            assert repeated.json()["already_member"] is True

            exhausted = await client.post(
                "/api/groups/join", headers=member,
                json={"invite_link": invite_link},
            )
            assert exhausted.status_code == 410

            outsider_revoke = await client.delete(
                f"/api/groups/{group_id}/invites/{token}", headers=member,
            )
            assert outsider_revoke.status_code == 403

            second_invite = await client.post(
                f"/api/groups/{group_id}/invites", headers=owner,
                json={"expires_in_hours": 24},
            )
            assert second_invite.status_code == 201
            second_token = second_invite.json()["invite_link"].rsplit("/", 1)[-1]
            revoked = await client.delete(
                f"/api/groups/{group_id}/invites/{second_token}", headers=admin,
            )
            assert revoked.status_code == 200
            assert (await client.get(second_invite.json()["invite_link"])).status_code == 404
            revoked_join = await client.post(
                "/api/groups/join", headers=member,
                json={"invite_token": second_token},
            )
            assert revoked_join.status_code == 404

            # Expired links remain unusable even when a valid token is supplied.
            expiring = await client.post(
                f"/api/groups/{group_id}/invites", headers=owner,
                json={"expires_in_hours": 1},
            )
            assert expiring.status_code == 201
            expiring_token = expiring.json()["invite_link"].rsplit("/", 1)[-1]
            with db_split.sqlite_connect(path) as db:
                db.execute(
                    "UPDATE group_invites SET expires_at=? WHERE token_hash=?",
                    (int(time.time()) - 1, hashlib.sha256(expiring_token.encode()).hexdigest()),
                )
            expired_preview = await client.get(expiring.json()["invite_link"])
            assert expired_preview.status_code == 404
            expired_join = await client.post(
                "/api/groups/join", headers=member,
                json={"invite_token": expiring_token},
            )
            assert expired_join.status_code == 410

    run(scenario())



def test_group_invite_join_requests_require_admin_approval(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    for user_id, username in [
        (95801, "approval_owner"),
        (95802, "approval_admin"),
        (95803, "approval_member"),
        (95804, "approval_guest"),
    ]:
        add_account(api_env, user_id, username)
        add_session(path, user_id, f"group-approval-session-{user_id}")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer group-approval-session-95801"}
            admin = {"Authorization": "Bearer group-approval-session-95802"}
            member = {"Authorization": "Bearer group-approval-session-95803"}
            guest = {"Authorization": "Bearer group-approval-session-95804"}

            created = await client.post(
                "/api/groups", headers=owner,
                json={"title": "Approval Group", "username": "approval_group", "description": ""},
            )
            assert created.status_code == 201
            group_id = created.json()["id"]
            joined_admin = await client.post(
                f"/api/groups/{group_id}/members", headers=owner,
                json={"telegram_id": 95802},
            )
            assert joined_admin.status_code == 201
            promoted = await client.post(
                f"/api/groups/{group_id}/admins", headers=owner,
                json={"telegram_id": 95802},
            )
            assert promoted.status_code == 201

            invite = await client.post(
                f"/api/groups/{group_id}/invites", headers=admin,
                json={"expires_in_hours": 24, "max_uses": 1, "require_approval": True},
            )
            assert invite.status_code == 201
            assert invite.json()["require_approval"] is True
            link = invite.json()["invite_link"]
            token = link.rsplit("/", 1)[-1]

            preview = await client.get(link)
            assert preview.status_code == 200
            assert preview.json()["require_approval"] is True

            request = await client.post(
                "/api/groups/join", headers=guest,
                json={"invite_link": link},
            )
            assert request.status_code == 200
            assert request.json()["join_requested"] is True
            assert request.json()["joined"] is False
            assert (await client.get(f"/api/groups/{group_id}", headers=guest)).status_code == 403

            repeated = await client.post(
                "/api/groups/join", headers=guest,
                json={"invite_token": token},
            )
            assert repeated.status_code == 200
            assert repeated.json()["join_requested"] is True

            listed = await client.get(
                f"/api/groups/{group_id}/join-requests", headers=admin,
            )
            assert listed.status_code == 200
            assert listed.json()["count"] == 1
            assert listed.json()["requests"][0]["telegram_id"] == 95804
            denied_list = await client.get(
                f"/api/groups/{group_id}/join-requests", headers=member,
            )
            assert denied_list.status_code == 403

            denied_approve = await client.post(
                f"/api/groups/{group_id}/join-requests/95804/approve", headers=member,
            )
            assert denied_approve.status_code == 403

            approved = await client.post(
                f"/api/groups/{group_id}/join-requests/95804/approve", headers=admin,
            )
            assert approved.status_code == 200
            assert approved.json()["approved"] is True
            assert approved.json()["joined"] is True
            joined_details = await client.get(f"/api/groups/{group_id}", headers=guest)
            assert joined_details.status_code == 200
            assert joined_details.json()["my_role"] == "member"
            with db_split.sqlite_connect(path) as db:
                uses = db.execute(
                    "SELECT uses FROM group_invites WHERE token_hash=?",
                    (hashlib.sha256(token.encode()).hexdigest(),),
                ).fetchone()[0]
                assert uses == 1

            exhausted = await client.post(
                "/api/groups/join", headers=member,
                json={"invite_token": token},
            )
            assert exhausted.status_code == 410

            declined_invite = await client.post(
                f"/api/groups/{group_id}/invites", headers=owner,
                json={"expires_in_hours": 24, "require_approval": True},
            )
            assert declined_invite.status_code == 201
            declined_token = declined_invite.json()["invite_link"].rsplit("/", 1)[-1]
            declined_request = await client.post(
                "/api/groups/join", headers=member,
                json={"invite_token": declined_token},
            )
            assert declined_request.status_code == 200
            assert declined_request.json()["join_requested"] is True
            declined = await client.post(
                f"/api/groups/{group_id}/join-requests/95803/decline", headers=owner,
            )
            assert declined.status_code == 200
            assert declined.json()["declined"] is True
            declined_list = await client.get(
                f"/api/groups/{group_id}/join-requests", headers=owner,
            )
            assert declined_list.status_code == 200
            assert declined_list.json()["count"] == 0

            # A user may submit a new request after the previous one was declined.
            requested_again = await client.post(
                "/api/groups/join", headers=member,
                json={"invite_token": declined_token},
            )
            assert requested_again.status_code == 200
            assert requested_again.json()["join_requested"] is True

    run(scenario())



def test_group_slow_mode_enforces_per_member_interval_and_admin_exemption(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    for user_id, username in [
        (95901, "slow_owner"),
        (95902, "slow_admin"),
        (95903, "slow_member"),
        (95904, "slow_outsider"),
    ]:
        add_account(api_env, user_id, username)
        add_session(path, user_id, f"slow-mode-session-{user_id}")

    async def scenario() -> None:
        async with await client_for(app) as client:
            owner = {"Authorization": "Bearer slow-mode-session-95901"}
            admin = {"Authorization": "Bearer slow-mode-session-95902"}
            member = {"Authorization": "Bearer slow-mode-session-95903"}
            outsider = {"Authorization": "Bearer slow-mode-session-95904"}

            created = await client.post(
                "/api/groups", headers=owner,
                json={"title": "Slow Mode Group", "username": "slow_mode_group", "description": ""},
            )
            assert created.status_code == 201
            group_id = created.json()["id"]
            for user_id in (95902, 95903):
                joined = await client.post(
                    f"/api/groups/{group_id}/members", headers=owner,
                    json={"telegram_id": user_id},
                )
                assert joined.status_code == 201
            promoted = await client.post(
                f"/api/groups/{group_id}/admins", headers=owner,
                json={"telegram_id": 95902},
            )
            assert promoted.status_code == 201

            invalid_bool = await client.put(
                f"/api/groups/{group_id}/slow-mode", headers=owner,
                json={"seconds": True},
            )
            assert invalid_bool.status_code == 400
            invalid_value = await client.put(
                f"/api/groups/{group_id}/slow-mode", headers=owner,
                json={"seconds": 7},
            )
            assert invalid_value.status_code == 400

            denied = await client.put(
                f"/api/groups/{group_id}/slow-mode", headers=member,
                json={"seconds": 10},
            )
            assert denied.status_code == 403

            enabled = await client.put(
                f"/api/groups/{group_id}/slow-mode", headers=admin,
                json={"seconds": 10},
            )
            assert enabled.status_code == 200
            assert enabled.json()["slow_mode_seconds"] == 10

            details = await client.get(f"/api/groups/{group_id}", headers=member)
            assert details.status_code == 200
            assert details.json()["slow_mode_seconds"] == 10

            first = await client.post(
                f"/api/groups/{group_id}/messages", headers=member,
                json={"body": "First message"},
            )
            assert first.status_code == 201

            blocked = await client.post(
                f"/api/groups/{group_id}/messages", headers=member,
                json={"body": "Too soon"},
            )
            assert blocked.status_code == 429
            assert blocked.headers.get("retry-after") is not None
            assert "Медленный режим" in blocked.json()["detail"]

            # Simulate elapsed delay without making the suite sleep.
            with db_split.sqlite_connect(path) as db:
                db.execute(
                    "UPDATE group_messages SET created_at=? WHERE id=?",
                    (int(time.time()) - 11, first.json()["id"]),
                )
            after_wait = await client.post(
                f"/api/groups/{group_id}/messages", headers=member,
                json={"body": "Delay elapsed"},
            )
            assert after_wait.status_code == 201

            # Group administrators are not held by member slow mode.
            admin_first = await client.post(
                f"/api/groups/{group_id}/messages", headers=admin,
                json={"body": "Admin message one"},
            )
            admin_second = await client.post(
                f"/api/groups/{group_id}/messages", headers=admin,
                json={"body": "Admin message two"},
            )
            assert admin_first.status_code == admin_second.status_code == 201

            outsider_message = await client.post(
                f"/api/groups/{group_id}/messages", headers=outsider,
                json={"body": "Not a member"},
            )
            assert outsider_message.status_code == 403

            disabled = await client.put(
                f"/api/groups/{group_id}/slow-mode", headers=owner,
                json={"seconds": 0},
            )
            assert disabled.status_code == 200
            unrestricted_first = await client.post(
                f"/api/groups/{group_id}/messages", headers=member,
                json={"body": "Slow mode disabled one"},
            )
            unrestricted_second = await client.post(
                f"/api/groups/{group_id}/messages", headers=member,
                json={"body": "Slow mode disabled two"},
            )
            assert unrestricted_first.status_code == unrestricted_second.status_code == 201

    run(scenario())



def test_push_device_registration_is_bound_to_the_active_session(api_env, monkeypatch) -> None:
    path, _auth_store, _fake_bot, app = api_env
    monkeypatch.setenv("FCM_SERVICE_ACCOUNT_JSON", "")
    monkeypatch.setenv("FCM_SERVICE_ACCOUNT_FILE", "")
    add_account(api_env, 96101, "push_owner")
    add_account(api_env, 96102, "push_second")
    add_session(path, 96101, "push-owner-session")
    add_session(path, 96101, "push-owner-other-session")
    add_session(path, 96102, "push-second-session")
    device_token = "fcm-test-registration-token-96101"

    async def scenario() -> None:
        async with await client_for(app) as client:
            missing_auth = await client.post(
                "/api/push/register",
                json={"token": device_token},
            )
            assert missing_auth.status_code == 401

            owner = {"Authorization": "Bearer push-owner-session"}
            second = {"Authorization": "Bearer push-second-session"}
            invalid = await client.post(
                "/api/push/register",
                headers=owner,
                json={"token": "short"},
            )
            assert invalid.status_code == 400

            unsupported = await client.post(
                "/api/push/register",
                headers=owner,
                json={"token": device_token, "platform": "ios"},
            )
            assert unsupported.status_code == 400

            registered = await client.post(
                "/api/push/register",
                headers=owner,
                json={"token": device_token, "platform": "android"},
            )
            assert registered.status_code == 200
            assert registered.json() == {"status": "registered", "platform": "android"}

            token_hash = hashlib.sha256(device_token.encode()).hexdigest()
            session_hash = hashlib.sha256(b"push-owner-session").hexdigest()
            with db_split.sqlite_connect(path) as db:
                record = db.execute(
                    """SELECT token_hash,token_value,telegram_id,session_token_hash,platform
                       FROM push_devices WHERE token_hash=?""",
                    (token_hash,),
                ).fetchone()
            assert record == (token_hash, device_token, 96101, session_hash, "android")

            # A token moved to a different authenticated account cannot remain attached
            # to the previous account or session.
            moved = await client.post(
                "/api/push/register",
                headers=second,
                json={"token": device_token},
            )
            assert moved.status_code == 200
            with db_split.sqlite_connect(path) as db:
                rows = db.execute(
                    """SELECT telegram_id,session_token_hash FROM push_devices
                       WHERE token_hash=?""",
                    (token_hash,),
                ).fetchall()
            assert rows == [(
                96102,
                hashlib.sha256(b"push-second-session").hexdigest(),
            )]

            # Re-register on the first account, then revoke that specific session.
            registered_again = await client.post(
                "/api/push/register",
                headers=owner,
                json={"token": device_token},
            )
            assert registered_again.status_code == 200
            survivor = {"Authorization": "Bearer push-owner-other-session"}
            revoked = await client.post(
                "/api/auth/sessions/revoke-others",
                headers=survivor,
            )
            assert revoked.status_code == 200
            with db_split.sqlite_connect(path) as db:
                remaining = db.execute(
                    "SELECT COUNT(*) FROM push_devices WHERE token_hash=?",
                    (token_hash,),
                ).fetchone()[0]
                old_session = db.execute(
                    "SELECT COUNT(*) FROM api_sessions WHERE token_hash=?",
                    (session_hash,),
                ).fetchone()[0]
            assert remaining == 0
            assert old_session == 0

            config = await client.get("/api/config")
            assert config.status_code == 200
            assert config.json()["push_notifications"] is True
            assert config.json()["push_delivery_ready"] is False

    run(scenario())


def test_firebase_service_account_assertion_is_signed() -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    import base64
    import json

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    credentials = {
        "project_id": "waysgram-test",
        "client_email": "push-test@example.invalid",
        "private_key": private_pem,
    }
    assertion = messenger_api._firebase_assertion(credentials, 1_800_000_000)
    header_part, claims_part, signature_part = assertion.split(".")
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    header = json.loads(decode(header_part))
    claims = json.loads(decode(claims_part))
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert claims["iss"] == credentials["client_email"]
    assert claims["scope"] == messenger_api.FCM_SCOPE
    assert claims["iat"] == 1_800_000_000
    assert claims["exp"] == 1_800_003_600
    private_key.public_key().verify(
        decode(signature_part),
        f"{header_part}.{claims_part}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_direct_message_media_album_is_atomic_grouped_and_private(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89501, "album_sender")
    add_account(api_env, 89502, "album_recipient")
    add_account(api_env, 89503, "album_intruder")
    add_session(path, 89501, "album-sender-session")
    add_session(path, 89502, "album-recipient-session")
    add_session(path, 89503, "album-intruder-session")

    image_bytes = BytesIO()
    Image.new("RGB", (3, 2), (80, 120, 180)).save(image_bytes, format="PNG")
    image_payload = image_bytes.getvalue()

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer album-sender-session"}
            recipient = {"Authorization": "Bearer album-recipient-session"}
            intruder = {"Authorization": "Bearer album-intruder-session"}

            media_ids = []
            uploaded_image = await client.post(
                "/api/media/images",
                headers={**sender, "Content-Type": "image/png"},
                content=image_payload,
            )
            assert uploaded_image.status_code == 201
            media_ids.append(uploaded_image.json()["id"])

            video_bytes = b"\x00\x00\x00\x18ftypisom" + (b"\x00" * 8)
            uploaded_video = await client.post(
                "/api/media/documents",
                headers={
                    **sender,
                    "Content-Type": "video/mp4",
                    "X-Filename": "direct-album-clip.mp4",
                },
                content=video_bytes,
            )
            assert uploaded_video.status_code == 201
            assert uploaded_video.json()["mime_type"] == "video/mp4"
            media_ids.append(uploaded_video.json()["id"])

            payload = {
                "recipient_id": 89502,
                "body": "Фото с поездки",
                "media_ids": media_ids,
            }
            sent = await client.post(
                "/api/messages/album",
                headers={**sender, "Idempotency-Key": "album-idempotency-key-0001"},
                json=payload,
            )
            assert sent.status_code == 201
            album = sent.json()
            assert album["status"] == "sent"
            assert album["count"] == 2
            assert len(album["messages"]) == 2
            album_id = album["album_id"]
            assert len(album_id) == 32
            assert [item["media_album_index"] for item in album["messages"]] == [0, 1]
            assert [item["media_type"] for item in album["messages"]] == ["image/png", "video/mp4"]
            assert all(item["media_album_id"] == album_id for item in album["messages"])
            assert all(item["media_album_count"] == 2 for item in album["messages"])
            assert album["messages"][0]["body"] == "Фото с поездки"
            assert album["messages"][1]["body"] == ""

            repeated = await client.post(
                "/api/messages/album",
                headers={**sender, "Idempotency-Key": "album-idempotency-key-0001"},
                json=payload,
            )
            assert repeated.status_code == 201
            assert repeated.json()["album_id"] == album_id
            assert [item["id"] for item in repeated.json()["messages"]] == [
                item["id"] for item in album["messages"]
            ]

            history = await client.get("/api/messages?with=89501", headers=recipient)
            assert history.status_code == 200
            received = [
                item for item in history.json()["messages"]
                if item.get("media_album_id") == album_id
            ]
            assert len(received) == 2
            assert [item["media_album_index"] for item in received] == [0, 1]

            for media_id in media_ids:
                allowed = await client.get(f"/api/media/{media_id}", headers=recipient)
                denied = await client.get(f"/api/media/{media_id}", headers=intruder)
                assert allowed.status_code == 200
                assert denied.status_code == 404

    run(scenario())
