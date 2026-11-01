from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import time
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bot as bot_module
from messenger_api import build_messenger_router, init_messenger_storage


class FakeBot:
    def __init__(self) -> None:
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
    with sqlite3.connect(path) as db:
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

            with sqlite3.connect(path) as db:
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

            conversations = await client.get("/api/conversations", headers=sender)
            assert conversations.status_code == 200
            assert conversations.json()["conversations"][0]["id"] == 82002

            created = await client.post(
                "/api/channels",
                headers=sender,
                json={"username": "alpha_news", "title": "Alpha News"},
            )
            assert created.status_code == 201
            channel_id = created.json()["id"]

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


def test_gift_purchase_is_idempotent_and_transfer_updates_inventory(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 83001, "buyer")
    add_account(api_env, 83002, "receiver")
    add_session(path, 83001, "buyer-session")
    add_session(path, 83002, "receiver-session")
    with sqlite3.connect(path) as db:
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

            with sqlite3.connect(path) as db:
                supply = db.execute("SELECT supply FROM gift_catalog WHERE id=1").fetchone()[0]
                transaction_count = db.execute("SELECT COUNT(*) FROM economy_transactions WHERE reason='gift_purchase:1'").fetchone()[0]
                gift_history_count = db.execute("SELECT COUNT(*) FROM gift_transactions WHERE serial_number=?", (serial,)).fetchone()[0]
            assert supply == 0
            assert transaction_count == 1
            assert gift_history_count == 2

    run(scenario())


def test_legacy_admin_gift_serials_are_migrated(api_env) -> None:
    path, _auth_store, _fake_bot, _app = api_env
    now = int(time.time())
    with sqlite3.connect(path) as db:
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
    with sqlite3.connect(path) as db:
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
