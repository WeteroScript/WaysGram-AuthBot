from __future__ import annotations

import asyncio
from io import BytesIO
import hashlib
import sqlite3
import time
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



def test_system_gift_auction_refunds_outbid_user_and_settles_winner(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 84001, "first_bidder")
    add_account(api_env, 84002, "second_bidder")
    add_session(path, 84001, "first-bidder-session")
    add_session(path, 84002, "second-bidder-session")
    now = int(time.time())
    with sqlite3.connect(path) as db:
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

            with sqlite3.connect(path) as db:
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

            with sqlite3.connect(path) as db:
                db.execute(
                    "UPDATE gift_auctions SET ends_at=? WHERE id=1",
                    (int(time.time()) - 1,),
                )

            auctions = await client.get("/api/auctions", headers=first)
            assert auctions.status_code == 200
            assert auctions.json()["auctions"][0]["status"] == "ended"

            with sqlite3.connect(path) as db:
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
                    "about": "A test bot",
                    "description": "Internal bot API test",
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
            assert payload["currency"] == "telegram_stars"
            assert payload["count"] == 1

            gift = payload["gifts"][0]
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

            with sqlite3.connect(path) as db:
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
            assert payload["currency"] == "telegram_stars"
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
