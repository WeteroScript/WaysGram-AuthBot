import asyncio
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI

import bot as bot_module
import db_split
import messenger_api
from messenger_api import build_messenger_router, init_messenger_storage
from test_messenger_api import FakeBot, add_account, add_session, client_for, run

ADMIN = 99001


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    store = bot_module.Store(path)
    store.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(store.init())
    run(bot_module.init_admin_storage())
    run(init_messenger_storage(path))
    fake_bot = FakeBot()
    app = FastAPI()
    app.include_router(
        build_messenger_router(path, store, lambda: fake_bot, bot_module.account_is_banned, admin_id=ADMIN)
    )

    async def fake_fetch(bot):
        return [
            {"id": "g1", "sticker": {"file_id": "f1", "file_unique_id": "u1", "type": "regular", "width": 512,
                                     "height": 512, "is_animated": False, "is_video": False, "emoji": "🎁",
                                     "mime_type": "image/webp"}, "star_count": 25},
            {"id": "g2", "sticker": {"file_id": "f2", "file_unique_id": "u2", "type": "regular", "width": 512,
                                     "height": 512, "is_animated": False, "is_video": False, "emoji": "🧸",
                                     "mime_type": "image/webp"}, "star_count": 50},
        ]

    monkeypatch.setattr(messenger_api, "fetch_telegram_gifts", fake_fetch)
    for uid, name in ((ADMIN, "boss"), (101, "buyer"), (102, "friend")):
        number = run(store.allocate_number(uid)) if False else None
        run(store.upsert_user(uid, uid))
        run(store.set_verified(uid, True))
        number = run(store.allocate_number(uid))
        run(bot_module.ensure_account(uid, number, name, f"User {uid}"))
        add_session(path, uid, f"s{uid}-session-token")
    return path, app


def headers(uid: int) -> dict[str, str]:
    return {"Authorization": f"Bearer s{uid}-session-token"}


def test_gifts_are_hidden_until_admin_sets_price_and_supply(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            hidden = (await client.get("/api/telegram/gifts", headers=headers(101))).json()
            assert hidden["count"] == 0
            # The full list is available to the app (it needs it to draw owned gifts); nothing in it is for sale.
            full = (await client.get("/api/telegram/gifts?all=1", headers=headers(101))).json()
            assert full["count"] == 2 and not any(g["for_sale"] for g in full["gifts"])
            everything = (await client.get("/api/telegram/gifts?all=1", headers=headers(ADMIN))).json()
            assert {g["id"] for g in everything["gifts"]} == {"g1", "g2"}
            assert all(g["price_stars"] == 0 and g["for_sale"] is False for g in everything["gifts"])

            # Price and stock are managed only through the AuthBot Telegram admin panel,
            # not through authenticated app REST sessions, even for the admin account.
            denied_user = await client.patch("/api/admin/telegram-gifts/g1", headers=headers(101), json={"price_stars": 5})
            denied_admin = await client.patch("/api/admin/telegram-gifts/g1", headers=headers(ADMIN), json={"price_stars": 40, "supply": 2})
            assert denied_user.status_code in (404, 405)
            assert denied_admin.status_code in (404, 405)
            await bot_module.set_telegram_gift_values("g1", price=40, supply=2)

            shown = (await client.get("/api/telegram/gifts", headers=headers(101))).json()
            assert [g["id"] for g in shown["gifts"]] == ["g1"]
            assert shown["gifts"][0]["price_stars"] == 40 and shown["gifts"][0]["remaining"] == 2
            assert (await client.patch("/api/admin/telegram-gifts/g1", headers=headers(ADMIN), json={"price_stars": -1})).status_code in (404, 405)

    run(scenario())


def test_buying_a_gift_charges_stars_and_reduces_stock(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            await bot_module.set_telegram_gift_values("g1", price=40, supply=2)
            # Client-supplied price and stock values must never override the
            # AuthBot administrator's configured listing.
            bought = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={"price_stars": 1, "supply": 9999},
            )
            assert bought.status_code == 201
            assert bought.json()["price_stars"] == 40
            assert bought.json()["stars"] == 5000 - 40
            mine = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert len(mine) == 1 and mine[0]["gift_name"] == "🎁"
            assert mine[0]["telegram_gift_id"] == "g1"
            assert bought.json()["gift"]["telegram_gift_id"] == "g1"

            # A gift for a friend ends up in the friend's inventory, the buyer pays.
            sent = await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={"recipient_id": 102})
            assert sent.status_code == 201
            assert sent.json()["stars"] == 5000 - 80
            assert len((await client.get("/api/me/gifts", headers=headers(102))).json()["gifts"]) == 1

            # The stock was 2, so the next purchase fails and costs nothing.
            sold_out = await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={})
            assert sold_out.status_code == 409
            assert (await client.get("/api/me", headers=headers(101))).json()["stars"] == 5000 - 80
            gone = (await client.get("/api/telegram/gifts", headers=headers(101))).json()
            assert gone["count"] == 0

    run(scenario())


def test_gift_purchase_rules(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            # Not priced: cannot be bought.
            assert (await client.post("/api/telegram/gifts/g2/purchase", headers=headers(101), json={})).status_code == 409
            await bot_module.set_telegram_gift_values("g2", price=9000, supply=5)
            # More than the 5000 welcome stars.
            poor = await client.post("/api/telegram/gifts/g2/purchase", headers=headers(101), json={})
            assert poor.status_code == 409
            # Unknown recipient.
            await bot_module.set_telegram_gift_values("g1", price=1, supply=5)
            assert (await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={"recipient_id": 424242})).status_code == 404
            assert (await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={"recipient_id": "x"})).status_code == 400
            # Nothing was charged by the failed attempts.
            assert (await client.get("/api/me", headers=headers(101))).json()["stars"] == 5000

    run(scenario())


def test_every_account_has_premium_and_admin_flag(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            me = (await client.get("/api/me", headers=headers(101))).json()
            assert me["is_premium"] is True and me["is_admin"] is False
            boss = (await client.get("/api/me", headers=headers(ADMIN))).json()
            assert boss["is_admin"] is True

    run(scenario())


def _png() -> bytes:
    import io

    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (64, 64), (200, 30, 30)).save(buffer, format="PNG")
    return buffer.getvalue()


def test_profile_avatar_lifecycle(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            png = {"Content-Type": "image/png"}
            uploaded = await client.post("/api/media/images", headers={**headers(101), **png}, content=_png())
            assert uploaded.status_code == 201
            media_id = uploaded.json()["id"]

            # Before it is set, nobody else can download the picture.
            assert (await client.get(f"/api/media/{media_id}", headers=headers(102))).status_code == 404
            assert (await client.get("/api/me", headers=headers(101))).json()["avatar_media_id"] == ""

            assert (await client.put("/api/me/avatar", headers=headers(101), json={"media_id": "zz"})).status_code == 400
            # Somebody else's picture cannot become your avatar.
            assert (await client.put("/api/me/avatar", headers=headers(102), json={"media_id": media_id})).status_code == 404
            set_ok = await client.put("/api/me/avatar", headers=headers(101), json={"media_id": media_id})
            assert set_ok.status_code == 200

            assert (await client.get("/api/me", headers=headers(101))).json()["avatar_media_id"] == media_id
            # Everybody sees the avatar on the profile and in search, and can download it.
            assert (await client.get("/api/users/101", headers=headers(102))).json()["avatar_media_id"] == media_id
            found = (await client.get("/api/users?q=buyer", headers=headers(102))).json()["users"]
            assert found and found[0]["avatar_media_id"] == media_id
            shown = await client.get(f"/api/media/{media_id}", headers=headers(102))
            assert shown.status_code == 200 and shown.headers["content-type"].startswith("image/")

            removed = await client.delete("/api/me/avatar", headers=headers(101))
            assert removed.status_code == 200
            assert (await client.get("/api/users/101", headers=headers(102))).json()["avatar_media_id"] == ""
            assert (await client.get(f"/api/media/{media_id}", headers=headers(102))).status_code == 404

    run(scenario())


def test_bio_is_saved_and_visible_to_others(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            saved = await client.patch("/api/me", headers=headers(101), json={"bio": "  Hello there  "})
            assert saved.status_code == 200 and saved.json()["bio"] == "Hello there"
            assert (await client.get("/api/users/101", headers=headers(102))).json()["bio"] == "Hello there"
            assert (await client.patch("/api/me", headers=headers(101), json={"bio": "x" * 141})).status_code == 400
            # Changing the name does not touch the bio.
            await client.patch("/api/me", headers=headers(101), json={"display_name": "Renamed"})
            assert (await client.get("/api/me", headers=headers(101))).json()["bio"] == "Hello there"

    run(scenario())


def test_telegram_gift_purchase_is_idempotent(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            await bot_module.set_telegram_gift_values("g1", price=40, supply=2)
            key = "wg-telegram-gift-buy-0001"
            first = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers={**headers(101), "Idempotency-Key": key},
                json={},
            )
            second = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers={**headers(101), "Idempotency-Key": key},
                json={},
            )
            assert first.status_code == 201 and second.status_code == 201
            assert second.json() == first.json()
            assert (await client.get("/api/me", headers=headers(101))).json()["stars"] == 4960
            assert (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"][0]["telegram_gift_id"] == "g1"

            reused = await client.post(
                "/api/telegram/gifts/g2/purchase",
                headers={**headers(101), "Idempotency-Key": key},
                json={},
            )
            assert reused.status_code == 409
            assert (await client.get("/api/me", headers=headers(101))).json()["stars"] == 4960

    run(scenario())


def test_removed_telegram_gift_cannot_be_purchased(env, monkeypatch: pytest.MonkeyPatch) -> None:
    path, app = env

    gift_one = {
        "id": "g1",
        "sticker": {
            "file_id": "f1", "file_unique_id": "u1", "type": "regular",
            "width": 512, "height": 512, "is_animated": False, "is_video": False,
            "emoji": "🎁", "mime_type": "image/webp",
        },
        "star_count": 25,
    }
    gift_two = {
        "id": "g2",
        "sticker": {
            "file_id": "f2", "file_unique_id": "u2", "type": "regular",
            "width": 512, "height": 512, "is_animated": False, "is_video": False,
            "emoji": "🧸", "mime_type": "image/webp",
        },
        "star_count": 50,
    }

    async def scenario() -> None:
        # Start with both gifts active and configure a sale for g1.
        await messenger_api.store_telegram_gifts(path, [gift_one, gift_two], synced_at=1)
        await bot_module.set_telegram_gift_values("g1", price=40, supply=2)

        # Telegram later removes g1. Force the next request to refresh the catalog.
        async def current_catalog(bot):
            return [gift_two]

        monkeypatch.setattr(messenger_api, "fetch_telegram_gifts", current_catalog)

        async with await client_for(app) as client:
            result = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={},
            )
            assert result.status_code == 409
            assert "недоступен" in result.json()["detail"].lower()
            balance = (await client.get("/api/me", headers=headers(101))).json()["stars"]
            assert balance == 5000
            active_admin_rows = await bot_module.telegram_gift_rows()
            assert [str(row["id"]) for row in active_admin_rows] == ["g2"]

        connection = db_split.sqlite_connect(path)
        try:
            assert connection.execute(
                "SELECT sold FROM telegram_gift_prices WHERE gift_id='g1'"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT is_available FROM telegram_gift_catalog WHERE gift_id='g1'"
            ).fetchone() == (0,)
        finally:
            connection.close()

    run(scenario())



def test_simultaneous_telegram_gift_purchases_cannot_oversell(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=40, supply=1)
        async with await client_for(app) as client:
            async def buy(key: str):
                return await client.post(
                    "/api/telegram/gifts/g1/purchase",
                    headers={**headers(101), "Idempotency-Key": key},
                    json={},
                )

            first, second = await asyncio.gather(
                buy("wg-concurrent-gift-buy-0001"),
                buy("wg-concurrent-gift-buy-0002"),
            )
            assert sorted([first.status_code, second.status_code]) == [201, 409]
            balance = (await client.get("/api/me", headers=headers(101))).json()["stars"]
            assert balance == 4960
            inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert len(inventory) == 1 and inventory[0]["telegram_gift_id"] == "g1"

        connection = db_split.sqlite_connect(path)
        try:
            assert connection.execute(
                "SELECT sold FROM telegram_gift_prices WHERE gift_id='g1'"
            ).fetchone() == (1,)
        finally:
            connection.close()

    run(scenario())


def test_auth_sessions_can_be_listed_and_revoked(env) -> None:
    path, app = env
    secondary = "s101-secondary-session-token"
    tertiary = "s101-tertiary-session-token"
    add_session(path, 101, secondary)

    async def scenario() -> None:
        async with await client_for(app) as client:
            listing = await client.get("/api/auth/sessions", headers=headers(101))
            assert listing.status_code == 200
            sessions = listing.json()["sessions"]
            assert listing.json()["count"] == 2
            current = [item for item in sessions if item["is_current"]]
            other = [item for item in sessions if not item["is_current"]]
            assert len(current) == 1 and len(other) == 1
            assert "token_hash" not in str(listing.json())
            assert "s101-session-token" not in str(listing.json())

            revoked = await client.delete(
                "/api/auth/sessions/" + other[0]["id"],
                headers=headers(101),
            )
            assert revoked.status_code == 200
            assert (await client.get("/api/auth/sessions", headers=headers(101))).json()["count"] == 1

            add_session(path, 101, tertiary)
            revoke_others = await client.post(
                "/api/auth/sessions/revoke-others",
                headers=headers(101),
                json={},
            )
            assert revoke_others.status_code == 200
            assert revoke_others.json()["revoked_sessions"] == 1
            assert (await client.get("/api/auth/sessions", headers=headers(101))).json()["count"] == 1
            assert (await client.get("/api/me", headers={"Authorization": "Bearer " + tertiary})).status_code == 401

    run(scenario())
