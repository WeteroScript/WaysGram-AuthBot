import asyncio
import json
import time
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
                                     "mime_type": "image/webp"}, "star_count": 25, "upgrade_star_count": 10},
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
            assert result.status_code == 201
            assert result.json()["gift"]["telegram_gift_id"] == "g1"
            balance = (await client.get("/api/me", headers=headers(101))).json()["stars"]
            assert balance == 4960
            inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert len(inventory) == 1 and inventory[0]["telegram_gift_id"] == "g1"
            archived_admin_rows = await bot_module.telegram_gift_rows()
            assert {str(row["id"]) for row in archived_admin_rows} == {"g1", "g2"}

        connection = db_split.sqlite_connect(path)
        try:
            assert connection.execute(
                "SELECT sold FROM telegram_gift_prices WHERE gift_id='g1'"
            ).fetchone() == (1,)
            assert connection.execute(
                "SELECT is_available FROM telegram_gift_catalog WHERE gift_id='g1'"
            ).fetchone() == (0,)
            receipt = connection.execute(
                """SELECT m.sender_telegram_id,m.recipient_telegram_id,m.body,mg.serial_number,mg.telegram_gift_id
                   FROM messages m JOIN message_gifts mg ON mg.message_id=m.id
                   WHERE m.sender_telegram_id=101 AND m.recipient_telegram_id=101"""
            ).fetchone()
            assert receipt is not None
            assert receipt[0:2] == (101, 101)
            assert "коллекционный подарок" in receipt[2].lower()
            assert receipt[4] == "g1"
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


def test_public_profile_includes_received_gifts(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=35, supply=1)
        async with await client_for(app) as client:
            purchase = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={"recipient_id": 102},
            )
            assert purchase.status_code == 201

            profile = await client.get("/api/users/102", headers=headers(101))
            assert profile.status_code == 200
            data = profile.json()
            assert data["id"] == 102
            assert len(data["gifts"]) == 1
            gift = data["gifts"][0]
            assert gift["telegram_gift_id"] == "g1"
            assert gift["gift_name"] == "🎁"
            assert gift["serial_number"] == purchase.json()["gift"]["serial_number"]

            # Public profile output must not include account credentials or phone data.
            assert "phone" not in data
            assert "token" not in str(data)
            assert "stars" not in data

    run(scenario())


def test_gift_market_listing_purchase_and_cancellation(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=30, supply=1)
        async with await client_for(app) as client:
            bought = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={},
            )
            assert bought.status_code == 201
            serial = bought.json()["gift"]["serial_number"]
            upgraded = await client.post(f"/api/gifts/{serial}/upgrade", headers=headers(101))
            assert upgraded.status_code == 200
            traits = upgraded.json()["attributes"]["collectible_traits"]

            listed = await client.post(
                f"/api/gifts/{serial}/list",
                headers=headers(101),
                json={"price_grams": 7},
            )
            assert listed.status_code == 201
            listing_id = listed.json()["listing_id"]
            assert listed.json()["currency"] == "grams"

            # A listed gift is locked against transfer and upgrade.
            assert (await client.post(
                "/api/gifts/transfer",
                headers=headers(101),
                json={"serial_number": serial, "recipient_id": 102},
            )).status_code == 409
            assert (await client.post(
                f"/api/gifts/{serial}/upgrade",
                headers=headers(101),
            )).status_code == 409

            market = await client.get("/api/gift-market", headers=headers(102))
            assert market.status_code == 200
            assert len(market.json()["listings"]) == 1
            assert market.json()["listings"][0]["listing_id"] == listing_id
            assert market.json()["listings"][0]["price_grams"] == 7
            assert market.json()["listings"][0]["attributes"]["collectible_traits"] == traits

            purchased = await client.post(
                f"/api/gift-market/{listing_id}/purchase",
                headers=headers(102),
            )
            assert purchased.status_code == 201
            assert purchased.json()["grams_balance"] == 8
            assert (await client.get("/api/me", headers=headers(101))).json()["grams"] == 22
            assert (await client.get("/api/me", headers=headers(102))).json()["grams"] == 8
            buyer_inventory = (await client.get("/api/me/gifts", headers=headers(102))).json()["gifts"]
            assert len(buyer_inventory) == 1 and buyer_inventory[0]["serial_number"] == serial
            assert buyer_inventory[0]["attributes"]["collectible_traits"] == traits
            assert (await client.get("/api/gift-market", headers=headers(101))).json()["count"] == 0

            # A sold listing cannot be purchased a second time.
            assert (await client.post(
                f"/api/gift-market/{listing_id}/purchase",
                headers=headers(102),
            )).status_code == 404

    run(scenario())


def test_gift_market_listing_can_be_cancelled(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=20, supply=1)
        async with await client_for(app) as client:
            bought = await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={})
            serial = bought.json()["gift"]["serial_number"]
            listed = await client.post(
                f"/api/gifts/{serial}/list", headers=headers(101), json={"price_grams": 5}
            )
            assert listed.status_code == 201
            assert (await client.delete(f"/api/gifts/{serial}/list", headers=headers(102))).status_code == 404
            cancelled = await client.delete(f"/api/gifts/{serial}/list", headers=headers(101))
            assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
            assert (await client.get("/api/gift-market", headers=headers(102))).json()["count"] == 0
            assert (await client.post(
                f"/api/gifts/{serial}/list", headers=headers(101), json={"price_grams": 9}
            )).status_code == 201

    run(scenario())



def test_collectible_gift_auction_refunds_outbidder_and_settles_ownership(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=20, supply=1)
        async with await client_for(app) as client:
            bought = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={},
            )
            assert bought.status_code == 201
            serial = bought.json()["gift"]["serial_number"]

            # An unupgraded gift is not eligible for collectible auctions.
            rejected = await client.post(
                f"/api/gifts/{serial}/auction",
                headers=headers(101),
                json={"starting_price_grams": 5, "duration_seconds": 3600},
            )
            assert rejected.status_code == 409

            upgraded = await client.post(f"/api/gifts/{serial}/upgrade", headers=headers(101))
            assert upgraded.status_code == 200
            traits = upgraded.json()["attributes"]["collectible_traits"]

            # This model is registered as an original Telegram auction release.
            connection = db_split.sqlite_connect(path)
            try:
                connection.execute(
                    """INSERT INTO telegram_auction_gift_registry
                       (gift_id,title,auction_slug,auction_start_date,gifts_per_round,
                        discovered_at,source_payload)
                       VALUES(?,?,?,?,?,?,?)""",
                    ("g1", "🎁", "historic-g1", 1700000000, 1000, 1700000001, "{}"),
                )
                connection.commit()
            finally:
                connection.close()

            created = await client.post(
                f"/api/gifts/{serial}/auction",
                headers=headers(101),
                json={"starting_price_grams": 5, "duration_seconds": 3600},
            )
            assert created.status_code == 201
            auction_id = created.json()["auction_id"]
            assert created.json()["currency"] == "grams"
            assert created.json()["minimum_bid_grams"] == 5

            # Fixed-price listing, direct transfer and chat transfer are locked during an auction.
            assert (await client.post(
                f"/api/gifts/{serial}/list",
                headers=headers(101),
                json={"price_grams": 8},
            )).status_code == 409
            assert (await client.post(
                "/api/gifts/transfer",
                headers=headers(101),
                json={"serial_number": serial, "recipient_id": 102},
            )).status_code == 409
            assert (await client.post(
                "/api/messages/gift",
                headers=headers(101),
                json={"recipient_id": 102, "serial_number": serial},
            )).status_code == 409
            assert (await client.post(
                f"/api/gift-auctions/{auction_id}/bid",
                headers=headers(101),
                json={"amount_grams": 5},
            )).status_code == 403

            auctions = (await client.get("/api/gift-auctions", headers=headers(102))).json()["auctions"]
            assert len(auctions) == 1
            assert auctions[0]["auction_id"] == auction_id
            assert auctions[0]["attributes"]["collectible_traits"] == traits

            too_low = await client.post(
                f"/api/gift-auctions/{auction_id}/bid",
                headers=headers(102),
                json={"amount_grams": 4},
            )
            assert too_low.status_code == 409

            first_bid = await client.post(
                f"/api/gift-auctions/{auction_id}/bid",
                headers=headers(102),
                json={"amount_grams": 5},
            )
            assert first_bid.status_code == 201
            assert first_bid.json()["grams_balance"] == 10
            outbid = await client.post(
                f"/api/gift-auctions/{auction_id}/bid",
                headers=headers(ADMIN),
                json={"amount_grams": 7},
            )
            assert outbid.status_code == 201
            assert outbid.json()["grams_balance"] == 8
            assert (await client.get("/api/me", headers=headers(102))).json()["grams"] == 15
            assert (await client.get("/api/me", headers=headers(ADMIN))).json()["grams"] == 8

            cannot_cancel = await client.delete(
                f"/api/gifts/{serial}/auction",
                headers=headers(101),
            )
            assert cannot_cancel.status_code == 409

            connection = db_split.sqlite_connect(path)
            try:
                connection.execute(
                    "UPDATE gift_collectible_auctions SET ends_at=? WHERE id=?",
                    (int(time.time()) - 1, auction_id),
                )
                connection.commit()
            finally:
                connection.close()

            settled = await client.get("/api/gift-auctions", headers=headers(102))
            assert settled.status_code == 200
            assert settled.json()["count"] == 0
            assert settled.json()["settled_count"] == 1

            seller_inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            winner_inventory = (await client.get("/api/me/gifts", headers=headers(ADMIN))).json()["gifts"]
            assert seller_inventory == []
            assert len(winner_inventory) == 1
            assert winner_inventory[0]["serial_number"] == serial
            assert winner_inventory[0]["attributes"]["collectible_traits"] == traits
            assert (await client.get("/api/me", headers=headers(101))).json()["grams"] == 22

            connection = db_split.sqlite_connect(path)
            try:
                status = connection.execute(
                    "SELECT status FROM gift_collectible_auctions WHERE id=?",
                    (auction_id,),
                ).fetchone()
                assert status == ("sold",)
                transaction = connection.execute(
                    """SELECT event_type,from_telegram_id,to_telegram_id
                       FROM gift_transactions WHERE serial_number=? AND event_type='auction_sale'""",
                    (serial,),
                ).fetchone()
                assert transaction == ("auction_sale", 101, ADMIN)
            finally:
                connection.close()

    run(scenario())


def test_collectible_gift_auction_can_be_cancelled_before_first_bid(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=20, supply=1)
        async with await client_for(app) as client:
            bought = await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={})
            serial = bought.json()["gift"]["serial_number"]
            upgraded = await client.post(f"/api/gifts/{serial}/upgrade", headers=headers(101))
            assert upgraded.status_code == 200

            created = await client.post(
                f"/api/gifts/{serial}/auction",
                headers=headers(101),
                json={"starting_price_grams": 6},
            )
            assert created.status_code == 201
            denied = await client.delete(f"/api/gifts/{serial}/auction", headers=headers(102))
            assert denied.status_code == 404

            cancelled = await client.delete(f"/api/gifts/{serial}/auction", headers=headers(101))
            assert cancelled.status_code == 200
            relisted = await client.post(
                f"/api/gifts/{serial}/list",
                headers=headers(101),
                json={"price_grams": 9},
            )
            assert relisted.status_code == 201

    run(scenario())


def test_telegram_gift_upgrade_uses_internal_stars_and_records_level(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=20, supply=1)
        async with await client_for(app) as client:
            bought = await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={})
            serial = bought.json()["gift"]["serial_number"]
            upgraded = await client.post(f"/api/gifts/{serial}/upgrade", headers=headers(101))
            assert upgraded.status_code == 200
            assert upgraded.json()["upgrade_level"] == 1
            assert upgraded.json()["price_stars"] == 10
            assert upgraded.json()["stars_balance"] == 4970
            traits = upgraded.json()["attributes"]["collectible_traits"]
            assert traits["version"] == 1
            assert traits["rarity"] in {"Обычная", "Необычная", "Редкая", "Эпическая", "Легендарная"}
            assert traits["model"] and traits["symbol"] and traits["backdrop"]

            mine = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert mine[0]["upgrade_level"] == 1
            assert mine[0]["attributes"]["upgrade_source"] == "waysgram_internal"
            assert mine[0]["attributes"]["collectible_traits"] == traits

            # A later level-up changes the level but never rerolls the collectible traits.
            second_upgrade = await client.post(f"/api/gifts/{serial}/upgrade", headers=headers(101))
            assert second_upgrade.status_code == 200
            assert second_upgrade.json()["upgrade_level"] == 2
            assert second_upgrade.json()["attributes"]["collectible_traits"] == traits

    run(scenario())


def test_startup_backfills_traits_for_previously_upgraded_gifts(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=20, supply=1)
        async with await client_for(app) as client:
            bought = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={},
            )
            serial = bought.json()["gift"]["serial_number"]
            upgraded = await client.post(f"/api/gifts/{serial}/upgrade", headers=headers(101))
            assert upgraded.status_code == 200

        # Simulate the attributes JSON written by the previous backend version.
        connection = db_split.sqlite_connect(path)
        try:
            connection.execute(
                "UPDATE user_gifts SET attributes_json=? WHERE serial_number=?",
                (json.dumps({
                    "upgrade_level": 1,
                    "last_upgraded_at": 123,
                    "upgrade_source": "waysgram_internal",
                }), serial),
            )
            connection.commit()
        finally:
            connection.close()

        await init_messenger_storage(path)
        async with await client_for(app) as client:
            inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            traits = inventory[0]["attributes"]["collectible_traits"]
            assert traits["version"] == 1
            assert traits["rarity"] in {"Обычная", "Необычная", "Редкая", "Эпическая", "Легендарная"}
            assert traits["model"] and traits["symbol"] and traits["backdrop"]

        # Startup is idempotent: a second initialization must preserve the assigned traits.
        await init_messenger_storage(path)
        async with await client_for(app) as client:
            inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert inventory[0]["attributes"]["collectible_traits"] == traits

    run(scenario())

def test_gift_purchase_creates_one_collectible_receipt_in_saved_messages(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=35, supply=2)
        async with await client_for(app) as client:
            key = "wg-saved-gift-purchase-0001"
            purchase_headers = {**headers(101), "Idempotency-Key": key}
            purchased = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=purchase_headers,
                json={},
            )
            retried = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=purchase_headers,
                json={},
            )

            assert purchased.status_code == 201
            assert retried.status_code == 201
            assert retried.json() == purchased.json()
            assert purchased.json()["price_stars"] == 35
            assert (await client.get("/api/me", headers=headers(101))).json()["stars"] == 5000 - 35

            serial = purchased.json()["gift"]["serial_number"]
            inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert len(inventory) == 1
            assert inventory[0]["serial_number"] == serial
            assert inventory[0]["telegram_gift_id"] == "g1"

            saved = await client.get("/api/messages?with=101", headers=headers(101))
            assert saved.status_code == 200
            receipts = [
                message for message in saved.json()["messages"]
                if message.get("gift_serial_number") == serial
            ]
            assert len(receipts) == 1
            receipt = receipts[0]
            assert receipt["sender_id"] == 101
            assert receipt["recipient_id"] == 101
            assert receipt["body"] == "Вы приобрели коллекционный подарок «🎁»"
            assert receipt["gift_name"] == "🎁"
            assert receipt["gift_telegram_gift_id"] == "g1"
            assert receipt["gift_upgrade_level"] == 0
            assert receipt["gift_attributes"] == {}

    run(scenario())


def test_gift_can_be_sent_as_a_dm_message_with_snapshot_and_atomic_ownership(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=40, supply=1)
        async with await client_for(app) as client:
            bought = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={},
            )
            assert bought.status_code == 201
            serial = bought.json()["gift"]["serial_number"]

            upgraded = await client.post(
                f"/api/gifts/{serial}/upgrade",
                headers=headers(101),
            )
            assert upgraded.status_code == 200
            assert upgraded.json()["upgrade_level"] == 1

            # An active marketplace listing locks the gift from chat transfers too.
            listing = await client.post(
                f"/api/gifts/{serial}/list",
                headers=headers(101),
                json={"price_grams": 5},
            )
            assert listing.status_code == 201
            blocked = await client.post(
                "/api/messages/gift",
                headers=headers(101),
                json={"recipient_id": 102, "serial_number": serial},
            )
            assert blocked.status_code == 409
            cancelled = await client.delete(
                f"/api/gifts/{serial}/list",
                headers=headers(101),
            )
            assert cancelled.status_code == 200

            key = "wg-chat-gift-send-0001"
            payload = {
                "recipient_id": 102,
                "serial_number": serial,
                "body": "Подарок для тебя",
            }
            sent = await client.post(
                "/api/messages/gift",
                headers={**headers(101), "Idempotency-Key": key},
                json=payload,
            )
            retried = await client.post(
                "/api/messages/gift",
                headers={**headers(101), "Idempotency-Key": key},
                json=payload,
            )
            assert sent.status_code == 201
            assert retried.status_code == 201 and retried.json() == sent.json()
            assert sent.json()["type"] == "gift"
            assert sent.json()["gift_serial_number"] == serial
            assert sent.json()["gift_upgrade_level"] == 1
            assert sent.json()["gift_attributes"]["upgrade_source"] == "waysgram_internal"
            traits = upgraded.json()["attributes"]["collectible_traits"]
            assert sent.json()["gift_attributes"]["collectible_traits"] == traits

            sender_inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            recipient_inventory = (await client.get("/api/me/gifts", headers=headers(102))).json()["gifts"]
            assert sender_inventory == []
            assert len(recipient_inventory) == 1
            assert recipient_inventory[0]["serial_number"] == serial
            assert recipient_inventory[0]["upgrade_level"] == 1

            sender_history = (await client.get("/api/messages?with=102", headers=headers(101))).json()
            receiver_history = (await client.get("/api/messages?with=101", headers=headers(102))).json()
            for history in (sender_history, receiver_history):
                item = next(message for message in history["messages"] if message["id"] == sent.json()["id"])
                assert item["gift_serial_number"] == serial
                assert item["gift_name"] == "🎁"
                assert item["gift_upgrade_level"] == 1
                assert item["gift_attributes"]["upgrade_source"] == "waysgram_internal"
                assert item["gift_attributes"]["collectible_traits"] == traits

            profile = (await client.get("/api/users/102", headers=headers(101))).json()
            public_gift = profile["gifts"][0]
            assert public_gift["serial_number"] == serial
            assert public_gift["upgrade_level"] == 1
            assert public_gift["attributes"]["upgrade_source"] == "waysgram_internal"
            assert public_gift["attributes"]["collectible_traits"] == traits
            assert public_gift["is_listed"] == 0

    run(scenario())

def test_waysgram_auction_requires_historical_telegram_auction_origin(env) -> None:
    path, app = env

    async def scenario() -> None:
        await bot_module.set_telegram_gift_values("g1", price=20, supply=1)
        async with await client_for(app) as client:
            bought = await client.post(
                "/api/telegram/gifts/g1/purchase",
                headers=headers(101),
                json={},
            )
            assert bought.status_code == 201
            serial = bought.json()["gift"]["serial_number"]
            upgraded = await client.post(
                f"/api/gifts/{serial}/upgrade", headers=headers(101)
            )
            assert upgraded.status_code == 200

            inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert inventory[0]["auction_eligible"] == 0

            # Being upgraded/collectible is not sufficient on its own.
            rejected = await client.post(
                f"/api/gifts/{serial}/auction",
                headers=headers(101),
                json={"starting_price_grams": 5, "duration_seconds": 3600},
            )
            assert rejected.status_code == 409
            assert "исторически" in rejected.json()["detail"].lower()

            # A legacy active auction for a non-eligible model is cancelled,
            # and its locked leading bid is returned automatically.
            connection = db_split.sqlite_connect(path)
            try:
                connection.execute(
                    "UPDATE accounts SET grams=97 WHERE telegram_id=102"
                )
                now = int(time.time())
                connection.execute(
                    """INSERT INTO gift_collectible_auctions
                       (serial_number,seller_telegram_id,starting_price_grams,current_bid_grams,
                        highest_bidder_telegram_id,status,starts_at,ends_at,created_at)
                       VALUES(?,?,?,?,?,'active',?,?,?)""",
                    (serial, 101, 3, 3, 102, now, now + 3600, now),
                )
                connection.commit()
            finally:
                connection.close()
            hidden = await client.get("/api/gift-auctions", headers=headers(102))
            assert hidden.status_code == 200 and hidden.json()["count"] == 0
            assert (await client.get("/api/me", headers=headers(102))).json()["grams"] == 100

            # Historical provenance is stored independently from live catalogue availability.
            connection = db_split.sqlite_connect(path)
            try:
                connection.execute(
                    """INSERT INTO telegram_auction_gift_registry
                       (gift_id,title,auction_slug,auction_start_date,gifts_per_round,
                        discovered_at,source_payload)
                       VALUES(?,?,?,?,?,?,?)""",
                    ("g1", "🎁", "historic-g1", 1700000000, 1000, 1700000001, "{}"),
                )
                connection.execute(
                    "UPDATE telegram_gift_catalog SET is_available=0 WHERE gift_id='g1'"
                )
                connection.commit()
            finally:
                connection.close()

            inventory = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert inventory[0]["auction_eligible"] == 1
            profile = (await client.get("/api/users/101", headers=headers(102))).json()
            assert profile["gifts"][0]["auction_eligible"] == 1

            # No current Telegram sale/auction is required for a WaysGram auction.
            created = await client.post(
                f"/api/gifts/{serial}/auction",
                headers=headers(101),
                json={"starting_price_grams": 5, "duration_seconds": 3600},
            )
            assert created.status_code == 201

    run(scenario())

