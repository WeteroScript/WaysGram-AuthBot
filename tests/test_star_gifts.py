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

            assert (await client.patch("/api/admin/telegram-gifts/g1", headers=headers(101), json={"price_stars": 5})).status_code == 403
            ok = await client.patch("/api/admin/telegram-gifts/g1", headers=headers(ADMIN), json={"price_stars": 40, "supply": 2})
            assert ok.status_code == 200 and ok.json()["for_sale"] is True

            shown = (await client.get("/api/telegram/gifts", headers=headers(101))).json()
            assert [g["id"] for g in shown["gifts"]] == ["g1"]
            assert shown["gifts"][0]["price_stars"] == 40 and shown["gifts"][0]["remaining"] == 2
            assert (await client.patch("/api/admin/telegram-gifts/g1", headers=headers(ADMIN), json={"price_stars": -1})).status_code == 400

    run(scenario())


def test_buying_a_gift_charges_stars_and_reduces_stock(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            await client.patch("/api/admin/telegram-gifts/g1", headers=headers(ADMIN), json={"price_stars": 40, "supply": 2})
            bought = await client.post("/api/telegram/gifts/g1/purchase", headers=headers(101), json={})
            assert bought.status_code == 201
            assert bought.json()["stars"] == 5000 - 40
            mine = (await client.get("/api/me/gifts", headers=headers(101))).json()["gifts"]
            assert len(mine) == 1 and mine[0]["gift_name"] == "🎁"

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
            await client.patch("/api/admin/telegram-gifts/g2", headers=headers(ADMIN), json={"price_stars": 9000, "supply": 5})
            # More than the 5000 welcome stars.
            poor = await client.post("/api/telegram/gifts/g2/purchase", headers=headers(101), json={})
            assert poor.status_code == 409
            # Unknown recipient.
            await client.patch("/api/admin/telegram-gifts/g1", headers=headers(ADMIN), json={"price_stars": 1, "supply": 5})
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