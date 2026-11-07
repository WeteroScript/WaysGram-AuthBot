from __future__ import annotations

import asyncio
import sqlite3
import db_split

import aiosqlite
from pathlib import Path
from types import SimpleNamespace

from messenger_api import init_messenger_storage
from telegram_mtproto import TelegramMTProtoGiftCatalog


class DocumentAttributeSticker:
    def __init__(self, alt: str, short_name: str):
        self.alt = alt
        self.stickerset = SimpleNamespace(short_name=short_name)


class DocumentAttributeImageSize:
    def __init__(self, w: int, h: int):
        self.w = w
        self.h = h


class FakeMTProtoClient:
    def __init__(self):
        document = SimpleNamespace(
            id=9001,
            dc_id=2,
            size=1024,
            mime_type="image/webp",
            attributes=[
                DocumentAttributeSticker("🎁", "GiftSet"),
                DocumentAttributeImageSize(512, 512),
            ],
        )
        self.gift = SimpleNamespace(
            id=123456789,
            title="WaysGram catalog test gift",
            sticker=document,
            stars=25,
            limited=True,
            sold_out=False,
            birthday=False,
            require_premium=True,
            limited_per_user=True,
            peer_color_available=True,
            auction=True,
            availability_remains=23,
            availability_total=100,
            availability_resale=5,
            convert_stars=5,
            first_sale_date=1700000000,
            last_sale_date=1700000100,
            upgrade_stars=100,
            resell_min_stars=30,
            released_by=None,
            per_user_total=2,
            per_user_remains=1,
            locked_until_date=1700000200,
            auction_slug="gift-auction-slug",
            gifts_per_round=50,
            auction_start_date=1700000300,
            upgrade_variants=8,
            background=SimpleNamespace(
                to_dict=lambda: {
                    "_": "StarGiftBackground",
                    "center_color": 111,
                    "edge_color": 222,
                }
            ),
        )
        self.requests = []
        self.download_calls = []

    async def __call__(self, request):
        self.requests.append(request)
        return SimpleNamespace(gifts=[self.gift])

    async def download_media(self, document, file=bytes):
        self.download_calls.append(document)
        return b"telegram-mtproto-sticker"


def test_mtproto_gift_catalog_persists_flags_and_downloads_sticker(tmp_path: Path) -> None:
    async def scenario() -> None:
        database = tmp_path / "waysgram.sqlite3"
        database.parent.mkdir(parents=True, exist_ok=True)
        # init_messenger_storage is normally called after Store.init() in bot.py.
        # These two base tables satisfy its legacy gift-serial migration in isolation.
        async with aiosqlite.connect(database) as db:
            await db.execute(
                "CREATE TABLE user_gifts (id INTEGER PRIMARY KEY, serial_number TEXT)"
            )
            await db.execute("CREATE TABLE gift_transactions (serial_number TEXT)")
            await db.commit()
        await init_messenger_storage(database)
        client = FakeMTProtoClient()
        provider = TelegramMTProtoGiftCatalog(client)

        result = await provider.sync(database)
        assert result["source"] == "telegram_mtproto"
        assert result["gift_count"] == 1
        assert client.requests
        assert type(client.requests[0]).__name__ == "GetStarGiftsRequest"
        assert client.requests[0].hash == 0

        with db_split.sqlite_connect(database) as db:
            row = db.execute(
                """SELECT gift_id,title,stars,limited,sold_out,require_premium,
                          limited_per_user,auction,availability_remains,availability_total,
                          upgrade_stars,auction_slug,gifts_per_round,sticker_emoji,
                          sticker_document_id,sticker_mime_type
                   FROM telegram_mtproto_gift_catalog"""
            ).fetchone()
            sync_state = db.execute(
                "SELECT source,gift_count FROM telegram_gift_sync_state WHERE id=1"
            ).fetchone()

        assert row == (
            "123456789",
            "WaysGram catalog test gift",
            25,
            1,
            0,
            1,
            1,
            1,
            23,
            100,
            100,
            "gift-auction-slug",
            50,
            "🎁",
            9001,
            "image/webp",
        )
        assert sync_state == ("telegram_mtproto", 1)

        sticker, mime_type = await provider.download_sticker("123456789")
        assert sticker == b"telegram-mtproto-sticker"
        assert mime_type == "image/webp"
        assert len(client.download_calls) == 1

        # The process-local sticker cache avoids repeated MTProto downloads.
        second_sticker, second_mime = await provider.download_sticker("123456789")
        assert second_sticker == sticker
        assert second_mime == mime_type
        assert len(client.download_calls) == 1

    asyncio.run(scenario())
