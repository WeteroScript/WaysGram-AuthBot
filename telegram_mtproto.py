from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import aiosqlite
from telethon import functions


MAX_STICKER_BYTES = 20 * 1024 * 1024
MAX_STICKER_CACHE_ITEMS = 48


def _value(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default) if obj is not None else default


def _int_value(obj: Any, name: str) -> int | None:
    value = _value(obj, name)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _flag(obj: Any, name: str) -> int:
    return int(bool(_value(obj, name, False)))


def _tl_json(obj: Any) -> str | None:
    if obj is None:
        return None
    try:
        if hasattr(obj, "to_dict"):
            value = obj.to_dict()
        else:
            value = {"value": str(obj)}
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    except Exception:
        return json.dumps({"value": str(obj)}, ensure_ascii=False)


def _sticker_metadata(document: Any) -> dict[str, Any]:
    attributes = list(_value(document, "attributes", []) or [])
    emoji = ""
    set_name = ""
    width = None
    height = None
    animated = False
    video = False
    for attribute in attributes:
        name = type(attribute).__name__
        if name == "DocumentAttributeSticker":
            emoji = str(_value(attribute, "alt", "") or emoji)
            sticker_set = _value(attribute, "stickerset")
            set_name = str(_value(sticker_set, "short_name", "") or set_name)
        if name == "DocumentAttributeImageSize":
            width = _int_value(attribute, "w")
            height = _int_value(attribute, "h")
        if name == "DocumentAttributeAnimated":
            animated = True
        if name == "DocumentAttributeVideo":
            video = True
    mime = str(_value(document, "mime_type", "") or "application/octet-stream")
    animated = animated or mime == "application/x-tgsticker"
    video = video or mime.startswith("video/")
    return {
        "emoji": emoji[:32],
        "set_name": set_name[:128],
        "width": width,
        "height": height,
        "is_animated": animated,
        "is_video": video,
        "mime_type": mime[:128],
        "document_id": _int_value(document, "id"),
        "dc_id": _int_value(document, "dc_id"),
        "size": _int_value(document, "size"),
    }


def _gift_payload(gift: Any, position: int, synced_at: int) -> dict[str, Any]:
    document = _value(gift, "sticker")
    sticker = _sticker_metadata(document)
    gift_id = _int_value(gift, "id")
    emoji = sticker["emoji"]
    title = str(_value(gift, "title", "") or emoji or f"Telegram gift {gift_id}")
    return {
        "gift_id": str(gift_id),
        "title": title[:160],
        "sticker_emoji": emoji,
        "sticker_set_name": sticker["set_name"],
        "sticker_width": sticker["width"],
        "sticker_height": sticker["height"],
        "sticker_is_animated": int(sticker["is_animated"]),
        "sticker_is_video": int(sticker["is_video"]),
        "sticker_mime_type": sticker["mime_type"],
        "sticker_document_id": sticker["document_id"],
        "sticker_dc_id": sticker["dc_id"],
        "sticker_size": sticker["size"],
        "stars": max(0, _int_value(gift, "stars") or 0),
        "limited": _flag(gift, "limited"),
        "sold_out": _flag(gift, "sold_out"),
        "birthday": _flag(gift, "birthday"),
        "require_premium": _flag(gift, "require_premium"),
        "limited_per_user": _flag(gift, "limited_per_user"),
        "peer_color_available": _flag(gift, "peer_color_available"),
        "auction": _flag(gift, "auction"),
        "availability_remains": _int_value(gift, "availability_remains"),
        "availability_total": _int_value(gift, "availability_total"),
        "availability_resale": _int_value(gift, "availability_resale"),
        "convert_stars": _int_value(gift, "convert_stars"),
        "first_sale_date": _int_value(gift, "first_sale_date"),
        "last_sale_date": _int_value(gift, "last_sale_date"),
        "upgrade_stars": _int_value(gift, "upgrade_stars"),
        "resell_min_stars": _int_value(gift, "resell_min_stars"),
        "released_by_json": _tl_json(_value(gift, "released_by")),
        "per_user_total": _int_value(gift, "per_user_total"),
        "per_user_remains": _int_value(gift, "per_user_remains"),
        "locked_until_date": _int_value(gift, "locked_until_date"),
        "auction_slug": str(_value(gift, "auction_slug", "") or "")[:256],
        "gifts_per_round": _int_value(gift, "gifts_per_round"),
        "auction_start_date": _int_value(gift, "auction_start_date"),
        "upgrade_variants": _int_value(gift, "upgrade_variants"),
        "background_json": _tl_json(_value(gift, "background")),
        "source_payload": json.dumps({
            "id": gift_id,
            "title": title,
            "sticker": sticker,
            "stars": max(0, _int_value(gift, "stars") or 0),
            "limited": bool(_value(gift, "limited", False)),
            "sold_out": bool(_value(gift, "sold_out", False)),
            "birthday": bool(_value(gift, "birthday", False)),
            "require_premium": bool(_value(gift, "require_premium", False)),
            "limited_per_user": bool(_value(gift, "limited_per_user", False)),
            "peer_color_available": bool(_value(gift, "peer_color_available", False)),
            "auction": bool(_value(gift, "auction", False)),
            "availability_remains": _int_value(gift, "availability_remains"),
            "availability_total": _int_value(gift, "availability_total"),
            "availability_resale": _int_value(gift, "availability_resale"),
            "convert_stars": _int_value(gift, "convert_stars"),
            "first_sale_date": _int_value(gift, "first_sale_date"),
            "last_sale_date": _int_value(gift, "last_sale_date"),
            "upgrade_stars": _int_value(gift, "upgrade_stars"),
            "resell_min_stars": _int_value(gift, "resell_min_stars"),
            "released_by": json.loads(_tl_json(_value(gift, "released_by")) or "null"),
            "per_user_total": _int_value(gift, "per_user_total"),
            "per_user_remains": _int_value(gift, "per_user_remains"),
            "locked_until_date": _int_value(gift, "locked_until_date"),
            "auction_slug": str(_value(gift, "auction_slug", "") or ""),
            "gifts_per_round": _int_value(gift, "gifts_per_round"),
            "auction_start_date": _int_value(gift, "auction_start_date"),
            "upgrade_variants": _int_value(gift, "upgrade_variants"),
            "background": json.loads(_tl_json(_value(gift, "background")) or "null"),
        }, ensure_ascii=False, separators=(",", ":"), default=str),
        "position": position,
        "synced_at": synced_at,
    }


class TelegramMTProtoGiftCatalog:
    """Bot-authenticated MTProto reader for Telegram's complete available gift list."""

    def __init__(self, client: Any):
        self.client = client
        self._sync_lock = asyncio.Lock()
        self._gifts: dict[str, Any] = {}
        self._media_cache: OrderedDict[str, tuple[bytes, str]] = OrderedDict()

    async def sync(self, database_path: Path) -> dict[str, Any]:
        async with self._sync_lock:
            response = await self.client(
                functions.payments.GetStarGiftsRequest(hash=0)
            )
            if type(response).__name__ == "StarGiftsNotModified":
                now = int(time.time())
                async with aiosqlite.connect(database_path) as db:
                    cur = await db.execute(
                        "SELECT COUNT(*) FROM telegram_mtproto_gift_catalog WHERE is_available=1"
                    )
                    count = int((await cur.fetchone())[0])
                    await db.execute(
                        """INSERT INTO telegram_gift_sync_state(id,last_synced_at,gift_count,source)
                           VALUES(1,?,?,'telegram_mtproto')
                           ON CONFLICT(id) DO UPDATE SET
                               last_synced_at=excluded.last_synced_at,
                               gift_count=excluded.gift_count,
                               source=excluded.source""",
                        (now, count),
                    )
                    await db.execute(
                        """INSERT OR IGNORE INTO telegram_auction_gift_registry
                           (gift_id,title,auction_slug,auction_start_date,gifts_per_round,
                            discovered_at,source_payload)
                           SELECT gift_id,title,auction_slug,auction_start_date,gifts_per_round,
                                  synced_at,source_payload
                           FROM telegram_mtproto_gift_catalog
                           WHERE auction=1
                             AND TRIM(COALESCE(auction_slug,''))<>''
                             AND auction_start_date IS NOT NULL
                              AND auction_start_date<=?
                             AND COALESCE(gifts_per_round,0)>0""",
                        (now,),
                    )
                    await db.commit()
                return {
                    "last_synced_at": now,
                    "gift_count": count,
                    "source": "telegram_mtproto",
                }

            gifts = _value(response, "gifts")
            if not isinstance(gifts, (list, tuple)):
                raise RuntimeError("MTProto payments.getStarGifts returned an unexpected result")

            now = int(time.time())
            payloads = [
                _gift_payload(gift, position, now)
                for position, gift in enumerate(gifts)
                if _int_value(gift, "id") is not None and _value(gift, "sticker") is not None
            ]
            if gifts and not payloads:
                raise RuntimeError("MTProto gift list contained no valid StarGift objects")

            columns = [
                "gift_id", "title", "sticker_emoji", "sticker_set_name",
                "sticker_width", "sticker_height", "sticker_is_animated",
                "sticker_is_video", "sticker_mime_type", "sticker_document_id",
                "sticker_dc_id", "sticker_size", "stars", "limited", "sold_out",
                "birthday", "require_premium", "limited_per_user", "peer_color_available",
                "auction", "availability_remains", "availability_total", "availability_resale",
                "convert_stars", "first_sale_date", "last_sale_date", "upgrade_stars",
                "resell_min_stars", "released_by_json", "per_user_total", "per_user_remains",
                "locked_until_date", "auction_slug", "gifts_per_round", "auction_start_date",
                "upgrade_variants", "background_json", "source_payload", "position", "synced_at",
            ]
            placeholders = ",".join("?" for _ in columns)
            updates = ",".join(
                f"{column}=excluded.{column}" for column in columns if column != "gift_id"
            )
            values = [tuple(item[column] for column in columns) for item in payloads]

            async with aiosqlite.connect(database_path) as db:
                await db.execute("BEGIN IMMEDIATE")
                if values:
                    await db.executemany(
                        f"""INSERT INTO telegram_mtproto_gift_catalog
                            ({",".join(columns)},is_available)
                            VALUES({placeholders},1)
                            ON CONFLICT(gift_id) DO UPDATE SET {updates},is_available=1""",
                        values,
                    )
                    gift_ids = [item["gift_id"] for item in payloads]
                    placeholders_ids = ",".join("?" for _ in gift_ids)
                    await db.execute(
                        f"""UPDATE telegram_mtproto_gift_catalog
                            SET is_available=0 WHERE gift_id NOT IN ({placeholders_ids})""",
                        gift_ids,
                    )
                else:
                    await db.execute(
                        "UPDATE telegram_mtproto_gift_catalog SET is_available=0"
                    )
                await db.execute(
                    """INSERT INTO telegram_gift_sync_state(id,last_synced_at,gift_count,source)
                       VALUES(1,?,?,'telegram_mtproto')
                       ON CONFLICT(id) DO UPDATE SET
                           last_synced_at=excluded.last_synced_at,
                           gift_count=excluded.gift_count,
                           source=excluded.source""",
                    (now, len(values)),
                )
                await db.execute(
                    """INSERT OR IGNORE INTO telegram_auction_gift_registry
                       (gift_id,title,auction_slug,auction_start_date,gifts_per_round,
                        discovered_at,source_payload)
                       SELECT gift_id,title,auction_slug,auction_start_date,gifts_per_round,
                              synced_at,source_payload
                       FROM telegram_mtproto_gift_catalog
                       WHERE auction=1
                         AND TRIM(COALESCE(auction_slug,''))<>''
                         AND auction_start_date IS NOT NULL
                              AND auction_start_date<=?
                         AND COALESCE(gifts_per_round,0)>0""",
                    (now,),
                )
                await db.commit()

            self._gifts = {
                str(_value(gift, "id")): gift
                for gift in gifts
                if _int_value(gift, "id") is not None and _value(gift, "sticker") is not None
            }
            self._media_cache.clear()
            return {
                "last_synced_at": now,
                "gift_count": len(values),
                "source": "telegram_mtproto",
            }

    async def download_sticker(self, gift_id: str) -> tuple[bytes, str]:
        key = str(gift_id)
        cached = self._media_cache.get(key)
        if cached is not None:
            self._media_cache.move_to_end(key)
            return cached

        gift = self._gifts.get(key)
        if gift is None:
            raise LookupError("Telegram gift is not present in the current MTProto cache")
        document = _value(gift, "sticker")
        size = _int_value(document, "size")
        if size is not None and size > MAX_STICKER_BYTES:
            raise ValueError("Telegram sticker file exceeds the supported size")

        payload = await self.client.download_media(document, file=bytes)
        if hasattr(payload, "getvalue"):
            payload = payload.getvalue()
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise RuntimeError("MTProto did not return sticker bytes")
        content = bytes(payload)
        if len(content) > MAX_STICKER_BYTES:
            raise ValueError("Telegram sticker file exceeds the supported size")
        mime_type = str(_value(document, "mime_type", "") or "application/octet-stream")
        result = (content, mime_type)
        self._media_cache[key] = result
        while len(self._media_cache) > MAX_STICKER_CACHE_ITEMS:
            self._media_cache.popitem(last=False)
        return result
