"""Two SQLite files instead of one.

* main file (``DATABASE_PATH``): accounts, virtual numbers, login codes, OTP receipts, API sessions, login log, admin log;
* messenger file (``MESSENGER_DATABASE_PATH``): private messages, groups, channels, bots, gifts, auctions,
  grams/stars ledger, media index and the Telegram gift catalog.

Every connection opened with ``aiosqlite.connect`` gets the messenger file attached under the schema name
``messenger``. SQLite resolves a table name that has no schema prefix by looking in ``main`` first and then in the
attached files, so the existing queries (including JOINs with ``accounts``) keep working unchanged. Only table
creation has to name the schema explicitly, which :func:`qualify_ddl` does.

A database created by an older version (everything in one file) is migrated automatically on the first start:
the tables are copied into the messenger file, checked by row count and only then dropped from the main file.
A backup of the original file is written next to it first.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

import aiosqlite
from aiosqlite.core import Connection

log = logging.getLogger(__name__)

SCHEMA = "messenger"

# Tables that live in the messenger file. Everything else stays in the main (accounts) file.
MESSENGER_TABLES = frozenset(
    {
        "messages",
        "message_events",
        "read_markers",
        "media_assets",
        "api_idempotency_records",
        "channels",
        "channel_admins",
        "channel_members",
        "channel_messages",
        "chat_groups",
        "group_members",
        "group_messages",
        "group_invites",
        "group_join_requests",
        "cloud_drafts",
        "contact_notes",
        "pinned_messages",
        "typing_indicators",
        "bots",
        "bot_commands",
        "bot_chats",
        "bot_messages",
        "gift_catalog",
        "user_gifts",
        "gift_transactions",
        "gift_auctions",
        "auction_bids",
        "economy_transactions",
        "telegram_gift_catalog",
        "telegram_gift_prices",
        "telegram_gift_sync_state",
        "telegram_mtproto_gift_catalog",
    }
)


def messenger_path_for(main_path: Path | str) -> Path:
    """Where the messenger file lives for a given main file."""
    override = os.getenv("MESSENGER_DATABASE_PATH", "").strip()
    if override:
        return Path(override)
    main = Path(main_path)
    return main.with_name(f"{main.stem}_messenger{main.suffix}")


def _is_file_database(location: str) -> bool:
    return bool(location) and location != ":memory:" and not location.startswith("file::memory:")


def sqlite_connect(database: Any, **kwargs: Any) -> sqlite3.Connection:
    """Plain (blocking) sqlite3 connection with the messenger file attached. Used by the async wrapper and by tools."""
    location = database.decode("utf-8") if isinstance(database, bytes) else str(database)
    connection = sqlite3.connect(location, **kwargs)
    if _is_file_database(location):
        target = messenger_path_for(location)
        target.parent.mkdir(parents=True, exist_ok=True)
        connection.execute(f"ATTACH DATABASE ? AS {SCHEMA}", (str(target),))
        connection.execute(f"PRAGMA {SCHEMA}.journal_mode=WAL").fetchall()
    return connection


def _connect(database: Any, *, iter_chunk_size: int = 64, loop: Any = None, **kwargs: Any) -> Connection:
    return Connection(lambda: sqlite_connect(database, **kwargs), iter_chunk_size)


_installed = False


def install() -> None:
    """Make every ``aiosqlite.connect`` attach the messenger file. Safe to call more than once."""
    global _installed
    if _installed:
        return
    aiosqlite.connect = _connect  # type: ignore[assignment]
    _installed = True


_CREATE_TABLE = re.compile(r"(CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+)(\w+)", re.IGNORECASE)
_CREATE_INDEX = re.compile(
    r"(CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+)(\w+)(\s+ON\s+)(\w+)", re.IGNORECASE
)


def qualify_ddl(script: str) -> str:
    """Put messenger tables and their indexes into the messenger file."""

    def table(match: re.Match[str]) -> str:
        name = match.group(2)
        if name in MESSENGER_TABLES:
            return f"{match.group(1)}{SCHEMA}.{name}"
        return match.group(0)

    def index(match: re.Match[str]) -> str:
        if match.group(4) in MESSENGER_TABLES:
            return f"{match.group(1)}{SCHEMA}.{match.group(2)}{match.group(3)}{match.group(4)}"
        return match.group(0)

    return _CREATE_INDEX.sub(index, _CREATE_TABLE.sub(table, script))


async def migrate_legacy(main_path: Path | str) -> list[str]:
    """Move messenger tables out of a single-file database. Returns the names of the moved tables."""
    main_path = Path(main_path)
    if not main_path.exists():
        return []
    async with aiosqlite.connect(main_path) as db:
        return await migrate_legacy_with(db, main_path)


async def migrate_legacy_with(db: aiosqlite.Connection, main_path: Path | str) -> list[str]:
    """Same as :func:`migrate_legacy` on an already open connection (the messenger file must be attached)."""
    main_path = Path(main_path)
    await db.commit()
    moved: list[str] = []
    cur = await db.execute("SELECT name FROM main.sqlite_master WHERE type='table'")
    in_main = {str(row[0]) for row in await cur.fetchall()}
    legacy = sorted(MESSENGER_TABLES & in_main)
    if not legacy:
        return []

    backup = main_path.with_name(main_path.name + ".pre-split.bak")
    if not backup.exists():
        await _backup(main_path, backup)
        log.warning("Database split: backup of the original file written to %s", backup)

    for name in legacy:
        cur = await db.execute(f"SELECT COUNT(*) FROM main.{name}")
        source_rows = int((await cur.fetchone())[0])
        cur = await db.execute(f"PRAGMA main.table_info({name})")
        source_columns = [str(row[1]) for row in await cur.fetchall()]
        cur = await db.execute(f"PRAGMA {SCHEMA}.table_info({name})")
        target_columns = [str(row[1]) for row in await cur.fetchall()]
        if not target_columns:
            # The messenger file has no such table yet: create it from the definition in the main file.
            cur = await db.execute("SELECT sql FROM main.sqlite_master WHERE type='table' AND name=?", (name,))
            definition = str((await cur.fetchone())[0])
            qualified = re.sub(
                rf'^(\s*CREATE\s+TABLE\s+)"?{name}"?', rf"\g<1>{SCHEMA}.{name}", definition, count=1, flags=re.IGNORECASE
            )
            if qualified == definition:
                raise RuntimeError(f"Database split: cannot create table {name} in the messenger file")
            await db.execute(qualified)
            cur = await db.execute(f"PRAGMA {SCHEMA}.table_info({name})")
            target_columns = [str(row[1]) for row in await cur.fetchall()]
        shared = [c for c in source_columns if c in target_columns]
        columns = ",".join(shared)
        await db.execute(
            f"INSERT OR IGNORE INTO {SCHEMA}.{name} ({columns}) SELECT {columns} FROM main.{name}"
        )
        cur = await db.execute(f"SELECT COUNT(*) FROM {SCHEMA}.{name}")
        target_rows = int((await cur.fetchone())[0])
        if target_rows < source_rows:
            await db.rollback()
            raise RuntimeError(
                f"Database split: {name} has {source_rows} rows but only {target_rows} were copied; "
                "the original table was left untouched"
            )
        await db.commit()
        await db.execute(f"DROP TABLE main.{name}")
        await db.commit()
        moved.append(name)
    log.warning("Database split: moved %d tables to %s", len(moved), messenger_path_for(main_path))
    return moved


async def _backup(source: Path, target: Path) -> None:
    def run() -> None:
        # Plain sqlite3 on purpose: the backup must not attach the messenger file.
        src = sqlite3.connect(source)
        try:
            dst = sqlite3.connect(target)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()

    await asyncio.to_thread(run)


install()