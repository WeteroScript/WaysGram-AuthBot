import asyncio
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import bot as bot_module
import db_split
from messenger_api import init_messenger_storage


def run(coro):
    return asyncio.run(coro)


def tables(path: Path) -> set[str]:
    conn = sqlite3.connect(path)  # plain connection: sees exactly one file
    try:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def init_all(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    store = bot_module.Store(path)
    store.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(store.init())
    run(bot_module.init_admin_storage())
    run(init_messenger_storage(path))


@pytest.fixture(autouse=True)
def no_env_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MESSENGER_DATABASE_PATH", raising=False)


def test_fresh_install_uses_two_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    init_all(path, monkeypatch)
    messenger = db_split.messenger_path_for(path)

    assert messenger.exists()
    main_tables = tables(path)
    messenger_tables = tables(messenger)

    assert {"users", "numbers", "auth_codes", "accounts", "api_sessions", "admin_logs"} <= main_tables
    assert not (db_split.MESSENGER_TABLES & main_tables)
    assert db_split.MESSENGER_TABLES <= messenger_tables
    assert not {"users", "numbers", "auth_codes", "accounts", "api_sessions"} & messenger_tables
    assert {
        "message_gifts", "message_contacts", "message_locations", "message_reactions",
        "gift_collectible_auctions", "gift_collectible_auction_bids",
    } <= messenger_tables


def test_queries_without_schema_and_joins_work_across_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    init_all(path, monkeypatch)
    with db_split.sqlite_connect(path) as conn:
        conn.execute(
            "INSERT INTO accounts(telegram_id,virtual_number,created_at,updated_at) VALUES(1,'+15550000001',1,1)"
        )
        conn.execute(
            "INSERT INTO messages(sender_telegram_id,recipient_telegram_id,body,created_at) VALUES(1,2,'hi',5)"
        )
        row = conn.execute(
            "SELECT a.virtual_number, m.body FROM messages m JOIN accounts a ON a.telegram_id=m.sender_telegram_id"
        ).fetchone()
    assert row == ("+15550000001", "hi")
    # The message went to the messenger file, the account to the main file.
    plain = sqlite3.connect(db_split.messenger_path_for(path))
    assert plain.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 1
    plain.close()
    plain = sqlite3.connect(path)
    assert plain.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
    plain.close()


def test_environment_variable_sets_messenger_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    custom = tmp_path / "elsewhere" / "chat.sqlite3"
    monkeypatch.setenv("MESSENGER_DATABASE_PATH", str(custom))
    path = tmp_path / "waysgram.sqlite3"
    init_all(path, monkeypatch)
    assert custom.exists()
    assert "messages" in tables(custom)
    assert "messages" not in tables(path)


def make_legacy_single_file(path: Path) -> None:
    """Rebuild what an older version produced: every table, including the messenger ones, in one file."""
    messenger = db_split.messenger_path_for(path)
    source = sqlite3.connect(messenger)
    definitions = [
        (name, sql)
        for name, sql in source.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL")
        if not name.startswith("sqlite_")
    ]
    source.close()
    legacy = sqlite3.connect(path)  # plain connection: tables land in the main file
    for _, sql in definitions:
        legacy.execute(sql)
    legacy.execute(
        "INSERT INTO messages(id,sender_telegram_id,recipient_telegram_id,body,created_at) VALUES(7,1,2,'old message',9)"
    )
    legacy.execute(
        "INSERT INTO message_contacts(message_id,contact_name,contact_phone,contact_email) "
        "VALUES(7,'Legacy Contact','+31 6 11111111','legacy@example.com')"
    )
    legacy.execute(
        "INSERT INTO message_locations(message_id,latitude,longitude,label) "
        "VALUES(7,52.1,5.1,'Legacy Location')"
    )
    legacy.execute("INSERT INTO gift_catalog(id,name,price_grams,supply,created_at) VALUES(3,'Old Gift',5,2,1)")
    legacy.commit()
    legacy.close()
    messenger.unlink()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(messenger) + suffix)
        if sidecar.exists():
            sidecar.unlink()


def test_legacy_single_file_database_is_migrated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    init_all(path, monkeypatch)
    make_legacy_single_file(path)
    assert "messages" in tables(path)

    init_all(path, monkeypatch)  # the next start of the new version

    messenger = db_split.messenger_path_for(path)
    assert not (db_split.MESSENGER_TABLES & tables(path))
    conn = sqlite3.connect(messenger)
    assert conn.execute("SELECT id,body FROM messages").fetchall() == [(7, "old message")]
    assert conn.execute(
        "SELECT contact_name,contact_phone,contact_email FROM message_contacts WHERE message_id=7"
    ).fetchall() == [("Legacy Contact", "+31 6 11111111", "legacy@example.com")]
    assert conn.execute(
        "SELECT latitude,longitude,label FROM message_locations WHERE message_id=7"
    ).fetchall() == [(52.1, 5.1, "Legacy Location")]
    assert conn.execute("SELECT name,price_grams,supply FROM gift_catalog").fetchall() == [("Old Gift", 5, 2)]
    # AUTOINCREMENT keeps counting after the migrated ids.
    conn.execute("INSERT INTO messages(sender_telegram_id,recipient_telegram_id,body,created_at) VALUES(1,2,'new',10)")
    assert conn.execute("SELECT MAX(id) FROM messages").fetchone()[0] == 8
    conn.close()
    # A backup of the original single file is kept.
    backup = path.with_name(path.name + ".pre-split.bak")
    assert backup.exists()
    assert "messages" in tables(backup)


def test_migration_is_repeatable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    init_all(path, monkeypatch)
    make_legacy_single_file(path)
    init_all(path, monkeypatch)
    init_all(path, monkeypatch)
    conn = sqlite3.connect(db_split.messenger_path_for(path))
    assert conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 1
    conn.close()


def test_qualify_ddl_only_touches_messenger_tables():
    script = """
    CREATE TABLE IF NOT EXISTS accounts (id INTEGER);
    CREATE TABLE IF NOT EXISTS messages (id INTEGER);
    CREATE INDEX IF NOT EXISTS idx_a ON accounts(id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_m
        ON messages(id);
    """
    result = db_split.qualify_ddl(script)
    assert "IF NOT EXISTS accounts (" in result
    assert "IF NOT EXISTS messenger.messages (" in result
    assert "IF NOT EXISTS idx_a ON accounts" in result
    assert "IF NOT EXISTS messenger.idx_m\n        ON messages" in result
