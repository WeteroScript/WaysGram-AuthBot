import asyncio
from pathlib import Path

import aiosqlite
import pytest
from cryptography.fernet import Fernet

import bot as bot_module
import db_split
from messenger_api import init_messenger_storage


ADMIN = 424242
RECIPIENT = 770077


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def account_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    monkeypatch.setattr(bot_module, "ADMIN_ID", ADMIN)
    store = bot_module.Store(path)
    store.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    monkeypatch.setattr(bot_module, "store", store)
    run(store.init())
    run(bot_module.init_admin_storage())
    run(init_messenger_storage(path))
    run(store.upsert_user(ADMIN, ADMIN, "admin_user"))
    run(store.set_verified(ADMIN, True))
    run(store.upsert_user(RECIPIENT, RECIPIENT, "recipient"))
    run(store.set_verified(RECIPIENT, True))
    return path, store


def rows(path: Path, sql: str, args=()):
    conn = db_split.sqlite_connect(path)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def add_session_rows(path: Path, account_id: int):
    conn = db_split.sqlite_connect(path)
    try:
        conn.execute(
            "INSERT INTO api_sessions(token_hash,telegram_id,expires_at,created_at) VALUES(?,?,?,?)",
            ("session-hash", account_id, 9999999999, 1),
        )
        conn.execute(
            """INSERT INTO push_devices(
                   token_hash,token_value,telegram_id,session_token_hash,platform,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?)""",
            ("device-hash", "device-token", account_id, "session-hash", "android", 1, 1),
        )
        conn.commit()
    finally:
        conn.close()


def test_admin_created_account_is_owned_by_admin_and_listed(account_store):
    path, store = account_store
    account_id = run(bot_module.admin_create_account("+15551234567", 100, 5))

    assert run(store.owned_numbers(ADMIN)) == [("+15551234567", account_id)]
    assert run(store.owned_numbers(RECIPIENT)) == []
    owner = run(store.resolve_number("+15551234567"))
    assert owner["telegram_id"] == account_id
    assert owner["chat_id"] == ADMIN
    assert owner["verified"] == 1


def test_transfer_changes_owner_and_revokes_all_existing_sessions(account_store):
    path, store = account_store
    account_id = run(bot_module.admin_create_account("+15551234567", 100, 5))
    add_session_rows(path, account_id)

    assert run(store.find_registered_user("@recipient")) == RECIPIENT
    assert run(store.transfer_number("+15551234567", ADMIN, RECIPIENT)) == account_id
    assert run(store.owned_numbers(ADMIN)) == []
    assert run(store.owned_numbers(RECIPIENT)) == [("+15551234567", account_id)]

    owner = run(store.resolve_number("+15551234567"))
    assert owner["telegram_id"] == account_id
    assert owner["chat_id"] == RECIPIENT
    assert rows(path, "SELECT COUNT(*) FROM api_sessions WHERE telegram_id=?", (account_id,))[0][0] == 0
    assert rows(path, "SELECT COUNT(*) FROM push_devices WHERE telegram_id=?", (account_id,))[0][0] == 0


def test_delete_removes_account_and_related_data_but_keeps_bot_owner(account_store):
    path, store = account_store
    account_id = run(bot_module.admin_create_account("+15551234567", 100, 5))
    add_session_rows(path, account_id)
    conn = db_split.sqlite_connect(path)
    try:
        conn.execute(
            "INSERT INTO messenger.messages(sender_telegram_id,recipient_telegram_id,body,created_at) VALUES(?,?,?,?)",
            (account_id, RECIPIENT, "test", 1),
        )
        conn.commit()
    finally:
        conn.close()

    assert run(store.delete_number("+15551234567", ADMIN)) is True
    assert rows(path, "SELECT COUNT(*) FROM accounts WHERE telegram_id=?", (account_id,))[0][0] == 0
    assert rows(path, "SELECT COUNT(*) FROM numbers WHERE number=?", ("+15551234567",))[0][0] == 0
    assert rows(path, "SELECT COUNT(*) FROM users WHERE telegram_id=?", (account_id,))[0][0] == 0
    assert rows(path, "SELECT COUNT(*) FROM users WHERE telegram_id=?", (ADMIN,))[0][0] == 1
    assert rows(path, "SELECT COUNT(*) FROM api_sessions WHERE telegram_id=?", (account_id,))[0][0] == 0
    assert rows(path, "SELECT COUNT(*) FROM push_devices WHERE telegram_id=?", (account_id,))[0][0] == 0
    assert rows(path, "SELECT COUNT(*) FROM messenger.messages WHERE sender_telegram_id=?", (account_id,))[0][0] == 0
