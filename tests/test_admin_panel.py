import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

import bot as bot_module
import db_split
import messenger_api
from messenger_api import init_messenger_storage

ADMIN = 424242


def run(coro):
    return asyncio.run(coro)


class Msg:
    def __init__(self, text=None, user_id=ADMIN):
        self.text = text
        self.from_user = SimpleNamespace(id=user_id)
        self.sent: list[tuple[str, object]] = []

    async def answer(self, text, reply_markup=None):
        self.sent.append((text, reply_markup))


class Cb:
    def __init__(self, data, message):
        self.data = data
        self.message = message
        self.from_user = SimpleNamespace(id=ADMIN)

    async def answer(self, text=None, show_alert=False):
        pass


@pytest.fixture
def panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "waysgram.sqlite3"
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    monkeypatch.setattr(bot_module, "ADMIN_ID", ADMIN)
    store = bot_module.Store(path)
    store.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    monkeypatch.setattr(bot_module, "store", store)
    run(store.init())
    run(bot_module.init_admin_storage())
    run(init_messenger_storage(path))
    bot_module.ADMIN_INPUT.clear()
    yield path, store
    bot_module.ADMIN_INPUT.clear()


def press(data: str) -> Msg:
    message = Msg()
    run(bot_module.admin_callback(Cb(data, message)))
    return message


def type_text(text: str) -> Msg:
    message = Msg(text)
    run(bot_module.admin_text_input(message))
    return message


def query(path: Path, sql: str, args=()):
    conn = db_split.sqlite_connect(path)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def test_admin_creates_account_with_number_stars_and_grams(panel) -> None:
    path, store = panel
    press("wgadm:newacct")
    assert "номер" in type_text("not a number").sent[-1][0]
    assert "Stars" in type_text("555 123 4567").sent[-1][0]
    assert "Gram" in type_text("700").sent[-1][0]
    done = type_text("12")
    assert "Аккаунт создан" in done.sent[0][0]

    rows = query(path, "SELECT telegram_id,virtual_number,stars,grams FROM accounts WHERE virtual_number='+15551234567'")
    assert len(rows) == 1 and rows[0][2:] == (700, 12)
    account_id = rows[0][0]
    assert account_id > 9_000_000_000_000
    assert query(path, "SELECT COUNT(*) FROM economy_transactions WHERE telegram_id=?", (account_id,))[0][0] == 2
    # Login codes for the new number are delivered to the administrator's chat.
    owner = run(store.resolve_number("+15551234567"))
    assert owner is not None and owner["chat_id"] == ADMIN and owner["verified"] == 1

    # The same number cannot be used twice.
    press("wgadm:newacct")
    assert "уже занят" in type_text("+1 555 123 4567").sent[-1][0]
    # A second account gets its own id.
    press("wgadm:newacct")
    type_text("5559990000")
    type_text("0")
    type_text("0")
    ids = {r[0] for r in query(path, "SELECT telegram_id FROM accounts")}
    assert len(ids) == 2


def test_account_range_is_validated(panel) -> None:
    path, store = panel
    press("wgadm:newacct")
    type_text("5551110000")
    assert "диапазон" in type_text("-5").sent[-1][0].lower()
    assert "целое число" in type_text("abc").sent[-1][0]
    assert query(path, "SELECT COUNT(*) FROM accounts")[0][0] == 0


def test_admin_creates_username_channel_for_an_account(panel) -> None:
    path, store = panel
    run(store.upsert_user(77, 77))
    run(bot_module.ensure_account(77, "+15550007777", "someone", "Some One"))

    press("wgadm:newuname")
    assert "от 2 до 32" in type_text("1bad").sent[-1][0]
    assert "от 2 до 32" in type_text("a").sent[-1][0]
    assert "от 2 до 32" in type_text("x" * 33).sent[-1][0]
    assert "Telegram ID" in type_text("Ab").sent[-1][0]
    assert "не найден" in type_text("999999").sent[-1][0]
    done = type_text("77")
    assert "создан канал @ab" in done.sent[0][0]
    rows = query(path, "SELECT username,title,owner_telegram_id FROM channels")
    assert rows == [("ab", "ab", 77)]

    # By phone number, and the long end of the length range.
    press("wgadm:newuname")
    long_name = "n" + "x" * 31
    assert len(long_name) == 32
    type_text(long_name)
    type_text("+1 555 000 7777")
    assert query(path, "SELECT owner_telegram_id FROM channels WHERE username=?", (long_name,)) == [(77,)]

    # A name that is already used by a channel or an account is refused.
    press("wgadm:newuname")
    assert "занят" in type_text("ab").sent[-1][0]
    press("wgadm:newuname")
    assert "занят" in type_text("someone").sent[-1][0]


def test_only_admin_can_use_the_new_functions(panel) -> None:
    path, store = panel
    stranger = Msg(user_id=1)
    callback = Cb("wgadm:newacct", stranger)
    callback.from_user = SimpleNamespace(id=1)
    run(bot_module.admin_callback(callback))
    assert bot_module.ADMIN_INPUT == {}
    run(bot_module.admin_text_input(Msg("5551234567", user_id=1)))
    assert query(path, "SELECT COUNT(*) FROM accounts")[0][0] == 0


def test_admin_edits_telegram_gift_prices_from_the_bot(panel) -> None:
    path, store = panel
    gifts = [
        {"id": "g1", "sticker": {"file_id": "f1", "file_unique_id": "u1", "type": "regular", "width": 512,
                                 "height": 512, "is_animated": False, "is_video": False, "emoji": "🎁",
                                 "mime_type": "image/webp"}, "star_count": 25},
        {"id": "g2", "sticker": {"file_id": "f2", "file_unique_id": "u2", "type": "regular", "width": 512,
                                 "height": 512, "is_animated": False, "is_video": False, "emoji": "🧸",
                                 "mime_type": "image/webp"}, "star_count": 50},
    ]
    run(messenger_api.store_telegram_gifts(path, gifts, int(time.time())))

    listing = press("wgadm:tggifts")
    assert "всего 2" in listing.sent[0][0]
    assert "⛔" in str(listing.sent[0][1])  # nothing is for sale yet

    press("wgadm:tggift:g1")
    assert "введите цену" in press("wgadm:tgprice:g1").sent[0][0].lower()
    assert "диапазон" in type_text("-1").sent[-1][0].lower()
    assert "Сохранено" in type_text("30").sent[0][0]
    press("wgadm:tgsupply:g1")
    saved = type_text("4")
    assert "Остаток" in saved.sent[0][0] or "Осталось: 4" in saved.sent[0][0]
    assert query(path, "SELECT price_stars,supply,sold FROM telegram_gift_prices WHERE gift_id='g1'") == [(30, 4, 0)]

    # The listing now puts the gift that is on sale first, and hiding resets both values.
    assert "✅" in press("wgadm:tggifts").sent[0][0] + str(press("wgadm:tggifts").sent[0][1])
    press("wgadm:tghide:g1")
    assert query(path, "SELECT price_stars,supply FROM telegram_gift_prices WHERE gift_id='g1'") == [(0, 0)]