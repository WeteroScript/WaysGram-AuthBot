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


def test_admin_creates_reusable_labels_and_assigns_accounts_and_channels(panel) -> None:
    path, store = panel
    run(store.upsert_user(770801, 770801))
    run(bot_module.ensure_account(770801, "+15550770801", "label_account", "Label Account"))
    now = int(time.time())
    with db_split.sqlite_connect(path) as db:
        cur = db.execute(
            "INSERT INTO channels(username,title,owner_telegram_id,created_at) VALUES(?,?,?,?)",
            ("label_channel", "Label Channel", 770801, now),
        )
        channel_id = int(cur.lastrowid)
        db.commit()

    menu = press("wgadm:labels")
    assert "шаблонов" in menu.sent[0][0].lower()
    press("wgadm:labelnew")
    assert "цвет метки" in type_text("Official").sent[0][0].lower()
    created = type_text("#1769AA")
    assert "Шаблон метки сохранён" in created.sent[0][0]
    assert query(path, "SELECT label_text,color FROM waysgram_labels") == [("Official", "#1769AA")]
    label_id = query(path, "SELECT id FROM waysgram_labels")[0][0]

    press(f"wgadm:labelassign:{label_id}")
    press(f"wgadm:labeltarget:account:{label_id}")
    assigned_account = type_text("770801")
    assert "метка выдана аккаунту" in assigned_account.sent[0][0].lower()

    press(f"wgadm:labelassign:{label_id}")
    press(f"wgadm:labeltarget:channel:{label_id}")
    assigned_channel = type_text("@label_channel")
    assert "метка выдана каналу" in assigned_channel.sent[0][0].lower()

    assignments = query(
        path,
        "SELECT target_type,target_id FROM waysgram_label_assignments WHERE label_id=? ORDER BY target_type",
        (label_id,),
    )
    assert assignments == [("account", 770801), ("channel", channel_id)]
    # Assigning the same saved template twice is idempotent.
    assert run(bot_module.admin_assign_label(label_id, "account", 770801)) is False


def test_admin_gift_display_name_uses_sticker_set_name() -> None:
    assert bot_module.telegram_gift_display_name("Telegram Gift 123", "PlushPepe", "123") == "Plush Pepe"
    assert bot_module.telegram_gift_display_name("", "GoldenDuck", "456") == "Golden Duck"
    assert bot_module.telegram_gift_display_name("Rare Gift", "SomeSet", "789") == "Rare Gift"


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


def test_admin_balance_credit_sends_system_message(panel) -> None:
    path, store = panel
    user_id = 770077
    run(bot_module.ensure_system_account())
    run(bot_module.ensure_account(user_id, "+15550770077", "credit_test", "Credit Test"))

    press(f"wgadm:credit:stars:{user_id}")
    completed = type_text("125")
    assert "Начислено 125 STARS" in completed.sent[0][0]

    messages = query(
        path,
        "SELECT body FROM messages WHERE sender_telegram_id=? AND recipient_telegram_id=? ORDER BY id",
        (bot_module.SYSTEM_ACCOUNT_ID, user_id),
    )
    assert len(messages) == 2
    assert "Начислено: +125 Stars" in messages[-1][0]
    assert "Текущий баланс: 5125 Stars" in messages[-1][0]



def test_admin_adds_telegram_gift_by_id(panel, monkeypatch: pytest.MonkeyPatch) -> None:
    path, store = panel

    class FakeMTProtoCatalog:
        def __init__(self):
            self.sync_calls = 0

        async def sync(self, database_path):
            self.sync_calls += 1
            return {"gift_count": 2, "source": "telegram_mtproto"}

    mtproto_catalog = FakeMTProtoCatalog()
    monkeypatch.setattr(bot_module, "mtproto_gift_catalog", mtproto_catalog)
    gifts = [
        {"id": "g1", "sticker": {"file_id": "f1", "file_unique_id": "u1", "type": "regular",
                                 "width": 512, "height": 512, "is_animated": False, "is_video": False,
                                 "emoji": "🎁", "mime_type": "image/webp"}, "star_count": 25},
        {"id": "g2", "sticker": {"file_id": "f2", "file_unique_id": "u2", "type": "regular",
                                 "width": 512, "height": 512, "is_animated": False, "is_video": False,
                                 "emoji": "🧸", "mime_type": "image/webp"}, "star_count": 50},
    ]
    run(messenger_api.store_telegram_gifts(path, gifts, int(time.time())))

    prompt = press("wgadm:tgadd")
    assert "Telegram Gift ID" in prompt.sent[0][0]
    added_unknown = type_text("unknown-id")
    assert "добавлен в управление WaysGram" in added_unknown.sent[0][0]
    assert "ID: unknown-id" in added_unknown.sent[0][0]
    assert "метаданные Telegram не найдены" in added_unknown.sent[0][0]
    assert "Подарок Telegram" in added_unknown.sent[0][0]
    assert "Telegram Gift unknown-id" not in added_unknown.sent[0][0]
    assert query(path, "SELECT price_stars,supply FROM telegram_gift_prices WHERE gift_id='unknown-id'") == [(0, 0)]

    press("wgadm:tgadd")
    added = type_text("g2")
    assert "добавлен в управление" in added.sent[0][0]
    assert "ID: g2" in added.sent[0][0]
    assert query(path, "SELECT price_stars,supply FROM telegram_gift_prices WHERE gift_id='g2'") == [(0, 0)]
    assert mtproto_catalog.sync_calls == 2



def test_admin_database_account_controls(panel) -> None:
    path, store = panel
    user_id = 770701
    run(store.upsert_user(user_id, user_id))
    run(store.set_verified(user_id, True))
    number = run(store.allocate_number(user_id))
    run(bot_module.ensure_account(user_id, number, "db_user", "Database User"))
    run(bot_module.ensure_system_account())

    conn = db_split.sqlite_connect(path)
    try:
        conn.execute(
            """INSERT INTO user_gifts(serial_number,gift_name,owner_telegram_id,acquired_at)
               VALUES('WG-DBTEST','Тестовый подарок',?,?)""",
            (user_id, int(time.time())),
        )
        conn.execute(
            "INSERT INTO channels(username,title,owner_telegram_id,created_at) VALUES('dbtest','DB test',?,?)",
            (user_id, int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()

    assert "Управление БД" in str(press("wgadm:home").sent[0][1])
    press("wgadm:db")
    users = press("wgadm:dbaccounts")
    assert "Пользователи" in users.sent[0][0]
    assert "@db_user (1)" in str(users.sent[0][1])
    owner = press(f"wgadm:dbowner:{user_id}")
    assert number in str(owner.sent[0][1])
    card = press(f"wgadm:dbaccount:{user_id}")
    assert "Stars" in card.sent[0][0] and "Gram" in card.sent[0][0]

    press(f"wgadm:dbdo:gifts:{user_id}")
    assert query(path, "SELECT COUNT(*) FROM user_gifts WHERE owner_telegram_id=?", (user_id,))[0][0] == 0

    press(f"wgadm:dbdo:stars:{user_id}")
    press(f"wgadm:dbdo:grams:{user_id}")
    assert query(path, "SELECT stars,grams FROM accounts WHERE telegram_id=?", (user_id,)) == [(0, 0)]
    assert query(path, "SELECT COUNT(*) FROM economy_transactions WHERE telegram_id=? AND amount<0", (user_id,))[0][0] == 2

    press(f"wgadm:dbdo:channels:{user_id}")
    assert query(path, "SELECT COUNT(*) FROM channels WHERE owner_telegram_id=?", (user_id,))[0][0] == 0

    press(f"wgadm:dbdo:account:{user_id}")
    assert query(path, "SELECT COUNT(*) FROM accounts WHERE telegram_id=?", (user_id,))[0][0] == 0
    assert query(path, "SELECT COUNT(*) FROM numbers WHERE telegram_id=?", (user_id,))[0][0] == 0


def test_admin_bulk_gift_import_and_hide_preserve_inventory(panel, monkeypatch: pytest.MonkeyPatch) -> None:
    path, store = panel
    class FakeCatalog:
        async def sync(self, database_path):
            return {"gift_count": 2, "source": "telegram_mtproto"}

    monkeypatch.setattr(bot_module, "mtproto_gift_catalog", FakeCatalog())
    conn = db_split.sqlite_connect(path)
    try:
        now = int(time.time())
        conn.execute(
            "INSERT INTO telegram_gift_sync_state(id,last_synced_at,gift_count,source) VALUES(1,?,?,?)",
            (now, 2, "telegram_mtproto"),
        )
        conn.execute(
            """INSERT INTO telegram_mtproto_gift_catalog
               (gift_id,title,stars,limited,sold_out,availability_remains,
                is_available,source_payload,position,synced_at)
               VALUES('limited','Limited gift',25,1,0,4,1,'{}',0,?)""",
            (now,),
        )
        conn.execute(
            """INSERT INTO telegram_mtproto_gift_catalog
               (gift_id,title,stars,limited,sold_out,availability_remains,
                is_available,source_payload,position,synced_at)
               VALUES('unlimited','Unlimited gift',50,0,0,NULL,1,'{}',1,?)""",
            (now,),
        )
        conn.execute(
            """INSERT INTO telegram_gift_prices(gift_id,price_stars,supply,sold,updated_at)
               VALUES('limited',25,7,3,?)""",
            (now,),
        )
        conn.execute(
            """INSERT INTO user_gifts(serial_number,gift_name,telegram_gift_id,owner_telegram_id,acquired_at)
               VALUES('WG-KEEP','Keep me','limited',123,?)""",
            (now,),
        )
        conn.commit()
    finally:
        conn.close()

    added = press("wgadm:dbgiftaddall")
    assert "Добавлено/обновлено подарков: 2" in added.sent[0][0]
    assert query(path, "SELECT price_stars,supply,sold FROM telegram_gift_prices WHERE gift_id='limited'") == [(25, 7, 3)]
    assert query(path, "SELECT price_stars,supply,sold FROM telegram_gift_prices WHERE gift_id='unlimited'") == [
        (50, bot_module.UNLIMITED_GIFT_SUPPLY, 0)
    ]

    press("wgadm:dbgifthideall")
    assert query(path, "SELECT COUNT(*) FROM telegram_gift_prices WHERE price_stars=0 AND supply=0")[0][0] == 2
    assert query(path, "SELECT COUNT(*) FROM user_gifts WHERE serial_number='WG-KEEP'")[0][0] == 1
