import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

import bot as bot_module


def run(coro):
    return asyncio.run(coro)


class FakeMessage:
    def __init__(self):
        self.sent = []
        self.chat = SimpleNamespace(id=1)

    async def answer(self, text, reply_markup=None):
        self.sent.append((text, reply_markup))


class FakeCallback:
    def __init__(self, user_id, data, message, fail_answer=False):
        self.from_user = SimpleNamespace(id=user_id)
        self.data = data
        self.message = message
        self.answers = []
        self.fail_answer = fail_answer

    async def answer(self, text=None, show_alert=False):
        if self.fail_answer:
            raise RuntimeError("query is too old")
        self.answers.append((text, show_alert))


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    instance = bot_module.Store(tmp_path / "w.sqlite3")
    instance.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(instance.init())
    monkeypatch.setattr(bot_module, "store", instance)
    run(instance.upsert_user(5, 1))
    run(instance.set_language(5, "ru"))
    return instance


def last_challenge(store):
    import aiosqlite

    async def read():
        async with aiosqlite.connect(store.path) as db:
            cur = await db.execute(
                "SELECT challenge_id,target,choices FROM captcha_challenges ORDER BY rowid DESC LIMIT 1"
            )
            return await cur.fetchone()

    import json

    cid, target, choices = run(read())
    return cid, target, json.loads(choices)


def test_correct_answer_verifies_and_shows_menu(store):
    message = FakeMessage()
    run(bot_module.ask_captcha(message, 5, "ru"))
    cid, target, choices = last_challenge(store)
    callback = FakeCallback(5, f"cap:{cid}:{choices.index(target)}", message)
    run(bot_module.captcha_handler(callback))
    assert run(store.get_user(5))["verified"] == 1
    assert "Главное меню" in message.sent[-1][0]


def test_menu_is_shown_even_when_the_button_is_too_old_to_answer(store):
    message = FakeMessage()
    run(bot_module.ask_captcha(message, 5, "ru"))
    cid, target, choices = last_challenge(store)
    callback = FakeCallback(5, f"cap:{cid}:{choices.index(target)}", message, fail_answer=True)
    run(bot_module.captcha_handler(callback))
    assert run(store.get_user(5))["verified"] == 1
    assert "Главное меню" in message.sent[-1][0]


def test_challenge_survives_a_restart(store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    message = FakeMessage()
    run(bot_module.ask_captcha(message, 5, "ru"))
    cid, target, choices = last_challenge(store)
    # A new process has a new Store object on the same database file.
    restarted = bot_module.Store(store.path)
    restarted.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    monkeypatch.setattr(bot_module, "store", restarted)
    callback = FakeCallback(5, f"cap:{cid}:{choices.index(target)}", message)
    run(bot_module.captcha_handler(callback))
    assert run(restarted.get_user(5))["verified"] == 1


def test_wrong_answer_asks_again_without_verifying(store):
    message = FakeMessage()
    run(bot_module.ask_captcha(message, 5, "ru"))
    cid, target, choices = last_challenge(store)
    wrong = next(i for i, c in enumerate(choices) if c != target)
    run(bot_module.captcha_handler(FakeCallback(5, f"cap:{cid}:{wrong}", message)))
    assert run(store.get_user(5))["verified"] == 0
    assert len(message.sent) == 2  # a fresh captcha was sent


def test_someone_elses_challenge_is_left_alone(store):
    message = FakeMessage()
    run(bot_module.ask_captcha(message, 5, "ru"))
    cid, target, choices = last_challenge(store)
    callback = FakeCallback(6, f"cap:{cid}:{choices.index(target)}", message)
    run(bot_module.captcha_handler(callback))
    assert callback.answers[-1][1] is True
    assert run(store.get_user(5))["verified"] == 0
    # The owner can still answer it afterwards.
    run(bot_module.captcha_handler(FakeCallback(5, f"cap:{cid}:{choices.index(target)}", message)))
    assert run(store.get_user(5))["verified"] == 1


def test_expired_challenge_asks_again(store):
    message = FakeMessage()
    run(store.save_challenge("oldone", 5, "🐧", ["🐧"] * 9, time.time() - 1))
    run(bot_module.captcha_handler(FakeCallback(5, "cap:oldone:0", message)))
    assert run(store.get_user(5))["verified"] == 0
    assert len(message.sent) == 1
