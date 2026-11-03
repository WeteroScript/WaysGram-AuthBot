from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bot as bot_module
from otp_webhook import OtpWebhookError, parse_telesrv_delivery


class FakeBot:
    def __init__(self) -> None:
        self.messages: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str):
        self.messages.append((chat_id, text))
        return SimpleNamespace(message_id=len(self.messages))


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database = tmp_path / "authbot.sqlite3"
    instance = bot_module.Store(database)
    monkeypatch.setattr(bot_module, "DATABASE_PATH", database)
    monkeypatch.setattr(bot_module, "store", instance)
    instance.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    asyncio.run(instance.init())
    asyncio.run(bot_module.init_admin_storage())
    return instance


def run(coro):
    return asyncio.run(coro)


def signed_request(number: str, code: str, delivery_id: str, secret: str, now: int | None = None):
    issued_at = int(time.time()) if now is None else int(now)
    payload = {
        "version": "1",
        "delivery_id": delivery_id,
        "purpose": "login_sms",
        "channel": "sms",
        "recipient": number,
        "code": code,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued_at + 300)),
        "expires_in": 300,
        "locale": "ru",
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    timestamp = str(issued_at)
    signature = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": delivery_id,
        "X-Telesrv-Timestamp": timestamp,
        "X-Telesrv-Signature": signature,
    }
    return body, headers


def test_parser_accepts_signed_login_sms_delivery() -> None:
    body, headers = signed_request("+11234567890", "482601", "otp_test_1", "shared-secret", now=1_800_000_000)
    delivery = parse_telesrv_delivery(body, headers, "shared-secret", now=1_800_000_000)
    assert delivery.delivery_id == "otp_test_1"
    assert delivery.number == "+11234567890"
    assert delivery.code == "482601"
    assert delivery.expires_in == 300
    assert len(delivery.payload_sha256) == 64


def test_parser_rejects_invalid_signature() -> None:
    body, headers = signed_request("+11234567890", "482601", "otp_test_2", "shared-secret")
    headers["X-Telesrv-Signature"] = "sha256=" + ("0" * 64)
    with pytest.raises(OtpWebhookError) as error:
        parse_telesrv_delivery(body, headers, "shared-secret")
    assert error.value.status_code == 401
    assert error.value.error_code == "SIGNATURE_INVALID"


def test_parser_rejects_wrong_purpose_and_non_six_digit_code() -> None:
    body, headers = signed_request("+11234567890", "482601", "otp_test_3", "shared-secret")
    payload = json.loads(body)
    payload["purpose"] = "change_phone"
    changed = json.dumps(payload, separators=(",", ":")).encode()
    timestamp = headers["X-Telesrv-Timestamp"]
    headers["X-Telesrv-Signature"] = "sha256=" + hmac.new(
        b"shared-secret", timestamp.encode("ascii") + b"." + changed, hashlib.sha256
    ).hexdigest()
    with pytest.raises(OtpWebhookError) as error:
        parse_telesrv_delivery(changed, headers, "shared-secret")
    assert error.value.error_code == "PURPOSE_UNSUPPORTED"


def test_parser_rejects_stale_delivery_and_wrong_idempotency_key() -> None:
    body, headers = signed_request("+11234567890", "482601", "otp_test_4", "shared-secret", now=1_800_000_000)
    with pytest.raises(OtpWebhookError) as expired:
        parse_telesrv_delivery(body, headers, "shared-secret", now=1_800_000_400)
    assert expired.value.error_code == "SIGNATURE_EXPIRED"

    headers["Idempotency-Key"] = "different-id"
    with pytest.raises(OtpWebhookError) as mismatch:
        parse_telesrv_delivery(body, headers, "shared-secret", now=1_800_000_000)
    assert mismatch.value.error_code == "REQUEST_INVALID"


def test_telesrv_webhook_delivers_code_and_deduplicates(
    store: bot_module.Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run(store.upsert_user(808, 9008))
    run(store.set_verified(808, True))
    number = run(store.allocate_number(808))
    fake_bot = FakeBot()
    monkeypatch.setattr(bot_module, "bot", fake_bot)
    monkeypatch.setattr(bot_module, "TELESRV_OTP_WEBHOOK_SECRET", "test-webhook-secret")
    body, headers = signed_request(number, "510246", "otp_delivery_808", "test-webhook-secret")

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=bot_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            delivered = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert delivered.status_code == 200
            assert delivered.json()["accepted"] is True
            assert delivered.json()["message_id"] == "authwaysgram:1"
            assert len(fake_bot.messages) == 1
            assert fake_bot.messages[0][0] == 9008
            assert "510246" in fake_bot.messages[0][1]
            latest_code = await store.latest_code(number)
            assert latest_code[0] == "510246"

            duplicate = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert duplicate.status_code == 200
            assert duplicate.json()["duplicate"] is True
            assert duplicate.json()["message_id"] == delivered.json()["message_id"]
            assert len(fake_bot.messages) == 1

            changed_body, changed_headers = signed_request(
                number, "510247", "otp_delivery_808", "test-webhook-secret"
            )
            conflict = await client.post(
                "/v1/otp/deliveries", content=changed_body, headers=changed_headers
            )
            assert conflict.status_code == 409
            assert len(fake_bot.messages) == 1

    run(scenario())


def test_telesrv_webhook_requires_configured_secret(
    store: bot_module.Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bot_module, "TELESRV_OTP_WEBHOOK_SECRET", "")
    body, headers = signed_request("+11234567890", "510246", "otp_delivery_no_secret", "secret")

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=bot_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert response.status_code == 503

    run(scenario())



def test_telesrv_webhook_retries_bot_delivery_without_replacing_code(
    store: bot_module.Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run(store.upsert_user(909, 9009))
    run(store.set_verified(909, True))
    number = run(store.allocate_number(909))

    class FailOnceBot(FakeBot):
        def __init__(self) -> None:
            super().__init__()
            self.attempts = 0

        async def send_message(self, chat_id: int, text: str):
            self.attempts += 1
            if self.attempts == 1:
                raise RuntimeError("temporary Telegram delivery failure")
            return await super().send_message(chat_id, text)

    fake_bot = FailOnceBot()
    monkeypatch.setattr(bot_module, "bot", fake_bot)
    monkeypatch.setattr(bot_module, "TELESRV_OTP_WEBHOOK_SECRET", "retry-webhook-secret")
    body, headers = signed_request(
        number, "771204", "otp_delivery_retry_909", "retry-webhook-secret"
    )

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=bot_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert first.status_code == 502
            assert first.json()["detail"]["error_code"] == "BOT_DELIVERY_FAILED"
            assert first.json()["detail"]["retryable"] is True
            assert (await store.latest_code(number))[0] == "771204"

            retry = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert retry.status_code == 200
            assert retry.json()["accepted"] is True
            assert retry.json()["message_id"] == "authwaysgram:1"
            assert len(fake_bot.messages) == 1
            assert "771204" in fake_bot.messages[0][1]
            assert fake_bot.attempts == 2
            assert (await store.latest_code(number))[0] == "771204"

            duplicate = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert duplicate.status_code == 200
            assert duplicate.json()["duplicate"] is True
            assert len(fake_bot.messages) == 1
            assert fake_bot.attempts == 2

    run(scenario())


def test_telesrv_webhook_retries_rate_limited_delivery_after_cooldown(
    store: bot_module.Store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run(store.upsert_user(910, 9010))
    run(store.set_verified(910, True))
    number = run(store.allocate_number(910))
    fake_bot = FakeBot()
    monkeypatch.setattr(bot_module, "bot", fake_bot)
    monkeypatch.setattr(bot_module, "TELESRV_OTP_WEBHOOK_SECRET", "rate-webhook-secret")
    body, headers = signed_request(
        number, "661903", "otp_delivery_rate_910", "rate-webhook-secret"
    )

    async def scenario() -> None:
        with __import__("sqlite3").connect(store.path) as conn:
            conn.execute(
                "UPDATE numbers SET last_code_requested_at=? WHERE number=?",
                (int(time.time()), number),
            )

        transport = httpx.ASGITransport(app=bot_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            limited = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert limited.status_code == 429
            assert limited.json()["detail"]["retryable"] is True
            assert fake_bot.messages == []

            with __import__("sqlite3").connect(store.path) as conn:
                conn.execute(
                    "UPDATE numbers SET last_code_requested_at=? WHERE number=?",
                    (int(time.time()) - 31, number),
                )

            retry = await client.post("/v1/otp/deliveries", content=body, headers=headers)
            assert retry.status_code == 200
            assert retry.json()["accepted"] is True
            assert len(fake_bot.messages) == 1
            assert "661903" in fake_bot.messages[0][1]

    run(scenario())
