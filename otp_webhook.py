from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping


MAX_BODY_BYTES = 64 * 1024
MAX_TIMESTAMP_SKEW_SECONDS = 300
PHONE_RE = re.compile(r"^\+1[0-9]{10}$")
CODE_RE = re.compile(r"^[0-9]{6}$")


class OtpWebhookError(ValueError):
    def __init__(self, message: str, status_code: int = 400, error_code: str = "REQUEST_INVALID"):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


@dataclass(frozen=True)
class OtpWebhookDelivery:
    delivery_id: str
    number: str
    code: str
    expires_in: int
    expires_at: int
    payload_sha256: str


def parse_telesrv_delivery(
    body: bytes,
    headers: Mapping[str, str],
    secret: str,
    now: int | None = None,
) -> OtpWebhookDelivery:
    """Validate one signed telesrv webhook request for an AuthBot virtual number."""
    if not secret:
        raise OtpWebhookError(
            "OTP webhook secret is not configured",
            status_code=503,
            error_code="WEBHOOK_NOT_CONFIGURED",
        )
    if len(body) > MAX_BODY_BYTES:
        raise OtpWebhookError(
            "Request body is too large",
            status_code=413,
            error_code="REQUEST_TOO_LARGE",
        )

    normalized_headers = {str(key).lower(): str(value) for key, value in headers.items()}
    timestamp = normalized_headers.get("x-telesrv-timestamp", "")
    signature = normalized_headers.get("x-telesrv-signature", "")
    idempotency_key = normalized_headers.get("idempotency-key", "")

    try:
        issued_at = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise OtpWebhookError(
            "Invalid webhook timestamp",
            status_code=401,
            error_code="SIGNATURE_INVALID",
        ) from exc

    current_time = int(time.time()) if now is None else int(now)
    if abs(current_time - issued_at) > MAX_TIMESTAMP_SKEW_SECONDS:
        raise OtpWebhookError(
            "Webhook timestamp is outside the accepted time window",
            status_code=401,
            error_code="SIGNATURE_EXPIRED",
        )

    signed = timestamp.encode("ascii") + b"." + body
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        signed,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise OtpWebhookError(
            "Webhook signature is invalid",
            status_code=401,
            error_code="SIGNATURE_INVALID",
        )

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OtpWebhookError(
            "Request body is not valid UTF-8 JSON",
            status_code=400,
            error_code="JSON_INVALID",
        ) from exc

    if not isinstance(payload, dict):
        raise OtpWebhookError("JSON payload must be an object")

    delivery_id = payload.get("delivery_id")
    if (
        payload.get("version") != "1"
        or not isinstance(delivery_id, str)
        or not delivery_id
        or len(delivery_id) > 128
        or delivery_id != idempotency_key
    ):
        raise OtpWebhookError("Delivery ID or protocol version is invalid")

    if payload.get("purpose") != "login_sms" or payload.get("channel") != "sms":
        raise OtpWebhookError(
            "Only WaysGram phone login codes are accepted",
            status_code=422,
            error_code="PURPOSE_UNSUPPORTED",
        )

    number = payload.get("recipient")
    code = payload.get("code")
    if not isinstance(number, str) or not PHONE_RE.fullmatch(number):
        raise OtpWebhookError(
            "Recipient is not an assigned WaysGram virtual number",
            status_code=422,
            error_code="RECIPIENT_INVALID",
        )
    if not isinstance(code, str) or not CODE_RE.fullmatch(code):
        raise OtpWebhookError(
            "The login code must contain exactly six digits",
            status_code=422,
            error_code="CODE_INVALID",
        )

    expires_at_raw = payload.get("expires_at")
    expires_in_raw = payload.get("expires_in")
    if not isinstance(expires_at_raw, str) or not isinstance(expires_in_raw, int):
        raise OtpWebhookError("Code expiry is missing or invalid")
    try:
        expiry = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            raise ValueError("timezone is required")
        expires_at = int(expiry.astimezone(timezone.utc).timestamp())
    except (TypeError, ValueError, OverflowError) as exc:
        raise OtpWebhookError("Code expiry timestamp is invalid") from exc

    seconds_remaining = min(expires_in_raw, expires_at - current_time)
    if not 1 <= expires_in_raw <= 900 or seconds_remaining < 1:
        raise OtpWebhookError(
            "The login code has expired or has an invalid lifetime",
            status_code=422,
            error_code="CODE_EXPIRED",
        )

    return OtpWebhookDelivery(
        delivery_id=delivery_id,
        number=number,
        code=code,
        expires_in=seconds_remaining,
        expires_at=expires_at,
        payload_sha256=hashlib.sha256(body).hexdigest(),
    )
