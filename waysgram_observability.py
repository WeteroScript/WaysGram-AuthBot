from __future__ import annotations

import importlib
import logging
import os
import re
from typing import Any

log = logging.getLogger("waysgram-observability")
_POSTHOG_CLIENT: Any | None = None
_ALLOWED_EVENT_PROPERTIES = frozenset({"surface", "visibility", "media_type", "catalog", "asset", "method"})


def enable_datadog_tracing() -> bool:
    """Enable ddtrace only when a Datadog Agent is configured for this process."""
    enabled = os.getenv("DD_TRACE_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return False

    os.environ.setdefault("DD_SERVICE", "waysgram-authbot")
    os.environ.setdefault("DD_ENV", os.getenv("APP_ENV", "production"))
    os.environ.setdefault("DD_VERSION", os.getenv("APP_VERSION", "unknown"))
    os.environ.setdefault("DD_LOGS_INJECTION", "true")
    importlib.import_module("ddtrace.auto")
    return True



def install_datadog_log_context() -> None:
    """Keep Datadog trace correlation fields in logs, even when tracing is disabled."""
    class DatadogLogContextFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.__dict__.setdefault("dd.trace_id", "0")
            record.__dict__.setdefault("dd.span_id", "0")
            record.__dict__.setdefault("dd.service", os.getenv("DD_SERVICE", "waysgram-authbot"))
            record.__dict__.setdefault("dd.env", os.getenv("DD_ENV", "production"))
            record.__dict__.setdefault("dd.version", os.getenv("DD_VERSION", "unknown"))
            return True

    for handler in logging.getLogger().handlers:
        handler.addFilter(DatadogLogContextFilter())

def initialize_observability(app: Any | None = None) -> Any | None:
    """Create one optional PostHog client and attach FastAPI exception middleware."""
    global _POSTHOG_CLIENT
    if _POSTHOG_CLIENT is not None:
        return _POSTHOG_CLIENT

    api_key = os.getenv("POSTHOG_API_KEY", "").strip()
    host = os.getenv("POSTHOG_HOST", "").strip()
    if not api_key or not host:
        if os.getenv("APP_ENV", "development").strip().lower() not in {"prod", "production"}:
            missing = "POSTHOG_API_KEY" if not api_key else "POSTHOG_HOST"
            log.warning(
                "%s variable required by PostHog is missing or un-configured; events will be missed until configured",
                missing,
            )
        return None

    try:
        from posthog import Posthog

        client = Posthog(
            project_api_key=api_key,
            host=host,
            enable_exception_autocapture=True,
            capture_exception_code_variables=False,
            disable_geoip=True,
        )
        if app is not None:
            try:
                from posthog.integrations.asgi import PosthogASGIMiddleware

                app.add_middleware(PosthogASGIMiddleware, client=client)
            except Exception as exc:
                log.warning("PostHog ASGI exception middleware unavailable (%s)", type(exc).__name__)
        _POSTHOG_CLIENT = client
        log.info("PostHog observability initialized")
        return client
    except Exception as exc:
        log.warning("PostHog initialization unavailable (%s)", type(exc).__name__)
        return None


def track_event(event_name: str, properties: dict[str, Any] | None = None) -> None:
    """Capture an allowlisted, aggregate backend event without account-level identity."""
    client = _POSTHOG_CLIENT
    if client is None or not re.fullmatch(r"[a-z0-9_]{1,64}", event_name):
        return

    safe_properties: dict[str, Any] = {}
    for key, value in (properties or {}).items():
        if key in _ALLOWED_EVENT_PROPERTIES and isinstance(value, (str, int, float, bool)):
            safe_properties[key] = value
    safe_properties["$process_person_profile"] = False

    try:
        client.capture(
            f"waysgram_{event_name}",
            distinct_id="waysgram_backend",
            properties=safe_properties,
        )
    except Exception as exc:
        log.debug("PostHog event capture failed (%s)", type(exc).__name__)


def capture_exception(exception: BaseException, surface: str = "backend") -> None:
    client = _POSTHOG_CLIENT
    if client is None:
        return
    try:
        client.capture_exception(
            exception,
            distinct_id="waysgram_backend",
            properties={"surface": surface, "$process_person_profile": False},
        )
    except Exception as exc:
        log.debug("PostHog exception capture failed (%s)", type(exc).__name__)


def shutdown_observability() -> None:
    global _POSTHOG_CLIENT
    client = _POSTHOG_CLIENT
    _POSTHOG_CLIENT = None
    if client is None:
        return
    try:
        client.shutdown()
    except Exception as exc:
        log.debug("PostHog shutdown failed (%s)", type(exc).__name__)
