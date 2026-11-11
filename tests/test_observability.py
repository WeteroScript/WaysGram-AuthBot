from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import Mock, patch

import waysgram_observability as observability


class ObservabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        observability._POSTHOG_CLIENT = None

    def tearDown(self) -> None:
        observability._POSTHOG_CLIENT = None

    def test_missing_posthog_configuration_is_non_fatal(self) -> None:
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            self.assertIsNone(observability.initialize_observability())

    def test_posthog_client_is_initialized_once(self) -> None:
        fake_client = Mock()
        fake_module = types.SimpleNamespace(Posthog=Mock(return_value=fake_client))
        with patch.dict(
            os.environ,
            {"POSTHOG_API_KEY": "phc_test", "POSTHOG_HOST": "https://eu.i.posthog.com"},
            clear=True,
        ), patch.dict(sys.modules, {"posthog": fake_module}):
            first = observability.initialize_observability()
            second = observability.initialize_observability()
        self.assertIs(first, fake_client)
        self.assertIs(second, fake_client)
        fake_module.Posthog.assert_called_once()
        self.assertTrue(fake_module.Posthog.call_args.kwargs["enable_exception_autocapture"])
        self.assertFalse(fake_module.Posthog.call_args.kwargs["capture_exception_code_variables"])

    def test_event_capture_only_sends_allowlisted_properties(self) -> None:
        client = Mock()
        observability._POSTHOG_CLIENT = client
        observability.track_event(
            "message_sent",
            {
                "surface": "direct",
                "body": "private message text",
                "recipient_id": 123456,
                "visibility": "private",
            },
        )
        client.capture.assert_called_once()
        args, kwargs = client.capture.call_args
        self.assertEqual(args, ("waysgram_message_sent",))
        self.assertEqual(kwargs["distinct_id"], "waysgram_backend")
        self.assertEqual(
            kwargs["properties"],
            {
                "surface": "direct",
                "visibility": "private",
                "$process_person_profile": False,
            },
        )

    def test_event_name_is_validated(self) -> None:
        client = Mock()
        observability._POSTHOG_CLIENT = client
        observability.track_event("bad event name")
        client.capture.assert_not_called()

    def test_shutdown_flushes_and_resets_client(self) -> None:
        client = Mock()
        observability._POSTHOG_CLIENT = client
        observability.shutdown_observability()
        client.shutdown.assert_called_once()
        self.assertIsNone(observability._POSTHOG_CLIENT)


if __name__ == "__main__":
    unittest.main()
