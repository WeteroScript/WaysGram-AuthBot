# WaysGram observability

This backend supports optional PostHog product analytics/error tracking and Datadog APM/log correlation. Both integrations are disabled or inert until their environment is configured; missing monitoring configuration must not prevent the API or Telegram bot from starting.

## PostHog

Set these variables in the backend hosting environment:

- `POSTHOG_API_KEY`: the WaysGram PostHog project token.
- `POSTHOG_HOST`: `https://eu.i.posthog.com` for the current EU project.

The backend creates one PostHog client per process, enables exception autocapture and FastAPI request exception middleware, and shuts the client down cleanly. Product events are aggregate backend events. The distinct ID is a fixed service identity and person-profile processing is disabled; raw account IDs, phone numbers, OTPs, session tokens, message bodies, gift IDs, and invite tokens are not sent. Event properties are allowlisted in `waysgram_observability.py`.

## Datadog

Datadog APM requires a Datadog Agent reachable from the backend container. Configure the Agent outside this application container with the organization's Datadog API key and site. Do not put `DD_API_KEY` in WaysGram application variables.

Set:

- `DD_TRACE_ENABLED=true`
- `DD_AGENT_HOST` to the Agent's reachable hostname or sidecar address.
- `DD_TRACE_AGENT_PORT=8126`
- `DD_SERVICE=waysgram-authbot`
- `DD_ENV=production`
- `DD_VERSION` to the deployed release identifier.
- `DD_LOGS_INJECTION=true`

The `ddtrace` auto-instrumentation hooks FastAPI and supported Python integrations. Log records include Datadog trace/span correlation fields. The Agent or hosting platform must also collect the container's stdout/stderr logs and tag them with the same service/environment/version values. Without a reachable Agent and log collection, adding the SDK alone will not create APM traces or searchable logs.

## Android client

The Android source-preparation step reads `POSTHOG_API_KEY` and `POSTHOG_HOST` from the build environment and injects them into the generated Telegram library BuildConfig. The project token is public client configuration, but it remains environment-driven and is not committed to source.

For GitHub Actions APK builds, configure repository secret `POSTHOG_API_KEY` and repository variable `POSTHOG_HOST` with `https://eu.i.posthog.com`. For a local build, export both variables before running `scripts/prepare-android-source.sh` and `scripts/prepare_android_dev_build.py`.

Android exception autocapture is enabled when the PostHog SDK is configured. Release builds that use R8/ProGuard need their mapping files uploaded to PostHog for readable de-obfuscated stack traces.

## Verification

After deployment/build with the variables configured:

1. Trigger a normal login, message send, channel/group creation, media upload, and gift purchase.
2. Confirm the corresponding `waysgram_*` events and exception events appear in PostHog.
3. Confirm Datadog has APM service `waysgram-authbot`, HTTP traces, and correlated stdout logs.
4. Keep session replay disabled unless a separate privacy review and explicit product decision authorizes it.
