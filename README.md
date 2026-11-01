# WaysGram AuthBot

Python Telegram bot for the WaysGram-owned account system. It provides Russian/English selection, emoji CAPTCHA, the user menu, an in-bot admin panel, virtual +1 login IDs, and a private HTTP API for WaysGram authentication.

## Virtual +1 numbers

The bot automatically generates a unique internal identifier in the format +1 followed by ten digits and saves it in its own SQLite database. These are **virtual WaysGram identifiers**, not carrier-issued phone numbers: they cannot receive calls or SMS and are intended only for logging in to WaysGram.

The bot creates six-digit one-time WaysGram codes itself. When the WaysGram backend asks for a code, the bot creates a short-lived code, encrypts it in SQLite, and sends a notification that the code is ready. The user retrieves the code by tapping Get code in the bot. The backend verifies the code through the bot's private API.

The bot does not read SMS, request Telegram login codes, or forward authentication codes belonging to Telegram or another service. In Settings, the `->` button returns to the main menu.

## Run

Python 3.11+:

1. Install dependencies: pip install -r requirements.txt
2. Set BOT_TOKEN, INTERNAL_API_TOKEN, and OTP_FERNET_KEY as hosting environment variables. OTP_FERNET_KEY is required; the process intentionally stops at startup if it is missing.
3. Deploy as a web service using the included Procfile: web: python bot.py

BOT_TOKEN is read only from the environment. Do not commit .env or put the bot token into source code. Generate `OTP_FERNET_KEY` using `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`, then store it as a hosting secret. Keep this key unchanged across restarts and redeployments. The bot uses long polling and starts its internal API in the same process. It binds to INTERNAL_API_PORT, then the hosting platform PORT, then 8081. Deploy as a web service (or an equivalent process that exposes this API), not as a worker-only service, so the WaysGram backend can reach it. Use persistent disk storage for DATABASE_PATH; ephemeral hosting storage can be lost on restart/redeploy.

## Environment

| Variable | Purpose |
|---|---|
| BOT_TOKEN | Required Telegram bot token |
| ADMIN_ID | Admin Telegram ID; defaults to 8888957702 |
| DATABASE_PATH | SQLite path; defaults to data/waysgram_authbot.sqlite3 |
| INTERNAL_API_TOKEN | Secret used to authenticate WaysGram backend calls |
| OTP_FERNET_KEY | Required persistent Fernet key used to encrypt OTP codes; generate it with the command above and keep it unchanged |
| INTERNAL_API_HOST | API bind host; defaults to 0.0.0.0 |
| INTERNAL_API_PORT | API bind port; defaults to 8081 |
| LOG_LEVEL | Logging level; defaults to INFO |

## Internal API

All endpoints except /health require the X-Internal-Token header.

- GET /health — health check.
- POST /internal/v1/number/resolve — JSON {"number":"+1XXXXXXXXXX"}; confirms that the virtual number is assigned and returns the linked Telegram user ID.
- POST /internal/v1/auth-code/request — JSON {"number":"+1XXXXXXXXXX"}; creates a six-digit code valid for five minutes, encrypts it in SQLite, and notifies the linked bot user. The actual code is revealed only after the user taps “Get code”. Requests are rate-limited.
- POST /internal/v1/auth-code/verify — JSON {"number":"+1XXXXXXXXXX","code":"123456"}; checks the code, limits attempts, and consumes the code after successful verification.

The WaysGram backend must be configured with `NEXUSGRAM_AUTHBOT_URL` (the public HTTPS base URL of this service) and `NEXUSGRAM_AUTHBOT_TOKEN` (the same secret as `INTERNAL_API_TOKEN`), use the verify endpoint, and enforce additional per-account and per-IP rate limits. Run this service with a persistent disk for `DATABASE_PATH`. This bot database stores the Telegram-to-virtual-number mapping and encrypted temporary authentication codes. The main WaysGram backend remains the source of truth for accounts, Stars, Gram balances, and gifts.

## Admin

Open AuthWaysGram_bot using Telegram account ID 8888957702 and send /admin. The panel shows user/number/code counts, service status, and recent Telegram user IDs.
