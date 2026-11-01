# WaysGram AuthBot

Python Telegram bot for the WaysGram-owned account system. It provides Russian/English selection, emoji CAPTCHA, the user menu, an in-bot admin panel, virtual +1 login IDs, and a private HTTP API for WaysGram authentication.

## Virtual +1 numbers

The bot automatically generates a unique internal identifier in the format +1 followed by ten digits and saves it in its own SQLite database. These are **virtual WaysGram identifiers**, not carrier-issued phone numbers: they cannot receive calls or SMS and are intended only for logging in to WaysGram.

The bot creates six-digit one-time WaysGram codes itself. When the WaysGram backend asks for a code, the bot creates a short-lived code, sends it to the Telegram account linked to that virtual number, and lets the user retrieve it using Get code. The backend verifies the code through the bot's private API.

The bot does not read SMS, request Telegram login codes, or forward authentication codes belonging to Telegram or another service.

## Run

Python 3.11+:

1. Install dependencies: pip install -r requirements.txt
2. Set BOT_TOKEN and the other environment variables in the hosting platform.
3. Start the worker: python bot.py

BOT_TOKEN is read only from the environment. Do not commit .env or put the bot token into source code. The bot uses long polling and starts an internal API on 0.0.0.0:8081 by default. Use persistent disk storage for DATABASE_PATH; ephemeral hosting storage can be lost on restart/redeploy.

## Environment

| Variable | Purpose |
|---|---|
| BOT_TOKEN | Required Telegram bot token |
| ADMIN_ID | Admin Telegram ID; defaults to 8888957702 |
| DATABASE_PATH | SQLite path; defaults to data/waysgram_authbot.sqlite3 |
| INTERNAL_API_TOKEN | Secret used to authenticate WaysGram backend calls |
| INTERNAL_API_HOST | API bind host; defaults to 0.0.0.0 |
| INTERNAL_API_PORT | API bind port; defaults to 8081 |
| LOG_LEVEL | Logging level; defaults to INFO |

## Internal API

All endpoints except /health require the X-Internal-Token header.

- GET /health — health check.
- POST /internal/v1/number/resolve — JSON {"number":"+1XXXXXXXXXX"}; confirms that the virtual number is assigned and returns the linked Telegram user ID.
- POST /internal/v1/auth-code/request — JSON {"number":"+1XXXXXXXXXX"}; creates a six-digit code valid for five minutes and sends it to the linked bot user. Requests are rate-limited.
- POST /internal/v1/auth-code/verify — JSON {"number":"+1XXXXXXXXXX","code":"123456"}; checks the code, limits attempts, and consumes the code after successful verification.

The WaysGram backend must use the verify endpoint and enforce additional per-account and per-IP rate limits. This bot database stores the Telegram-to-virtual-number mapping and temporary authentication codes. The main WaysGram backend remains the source of truth for accounts, Stars, Gram balances, and gifts.

## Admin

Open AuthWaysGram_bot using Telegram account ID 8888957702 and send /admin. The panel shows user/number/code counts, service status, and recent Telegram user IDs.
