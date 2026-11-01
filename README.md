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

The Android/API integration currently uses this service for virtual-number resolution and OTP verification. The AuthBot SQLite database also stores WaysGram account balances, gift catalog entries, gift inventory, and administrator audit records. Keep `DATABASE_PATH` on persistent storage. The migration of all messaging and account-session APIs into this service is a separate implementation stage; the current OTP endpoints do not yet provide chat or message transport.

## Admin panel

Open the bot using Telegram account ID `8888957702` and send `/admin`. The panel is entirely inside Telegram; there is no web or Android admin interface.

Current sections:
- **Statistics:** account count, blocked accounts, issued virtual numbers, active OTP codes, gift catalog/inventory counts, and total Stars/Gram balances.
- **Accounts:** search by Telegram ID or virtual `+1` identifier; inspect account status and balances; block/unblock an account.
- **Balances:** administrator-only Stars and Gram crediting, with a transaction record and audit log.
- **Gift catalog:** create a gift with a name, Gram price, and available supply.
- **Gift inventory:** inspect issued gifts and their serial numbers; issue a catalog gift to an account.
- **Transactions and audit log:** inspect recent balance changes and administrator actions.

Admin actions are restricted to `ADMIN_ID`. Account suspensions are enforced by the bot's number-resolution and OTP-verification API. Balance credits are internal WaysGram ledger entries; this release does not implement cash-out or external payment processing.
