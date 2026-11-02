#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

if ! command -v pkg >/dev/null 2>&1; then
  echo "Этот скрипт предназначен для Termux на Android." >&2
  exit 1
fi

pkg update -y
pkg install -y python clang rust openssl libffi pkg-config

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if [[ ! -f .env ]]; then
  cp .env.example .env
  chmod 600 .env
  # Docker's default data path is not writable in a normal Termux app sandbox.
  sed -i "s|^DATABASE_PATH=/data/waysgram_authbot.sqlite3$|DATABASE_PATH=$PWD/data/waysgram_authbot.sqlite3|" .env
  # Keep the test API reachable only from the same Android device.
  sed -i "s|^INTERNAL_API_HOST=0.0.0.0$|INTERNAL_API_HOST=127.0.0.1|" .env
  echo "Создан .env. Заполни BOT_TOKEN, ADMIN_ID, INTERNAL_API_TOKEN и OTP_FERNET_KEY, затем снова запусти этот скрипт."
  exit 0
fi

set -a
# .env contains shell-compatible KEY=value assignments.
# shellcheck disable=SC1091
source .env
set +a

missing=()
[[ -n "${BOT_TOKEN:-}" ]] || missing+=(BOT_TOKEN)
[[ -n "${INTERNAL_API_TOKEN:-}" ]] || missing+=(INTERNAL_API_TOKEN)
[[ -n "${OTP_FERNET_KEY:-}" ]] || missing+=(OTP_FERNET_KEY)

if (( ${#missing[@]} > 0 )); then
  printf 'Не заполнены обязательные переменные: %s\n' "${missing[*]}" >&2
  exit 1
fi

db_dir="${DATABASE_PATH%/*}"
if [[ "$db_dir" == "$DATABASE_PATH" ]]; then
  db_dir="."
fi
mkdir -p "$db_dir"
echo "Запуск WaysGram AuthBot. Локальный API: http://127.0.0.1:${INTERNAL_API_PORT:-8081}"
exec python bot.py
