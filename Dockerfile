FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATABASE_PATH=/data/waysgram_authbot.sqlite3 \
    INTERNAL_API_HOST=0.0.0.0 \
    INTERNAL_API_PORT=8081 \
    PUBLIC_API_BASE_URL=https://bot-1793554244-6434-weterochina.bothost.tech

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --create-home --home-dir /home/waysgram waysgram \
    && mkdir -p /data \
    && chown -R waysgram:waysgram /app /data

COPY --chown=waysgram:waysgram . .

VOLUME ["/data"]
EXPOSE 8081
USER waysgram

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('INTERNAL_API_PORT', '8081') + '/health', timeout=4).read()"

CMD ["python", "bot.py"]
