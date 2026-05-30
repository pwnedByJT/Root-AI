"""
config.py
Centralised environment variable loading for Root AI.

All modules import from here — never call os.getenv() outside this file.
"""

import os

from dotenv import load_dotenv

load_dotenv()

# ── Discord ──────────────────────────────────────────────────────────────────
DISCORD_TOKEN: str = os.getenv("ROOT_AI_DISCORD_TOKEN") or os.getenv("DISCORD_TOKEN", "")
BOT_PREFIX: str = os.getenv("BOT_PREFIX", ".")
BOT_OWNER_ID: int = 389271525485707274  # pwnedByJT — used for @mentions in access-denied replies

if not DISCORD_TOKEN:
    raise EnvironmentError(
        "No Discord token found. Set ROOT_AI_DISCORD_TOKEN or DISCORD_TOKEN in your .env file."
    )

# ── LLM / Ollama ─────────────────────────────────────────────────────────────
LOCAL_LLM_URL: str = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/v1")
LOCAL_MODEL_NAME: str = os.getenv("LOCAL_MODEL_NAME", "llama3.1")

# ── SSH / Parrot OS ───────────────────────────────────────────────────────────
PARROT_HOST: str = os.getenv("PARROT_HOST", "127.0.0.1")
PARROT_USER: str = os.getenv("PARROT_USER", "")
PARROT_PASS: str = os.getenv("PARROT_PASS", "")

# ── Twitch ────────────────────────────────────────────────────────────────────
TWITCH_CLIENT_ID: str = os.getenv("ROOT_AI_TWITCH_CLIENT_ID", "")
TWITCH_CLIENT_SECRET: str = os.getenv("ROOT_AI_TWITCH_CLIENT_SECRET", "")
TWITCH_BROADCASTER_LOGIN: str = "pwnedByJT"
TWITCH_NOTIFY_CHANNEL_ID: int = 1207980068807249930
