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
GUILD_ID: int = int(os.getenv("DISCORD_GUILD_ID", "0"))

if not DISCORD_TOKEN:
    raise EnvironmentError(
        "No Discord token found. Set ROOT_AI_DISCORD_TOKEN or DISCORD_TOKEN in your .env file."
    )

if not GUILD_ID:
    raise EnvironmentError(
        "DISCORD_GUILD_ID is not set in your .env file. "
        "Required for instant slash command sync. Set it to your Discord server ID."
    )

# ── LLM / Ollama ─────────────────────────────────────────────────────────────
LOCAL_LLM_URL: str = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/v1")
LOCAL_MODEL_NAME: str = os.getenv("LOCAL_MODEL_NAME", "llama3.1")

# ── SSH / Parrot OS ───────────────────────────────────────────────────────────
PARROT_HOST: str = os.getenv("PARROT_HOST", "127.0.0.1")
PARROT_USER: str = os.getenv("PARROT_USER", "")
PARROT_PASS: str = os.getenv("PARROT_PASS", "")
C2_SUBNET_CIDR: str = os.getenv("C2_SUBNET_CIDR", "192.168.1.0/24")

# ── Twitch ────────────────────────────────────────────────────────────────────
TWITCH_CLIENT_ID: str = os.getenv("ROOT_AI_TWITCH_CLIENT_ID", "")
TWITCH_CLIENT_SECRET: str = os.getenv("ROOT_AI_TWITCH_CLIENT_SECRET", "")
TWITCH_BROADCASTER_LOGIN: str = "pwnedByJT"
TWITCH_NOTIFY_CHANNEL_ID: int = 1207980068807249930

# ── GitHub (Phase 4 Repo Auditor) ────────────────────────────────────────────
# Optional: set a PAT to authenticate private-repo clones. Never logged.
GITHUB_PAT: str = os.getenv("GITHUB_PAT", "")

# ── HTB / THM Streak Monitor ──────────────────────────────────────────────────
# HTB_API_TOKEN: generate at https://app.hackthebox.com/profile/settings → App Tokens
HTB_API_TOKEN: str = os.getenv("HTB_API_TOKEN", "")
# SEC_MONITOR_CHANNEL_ID: Discord channel where streak-danger alerts are posted
SEC_MONITOR_CHANNEL_ID: int = int(os.getenv("SEC_MONITOR_CHANNEL_ID", "0"))

# ── Shodan (Phase 1 / 5 — OSINT & Watchdog) ──────────────────────────────────
# Free-tier api.host() — no query credits consumed. Leave empty to disable Shodan.
# Generate at: https://account.shodan.io → API Keys
SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")

# ── NVD (Phase 7 — CVE enrichment) ────────────────────────────────────────────
# Optional. Without a key: 5 req / 30 s (6.5 s sleep between lookups).
# With a key: 50 req / 30 s (0.6 s sleep) — significantly faster enrichment.
# Register free at: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

# ── Phase 5 Bug Bounty Watchdog ───────────────────────────────────────────────
# WATCHDOG_CHANNEL_ID: Discord channel where new-asset alerts are posted
WATCHDOG_CHANNEL_ID: int = int(os.getenv("WATCHDOG_CHANNEL_ID", "0"))
# WATCHDOG_DB_PATH: local SQLite file for target/subdomain baseline storage
WATCHDOG_DB_PATH: str = os.getenv("WATCHDOG_DB_PATH", "data/watchdog.db")
# WATCHDOG_INTERVAL_HOURS: how often the background loop rescans all targets
WATCHDOG_INTERVAL_HOURS: int = int(os.getenv("WATCHDOG_INTERVAL_HOURS", "6"))
