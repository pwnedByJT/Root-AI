"""
main.py
Root AI Discord Bot — entry point.

Responsibilities
----------------
* Configure logging.
* Instantiate the bot and attach a shared ChatContextManager as ``bot.chat_manager``.
* Load all extensions (Cogs) via ``setup_hook`` using the discord.py 2.x async API.
* Verify the Ollama gateway is reachable on ``on_ready``.
* Start the bot.
"""

from __future__ import annotations

import logging

import discord
from discord.ext import commands

import config
from services.llm_manager import ChatContextManager, get_ollama_client

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("root_ai")

# ---------------------------------------------------------------------------
# Extensions to load (order matters: tools must register before ai_chat uses them)
# ---------------------------------------------------------------------------

EXTENSIONS = [
    "cogs.security",
    "cogs.moderation",
    "cogs.twitch",
    "cogs.sec_monitor",   # HTB/THM accountability tracker + /streak command
    "cogs.rep",
    "cogs.shop",
    "cogs.recon",         # Phase 1 OSINT — /recon slash command
    "cogs.nuclei",        # Phase 10 Nuclei Scanner — /nuclei + run_nuclei_scan()
    "cogs.autopwn",       # Phase 2 ReAct pentest agent — /autopwn slash command
    "cogs.c2_dashboard",  # Phase 3 Persistent C2 dashboard — /c2_dashboard
    "cogs.audit_repo",    # Phase 4 Repo security audit — /audit_repo + H1 export
    "cogs.watchdog",          # Phase 5 Bug Bounty Watchdog — /watchdog + background loop
    "cogs.exploit_suggester", # Phase 8 Exploit Suggester — /exploits + search_exploits()
    "cogs.ai_chat",           # Always last — consumes all registered tools
]

# ---------------------------------------------------------------------------
# Bot subclass
# ---------------------------------------------------------------------------


class RootAIBot(commands.Bot):
    """
    Bot subclass that owns the shared ``ChatContextManager`` instance and loads
    all extensions asynchronously via ``setup_hook``.
    """

    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True  # CRITICAL: Required to fetch users and modify their roles

        super().__init__(command_prefix=config.BOT_PREFIX, intents=intents)

        # Attach the chat manager so cogs can access it via ``bot.chat_manager``
        self.chat_manager = ChatContextManager()

    async def setup_hook(self) -> None:
        """Called by discord.py before the bot connects — safe place for async setup."""
        for ext in EXTENSIONS:
            try:
                await self.load_extension(ext)
                log.info("Loaded extension: %s", ext)
            except Exception:  # pylint: disable=broad-except
                log.exception("Failed to load extension: %s", ext)

        # Copy all globally-registered Cog commands into the guild so they
        # appear instantly (guild sync propagates immediately; global takes ~1 hour).
        guild = discord.Object(id=config.GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        synced = await self.tree.sync(guild=guild)
        log.info("Synced %d slash command(s) to guild %d", len(synced), config.GUILD_ID)

    async def on_ready(self) -> None:
        log.info("Logged in as %s (ID: %s)", self.user, self.user.id)
        log.info("Bot prefix: '%s'", config.BOT_PREFIX)

        # Verify Ollama gateway is reachable
        try:
            client = get_ollama_client()
            models = await client.models.list()
            model_names = [m.id for m in models.data]
            log.info("Ollama gateway online. Available models: %s", model_names)
        except Exception as exc:  # pylint: disable=broad-except
            log.warning(
                "Could not reach Ollama gateway at %s — %s",
                config.LOCAL_LLM_URL,
                exc,
            )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    bot = RootAIBot()
    bot.run(config.DISCORD_TOKEN, log_handler=None)  # logging already configured above
