"""
cogs/ai_chat.py
on_message event handler and misc utility commands (ping).

Mention handling
----------------
Any guild member may @-mention the bot to start a conversation.  The message
(minus the bot's own mention tag) is forwarded to ChatContextManager.chat().
The full ``discord.Message`` object is passed through so tool callables in the
cogs can access guild/member context.

Twitch integration
------------------
Stream status is injected into the LLM system prompt on every call via
``_get_twitch_context()`` so the model can answer "are you live?" naturally
from context rather than via a tool call.  A compact status footer is also
appended to every reply by ``_build_twitch_footer()``.

Both helpers read ``TwitchCog.is_live`` (the cached last-poll value) — no
extra Twitch API call is made during message handling.

Moderation / security gate
--------------------------
Moderation and security tools are gated at TWO layers:
  1. The LLM system prompt instructs the model to refuse restricted actions
     for anyone who is not pwnedByJT.
  2. ChatContextManager._execute_tool() performs a hard code-level check
     against config.BOT_OWNER_ID before dispatching any restricted tool.

Command processing
------------------
``bot.process_commands(message)`` is always called at the end of on_message so
prefix commands work independently of the mention handler.
"""

from __future__ import annotations

import logging

import discord
from discord import app_commands
from discord.ext import commands

import config
from services.llm_manager import ChatContextManager

log = logging.getLogger("root_ai.ai_chat")

MAX_DISCORD_MSG = 1900  # keep a buffer below Discord's 2 000-character hard limit


def _truncate(text: str) -> str:
    """Ensure the reply fits within Discord's message length limit."""
    if len(text) > MAX_DISCORD_MSG:
        return text[:MAX_DISCORD_MSG] + "... [Output Truncated]"
    return text


class AIChatCog(commands.Cog, name="AI Chat"):
    """Handles @-mention messages and routes them through the LLM pipeline."""

    def __init__(self, bot: commands.Bot, chat_manager: ChatContextManager) -> None:
        self.bot = bot
        self._chat = chat_manager

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        # Never respond to ourselves
        if message.author == self.bot.user:
            return

        # Only respond when directly mentioned — open to all community members.
        # Moderation/security tool access is enforced inside ChatContextManager.
        if self.bot.user and self.bot.user.mentioned_in(message):
            # Strip the bot's own mention tag; leave other @mentions intact
            # so moderation tool targets (e.g. <@12345>) survive into the LLM.
            user_text = (
                message.content
                .replace(f"<@{self.bot.user.id}>", "")
                .replace(f"<@!{self.bot.user.id}>", "")
                .strip()
            )

            if not user_text:
                user_text = "Hey! What can you do, and how can you help me?"

            log.info(
                "Mention received | channel=%s | author=%s | text=%r",
                message.channel.id,
                message.author,
                user_text,
            )

            async with message.channel.typing():
                try:
                    # Inject cached Twitch stream state into the LLM system prompt
                    # so the model can answer "are you live?" without a tool call.
                    stream_context = self._get_twitch_context()
                    response_text = await self._chat.chat(
                        message, user_text, stream_context=stream_context
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.exception("Error in chat_manager.chat")
                    response_text = f"An internal error occurred: {exc}"

            # Append a compact Twitch status footer below every AI response.
            footer = self._build_twitch_footer()
            if footer:
                response_text = f"{response_text}\n\n{footer}"

            await message.reply(_truncate(response_text))

        # NOTE: process_commands() is NOT called here intentionally.
        # Using @commands.Cog.listener() adds an *additional* listener alongside
        # the default Bot.on_message, which already calls process_commands().
        # Calling it here too would cause every prefix command to fire twice.

    # ------------------------------------------------------------------
    # Twitch helpers
    # ------------------------------------------------------------------

    def _get_twitch_context(self) -> str:
        """
        Build a STREAM STATUS context string for injection into the LLM system
        prompt.  Reads the cached ``TwitchCog.is_live`` value — no API call.

        Returns an empty string if TwitchCog is not loaded or the first
        background poll hasn't completed yet (``is_live is None``).
        """
        twitch_cog = self.bot.get_cog("Twitch")
        if twitch_cog is None or twitch_cog.is_live is None:
            return ""

        if twitch_cog.is_live:
            return (
                "\n\nSTREAM STATUS: pwnedByJT is currently **LIVE** on Twitch. "
                "Watch at https://twitch.tv/pwnedByJT"
            )
        return (
            "\n\nSTREAM STATUS: pwnedByJT is currently **offline** on Twitch. "
            "Channel: https://twitch.tv/pwnedByJT"
        )

    def _build_twitch_footer(self) -> str:
        """
        Return a one-line Twitch status footer for appending to every bot reply.

        Returns an empty string if TwitchCog is not loaded or the first poll
        hasn't run yet, so no footer is shown at bot startup before status is
        actually known.
        """
        twitch_cog = self.bot.get_cog("Twitch")
        if twitch_cog is None or twitch_cog.is_live is None:
            return ""

        if twitch_cog.is_live:
            return "📺 pwnedByJT is **LIVE** → https://twitch.tv/pwnedByJT"
        return "📺 pwnedByJT is offline · https://twitch.tv/pwnedByJT"

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    @app_commands.command(name="ping", description="Check if the bot is alive.")
    async def ping(self, interaction: discord.Interaction) -> None:
        """Simple latency check."""
        await interaction.response.send_message("pong", ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(AIChatCog(bot, chat_manager))
