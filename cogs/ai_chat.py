"""
cogs/ai_chat.py
on_message event handler and misc utility commands (ping).

Mention handling
----------------
Any guild member may @-mention the bot to start a conversation.  The message
(minus the bot's own mention tag) is forwarded to ChatContextManager.chat().
The full ``discord.Message`` object is passed through so tool callables in the
cogs can access guild/member context.

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
            # FIX: Only strip the bot's specific mention so target users stay in the text!
            user_text = (
                message.content
                .replace(f"<@{self.bot.user.id}>", "")
                .replace(f"<@!{self.bot.user.id}>", "")
                .strip()
            )

            if not user_text:
                user_text = "System check."

            log.info(
                "Mention received | channel=%s | author=%s | text=%r",
                message.channel.id,
                message.author,
                user_text,
            )

            async with message.channel.typing():
                try:
                    response_text = await self._chat.chat(message, user_text)
                except Exception as exc:  # pylint: disable=broad-except
                    log.exception("Error in chat_manager.chat")
                    response_text = f"An internal error occurred: {exc}"

            await message.reply(_truncate(response_text))

        # NOTE: process_commands() is NOT called here intentionally.
        # Using @commands.Cog.listener() adds an *additional* listener alongside
        # the default Bot.on_message, which already calls process_commands().
        # Calling it here too would cause every prefix command to fire twice.

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
