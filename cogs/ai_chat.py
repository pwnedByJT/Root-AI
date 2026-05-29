"""
cogs/ai_chat.py
on_message event handler and misc utility commands (ping).

Access gate
-----------
Only the owner ("pwnedbyjt") may interact with the bot.  Any other user who
@-mentions it receives an access-denied reply and nothing further happens.

Mention handling
----------------
When the authorised user @-mentions the bot, the message (minus the bot's own
mention tag) is forwarded to ChatContextManager.chat().  The full
``discord.Message`` object is passed through so tool callables in the cogs can
access guild/member context.

Command processing
------------------
``bot.process_commands(message)`` is always called at the end of on_message so
prefix commands work independently of the mention gate.
"""

from __future__ import annotations

import logging

import discord
from discord.ext import commands

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

        # EXCLUSIVE ACCESS LOCKDOWN: Only respond to the authorised owner
        if message.author.name.lower() != "pwnedbyjt":
            if self.bot.user and self.bot.user.mentioned_in(message):
                await message.reply(
                    "Access Denied: Please get with <@!123456789> if you want me to talk with you."
                    # Note: swap 123456789 with your actual Discord user ID for the ping to resolve.
                )
            return

        # Only respond when directly mentioned
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

    @commands.command(name="ping")
    async def ping(self, ctx: commands.Context) -> None:
        """Simple latency check."""
        await ctx.reply("pong")


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(AIChatCog(bot, chat_manager))
