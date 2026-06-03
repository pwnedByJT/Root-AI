"""
cogs/moderation.py
Discord role management and moderation actions (add role, remove role, kick, ban).

Supported roles
---------------
Only roles in ALLOWED_ROLES may be assigned or removed via the LLM pipeline.
The bot's own highest role MUST sit above all five roles in the Discord role
hierarchy, otherwise Discord will raise Forbidden on any manage-roles call.

Each action is implemented as a standalone async function, then wrapped in a
thin handler closure and registered with the ChatContextManager tool registry.
"""

from __future__ import annotations

import logging
import re

import discord
from discord.ext import commands

from services.llm_manager import ChatContextManager

# ---------------------------------------------------------------------------
# Intent predicate — shared by all moderation tools
# ---------------------------------------------------------------------------

_MENTION_RE = re.compile(r"<@!?\d+>")


def _mention_predicate(user_text: str) -> bool:
    """
    Returns True only when a Discord @mention (<@ID> or <@!ID>) is present.

    All moderation tools require an explicit target user.  If the LLM hallucinates
    a role/kick/ban call on a message with no @mention, the guardrail drops it.
    """
    return bool(_MENTION_RE.search(user_text))

log = logging.getLogger("root_ai.moderation")

# ---------------------------------------------------------------------------
# Allowed roles — only these may be assigned or removed via the bot
# ---------------------------------------------------------------------------

ALLOWED_ROLES: list[str] = ["Newcomer", "Alumni", "Support", "Admin", "R6"]


# ---------------------------------------------------------------------------
# Core tool logic
# ---------------------------------------------------------------------------


async def remove_user_role(target_user: str, role_name: str, message: discord.Message) -> str:
    """Strips *role_name* from a Discord user (must be in ALLOWED_ROLES)."""
    log.info("DISCORD API: Attempting to remove role '%s' from %s", role_name, target_user)

    # Allowlist check (case-insensitive)
    normalised = next((r for r in ALLOWED_ROLES if r.lower() == role_name.lower()), None)
    if not normalised:
        return (
            f"Execution Failed: '{role_name}' is not a manageable role. "
            f"Allowed roles: {', '.join(ALLOWED_ROLES)}."
        )

    try:
        clean_id_match = re.search(r"\d+", target_user)
        if not clean_id_match:
            return "Execution Failed: Could not extract a valid user ID from the target."

        member = message.guild.get_member(int(clean_id_match.group()))
        if not member:
            return "Execution Failed: Could not locate that user in the current server."

        # Case-insensitive role lookup against guild roles
        target_role = discord.utils.find(
            lambda r: r.name.lower() == normalised.lower(), message.guild.roles
        )
        if not target_role:
            return f"Execution Failed: A role named '{normalised}' does not exist on this server."

        if target_role in member.roles:
            await member.remove_roles(target_role)
            return f"Success: **{normalised}** role removed from {member.mention}."
        return f"Status: {member.mention} does not currently hold the **{normalised}** role."

    except discord.Forbidden:
        return (
            "Permission Denied: I do not have the 'Manage Roles' permission, "
            "or my bot role is lower in the hierarchy than the target role."
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Role removal error: %s", exc)
        return f"Execution Failed: Internal API error - {exc}"


async def add_user_role(target_user: str, role_name: str, message: discord.Message) -> str:
    """Grants *role_name* to a Discord user (must be in ALLOWED_ROLES)."""
    log.info("DISCORD API: Attempting to add role '%s' to %s", role_name, target_user)

    # Allowlist check (case-insensitive)
    normalised = next((r for r in ALLOWED_ROLES if r.lower() == role_name.lower()), None)
    if not normalised:
        return (
            f"Execution Failed: '{role_name}' is not a manageable role. "
            f"Allowed roles: {', '.join(ALLOWED_ROLES)}."
        )

    try:
        clean_id_match = re.search(r"\d+", target_user)
        if not clean_id_match:
            return "Execution Failed: Could not extract a valid user ID from the target."

        member = message.guild.get_member(int(clean_id_match.group()))
        if not member:
            return "Execution Failed: Could not locate that user in the current server."

        # Case-insensitive role lookup against guild roles
        target_role = discord.utils.find(
            lambda r: r.name.lower() == normalised.lower(), message.guild.roles
        )
        if not target_role:
            return f"Execution Failed: A role named '{normalised}' does not exist on this server."

        if target_role not in member.roles:
            await member.add_roles(target_role)
            return f"Success: **{normalised}** role granted to {member.mention}."
        return f"Status: {member.mention} already holds the **{normalised}** role."

    except discord.Forbidden:
        return (
            "Permission Denied: I do not have the 'Manage Roles' permission, "
            "or my bot role is lower in the hierarchy than the target role."
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Role addition error: %s", exc)
        return f"Execution Failed: Internal API error - {exc}"


async def kick_user(target_user: str, message: discord.Message) -> str:
    """Kicks a Discord user from the server."""
    log.info("DISCORD API: Attempting to kick %s", target_user)
    try:
        clean_id_match = re.search(r"\d+", target_user)
        if not clean_id_match:
            return "Execution Failed: Could not extract a valid user ID from the target."

        member = message.guild.get_member(int(clean_id_match.group()))
        if not member:
            return "Execution Failed: Could not locate that user in the current server."

        await member.kick(reason="Kicked via Root AI pipeline request.")
        return f"Success: {member.mention} has been kicked from the server."

    except discord.Forbidden:
        return (
            "Permission Denied: I do not have the 'Kick Members' permission, "
            "or my bot role is lower in the hierarchy than the target user."
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Kick error: %s", exc)
        return f"Execution Failed: Internal API error - {exc}"


async def ban_user(target_user: str, message: discord.Message) -> str:
    """Bans a Discord user from the server."""
    log.info("DISCORD API: Attempting to ban %s", target_user)
    try:
        clean_id_match = re.search(r"\d+", target_user)
        if not clean_id_match:
            return "Execution Failed: Could not extract a valid user ID from the target."

        member = message.guild.get_member(int(clean_id_match.group()))
        if not member:
            return "Execution Failed: Could not locate that user in the current server."

        await member.ban(reason="Banned via Root AI pipeline request.")
        return f"Success: {member.mention} has been banned from the server."

    except discord.Forbidden:
        return (
            "Permission Denied: I do not have the 'Ban Members' permission, "
            "or my bot role is lower in the hierarchy than the target user."
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Ban error: %s", exc)
        return f"Execution Failed: Internal API error - {exc}"


# ---------------------------------------------------------------------------
# Tool specs
# ---------------------------------------------------------------------------

REMOVE_ROLE_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "remove_user_role",
        "description": (
            "CRITICAL: Use ONLY when explicitly asked to remove, revoke, or strip a role "
            "from a Discord user AND a Discord @mention (<@ID>) is present in the message. "
            "NEVER call for general questions, education, or messages without an @mention."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_user": {
                    "type": "string",
                    "description": (
                        "The Discord mention or username of the person losing the role "
                        "(e.g., <@123456789>)."
                    ),
                },
                "role_name": {
                    "type": "string",
                    "description": "The exact role to remove.",
                    "enum": ALLOWED_ROLES,
                },
            },
            "required": ["target_user", "role_name"],
        },
    },
}

ADD_ROLE_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "add_user_role",
        "description": (
            "CRITICAL: Use ONLY when explicitly asked to add, grant, or assign a role "
            "to a Discord user AND a Discord @mention (<@ID>) is present in the message. "
            "NEVER call for general questions, education, or messages without an @mention."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_user": {
                    "type": "string",
                    "description": (
                        "The Discord mention or username of the person receiving the role "
                        "(e.g., <@123456789>)."
                    ),
                },
                "role_name": {
                    "type": "string",
                    "description": "The exact role to grant.",
                    "enum": ALLOWED_ROLES,
                },
            },
            "required": ["target_user", "role_name"],
        },
    },
}

KICK_USER_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "kick_user",
        "description": (
            "CRITICAL: Use ONLY when explicitly asked to kick a specific Discord user "
            "AND a Discord @mention (<@ID>) is present in the message. "
            "NEVER call for general questions or messages without an @mention."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_user": {
                    "type": "string",
                    "description": (
                        "The Discord mention or username of the person to kick "
                        "(e.g., <@123456789>)."
                    ),
                }
            },
            "required": ["target_user"],
        },
    },
}

BAN_USER_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "ban_user",
        "description": (
            "CRITICAL: Use ONLY when explicitly asked to ban a specific Discord user "
            "AND a Discord @mention (<@ID>) is present in the message. "
            "NEVER call for general questions or messages without an @mention."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_user": {
                    "type": "string",
                    "description": (
                        "The Discord mention or username of the person to ban "
                        "(e.g., <@123456789>)."
                    ),
                }
            },
            "required": ["target_user"],
        },
    },
}


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class ModerationCog(commands.Cog, name="Moderation"):
    """Registers role management and moderation tools with the ChatContextManager."""

    def __init__(self, bot: commands.Bot, chat_manager: ChatContextManager) -> None:
        self.bot = bot
        self._chat = chat_manager
        self._register_tools()

    def _register_tools(self) -> None:
        async def _remove_role_handler(args: dict, message: discord.Message) -> str:
            return await remove_user_role(
                args.get("target_user", ""),
                args.get("role_name", ""),
                message,
            )

        async def _add_role_handler(args: dict, message: discord.Message) -> str:
            return await add_user_role(
                args.get("target_user", ""),
                args.get("role_name", ""),
                message,
            )

        async def _kick_handler(args: dict, message: discord.Message) -> str:
            return await kick_user(args.get("target_user", ""), message)

        async def _ban_handler(args: dict, message: discord.Message) -> str:
            return await ban_user(args.get("target_user", ""), message)

        self._chat.register_tool("remove_user_role", _remove_role_handler, REMOVE_ROLE_TOOL_SPEC, predicate=_mention_predicate)
        self._chat.register_tool("add_user_role", _add_role_handler, ADD_ROLE_TOOL_SPEC, predicate=_mention_predicate)
        self._chat.register_tool("kick_user", _kick_handler, KICK_USER_TOOL_SPEC, predicate=_mention_predicate)
        self._chat.register_tool("ban_user", _ban_handler, BAN_USER_TOOL_SPEC, predicate=_mention_predicate)


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(ModerationCog(bot, chat_manager))
