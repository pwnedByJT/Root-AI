"""
cogs/moderation.py
Discord role management and moderation actions (add role, remove role, kick, ban).

Each action is implemented as a standalone async function, then wrapped in a
thin handler closure and registered with the ChatContextManager tool registry.
"""

from __future__ import annotations

import logging
import re

import discord
from discord.ext import commands

from services.llm_manager import ChatContextManager

log = logging.getLogger("root_ai.moderation")


# ---------------------------------------------------------------------------
# Core tool logic
# ---------------------------------------------------------------------------


async def remove_user_role(target_user: str, message: discord.Message) -> str:
    """Strips the 'Admin' role from a Discord user."""
    log.info("DISCORD API: Attempting to remove admin from %s", target_user)
    try:
        clean_id_match = re.search(r"\d+", target_user)
        if not clean_id_match:
            return "Execution Failed: Could not extract a valid user ID from the target."

        member = message.guild.get_member(int(clean_id_match.group()))
        if not member:
            return "Execution Failed: Could not locate that user in the current server."

        role_name = "Admin"
        target_role = discord.utils.get(message.guild.roles, name=role_name)
        if not target_role:
            return f"Execution Failed: A role named '{role_name}' does not exist on this server."

        if target_role in member.roles:
            await member.remove_roles(target_role)
            return f"Success: {role_name} access revoked from {member.mention}."
        return f"Status: {member.mention} does not currently hold the {role_name} role."

    except discord.Forbidden:
        return (
            "Permission Denied: I do not have the 'Manage Roles' permission, "
            "or my bot role is lower in the hierarchy than the target role."
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.error("Role removal error: %s", exc)
        return f"Execution Failed: Internal API error - {exc}"


async def add_user_role(target_user: str, message: discord.Message) -> str:
    """Grants the 'Admin' role to a Discord user."""
    log.info("DISCORD API: Attempting to add admin to %s", target_user)
    try:
        clean_id_match = re.search(r"\d+", target_user)
        if not clean_id_match:
            return "Execution Failed: Could not extract a valid user ID from the target."

        member = message.guild.get_member(int(clean_id_match.group()))
        if not member:
            return "Execution Failed: Could not locate that user in the current server."

        role_name = "Admin"
        target_role = discord.utils.get(message.guild.roles, name=role_name)
        if not target_role:
            return f"Execution Failed: A role named '{role_name}' does not exist on this server."

        if target_role not in member.roles:
            await member.add_roles(target_role)
            return f"Success: {role_name} access granted to {member.mention}."
        return f"Status: {member.mention} already holds the {role_name} role."

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
        "description": "Revokes administrative privileges or roles from a specific Discord user.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_user": {
                    "type": "string",
                    "description": (
                        "The Discord mention or username of the person losing access "
                        "(e.g., <@123456789>)."
                    ),
                }
            },
            "required": ["target_user"],
        },
    },
}

ADD_ROLE_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "add_user_role",
        "description": "Grants administrative privileges or roles to a specific Discord user.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_user": {
                    "type": "string",
                    "description": (
                        "The Discord mention or username of the person gaining access "
                        "(e.g., <@123456789>)."
                    ),
                }
            },
            "required": ["target_user"],
        },
    },
}

KICK_USER_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "kick_user",
        "description": (
            "Kicks a specific user from the Discord server. "
            "Use this when the user explicitly asks to kick someone."
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
            "Bans a specific user from the Discord server. "
            "Use this when the user explicitly asks to ban someone."
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
            return await remove_user_role(args.get("target_user", ""), message)

        async def _add_role_handler(args: dict, message: discord.Message) -> str:
            return await add_user_role(args.get("target_user", ""), message)

        async def _kick_handler(args: dict, message: discord.Message) -> str:
            return await kick_user(args.get("target_user", ""), message)

        async def _ban_handler(args: dict, message: discord.Message) -> str:
            return await ban_user(args.get("target_user", ""), message)

        self._chat.register_tool("remove_user_role", _remove_role_handler, REMOVE_ROLE_TOOL_SPEC)
        self._chat.register_tool("add_user_role", _add_role_handler, ADD_ROLE_TOOL_SPEC)
        self._chat.register_tool("kick_user", _kick_handler, KICK_USER_TOOL_SPEC)
        self._chat.register_tool("ban_user", _ban_handler, BAN_USER_TOOL_SPEC)


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(ModerationCog(bot, chat_manager))
