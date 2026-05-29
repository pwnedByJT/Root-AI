"""
cogs/security.py
SSH-based nmap scanning via the Parrot OS WSL workstation.

Registers ``run_parrot_nmap_scan`` with the shared ChatContextManager so
the LLM can invoke it as a tool call.
"""

from __future__ import annotations

import logging
import re

import asyncssh
import discord
from discord.ext import commands

from config import PARROT_HOST, PARROT_PASS, PARROT_USER
from services.llm_manager import ChatContextManager

log = logging.getLogger("root_ai.security")

# ---------------------------------------------------------------------------
# Input sanitisation helpers
# ---------------------------------------------------------------------------

# Allowlist: only characters that are safe in nmap targets / arguments
_SAFE_TARGET_RE = re.compile(r"[^a-zA-Z0-9.\-/:_]")
_SAFE_ARGS_RE = re.compile(r"[^a-zA-Z0-9.\-_ ]")


def _sanitize(value: str, pattern: re.Pattern, max_len: int = 256) -> str:
    """Strip characters not in the allowlist and trim length."""
    return pattern.sub("", value)[:max_len].strip()


# ---------------------------------------------------------------------------
# Core tool logic (pure async — no Discord coupling)
# ---------------------------------------------------------------------------


async def run_parrot_nmap_scan(target: str, arguments: str = "-F") -> str:
    """
    SSH into the Parrot OS WSL instance and run an nmap scan.
    Returns raw stdout / stderr as a string.
    """
    clean_target = _sanitize(target, _SAFE_TARGET_RE)
    clean_args = _sanitize(arguments, _SAFE_ARGS_RE)

    if not clean_target:
        return "Error: invalid or empty target after sanitization."

    command = f"nmap {clean_args} {clean_target}"
    log.info("SSH → Parrot OS | command: %s", command)

    try:
        async with asyncssh.connect(
            host=PARROT_HOST,
            username=PARROT_USER,
            password=PARROT_PASS,
            known_hosts=None,          # home-lab: skip strict host checking
            connect_timeout=15,
        ) as conn:
            result = await conn.run(command, check=False, timeout=120)
            output = result.stdout or ""
            stderr = result.stderr or ""
            if result.returncode != 0 and not output:
                return f"nmap exited with code {result.returncode}.\nSTDERR:\n{stderr}"
            return output if output else stderr
    except asyncssh.DisconnectError as exc:
        log.error("SSH disconnect: %s", exc)
        return f"SSH disconnect error: {exc}"
    except asyncssh.PermissionDenied:
        log.error("SSH permission denied for user '%s'", PARROT_USER)
        return "SSH error: permission denied. Check PARROT_USER / PARROT_PASS."
    except Exception as exc:  # pylint: disable=broad-except
        log.exception("Unexpected SSH error")
        return f"SSH error: {exc}"


# ---------------------------------------------------------------------------
# Tool spec
# ---------------------------------------------------------------------------

NMAP_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "run_parrot_nmap_scan",
        "description": (
            "Run an nmap scan against a target host, IP address, or CIDR range "
            "via a locally connected Parrot OS security workstation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The hostname, IP address, or CIDR range to scan.",
                },
                "arguments": {
                    "type": "string",
                    "description": (
                        "nmap command-line flags to pass before the target. "
                        "Defaults to '-F' (fast scan)."
                    ),
                    "default": "-F",
                },
            },
            "required": ["target"],
        },
    },
}


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class SecurityCog(commands.Cog, name="Security"):
    """Registers the nmap SSH tool with the ChatContextManager."""

    def __init__(self, bot: commands.Bot, chat_manager: ChatContextManager) -> None:
        self.bot = bot
        self._chat = chat_manager
        self._register_tools()

    def _register_tools(self) -> None:
        async def _nmap_handler(args: dict, message: discord.Message) -> str:
            target: str = args.get("target", "127.0.0.1")
            arguments: str = args.get("arguments", "-F")
            return await run_parrot_nmap_scan(target=target, arguments=arguments)

        self._chat.register_tool("run_parrot_nmap_scan", _nmap_handler, NMAP_TOOL_SPEC)


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(SecurityCog(bot, chat_manager))
