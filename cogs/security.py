"""
cogs/security.py
SSH-based nmap scanning via the Parrot OS WSL workstation.

Registers ``run_parrot_nmap_scan`` with the shared ChatContextManager so
the LLM can invoke it as a tool call.

Intent predicate
----------------
``_nmap_predicate`` is passed to ``register_tool`` so the LLM manager can
reject hallucinated scan calls before they execute.  It requires the user's
message to contain either:
  - An IPv4 address or CIDR range  (unambiguous network target), OR
  - An explicit scan keyword (scan/nmap/recon/audit/enumerate/ports)
    combined with a hostname or domain.
This prevents the model from calling ``run_parrot_nmap_scan`` on unrelated
questions like "what is 10 * 10?".
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
# Intent predicate — guards against hallucinated tool calls
# ---------------------------------------------------------------------------

_IP_CIDR_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_SCAN_KW_RE = re.compile(
    r"\b(?:scan|nmap|recon|audit|enumerate|ports?|host\s*discovery)\b",
    re.IGNORECASE,
)
_HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def _nmap_predicate(user_text: str) -> bool:
    """
    Returns True only when the message legitimately warrants a network scan.

    Conditions (either must be true):
    - An IPv4 address or CIDR range is present (e.g. 192.168.1.1, 10.0.0.0/24)
    - A scan-intent keyword (scan, nmap, recon …) AND a hostname/domain are present

    This rejects calls triggered by math, coding, or general questions that
    contain no network target.
    """
    has_ip = bool(_IP_CIDR_RE.search(user_text))
    has_kw = bool(_SCAN_KW_RE.search(user_text))
    has_host = bool(_HOSTNAME_RE.search(user_text))
    return has_ip or (has_kw and has_host)


# ---------------------------------------------------------------------------
# Core tool logic (pure async — no Discord coupling)
# ---------------------------------------------------------------------------


async def run_parrot_command(command: str, timeout: int = 120) -> str:
    """
    SSH into the Parrot OS WSL instance and run *command* verbatim.

    The caller is responsible for sanitising the command string before passing
    it here.  Returns raw stdout (falling back to stderr on empty stdout).
    """
    log.info("SSH → Parrot OS | command: %s", command[:160])
    try:
        async with asyncssh.connect(
            host=PARROT_HOST,
            username=PARROT_USER,
            password=PARROT_PASS,
            known_hosts=None,          # home-lab: skip strict host checking
            connect_timeout=15,
        ) as conn:
            result = await conn.run(command, check=False, timeout=timeout)
            output = result.stdout or ""
            stderr = result.stderr or ""
            if result.returncode != 0 and not output:
                return f"Command exited with code {result.returncode}.\nSTDERR:\n{stderr}"
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
    return await run_parrot_command(command)


# ---------------------------------------------------------------------------
# Tool spec
# ---------------------------------------------------------------------------

NMAP_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "run_parrot_nmap_scan",
        "description": (
            "CRITICAL: Use ONLY when the user EXPLICITLY requests a network security scan, "
            "nmap audit, or infrastructure recon AND their message contains a specific scan "
            "target such as an IP address (e.g. 192.168.1.1), CIDR range (e.g. 10.0.0.0/24), "
            "or hostname (e.g. example.com). "
            "NEVER call this tool for general conversation, programming help, mathematical "
            "calculations, security education questions, or any message that does not name "
            "an explicit network target."
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

        self._chat.register_tool(
            "run_parrot_nmap_scan",
            _nmap_handler,
            NMAP_TOOL_SPEC,
            predicate=_nmap_predicate,
        )


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(SecurityCog(bot, chat_manager))
