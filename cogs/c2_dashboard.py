"""
cogs/c2_dashboard.py
Phase 3 — Persistent C2 Dashboard

Slash command: /c2_dashboard

Sends a persistent button-grid embed into the channel.  Buttons survive bot
restarts because each button has a fixed ``custom_id`` and the view is
registered with ``bot.add_view()`` in ``setup()``.  Discord re-dispatches
interactions by ``custom_id`` alone — no message-ID storage required.

Buttons (all ephemeral output, dashboard message stays clean):
  🔍 Subnet Scan   — nmap -sn ping sweep of C2_SUBNET_CIDR
  📡 ARP Cache     — ip neigh show (local network host table)
  💻 Host Stats    — uptime, memory, and top CPU snapshot
  🌐 Interfaces    — ip -br addr + ss -tulpn (ports & interfaces)

Security boundaries:
  - /c2_dashboard and every button are restricted to BOT_OWNER_ID.
  - C2_SUBNET_CIDR is env-configurable (default 192.168.1.0/24).
  - Per-button cooldown (10 s, in-memory) prevents button spam.
  - asyncio.Lock ensures one SSH command runs at a time.
  - All button outputs are ephemeral — only the invoker sees them.
  - SSH command strings are built from controlled constants; no
    user-supplied strings reach the shell.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID, C2_SUBNET_CIDR, PARROT_HOST
from cogs.security import run_parrot_command

log = logging.getLogger("root_ai.c2")

# ---------------------------------------------------------------------------
# Module-level state (shared between persistent view instances and the cog)
# ---------------------------------------------------------------------------

_lock = asyncio.Lock()                  # one SSH command at a time
_cooldowns: dict[str, float] = {}      # custom_id → last_used monotonic time

_COOLDOWN_SECS = 10                     # seconds between uses of the same button
_SSH_TIMEOUT_SCAN = 60                  # subnet scan can take a while
_SSH_TIMEOUT_FAST = 20                  # fast local commands

# Maximum characters to display in an ephemeral reply before truncation
_MAX_OUTPUT = 1800

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ready(custom_id: str) -> tuple[bool, float]:
    """
    Check and update the per-button cooldown.

    Returns (True, 0.0) if the button is ready, or (False, remaining_s) if on
    cooldown.  Updates the timestamp on success so the next call is also timed.
    """
    now = time.monotonic()
    last = _cooldowns.get(custom_id, 0.0)
    remaining = _COOLDOWN_SECS - (now - last)
    if remaining > 0:
        return False, remaining
    _cooldowns[custom_id] = now
    return True, 0.0


def _truncate(text: str, label: str) -> str:
    """Wrap output in a code block, truncating if needed."""
    if not text.strip():
        return f"*(no output from {label})*"
    if len(text) > _MAX_OUTPUT:
        text = text[:_MAX_OUTPUT] + "\n... [truncated]"
    return f"```\n{text}\n```"


async def _run_c2(
    interaction: discord.Interaction,
    command: str,
    label: str,
    timeout: int,
    custom_id: str,
) -> None:
    """
    Shared button handler: owner-gate → cooldown → defer → SSH → ephemeral reply.

    Parameters
    ----------
    interaction:  The button interaction.
    command:      Pre-built, sanitised shell command to run on Parrot OS.
    label:        Human-readable action name for error/status messages.
    timeout:      SSH command timeout in seconds.
    custom_id:    Button custom_id used for the per-button cooldown key.
    """
    # ── Owner gate ────────────────────────────────────────────────────────────
    if interaction.user.id != BOT_OWNER_ID:
        await interaction.response.send_message(
            "⛔ The C2 dashboard is restricted to the server administrator.",
            ephemeral=True,
        )
        return

    # ── Cooldown check ────────────────────────────────────────────────────────
    ready, remaining = _is_ready(custom_id)
    if not ready:
        await interaction.response.send_message(
            f"⏳ **{label}** is on cooldown. Try again in `{remaining:.1f}s`.",
            ephemeral=True,
        )
        return

    # ── Defer (SSH will exceed the 3-second window) ───────────────────────────
    await interaction.response.defer(thinking=True, ephemeral=True)

    # ── Concurrency guard ─────────────────────────────────────────────────────
    if _lock.locked():
        await interaction.followup.send(
            "⚠️ Another C2 command is running. Please wait a moment.",
            ephemeral=True,
        )
        return

    async with _lock:
        log.info("C2: running '%s' | user=%s", label, interaction.user)
        try:
            output = await asyncio.wait_for(
                run_parrot_command(command, timeout=timeout),
                timeout=timeout + 5,
            )
        except asyncio.TimeoutError:
            output = f"Command timed out after {timeout}s."
        except Exception as exc:
            log.error("C2: command error (%s): %s", label, exc)
            output = f"Error: {exc}"

    embed = discord.Embed(
        title=f"🖥️ {label}",
        description=_truncate(output, label),
        color=discord.Color.from_rgb(30, 215, 96),
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_footer(text=f"Root AI • C2 Panel  |  Host: {PARROT_HOST}")
    await interaction.followup.send(embed=embed, ephemeral=True)


# ---------------------------------------------------------------------------
# Persistent View — fixed custom_ids survive bot restarts
# ---------------------------------------------------------------------------


class C2DashboardView(discord.ui.View):
    """
    Persistent C2 button grid.

    Registered with ``bot.add_view()`` at startup so interactions are
    re-dispatched by ``custom_id`` after a bot restart without needing to
    re-send the message.
    """

    def __init__(self) -> None:
        super().__init__(timeout=None)   # Never expires — persistent view

    # ------------------------------------------------------------------
    # Button: Subnet Scan
    # ------------------------------------------------------------------

    @discord.ui.button(
        label="Subnet Scan",
        style=discord.ButtonStyle.danger,
        emoji="🔍",
        custom_id="c2:subnet_scan",
        row=0,
    )
    async def subnet_scan(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """nmap ping-sweep of the configured home subnet."""
        command = f"nmap -T4 -sn {C2_SUBNET_CIDR} 2>&1 | head -60"
        await _run_c2(
            interaction=interaction,
            command=command,
            label=f"Subnet Scan  ({C2_SUBNET_CIDR})",
            timeout=_SSH_TIMEOUT_SCAN,
            custom_id="c2:subnet_scan",
        )

    # ------------------------------------------------------------------
    # Button: ARP Cache
    # ------------------------------------------------------------------

    @discord.ui.button(
        label="ARP Cache",
        style=discord.ButtonStyle.primary,
        emoji="📡",
        custom_id="c2:arp_cache",
        row=0,
    )
    async def arp_cache(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Show the local ARP/neighbour table."""
        command = "ip neigh show 2>&1"
        await _run_c2(
            interaction=interaction,
            command=command,
            label="ARP Cache",
            timeout=_SSH_TIMEOUT_FAST,
            custom_id="c2:arp_cache",
        )

    # ------------------------------------------------------------------
    # Button: Host Stats
    # ------------------------------------------------------------------

    @discord.ui.button(
        label="Host Stats",
        style=discord.ButtonStyle.secondary,
        emoji="💻",
        custom_id="c2:host_stats",
        row=0,
    )
    async def host_stats(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Parrot OS uptime, memory, and top CPU snapshot."""
        command = (
            "echo '=== Uptime ===' && uptime && "
            "echo && echo '=== Memory ===' && free -h && "
            "echo && echo '=== CPU (top 5 processes) ===' && "
            "ps aux --sort=-%cpu | head -6 2>&1"
        )
        await _run_c2(
            interaction=interaction,
            command=command,
            label="Host Stats",
            timeout=_SSH_TIMEOUT_FAST,
            custom_id="c2:host_stats",
        )

    # ------------------------------------------------------------------
    # Button: Interfaces & Listeners
    # ------------------------------------------------------------------

    @discord.ui.button(
        label="Interfaces",
        style=discord.ButtonStyle.secondary,
        emoji="🌐",
        custom_id="c2:interfaces",
        row=0,
    )
    async def interfaces(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Network interface addresses and listening TCP/UDP ports."""
        command = (
            "echo '=== Interfaces ===' && ip -br addr 2>&1 && "
            "echo && echo '=== Listening Ports ===' && "
            "ss -tulpn 2>&1 | head -30"
        )
        await _run_c2(
            interaction=interaction,
            command=command,
            label="Interfaces & Listeners",
            timeout=_SSH_TIMEOUT_FAST,
            custom_id="c2:interfaces",
        )


# ---------------------------------------------------------------------------
# Dashboard embed
# ---------------------------------------------------------------------------


def _build_dashboard_embed() -> discord.Embed:
    embed = discord.Embed(
        title="🖥️ C2 Dashboard — Root AI",
        description=(
            "Local network command and control panel.\n"
            "All outputs are **ephemeral** — only you see the results.\n\n"
            "Use the buttons below to query the Parrot OS host."
        ),
        color=discord.Color.from_rgb(30, 215, 96),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="🌐 Subnet", value=f"`{C2_SUBNET_CIDR}`", inline=True)
    embed.add_field(name="🔌 Host", value=f"`{PARROT_HOST}`", inline=True)
    embed.add_field(
        name="📋 Actions",
        value=(
            "🔍 **Subnet Scan** — nmap ping sweep\n"
            "📡 **ARP Cache** — local neighbour table\n"
            "💻 **Host Stats** — uptime / memory / CPU\n"
            "🌐 **Interfaces** — IPs + listening ports"
        ),
        inline=False,
    )
    embed.set_footer(text="Root AI • Phase 3 C2 Panel  |  Authorised use only")
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class C2DashboardCog(commands.Cog, name="C2"):
    """
    Phase 3 — Persistent C2 Dashboard.

    /c2_dashboard posts the button grid; buttons survive bot restarts via
    fixed custom_ids registered with bot.add_view().
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(
        name="c2_dashboard",
        description="[OWNER] Open the persistent C2 control panel in this channel.",
    )
    async def c2_dashboard(self, interaction: discord.Interaction) -> None:
        """Post (or re-post) the C2 dashboard in the current channel."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/c2_dashboard` is an owner-only command.", ephemeral=True
            )
            return

        log.info("C2: dashboard posted by %s in channel %s", interaction.user, interaction.channel_id)

        embed = _build_dashboard_embed()
        view = C2DashboardView()
        await interaction.response.send_message(embed=embed, view=view)


# ---------------------------------------------------------------------------
# Extension setup
# ---------------------------------------------------------------------------


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(C2DashboardCog(bot))
    # Register the persistent view so Discord can re-dispatch button interactions
    # to this process after a bot restart, matching on custom_id alone.
    bot.add_view(C2DashboardView())
    log.info("C2: persistent view registered (custom_ids: subnet_scan, arp_cache, host_stats, interfaces)")
