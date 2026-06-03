"""
cogs/recon.py
Phase 1 — Autonomous OSINT & Attack Surface Mapping

Slash command: /recon <target_domain>

Pipeline (runs concurrently):
  1. crt.sh Certificate Transparency log query — passive subdomain enumeration
  2. Nmap scan via the existing SSH→Parrot OS tunnel (reuses run_parrot_nmap_scan)

Output:
  - Rich Discord Embed: subdomains, open ports, scan metadata
  - ReconView: "Send to Auto-Pwn" button (Phase 2 stub — result cached in View)

Security boundaries:
  - /recon is restricted to the bot owner (BOT_OWNER_ID) at the code level.
  - FQDN regex validation runs before any network call to prevent injection/SSRF.
  - crt.sh is read-only passive recon — no active probing on that path.
  - Nmap is rate-limited to T4 timing; target is validated before SSH dispatch.

Phase 2 integration point:
  - ReconResult dataclass is the contract between Phase 1 and Phase 2.
  - When Phase 2 (auto-pwn) is implemented, ReconView.autopwn_button should
    call the AutoPwnCog pipeline and pass result.domain + result.open_ports.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID
from cogs.security import run_parrot_command, run_parrot_nmap_scan

log = logging.getLogger("root_ai.recon")

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# Strict FQDN regex — must match before any outbound request is made.
# Prevents command injection, SSRF against internal IPs, and malformed input.
_FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Block private/loopback ranges from being targeted — belt-and-suspenders SSRF guard.
_PRIVATE_RANGE_RE = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


def _validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate *domain* as a public FQDN.

    Returns (True, cleaned_domain) on success or (False, error_message) on failure.
    """
    clean = domain.strip().lower()
    if _PRIVATE_RANGE_RE.match(clean):
        return False, f"`{domain}` resolves to a private/loopback range — not allowed."
    if not _FQDN_RE.match(clean):
        return False, f"`{domain}` is not a valid fully-qualified domain name."
    if len(clean) > 253:
        return False, "Domain name exceeds the 253-character FQDN limit."
    return True, clean


# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------


@dataclass
class ReconResult:
    """
    Immutable snapshot of a completed recon run.
    Passed to ReconView so the "Send to Auto-Pwn" button can hand it to Phase 2.
    """

    domain: str
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    raw_nmap: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OSINT helpers
# ---------------------------------------------------------------------------

# Maximum subdomains to display in the embed (crt.sh can return thousands)
_MAX_DISPLAY_SUBS = 30


async def _crtsh_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains of *domain*.

    Returns a deduplicated, sorted list of subdomains (wildcards excluded).
    Returns an empty list on any network or parse error.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=25),
            ) as resp:
                if resp.status != 200:
                    log.warning("crt.sh returned HTTP %d for %s", resp.status, domain)
                    return []
                data = await resp.json(content_type=None)

        seen: set[str] = set()
        results: list[str] = []
        apex = domain.lower()

        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                # Skip wildcards, the apex domain itself, and duplicates
                if (
                    not name
                    or name.startswith("*.")
                    or name == apex
                    or name in seen
                ):
                    continue
                # Only keep names that are subdomains of the target
                if name.endswith(f".{apex}"):
                    seen.add(name)
                    results.append(name)

        log.info("crt.sh: %d unique subdomains for %s", len(results), domain)
        return sorted(results)

    except asyncio.TimeoutError:
        log.warning("crt.sh timed out for %s", domain)
        return []
    except Exception as exc:  # pylint: disable=broad-except
        log.error("crt.sh error for %s: %s", domain, exc)
        return []


async def _subfinder_subdomains(domain: str) -> list[str]:
    """
    Run subfinder on Parrot OS via SSH and return discovered subdomains.

    Requires subfinder to be installed on the Parrot host (free / open-source).
    Returns [] gracefully if the binary is missing or the SSH call fails.
    """
    try:
        cmd = f"subfinder -d '{domain}' -silent -all 2>/dev/null | head -500"
        output = await run_parrot_command(cmd, timeout=60)
        if "command not found" in output or not output.strip():
            return []
        results = [
            line.strip().lower()
            for line in output.splitlines()
            if line.strip() and line.strip().endswith(f".{domain.lower()}")
        ]
        log.info("subfinder: %d subdomains for %s", len(results), domain)
        return sorted(set(results))
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("subfinder failed for %s: %s", domain, exc)
        return []


async def _assetfinder_subdomains(domain: str) -> list[str]:
    """
    Run assetfinder on Parrot OS via SSH and return discovered subdomains.

    Requires assetfinder to be installed on the Parrot host (free / open-source).
    Returns [] gracefully if the binary is missing or the SSH call fails.
    """
    try:
        cmd = f"assetfinder --subs-only '{domain}' 2>/dev/null | head -200"
        output = await run_parrot_command(cmd, timeout=45)
        if "command not found" in output or not output.strip():
            return []
        results = [
            line.strip().lower()
            for line in output.splitlines()
            if line.strip() and line.strip().endswith(f".{domain.lower()}")
        ]
        log.info("assetfinder: %d subdomains for %s", len(results), domain)
        return sorted(set(results))
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("assetfinder failed for %s: %s", domain, exc)
        return []


async def gather_subdomains(domain: str) -> list[str]:
    """
    Combine crt.sh + subfinder + assetfinder results into a single deduplicated list.

    Public API — importable by ``cogs.watchdog`` to avoid code duplication.
    All three sources run concurrently; any that fail are silently skipped.
    """
    results = await asyncio.gather(
        _crtsh_subdomains(domain),
        _subfinder_subdomains(domain),
        _assetfinder_subdomains(domain),
        return_exceptions=True,
    )
    merged: set[str] = set()
    for r in results:
        if isinstance(r, list):
            merged.update(r)
    return sorted(merged)


def _parse_open_ports(nmap_output: str) -> list[str]:
    """
    Extract open port lines from nmap stdout.

    Example input line:
        ``80/tcp   open  http    nginx 1.18.0``
    Returns lines as-is, stripped of leading whitespace.
    """
    ports = []
    for line in nmap_output.splitlines():
        stripped = line.strip()
        if ("open" in stripped) and ("/" in stripped):
            # Match lines like "80/tcp open ..."
            if re.match(r"^\d+/(tcp|udp)\s+open", stripped):
                ports.append(stripped)
    return ports


# ---------------------------------------------------------------------------
# Discord UI — Embed builder
# ---------------------------------------------------------------------------


def _build_recon_embed(result: ReconResult) -> discord.Embed:
    """Build the main recon report embed from a completed ReconResult."""
    embed = discord.Embed(
        title=f"🔍 Recon Report — `{result.domain}`",
        description=(
            "Passive subdomain enumeration via **crt.sh CT logs** + "
            "active port scan via **Parrot OS / nmap**.\n\n"
            "⚠️ *Use only on targets you own or have explicit written permission to test.*"
        ),
        color=discord.Color.from_rgb(220, 50, 50),
        timestamp=result.timestamp,
    )

    # ── Subdomains field ─────────────────────────────────────────────────────
    total_subs = len(result.subdomains)
    if result.subdomains:
        display = result.subdomains[:_MAX_DISPLAY_SUBS]
        sub_text = "\n".join(f"`{s}`" for s in display)
        if total_subs > _MAX_DISPLAY_SUBS:
            sub_text += f"\n`... +{total_subs - _MAX_DISPLAY_SUBS} more`"
        embed.add_field(
            name=f"🌐 Subdomains  ({total_subs} discovered)",
            value=sub_text[:1020],
            inline=False,
        )
    else:
        embed.add_field(
            name="🌐 Subdomains",
            value="None discovered via passive CT log recon.",
            inline=False,
        )

    # ── Open ports field ─────────────────────────────────────────────────────
    total_ports = len(result.open_ports)
    if result.open_ports:
        ports_text = "\n".join(f"`{p}`" for p in result.open_ports[:20])
        if total_ports > 20:
            ports_text += f"\n`... +{total_ports - 20} more`"
        embed.add_field(
            name=f"🔓 Open Ports  ({total_ports} found)",
            value=ports_text[:1020],
            inline=False,
        )
    else:
        embed.add_field(
            name="🔓 Open Ports",
            value=(
                "No open ports detected in the top-500 scan.\n"
                "`Run /recon again with a deeper scan flag for full coverage.`"
            ),
            inline=False,
        )

    # ── Error notes (if any partial failures occurred) ───────────────────────
    if result.error_notes:
        embed.add_field(
            name="⚠️ Scan Notes",
            value="\n".join(f"• {n}" for n in result.error_notes)[:512],
            inline=False,
        )

    embed.set_footer(text="Root AI • Phase 1 OSINT Engine  |  Authorised use only")
    return embed


# ---------------------------------------------------------------------------
# Discord UI — Button View
# ---------------------------------------------------------------------------


class ReconView(discord.ui.View):
    """
    Interactive view attached to the recon embed.

    Holds the ReconResult so the button callback can pass it to Phase 2
    without needing a global cache or database lookup.
    """

    def __init__(self, result: ReconResult) -> None:
        super().__init__(timeout=300)  # 5-minute window
        self.result = result

    @discord.ui.button(
        label="Send to Auto-Pwn",
        style=discord.ButtonStyle.danger,
        emoji="⚡",
    )
    async def autopwn_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Phase 2 integration point — stub until Auto-Pwn pipeline is built."""
        # Hard owner check on every button press
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ **Auto-Pwn** is restricted to the server administrator.",
                ephemeral=True,
            )
            return

        # Disable the button to prevent double-fire
        button.disabled = True
        button.label = "⏳ Running Auto-Pwn..."
        button.emoji = discord.PartialEmoji(name="⏳")
        await interaction.response.edit_message(view=self)

        # ── Phase 2 handoff ───────────────────────────────────────────────
        # edit_message() has consumed the interaction response; all further
        # Discord messages in start_autopwn() use interaction.followup.
        autopwn_cog = interaction.client.get_cog("AutoPwn")
        if autopwn_cog is None:
            await interaction.followup.send(
                "⚠️ AutoPwn cog is not loaded — check bot startup logs.",
                ephemeral=True,
            )
            return
        await autopwn_cog.start_autopwn(interaction, self.result)

    async def on_timeout(self) -> None:
        """Disable all buttons when the view expires to prevent stale interactions."""
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                item.disabled = True


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class ReconCog(commands.Cog, name="Recon"):
    """
    Phase 1 — OSINT & Attack Surface Mapping.

    Orchestrates passive subdomain enumeration (crt.sh) and active port
    scanning (Nmap via Parrot OS SSH) behind a single Discord slash command.
    Results are surfaced as a rich Embed with a Phase 2 integration button.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(
        name="recon",
        description="[OWNER] Run OSINT recon on a bug bounty / authorised target domain.",
    )
    @app_commands.describe(
        target_domain="Fully-qualified domain name to recon (e.g. example.com)",
    )
    async def recon(
        self, interaction: discord.Interaction, target_domain: str
    ) -> None:
        """
        Phase 1 entry point.

        Runs crt.sh subdomain enum and nmap concurrently, then renders
        a rich Discord embed with an Auto-Pwn hand-off button.
        """
        # ── Owner gate ────────────────────────────────────────────────────────
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/recon` is an owner-only command.",
                ephemeral=True,
            )
            return

        # ── Input validation ─────────────────────────────────────────────────
        valid, clean_domain_or_err = _validate_domain(target_domain)
        if not valid:
            await interaction.response.send_message(
                f"⚠️ Invalid target: {clean_domain_or_err}", ephemeral=True
            )
            return

        clean_domain: str = clean_domain_or_err

        # ── Defer immediately — pipeline takes > 3 seconds ───────────────────
        await interaction.response.defer(thinking=True)
        log.info("RECON: Starting recon on '%s' for user %s", clean_domain, interaction.user)

        # ── Run OSINT tools concurrently ─────────────────────────────────────
        # gather_subdomains (crt.sh + subfinder + assetfinder, ~5–60 s) and
        # nmap (active, ~15–60 s) run in parallel.
        nmap_args = "-T4 --top-ports 500 --open"
        sub_task = gather_subdomains(clean_domain)
        nmap_task = run_parrot_nmap_scan(clean_domain, nmap_args)

        results = await asyncio.gather(sub_task, nmap_task, return_exceptions=True)
        subdomains_raw, nmap_output_raw = results

        # Gracefully degrade if either task failed
        error_notes: list[str] = []
        subdomains: list[str] = []
        nmap_output: str = ""

        if isinstance(subdomains_raw, Exception):
            log.error("RECON: subdomain gather failed: %s", subdomains_raw)
            error_notes.append(f"Subdomain enumeration failed: {subdomains_raw}")
        else:
            subdomains = subdomains_raw  # type: ignore[assignment]

        if isinstance(nmap_output_raw, Exception):
            log.error("RECON: nmap failed: %s", nmap_output_raw)
            error_notes.append(f"Nmap scan failed: {nmap_output_raw}")
        else:
            nmap_output = nmap_output_raw  # type: ignore[assignment]

        open_ports = _parse_open_ports(nmap_output)
        log.info(
            "RECON: %s — %d subdomains, %d open ports",
            clean_domain,
            len(subdomains),
            len(open_ports),
        )

        # ── Build and send result ─────────────────────────────────────────────
        result = ReconResult(
            domain=clean_domain,
            subdomains=subdomains,
            open_ports=open_ports,
            raw_nmap=nmap_output,
            error_notes=error_notes,
        )

        embed = _build_recon_embed(result)
        view = ReconView(result)

        await interaction.followup.send(embed=embed, view=view)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ReconCog(bot))
