"""
cogs/subdomain_brute.py
Phase 12 — Active Subdomain Brute-Forcer

Slash command: /subdomain_brute <domain> [wordlist]
Public API:    brute_subdomains(domain, wordlist="small") -> BruteResult
               └─ Called by ReconView "Brute Subs" button and /watchdog scan --brute.

Pipeline (/subdomain_brute):
  1. Validate target FQDN (re-uses recon.py's _validate_domain)
  2. Resolve wordlist path on Parrot OS (SecLists DNS wordlists; graceful fallback)
  3. Wildcard DNS pre-check — abort with warning if nonsense probe resolves
  4. SSH to Parrot OS: gobuster dns -d <domain> -w <wordlist> -t 50 -q --no-color
  5. Parse "Found: <subdomain>" output lines; deduplicate + cap at _MAX_RESULTS
  6. Post embed — highlights new vs. passive-known subdomains when baseline available

Wordlist sizes (slash command exposes small + medium only):
  - small   ~5k lines  ~60s via gobuster -t 50
  - medium  ~20k lines ~4 min via gobuster -t 50
  - large   ~110k lines ~12 min (public API only — exceeds Discord 15-min token)

Security boundaries:
  - /subdomain_brute gated to BOT_OWNER_ID.
  - asyncio.Lock prevents concurrent brute jobs (Parrot OS DNS storm protection).
  - Target validated by _validate_domain before any SSH dispatch.
  - Wordlist path resolved at runtime; never taken from user input.
  - gobuster command is built from controlled constants + single-quoted domain.
  - Wildcard DNS pre-check prevents false-positive floods poisoning watchdog diffs.

Prerequisites on Parrot OS:
  gobuster     — sudo apt install gobuster
  SecLists     — sudo apt install seclists
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID
from cogs.recon import _validate_domain
from cogs.security import run_parrot_command

log = logging.getLogger("root_ai.subdomain_brute")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_RESULTS = 200          # cap on discovered subdomains per run
_GOBUSTER_THREADS = 50      # -t flag — concurrent DNS resolvers

_brute_lock = asyncio.Lock()  # one brute at a time — prevents DNS storm

# Wordlist candidate paths checked in order; first existing path wins.
# SecLists is the primary target; multiple install locations are checked for
# different Parrot OS versions and custom setups.
_WORDLISTS: dict[str, list[str]] = {
    "small": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/dnsrecon/wordlists/subdomains-top1mil-5000.txt",
        "/opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ],
    "medium": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/opt/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    ],
    "large": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/opt/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    ],
}

# SSH timeout budget per wordlist size (gobuster runtime + overhead)
_TIMEOUTS: dict[str, int] = {
    "small":  120,   # gobuster ~60s + 60s headroom
    "medium": 330,   # gobuster ~4min + 90s headroom
    "large":  780,   # gobuster ~12min + 60s headroom (API only)
}

# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------


@dataclass
class BruteResult:
    """Result of a single subdomain brute-force run."""

    domain: str
    found: list[str] = field(default_factory=list)   # discovered subdomains
    wordlist_size: str = "small"                       # "small" / "medium" / "large"
    wordlist_path: str = ""                            # resolved path used
    duration_s: float = 0.0
    wildcard_detected: bool = False                    # True → results unreliable
    error: str = ""                                    # non-empty on failure


# ---------------------------------------------------------------------------
# Wordlist resolver
# ---------------------------------------------------------------------------


async def _resolve_wordlist(size: str) -> Optional[str]:
    """
    Return the first existing SecLists DNS wordlist path on Parrot OS, or None.

    Checks candidate paths from _WORDLISTS[size] in order.
    Returns None and logs a warning when no path is found — the caller
    should surface a clear "install seclists" message to the user.

    Prerequisites:
        sudo apt install seclists
    """
    candidates = _WORDLISTS.get(size, _WORDLISTS["small"])
    for path in candidates:
        result = await run_parrot_command(f"test -f '{path}' && echo ok", timeout=10)
        if "ok" in result:
            return path
    log.warning(
        "SubdomainBrute: no SecLists DNS wordlist found for size=%r. "
        "Install with: sudo apt install seclists",
        size,
    )
    return None


# ---------------------------------------------------------------------------
# Wildcard DNS detection
# ---------------------------------------------------------------------------


async def _detect_wildcard(domain: str) -> bool:
    """
    Probe a statistically impossible subdomain to detect wildcard DNS.

    If the probe resolves → wildcard is active → brute results would be all
    false positives.  We abort before running gobuster to avoid poisoning
    watchdog baselines.

    Uses dig with a host fallback; treats any non-NXDOMAIN response as
    evidence of wildcard resolution.
    """
    probe = f"xyzzy-brute-probe-99k4j.{domain}"
    cmd = (
        f"(dig +short +time=5 +tries=1 '{probe}' A 2>/dev/null || "
        f"host -t A '{probe}' 2>/dev/null) | head -3"
    )
    try:
        result = await run_parrot_command(cmd, timeout=15)
    except Exception:
        return False  # SSH failure — assume no wildcard; gobuster will handle it

    result = result.strip().lower()
    if not result:
        return False  # empty output = NXDOMAIN = no wildcard
    # Negative indicators from dig / host
    for indicator in ("not found", "nxdomain", "can't find", "no answer", "servfail"):
        if indicator in result:
            return False
    # Any remaining output (IP address, CNAME) indicates the probe resolved
    log.warning("SubdomainBrute: wildcard DNS detected for %s — probe resolved: %r", domain, result[:80])
    return True


# ---------------------------------------------------------------------------
# gobuster DNS parser
# ---------------------------------------------------------------------------


def _parse_gobuster_output(output: str, domain: str) -> list[str]:
    """
    Extract subdomains from gobuster dns --quiet --no-color output.

    gobuster writes one line per found entry:
        ``Found: api.example.com``

    Filters to only lines whose subdomain ends with ``.{domain}`` to exclude
    any noise from gobuster version/progress lines that may slip through.
    Returns a deduplicated list in discovery order, capped at _MAX_RESULTS.
    """
    apex = domain.lower()
    seen: set[str] = set()
    found: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        # gobuster dns -q lines look like: "Found: sub.example.com"
        if not lower.startswith("found:"):
            continue
        sub = stripped.split(":", 1)[1].strip().lower()
        if not sub.endswith(f".{apex}"):
            continue
        if sub in seen:
            continue
        seen.add(sub)
        found.append(sub)
        if len(found) >= _MAX_RESULTS:
            break

    return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def brute_subdomains(
    domain: str,
    wordlist: str = "small",
) -> BruteResult:
    """
    Run gobuster dns against *domain* via Parrot OS SSH.

    Parameters
    ----------
    domain:
        Validated public FQDN — must pass _validate_domain() before calling.
    wordlist:
        ``"small"`` (~5k, ~60s), ``"medium"`` (~20k, ~4 min),
        or ``"large"`` (~110k, ~12 min — API-only, not exposed via slash command).

    Returns
    -------
    BruteResult
        ``found`` contains deduplicated subdomains in discovery order, capped at
        _MAX_RESULTS.  ``wildcard_detected=True`` means found list is UNRELIABLE
        and callers should not merge results into production baselines.
        ``error`` is non-empty on SSH, binary-not-found, or wordlist-missing failures.

    Notes
    -----
    - All brute runs are serialised under _brute_lock (one at a time globally).
    - Wildcard DNS is detected via a pre-check probe before gobuster runs.
    - gobuster binary must be installed on Parrot OS: ``sudo apt install gobuster``
    - SecLists DNS wordlists required: ``sudo apt install seclists``
    """
    t0 = time.monotonic()
    result = BruteResult(domain=domain, wordlist_size=wordlist)

    # ── Resolve wordlist path ────────────────────────────────────────────────
    wordlist_path = await _resolve_wordlist(wordlist)
    if not wordlist_path:
        result.error = (
            f"No SecLists DNS wordlist found for size={wordlist!r}. "
            "Install with: sudo apt install seclists"
        )
        result.duration_s = time.monotonic() - t0
        return result
    result.wordlist_path = wordlist_path

    # ── Wildcard DNS pre-check ────────────────────────────────────────────────
    try:
        is_wildcard = await _detect_wildcard(domain)
    except Exception:
        is_wildcard = False  # graceful degradation

    if is_wildcard:
        result.wildcard_detected = True
        result.duration_s = time.monotonic() - t0
        log.warning("SubdomainBrute: aborting %s — wildcard DNS active", domain)
        return result

    # ── gobuster dns ─────────────────────────────────────────────────────────
    cmd = (
        f"gobuster dns "
        f"-d '{domain}' "
        f"-w '{wordlist_path}' "
        f"-t {_GOBUSTER_THREADS} "
        f"-q --no-color "
        f"2>/dev/null"
    )
    timeout = _TIMEOUTS.get(wordlist, 120)

    log.info("SubdomainBrute: starting | domain=%s | wordlist=%s | timeout=%ds", domain, wordlist, timeout)

    async with _brute_lock:
        try:
            raw_output = await asyncio.wait_for(
                run_parrot_command(cmd, timeout=timeout),
                timeout=timeout + 30,
            )
        except asyncio.TimeoutError:
            result.error = f"gobuster timed out after {timeout}s."
            result.duration_s = time.monotonic() - t0
            log.warning("SubdomainBrute: timeout | domain=%s", domain)
            return result
        except Exception as exc:
            result.error = f"SSH error: {exc}"
            result.duration_s = time.monotonic() - t0
            log.error("SubdomainBrute: SSH error | domain=%s | %s", domain, exc)
            return result

    # Detect missing binary
    lower = raw_output.lower()
    if "command not found" in lower or ("not found" in lower and "gobuster" in lower):
        result.error = (
            "gobuster not found on Parrot OS. "
            "Install with: sudo apt install gobuster"
        )
        result.duration_s = time.monotonic() - t0
        return result

    result.found = _parse_gobuster_output(raw_output, domain)
    result.duration_s = time.monotonic() - t0

    log.info(
        "SubdomainBrute: complete | domain=%s | found=%d | duration=%.1fs",
        domain, len(result.found), result.duration_s,
    )
    return result


# ---------------------------------------------------------------------------
# Embed builder
# ---------------------------------------------------------------------------


def _build_brute_embed(
    result: BruteResult,
    passive_known: list[str] | None = None,
) -> discord.Embed:
    """
    Build the brute-force results embed.

    When *passive_known* is provided (e.g. from a prior /recon run), the embed
    highlights subdomains that are genuinely new vs. already known passively.
    This prevents alert fatigue when brute findings overlap with crt.sh results.
    """
    passive_set = set(passive_known or [])
    new_only = [s for s in result.found if s not in passive_set]
    overlap = [s for s in result.found if s in passive_set]
    wordlist_size = result.wordlist_size

    # ── Determine embed state ────────────────────────────────────────────────
    if result.wildcard_detected:
        color = discord.Color.yellow()
        title = f"⚠️ Brute Force — `{result.domain}` — Wildcard DNS Detected"
    elif result.error:
        color = discord.Color.red()
        title = f"❌ Brute Force — `{result.domain}` — Error"
    elif result.found:
        color = discord.Color.green()
        title = f"🔨 Brute Force — `{result.domain}` — {len(result.found)} Subdomain(s)"
    else:
        color = discord.Color.greyple()
        title = f"🔨 Brute Force — `{result.domain}` — Nothing Found"

    embed = discord.Embed(
        title=title,
        color=color,
        timestamp=datetime.now(timezone.utc),
    )

    # ── Wildcard warning ─────────────────────────────────────────────────────
    if result.wildcard_detected:
        embed.description = (
            "⚠️ **Wildcard DNS is active** on this domain.\n\n"
            "A nonsense probe subdomain resolved successfully, meaning every entry "
            "in the wordlist would appear as 'Found'. Brute-force was aborted to "
            "prevent false-positive floods.\n\n"
            "**Recommendation:** Verify wildcard DNS with `dig \\*.example.com` and "
            "consider auditing DNS records manually."
        )
        embed.set_footer(text=f"Root AI • Phase 12 Subdomain Brute-Forcer  |  {result.duration_s:.0f}s")
        return embed

    # ── Error state ──────────────────────────────────────────────────────────
    if result.error:
        embed.description = f"```\n{result.error[:1000]}\n```"
        embed.set_footer(text="Root AI • Phase 12 Subdomain Brute-Forcer")
        return embed

    # ── No results ───────────────────────────────────────────────────────────
    if not result.found:
        embed.description = (
            f"No subdomains resolved from the `{wordlist_size}` wordlist "
            f"({result.wordlist_path.split('/')[-1]}).\n\n"
            "• Try the `medium` wordlist for broader coverage.\n"
            "• Verify gobuster and SecLists are up to date on Parrot OS."
        )
        embed.set_footer(
            text=f"Root AI • Phase 12 Subdomain Brute-Forcer  |  {result.duration_s:.0f}s"
        )
        return embed

    # ── Results summary ──────────────────────────────────────────────────────
    stats_lines = [f"Total found: **{len(result.found)}**"]
    if passive_known is not None:
        stats_lines.append(f"New (not in passive recon): **{len(new_only)}**")
        stats_lines.append(f"Already known (overlap): **{len(overlap)}**")
    stats_lines.append(f"Wordlist: `{result.wordlist_path.split('/')[-1]}`")
    embed.add_field(
        name="📊 Summary",
        value="\n".join(stats_lines),
        inline=False,
    )

    # ── New subdomains (primary finding list) ────────────────────────────────
    display_list = new_only if passive_known is not None else result.found
    display_label = "🆕 New Subdomains" if passive_known is not None else "🌐 Found Subdomains"
    if display_list:
        lines = [f"`{s}`" for s in display_list[:50]]
        if len(display_list) > 50:
            lines.append(f"`... +{len(display_list) - 50} more`")
        text = "\n".join(lines)
        embed.add_field(
            name=f"{display_label} ({len(display_list)})",
            value=text[:1020],
            inline=False,
        )
    elif passive_known is not None and not new_only:
        embed.add_field(
            name="🆕 New Subdomains",
            value="All found subdomains were already known from passive recon.",
            inline=False,
        )

    # ── Overlap field (only when passive baseline available + there IS overlap) ─
    if passive_known is not None and overlap:
        lines = [f"`{s}`" for s in overlap[:20]]
        if len(overlap) > 20:
            lines.append(f"`... +{len(overlap) - 20} more`")
        embed.add_field(
            name=f"✅ Already Known ({len(overlap)})",
            value="\n".join(lines)[:1020],
            inline=False,
        )

    embed.set_footer(
        text=(
            f"Root AI • Phase 12 Subdomain Brute-Forcer  |  "
            f"{result.duration_s:.0f}s  |  gobuster dns -t {_GOBUSTER_THREADS}"
        )
    )
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class SubdomainBruteCog(commands.Cog, name="SubdomainBrute"):
    """
    Phase 12 — Active Subdomain Brute-Forcer.

    Runs gobuster dns against a target domain via Parrot OS SSH using SecLists
    DNS wordlists.  Wildcard DNS is detected before brute-force starts to
    prevent false-positive floods that would poison watchdog baselines.

    Exposes /subdomain_brute for direct use and start_brute() for the
    ReconView "Brute Subs" button integration.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ------------------------------------------------------------------
    # Public API — called by ReconView "Brute Subs" button
    # ------------------------------------------------------------------

    async def start_brute(
        self,
        interaction: discord.Interaction,
        domain: str,
        passive_known: list[str] | None = None,
        wordlist: str = "small",
    ) -> None:
        """
        Entry point called from ReconView.brute_button.

        The interaction response is already consumed by edit_message() in the
        button handler — use interaction.followup throughout.
        """
        if _brute_lock.locked():
            await interaction.followup.send(
                "⚠️ A brute-force job is already running. Please wait for it to finish.",
                ephemeral=True,
            )
            return

        log.info(
            "SubdomainBrute: start_brute | domain=%s | wordlist=%s | passive_known=%d",
            domain, wordlist, len(passive_known or []),
        )

        result = await brute_subdomains(domain, wordlist=wordlist)
        embed = _build_brute_embed(result, passive_known=passive_known)
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ------------------------------------------------------------------
    # Slash command
    # ------------------------------------------------------------------

    @app_commands.command(
        name="subdomain_brute",
        description="[OWNER] Active DNS subdomain brute-force via gobuster on Parrot OS.",
    )
    @app_commands.describe(
        target="Target FQDN to brute-force (e.g. example.com)",
        wordlist="Wordlist size (small ~60s | medium ~4 min)",
    )
    @app_commands.choices(wordlist=[
        app_commands.Choice(name="small  — ~5k words  (~60s)",  value="small"),
        app_commands.Choice(name="medium — ~20k words (~4 min)", value="medium"),
    ])
    async def subdomain_brute(
        self,
        interaction: discord.Interaction,
        target: str,
        wordlist: str = "small",
    ) -> None:
        """Phase 12 entry point — active subdomain brute-force via slash command."""

        # ── Owner gate ────────────────────────────────────────────────────────
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/subdomain_brute` is an owner-only command.", ephemeral=True
            )
            return

        # ── FQDN validation ──────────────────────────────────────────────────
        valid, clean_or_err = _validate_domain(target)
        if not valid:
            await interaction.response.send_message(
                f"⚠️ Invalid target: {clean_or_err}", ephemeral=True
            )
            return
        clean_target: str = clean_or_err

        # ── Concurrency guard ────────────────────────────────────────────────
        if _brute_lock.locked():
            await interaction.response.send_message(
                "⚠️ A brute-force job is already running. Please wait for it to finish.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(thinking=True)
        log.info(
            "SubdomainBrute: /subdomain_brute | target=%s | wordlist=%s | user=%s",
            clean_target, wordlist, interaction.user,
        )

        result = await brute_subdomains(clean_target, wordlist=wordlist)
        embed = _build_brute_embed(result)
        await interaction.followup.send(embed=embed)

        log.info(
            "SubdomainBrute: complete | target=%s | found=%d | wildcard=%s | duration=%.1fs",
            clean_target, len(result.found), result.wildcard_detected, result.duration_s,
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SubdomainBruteCog(bot))
