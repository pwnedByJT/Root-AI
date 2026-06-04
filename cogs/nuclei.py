"""
cogs/nuclei.py
Phase 10 — Nuclei Template Scanner

Slash command: /nuclei <target> [severity]
Public API:    run_nuclei_scan(target, severity="critical,high,medium") -> list[NucleiFinding]
               └─ Called by AutoPwn pipeline and Watchdog background loop.

Pipeline (/nuclei):
  1. Validate target FQDN (re-uses recon.py's _validate_domain)
  2. Sanitize severity string against allowlist
  3. SSH to Parrot OS: nuclei -u 'https://<target>' -jsonl -silent ...
  4. Parse JSONL output line by line (defensive — malformed lines skipped)
  5. Deduplicate by template_id:matched_url; cap at 25 results
  6. Sort by severity order (critical → info)
  7. Post severity-bucketed embed

Security boundaries:
  - /nuclei is gated to BOT_OWNER_ID.
  - asyncio.Lock prevents concurrent nuclei scans (one at a time — Parrot OS protection).
  - Target is FQDN-validated by _validate_domain + residual-char stripping.
  - Severity values validated against strict allowlist before shell use — no raw user input.
  - nuclei command built from controlled constants only.
  - -silent flag suppresses banner (prevents first-line JSONL corruption).
  - 2>/dev/null suppresses stderr noise from non-existent templates.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID
from cogs.recon import _validate_domain
from cogs.security import run_parrot_command

log = logging.getLogger("root_ai.nuclei")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_ALLOWLIST: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}

_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

_MAX_FINDINGS = 25

_nuclei_lock = asyncio.Lock()  # one nuclei scan at a time — Parrot OS protection

# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------


@dataclass
class NucleiFinding:
    """A single nuclei template match."""

    template_id: str
    name: str
    severity: str          # normalised lower-case; guaranteed in _SEVERITY_ALLOWLIST
    matched_url: str
    description: str = ""
    cvss_score: Optional[float] = None


# ---------------------------------------------------------------------------
# Input sanitisation
# ---------------------------------------------------------------------------

_SAFE_TARGET_RE = re.compile(r"[^a-zA-Z0-9.\-]")


def _sanitize_target(target: str) -> str:
    """Strip residual non-FQDN characters and cap length."""
    return _SAFE_TARGET_RE.sub("", target)[:253]


def _sanitize_severity(severity: str) -> str:
    """
    Validate each comma-separated token against the allowlist.

    Returns a cleaned, lower-cased severity string.
    Raises ValueError if any token is unknown — prevents shell injection.
    """
    tokens = [t.strip().lower() for t in severity.split(",") if t.strip()]
    if not tokens:
        raise ValueError("At least one severity level must be specified.")
    for tok in tokens:
        if tok not in _SEVERITY_ALLOWLIST:
            raise ValueError(
                f"Unknown severity level: {tok!r}. "
                f"Valid values: {', '.join(sorted(_SEVERITY_ALLOWLIST))}"
            )
    return ",".join(tokens)


# ---------------------------------------------------------------------------
# JSONL parser
# ---------------------------------------------------------------------------


def _parse_nuclei_line(line: str) -> Optional[NucleiFinding]:
    """
    Parse a single nuclei JSONL output line into a NucleiFinding.

    Returns None on any parse error — callers skip None entries.
    Nuclei's -jsonl flag writes one JSON object per line; -silent suppresses
    the banner that would otherwise corrupt the first line.
    """
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    template_id: str = obj.get("template-id", "")
    matched_url: str = obj.get("matched-at", "")
    if not template_id or not matched_url:
        return None

    info: dict = obj.get("info", {}) or {}
    name: str = info.get("name", template_id) or template_id
    severity: str = (info.get("severity") or "info").lower()
    if severity not in _SEVERITY_ALLOWLIST:
        severity = "info"

    description: str = info.get("description", "") or ""

    cvss_score: Optional[float] = None
    classification = info.get("classification") or {}
    if isinstance(classification, dict):
        raw_score = classification.get("cvss-score")
        if raw_score is not None:
            try:
                cvss_score = float(raw_score)
            except (TypeError, ValueError):
                pass

    return NucleiFinding(
        template_id=template_id,
        name=name,
        severity=severity,
        matched_url=matched_url,
        description=description,
        cvss_score=cvss_score,
    )


# ---------------------------------------------------------------------------
# Core scanner (public API)
# ---------------------------------------------------------------------------


async def run_nuclei_scan(
    target: str,
    severity: str = "critical,high,medium",
) -> list[NucleiFinding]:
    """
    Run nuclei against *target* via Parrot OS SSH and return parsed findings.

    Parameters
    ----------
    target:
        FQDN to scan — ``https://`` is prepended automatically for nuclei's -u flag.
    severity:
        Comma-separated severity filter (e.g. ``"critical,high"``).  Each token must
        be in _SEVERITY_ALLOWLIST; ValueError raised (and [] returned) otherwise.

    Returns
    -------
    list[NucleiFinding]
        Up to _MAX_FINDINGS findings, deduplicated by ``template_id:matched_url``
        and sorted critical → info.  Returns [] on SSH error, timeout, or when
        nuclei reports no templates found.
    """
    try:
        clean_sev = _sanitize_severity(severity)
    except ValueError as exc:
        log.error("Nuclei: invalid severity %r — %s", severity, exc)
        return []

    safe_target = _sanitize_target(target)
    url = f"https://{safe_target}"

    cmd = (
        f"nuclei -u '{url}' -jsonl -silent "
        f"-severity {clean_sev} "
        f"-timeout 5 -c 25 -bs 25 -rl 100 2>/dev/null"
    )

    log.info("Nuclei: scanning %s (severity=%s)", url, clean_sev)

    async with _nuclei_lock:
        try:
            raw_output = await asyncio.wait_for(
                run_parrot_command(cmd, timeout=120),
                timeout=130,
            )
        except asyncio.TimeoutError:
            log.warning("Nuclei: scan timed out for %s", url)
            return []
        except Exception as exc:
            log.error("Nuclei: SSH error for %s: %s", url, exc)
            return []

    # Detect "no templates" conditions — nuclei writes these to stderr (suppressed)
    # but may also appear in stdout if -silent is not honoured by old versions.
    lower_out = raw_output.lower()
    if "no templates" in lower_out or "no results" in lower_out:
        log.info("Nuclei: no templates found for %s", url)
        return []

    # Parse JSONL line by line — defensive; one bad line must not abort the rest
    seen: set[str] = set()
    findings: list[NucleiFinding] = []

    for line in raw_output.splitlines():
        finding = _parse_nuclei_line(line)
        if finding is None:
            continue
        dedup_key = f"{finding.template_id}:{finding.matched_url}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        findings.append(finding)
        if len(findings) >= _MAX_FINDINGS:
            break

    # Sort by severity: critical first, info last
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    log.info("Nuclei: %d finding(s) for %s", len(findings), url)
    return findings


# ---------------------------------------------------------------------------
# Embed builder
# ---------------------------------------------------------------------------


def _build_nuclei_embed(
    target: str,
    findings: list[NucleiFinding],
    duration_s: float,
) -> discord.Embed:
    """Build a severity-bucketed Discord embed for nuclei scan results."""
    footer = f"Root AI • Phase 10 Nuclei Scanner  |  {duration_s:.0f}s"

    if not findings:
        embed = discord.Embed(
            title=f"🔬 Nuclei Scan — `{target}`",
            description="✅ No findings at the requested severity level(s).",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(text=footer)
        return embed

    # Bucket findings by severity
    by_severity: dict[str, list[NucleiFinding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    critical_count = len(by_severity.get("critical", []))
    high_count = len(by_severity.get("high", []))
    color = (
        discord.Color.red()    if critical_count > 0 else
        discord.Color.orange() if high_count > 0     else
        discord.Color.yellow()
    )

    embed = discord.Embed(
        title=f"🔬 Nuclei Scan — `{target}`",
        description=(
            f"**{len(findings)}** finding(s) across "
            f"**{len(by_severity)}** severity level(s)."
        ),
        color=color,
        timestamp=datetime.now(timezone.utc),
    )

    # One field per severity bucket — show up to 10 per bucket
    for sev in ("critical", "high", "medium", "low", "info"):
        bucket = by_severity.get(sev)
        if not bucket:
            continue
        emoji = _SEVERITY_EMOJI.get(sev, "•")
        lines = []
        for f in bucket[:10]:
            score_str = f" (CVSS {f.cvss_score:.1f})" if f.cvss_score is not None else ""
            name_trunc = f.name[:60]
            lines.append(f"`{f.template_id}` — {name_trunc}{score_str}")
        if len(bucket) > 10:
            lines.append(f"`... +{len(bucket) - 10} more`")
        embed.add_field(
            name=f"{emoji} {sev.capitalize()} ({len(bucket)})",
            value="\n".join(lines)[:1020],
            inline=False,
        )

    embed.set_footer(text=footer)
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class NucleiCog(commands.Cog, name="Nuclei"):
    """
    Phase 10 — Nuclei Template Scanner.

    Runs Project Discovery's nuclei against a target via Parrot OS SSH.
    Findings are parsed from JSONL output line-by-line, deduplicated by
    template_id:matched_url, severity-sorted, and posted as a bucketed embed.

    The public run_nuclei_scan() function is the integration API consumed by
    the AutoPwn pipeline (pre-loop seeding) and the Watchdog background loop
    (new-subdomain scanning).
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(
        name="nuclei",
        description="[OWNER] Run a nuclei template scan against a target domain.",
    )
    @app_commands.describe(
        target="Target FQDN to scan (e.g. example.com)",
        severity="Comma-separated severity filter (default: critical,high,medium)",
    )
    async def nuclei(
        self,
        interaction: discord.Interaction,
        target: str,
        severity: str = "critical,high,medium",
    ) -> None:
        """Phase 10 entry point — nuclei template scan via slash command."""

        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/nuclei` is an owner-only command.", ephemeral=True
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

        # ── Severity validation ──────────────────────────────────────────────
        try:
            clean_sev = _sanitize_severity(severity)
        except ValueError as exc:
            await interaction.response.send_message(
                f"⚠️ {exc}", ephemeral=True
            )
            return

        # ── Concurrency guard ────────────────────────────────────────────────
        if _nuclei_lock.locked():
            await interaction.response.send_message(
                "⚠️ A nuclei scan is already running. Please wait for it to finish.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(thinking=True)
        log.info(
            "Nuclei: /nuclei invoked | target=%s | severity=%s | user=%s",
            clean_target, clean_sev, interaction.user,
        )

        t0 = time.monotonic()
        findings = await run_nuclei_scan(clean_target, severity=clean_sev)
        duration = time.monotonic() - t0

        embed = _build_nuclei_embed(clean_target, findings, duration)
        await interaction.followup.send(embed=embed)

        log.info(
            "Nuclei: complete | target=%s | findings=%d | duration=%.1fs",
            clean_target, len(findings), duration,
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(NucleiCog(bot))
