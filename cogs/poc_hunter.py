"""
cogs/poc_hunter.py
Phase 13 — CVE PoC Hunter

Public API:    fetch_poc_repos(cve_id) -> PoCResult
Slash command: /poc <cve_id>

Data sources (all concurrent, each fails gracefully):
  1. nomi-sec PoC-in-GitHub API  — curated list, up to 100 results
     https://poc-in-github.motikan2010.net/api/v1/?cve_id=CVE-XXXX-XXXX
  2. GitHub Search API           — repository search, sorted by stars
     https://api.github.com/search/repositories?q={CVE_ID}&sort=stars
  3. trickest/cve                — check for a curated PoC write-up
     https://github.com/trickest/cve/blob/main/{year}/{CVE_ID}.md

Design notes:
  - CVE IDs are validated with a strict regex before any outbound request.
  - asyncio.Semaphore(2) limits concurrent fan-out (not a Lock — HTTP, not SSH).
  - Results are deduplicated by full_name and sorted by stars descending.
  - GITHUB_PAT (if set) is passed as a Bearer token to raise the rate limit
    from 10 → 30 req/min.  Graceful degradation without the token.
  - No Parrot OS SSH — all calls go directly to external HTTPS APIs.
  - No LLM tool registration — follows the recon/watchdog pattern.

Watchdog integration:
  - _scan_and_alert() calls fetch_poc_repos() for newly discovered CVEs
    with CVSS score ≥ 9.0 (cap: 3 CVEs per scan to stay within rate limits).
  - Results flow into _build_alert_embed() and _build_scan_embed() via the
    poc_results keyword arg added in Phase 13.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID, GITHUB_PAT

log = logging.getLogger("root_ai.poc_hunter")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAX_RESULTS = 10          # max repos returned by fetch_poc_repos()
_MAX_DISPLAY = 8           # repos shown in Discord embed
_poc_sem = asyncio.Semaphore(2)  # limit concurrent HTTP fan-out per call

# Base URLs
_NOMI_SEC_URL = "https://poc-in-github.motikan2010.net/api/v1/"
_GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
_TRICKEST_CONTENTS_URL = "https://api.github.com/repos/trickest/cve/contents/{year}/{cve_id}.md"
_TRICKEST_HTML_URL = "https://github.com/trickest/cve/blob/main/{year}/{cve_id}.md"


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class PoCRepo:
    """A single GitHub repository identified as a PoC for a CVE."""

    full_name: str
    url: str
    stars: int
    description: str
    language: str
    pushed_at: str      # ISO 8601 string — displayed as YYYY-MM-DD
    is_fork: bool = False
    source: str = ""    # "nomi-sec" | "github"


@dataclass
class PoCResult:
    """
    Aggregated PoC hunt result for one CVE.

    repos            — deduplicated, sorted by stars desc, capped at _MAX_RESULTS
    total_github_results — raw GitHub Search total_count (may be much larger)
    trickest_url     — direct link to trickest/cve write-up if one exists
    error            — set when the CVE ID is invalid or all sources fail
    """

    cve_id: str
    repos: list[PoCRepo] = field(default_factory=list)
    total_github_results: int = 0
    trickest_url: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# GitHub API header builder
# ---------------------------------------------------------------------------


def _github_headers() -> dict[str, str]:
    """
    Build GitHub API request headers.
    Includes Bearer token when GITHUB_PAT is configured (raises rate limit
    from 10 → 30 req/min for search endpoints).
    """
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Root-AI-Bot/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_PAT:
        headers["Authorization"] = f"Bearer {GITHUB_PAT}"
    return headers


# ---------------------------------------------------------------------------
# Per-source fetch helpers
# ---------------------------------------------------------------------------


async def _fetch_nomi_sec(
    cve_id: str,
    session: aiohttp.ClientSession,
) -> list[PoCRepo]:
    """
    Query the nomi-sec PoC-in-GitHub API.

    Returns up to _MAX_RESULTS repos; never raises (returns [] on any failure).
    """
    async with _poc_sem:
        try:
            async with session.get(
                _NOMI_SEC_URL,
                params={"cve_id": cve_id},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    log.debug("nomi-sec: HTTP %d for %s", resp.status, cve_id)
                    return []
                data = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            log.warning("nomi-sec: timeout for %s", cve_id)
            return []
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("nomi-sec: error for %s: %s", cve_id, exc)
            return []

    pocs: list[dict] = data.get("pocs", [])
    if not isinstance(pocs, list):
        return []

    results: list[PoCRepo] = []
    for entry in pocs[:_MAX_RESULTS]:
        if not isinstance(entry, dict):
            continue
        full_name = entry.get("full_name", "")
        if not full_name:
            continue
        results.append(
            PoCRepo(
                full_name=full_name,
                url=entry.get("html_url", f"https://github.com/{full_name}"),
                stars=int(entry.get("stargazers_count", 0)),
                description=(entry.get("description") or entry.get("vuln_description") or "")[:200],
                language="",  # nomi-sec does not return language
                pushed_at=entry.get("pushed_at", ""),
                is_fork=False,
                source="nomi-sec",
            )
        )

    log.info("nomi-sec: %d PoC(s) for %s", len(results), cve_id)
    return results


async def _fetch_github_search(
    cve_id: str,
    session: aiohttp.ClientSession,
) -> tuple[list[PoCRepo], int]:
    """
    Query GitHub Search API for repositories matching the CVE ID.

    Returns (repos, total_count).  Never raises — returns ([], 0) on failure.
    """
    async with _poc_sem:
        try:
            async with session.get(
                _GITHUB_SEARCH_URL,
                params={
                    "q": cve_id,
                    "sort": "stars",
                    "order": "desc",
                    "per_page": str(_MAX_RESULTS),
                },
                headers=_github_headers(),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 422:
                    log.debug("github-search: 422 Unprocessable for %s (no results)", cve_id)
                    return [], 0
                if resp.status == 403:
                    log.warning(
                        "github-search: 403 rate-limited for %s — set GITHUB_PAT to raise limit",
                        cve_id,
                    )
                    return [], 0
                if resp.status != 200:
                    log.debug("github-search: HTTP %d for %s", resp.status, cve_id)
                    return [], 0
                data = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            log.warning("github-search: timeout for %s", cve_id)
            return [], 0
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("github-search: error for %s: %s", cve_id, exc)
            return [], 0

    total_count: int = int(data.get("total_count", 0))
    items: list[dict] = data.get("items", [])
    if not isinstance(items, list):
        return [], total_count

    results: list[PoCRepo] = []
    for item in items[:_MAX_RESULTS]:
        if not isinstance(item, dict):
            continue
        full_name = item.get("full_name", "")
        if not full_name:
            continue
        results.append(
            PoCRepo(
                full_name=full_name,
                url=item.get("html_url", f"https://github.com/{full_name}"),
                stars=int(item.get("stargazers_count", 0)),
                description=(item.get("description") or "")[:200],
                language=item.get("language") or "",
                pushed_at=item.get("pushed_at", ""),
                is_fork=bool(item.get("fork", False)),
                source="github",
            )
        )

    log.info("github-search: %d result(s) (total %d) for %s", len(results), total_count, cve_id)
    return results, total_count


async def _check_trickest(
    cve_id: str,
    session: aiohttp.ClientSession,
) -> str:
    """
    Check if trickest/cve has a curated entry for this CVE.

    Returns the direct GitHub URL if found, "" otherwise.
    Uses the GitHub Contents API (HEAD check via GET, 404 = not present).
    """
    try:
        year = cve_id.split("-")[1]  # CVE-2021-44228 → "2021"
    except IndexError:
        return ""

    url = _TRICKEST_CONTENTS_URL.format(year=year, cve_id=cve_id.upper())
    async with _poc_sem:
        try:
            async with session.get(
                url,
                headers=_github_headers(),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    html_url = _TRICKEST_HTML_URL.format(year=year, cve_id=cve_id.upper())
                    log.info("trickest: entry found for %s → %s", cve_id, html_url)
                    return html_url
                # 404 = not indexed yet — normal for recent CVEs
                log.debug("trickest: %s not in trickest/cve (HTTP %d)", cve_id, resp.status)
                return ""
        except asyncio.TimeoutError:
            log.debug("trickest: timeout for %s", cve_id)
            return ""
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("trickest: error for %s: %s", cve_id, exc)
            return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_poc_repos(cve_id: str) -> PoCResult:
    """
    Fetch public PoC repositories for *cve_id* from multiple sources.

    Sources run concurrently (nomi-sec, GitHub Search, trickest check).
    Results are deduplicated by full_name (case-insensitive) and sorted
    by stars descending, capped at _MAX_RESULTS.

    Returns a PoCResult with error set when the CVE ID fails validation.
    Public API — imported by ``cogs.watchdog`` for automated PoC alerts.
    """
    # Normalise + validate
    clean_cve = cve_id.strip().upper()
    if not _CVE_RE.match(clean_cve):
        return PoCResult(
            cve_id=cve_id,
            error=f"`{cve_id}` is not a valid CVE ID (expected format: CVE-YYYY-NNNN).",
        )

    result = PoCResult(cve_id=clean_cve)

    async with aiohttp.ClientSession() as session:
        nomi_task = _fetch_nomi_sec(clean_cve, session)
        github_task = _fetch_github_search(clean_cve, session)
        trickest_task = _check_trickest(clean_cve, session)

        nomi_raw, github_raw, trickest_url = await asyncio.gather(
            nomi_task, github_task, trickest_task, return_exceptions=True
        )

    # Trickest URL
    if isinstance(trickest_url, str):
        result.trickest_url = trickest_url

    # GitHub total
    github_repos: list[PoCRepo] = []
    if isinstance(github_raw, tuple):
        github_repos, result.total_github_results = github_raw

    # nomi-sec repos
    nomi_repos: list[PoCRepo] = nomi_raw if isinstance(nomi_raw, list) else []

    # Merge + deduplicate by full_name (prefer nomi-sec entry — has vuln_description)
    seen: set[str] = set()
    merged: list[PoCRepo] = []
    for repo in nomi_repos + github_repos:
        key = repo.full_name.lower()
        if key not in seen:
            seen.add(key)
            merged.append(repo)

    # Sort by stars descending
    merged.sort(key=lambda r: r.stars, reverse=True)
    result.repos = merged[:_MAX_RESULTS]

    log.info(
        "fetch_poc_repos: %s — %d unique repo(s), trickest=%s",
        clean_cve,
        len(result.repos),
        bool(result.trickest_url),
    )
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_pushed_at(pushed_at: str) -> str:
    """Convert ISO 8601 pushed_at to a compact 'YYYY-MM-DD' string."""
    if not pushed_at:
        return ""
    try:
        dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return pushed_at[:10]


# ---------------------------------------------------------------------------
# Embed builder
# ---------------------------------------------------------------------------


def _build_poc_embed(result: PoCResult) -> discord.Embed:
    """Rich embed showing PoC hunt results for one CVE."""
    if result.error:
        return discord.Embed(
            title=f"🧬 CVE PoC Hunter — `{result.cve_id}`",
            description=f"⚠️ {result.error}",
            color=discord.Color.orange(),
        )

    has_pocs = bool(result.repos)
    color = discord.Color.from_rgb(220, 50, 50) if has_pocs else discord.Color.green()

    description_parts = []
    if result.total_github_results:
        description_parts.append(
            f"**{result.total_github_results}** matching GitHub repositories."
        )
    if has_pocs:
        description_parts.append(
            f"Showing top **{min(len(result.repos), _MAX_DISPLAY)}** by ⭐ stars."
        )
        description_parts.append(
            "⚠️ *Review each repo carefully before use — authorised testing only.*"
        )
    else:
        description_parts.append(
            "No public PoC repositories found across nomi-sec and GitHub Search."
        )
        description_parts.append(
            "This CVE may be newly disclosed, low-severity, or the PoC may be private."
        )

    embed = discord.Embed(
        title=f"🧬 CVE PoC Hunter — `{result.cve_id}`",
        description="\n".join(description_parts),
        color=color,
        timestamp=datetime.now(timezone.utc),
    )

    # ── trickest/cve field ───────────────────────────────────────────────────
    if result.trickest_url:
        embed.add_field(
            name="📖 trickest/cve Write-up",
            value=f"[View curated PoC analysis →]({result.trickest_url})",
            inline=False,
        )

    # ── Repos field ─────────────────────────────────────────────────────────
    if has_pocs:
        lines: list[str] = []
        for repo in result.repos[:_MAX_DISPLAY]:
            # Line 1: stars + name + language
            lang_tag = f" `{repo.language}`" if repo.language else ""
            fork_tag = " `fork`" if repo.is_fork else ""
            pushed = _format_pushed_at(repo.pushed_at)
            pushed_tag = f" · {pushed}" if pushed else ""
            lines.append(
                f"⭐ **{repo.stars:,}**{lang_tag}{fork_tag}  [`{repo.full_name}`]({repo.url}){pushed_tag}"
            )
            # Line 2: description (truncated)
            if repo.description:
                desc = repo.description[:100]
                if len(repo.description) > 100:
                    desc += "…"
                lines.append(f"  ↳ {desc}")

        total_shown = min(len(result.repos), _MAX_DISPLAY)
        total_available = max(len(result.repos), result.total_github_results)
        field_name = (
            f"💥 PoC Repositories ({total_shown} shown"
            + (f" of {total_available}+" if total_available > total_shown else "")
            + ")"
        )
        embed.add_field(
            name=field_name,
            value="\n".join(lines)[:1020],
            inline=False,
        )

    # ── Source attribution ───────────────────────────────────────────────────
    sources = "nomi-sec PoC-in-GitHub · GitHub Search"
    if result.trickest_url:
        sources += " · trickest/cve"
    embed.set_footer(
        text=f"Root AI • Phase 13 CVE PoC Hunter  |  Sources: {sources}"
    )
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class PoCHunterCog(commands.Cog, name="PoCHunter"):
    """
    Phase 13 — CVE PoC Hunter.

    Aggregates public proof-of-concept repositories for a given CVE ID from
    nomi-sec PoC-in-GitHub, GitHub Search, and trickest/cve.  Results are
    deduplicated, sorted by stars, and surfaced as a rich Discord embed.

    /poc <CVE-ID>        — on-demand PoC hunt
    fetch_poc_repos()    — public API consumed by cogs.watchdog
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(
        name="poc",
        description="[OWNER] Hunt public GitHub PoC exploits for a CVE ID.",
    )
    @app_commands.describe(
        cve_id="CVE identifier to hunt (e.g. CVE-2021-44228)",
    )
    async def poc(
        self,
        interaction: discord.Interaction,
        cve_id: str,
    ) -> None:
        """Phase 13 entry point — on-demand CVE PoC hunt."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/poc` is an owner-only command.", ephemeral=True
            )
            return

        clean = cve_id.strip().upper()
        if not _CVE_RE.match(clean):
            await interaction.response.send_message(
                f"⚠️ `{cve_id}` is not a valid CVE ID.\n"
                "Expected format: `CVE-YYYY-NNNN` (e.g. `CVE-2021-44228`)",
                ephemeral=True,
            )
            return

        await interaction.response.defer(thinking=True)
        log.info("PoCHunter: /poc cve_id=%s user=%s", clean, interaction.user)

        result = await fetch_poc_repos(clean)
        embed = _build_poc_embed(result)
        await interaction.followup.send(embed=embed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(PoCHunterCog(bot))
