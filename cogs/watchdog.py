"""
cogs/watchdog.py
Phase 5 — Bug Bounty Watchdog (Persistent Asset Monitor)

Slash commands: /watchdog add <domain>
                /watchdog remove <domain>
                /watchdog list
                /watchdog scan <domain>

Background task (tasks.loop):
  - Runs every WATCHDOG_INTERVAL_HOURS (default 6 h).
  - For every tracked target:
      • gather_subdomains() — crt.sh + subfinder + assetfinder (passive)
      • _shodan_host_info() — per-IP Shodan api.host() (free tier, sequential)
  - On first scan of a domain: posts a "baseline established" embed instead of
    flooding the channel with every discovered asset.
  - On subsequent scans: diffs current results against the SQLite baseline and
    posts a Discord alert when new subdomains, IPs, services, version changes,
    or CVEs are found.

Storage:
  - Local SQLite at WATCHDOG_DB_PATH (default data/watchdog.db).
  - Five tables: targets, subdomains, shodan_ips, shodan_services, shodan_vulns.
  - All DB I/O is wrapped in asyncio.to_thread() — no blocking the event loop.

Security boundaries:
  - All /watchdog subcommands are gated to BOT_OWNER_ID.
  - Domain input re-uses recon.py's _validate_domain() — same FQDN regex + private-range guard.
  - Shodan calls go via cogs.recon._shodan_host_info() — same 1 req/s rate-limit and SSRF guards.

Tool requirements on Parrot OS (for gather_subdomains):
  - subfinder   (https://github.com/projectdiscovery/subfinder)
  - assetfinder (https://github.com/tomnomnom/assetfinder)
  Both are free / open-source. Graceful degradation if either is missing.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands, tasks

from config import BOT_OWNER_ID, WATCHDOG_CHANNEL_ID, WATCHDOG_DB_PATH, WATCHDOG_INTERVAL_HOURS
from cogs.recon import (
    CVEDetail,
    ShodanResult,
    _shodan_host_info,
    _validate_domain,
    enrich_cves,
    gather_subdomains,
)

log = logging.getLogger("root_ai.watchdog")


# ---------------------------------------------------------------------------
# Diff dataclass
# ---------------------------------------------------------------------------


@dataclass
class ScanDiff:
    """Unified diff for one watchdog scan cycle — covers all tracked asset types."""

    new_subs: list[str] = field(default_factory=list)
    new_ips: list[str] = field(default_factory=list)
    new_services: list[dict] = field(default_factory=list)   # {ip, port, proto, product, version}
    changed_versions: list[dict] = field(default_factory=list)  # {ip, port, proto, old, new}
    new_cves: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_subs
            or self.new_ips
            or self.new_services
            or self.changed_versions
            or self.new_cves
        )


# ---------------------------------------------------------------------------
# SQLite helpers (all wrapped in asyncio.to_thread for non-blocking I/O)
# ---------------------------------------------------------------------------


class WatchdogDB:
    """
    Thin async wrapper around a synchronous SQLite connection.

    All public methods are coroutines that offload blocking sqlite3 calls
    via asyncio.to_thread().  No third-party aiosqlite required.
    """

    def __init__(self, db_path: str) -> None:
        self._path = db_path

    # ── Schema ────────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create tables if they don't exist.  Called synchronously in a thread."""
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with sqlite3.connect(self._path) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain      TEXT    NOT NULL UNIQUE,
                    channel_id  INTEGER NOT NULL,
                    added_at    TEXT    NOT NULL,
                    last_scanned TEXT
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS subdomains (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    subdomain   TEXT    NOT NULL,
                    first_seen  TEXT    NOT NULL,
                    last_seen   TEXT    NOT NULL,
                    UNIQUE(target_id, subdomain)
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS shodan_ips (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    ip          TEXT    NOT NULL,
                    first_seen  TEXT    NOT NULL,
                    last_seen   TEXT    NOT NULL,
                    UNIQUE(target_id, ip)
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS shodan_services (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    ip          TEXT    NOT NULL,
                    port        INTEGER NOT NULL,
                    proto       TEXT    NOT NULL,
                    product     TEXT    NOT NULL DEFAULT '',
                    version     TEXT    NOT NULL DEFAULT '',
                    first_seen  TEXT    NOT NULL,
                    last_seen   TEXT    NOT NULL,
                    UNIQUE(target_id, ip, port, proto)
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS shodan_vulns (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    cve         TEXT    NOT NULL,
                    first_seen  TEXT    NOT NULL,
                    last_seen   TEXT    NOT NULL,
                    UNIQUE(target_id, cve)
                )
                """
            )
            con.commit()

    async def init(self) -> None:
        await asyncio.to_thread(self._init_db)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_target_id(self, domain: str) -> Optional[int]:
        with sqlite3.connect(self._path) as con:
            row = con.execute(
                "SELECT id FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
        return row[0] if row else None

    # ── Targets ───────────────────────────────────────────────────────────────

    def _add_target(self, domain: str, channel_id: int) -> bool:
        """Insert a target; return True if inserted, False if it already existed."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite3.connect(self._path) as con:
                con.execute(
                    "INSERT INTO targets (domain, channel_id, added_at) VALUES (?,?,?)",
                    (domain, channel_id, now),
                )
                con.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    async def add_target(self, domain: str, channel_id: int) -> bool:
        return await asyncio.to_thread(self._add_target, domain, channel_id)

    def _remove_target(self, domain: str) -> bool:
        """Delete a target (cascade removes all baseline data); return True if found."""
        with sqlite3.connect(self._path) as con:
            cur = con.execute("DELETE FROM targets WHERE domain = ?", (domain,))
            con.commit()
        return cur.rowcount > 0

    async def remove_target(self, domain: str) -> bool:
        return await asyncio.to_thread(self._remove_target, domain)

    def _list_targets(self) -> list[dict]:
        with sqlite3.connect(self._path) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT domain, channel_id, added_at, last_scanned FROM targets ORDER BY domain"
            ).fetchall()
        return [dict(r) for r in rows]

    async def list_targets(self) -> list[dict]:
        return await asyncio.to_thread(self._list_targets)

    def _get_target_last_scanned(self, domain: str) -> Optional[str]:
        """Return the stored last_scanned ISO string, or None if this is a first scan."""
        with sqlite3.connect(self._path) as con:
            row = con.execute(
                "SELECT last_scanned FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
        return row[0] if row else None

    async def get_target_last_scanned(self, domain: str) -> Optional[str]:
        return await asyncio.to_thread(self._get_target_last_scanned, domain)

    # ── Baseline reads ────────────────────────────────────────────────────────

    def _get_subdomain_baseline(self, domain: str) -> set[str]:
        with sqlite3.connect(self._path) as con:
            rows = con.execute(
                """
                SELECT s.subdomain FROM subdomains s
                JOIN targets t ON t.id = s.target_id
                WHERE t.domain = ?
                """,
                (domain,),
            ).fetchall()
        return {r[0] for r in rows}

    async def get_baseline(self, domain: str) -> set[str]:
        return await asyncio.to_thread(self._get_subdomain_baseline, domain)

    def _get_shodan_ip_baseline(self, domain: str) -> set[str]:
        with sqlite3.connect(self._path) as con:
            rows = con.execute(
                """
                SELECT si.ip FROM shodan_ips si
                JOIN targets t ON t.id = si.target_id
                WHERE t.domain = ?
                """,
                (domain,),
            ).fetchall()
        return {r[0] for r in rows}

    async def get_shodan_ip_baseline(self, domain: str) -> set[str]:
        return await asyncio.to_thread(self._get_shodan_ip_baseline, domain)

    def _get_shodan_service_baseline(
        self, domain: str
    ) -> dict[tuple[str, int, str], dict]:
        """
        Return {(ip, port, proto): {product, version}} for all stored services.

        Used for both new-service detection and version-change detection.
        Stored as a dict keyed by the composite identity tuple so both checks
        are O(1) lookups rather than O(n) scans.
        """
        with sqlite3.connect(self._path) as con:
            rows = con.execute(
                """
                SELECT ss.ip, ss.port, ss.proto, ss.product, ss.version
                FROM shodan_services ss
                JOIN targets t ON t.id = ss.target_id
                WHERE t.domain = ?
                """,
                (domain,),
            ).fetchall()
        return {(r[0], r[1], r[2]): {"product": r[3], "version": r[4]} for r in rows}

    async def get_shodan_service_baseline(
        self, domain: str
    ) -> dict[tuple[str, int, str], dict]:
        return await asyncio.to_thread(self._get_shodan_service_baseline, domain)

    def _get_vuln_baseline(self, domain: str) -> set[str]:
        with sqlite3.connect(self._path) as con:
            rows = con.execute(
                """
                SELECT sv.cve FROM shodan_vulns sv
                JOIN targets t ON t.id = sv.target_id
                WHERE t.domain = ?
                """,
                (domain,),
            ).fetchall()
        return {r[0] for r in rows}

    async def get_vuln_baseline(self, domain: str) -> set[str]:
        return await asyncio.to_thread(self._get_vuln_baseline, domain)

    # ── Upsert ───────────────────────────────────────────────────────────────

    def _full_upsert(
        self, domain: str, subdomains: list[str], sd: Optional[ShodanResult]
    ) -> None:
        """
        Atomically upsert subdomains + Shodan data and stamp last_scanned.

        Uses a single timestamp for consistency across all five tables.
        The ON CONFLICT for shodan_services updates product AND version so
        version-change detection sees the latest state on the *next* scan
        rather than re-alerting on the same change forever.
        """
        now = datetime.now(timezone.utc).isoformat()
        target_id = self._get_target_id(domain)
        if target_id is None:
            return

        with sqlite3.connect(self._path) as con:
            # Subdomains
            for sub in subdomains:
                con.execute(
                    """
                    INSERT INTO subdomains (target_id, subdomain, first_seen, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(target_id, subdomain)
                        DO UPDATE SET last_seen = excluded.last_seen
                    """,
                    (target_id, sub, now, now),
                )

            if sd is not None:
                # IPs
                for ip in sd.ips:
                    con.execute(
                        """
                        INSERT INTO shodan_ips (target_id, ip, first_seen, last_seen)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(target_id, ip)
                            DO UPDATE SET last_seen = excluded.last_seen
                        """,
                        (target_id, ip, now, now),
                    )

                # Services — advance product+version on conflict so the baseline
                # reflects the current state after each alert fires once.
                for svc in sd.services:
                    con.execute(
                        """
                        INSERT INTO shodan_services
                            (target_id, ip, port, proto, product, version, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(target_id, ip, port, proto)
                            DO UPDATE SET
                                product   = excluded.product,
                                version   = excluded.version,
                                last_seen = excluded.last_seen
                        """,
                        (
                            target_id,
                            svc["ip"],
                            svc["port"],
                            svc["proto"],
                            svc.get("product", ""),
                            svc.get("version", ""),
                            now,
                            now,
                        ),
                    )

                # CVEs
                for cve in sd.vulns:
                    con.execute(
                        """
                        INSERT INTO shodan_vulns (target_id, cve, first_seen, last_seen)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(target_id, cve)
                            DO UPDATE SET last_seen = excluded.last_seen
                        """,
                        (target_id, cve, now, now),
                    )

            con.execute(
                "UPDATE targets SET last_scanned = ? WHERE id = ?", (now, target_id)
            )
            con.commit()

    async def full_upsert(
        self, domain: str, subdomains: list[str], sd: Optional[ShodanResult]
    ) -> None:
        """Upsert all baseline data and update last_scanned in a single DB transaction."""
        await asyncio.to_thread(self._full_upsert, domain, subdomains, sd)


# ---------------------------------------------------------------------------
# Diff builder
# ---------------------------------------------------------------------------


def _build_diff(
    current_subs: list[str],
    baseline_subs: set[str],
    sd: Optional[ShodanResult],
    ip_baseline: set[str],
    svc_baseline: dict[tuple[str, int, str], dict],
    vuln_baseline: set[str],
) -> ScanDiff:
    """
    Compute the full diff between current scan results and stored baselines.

    Shodan diffs (IPs, services, version changes, CVEs) are skipped when *sd*
    is None — either SHODAN_API_KEY is unset or the lookup failed.  Subdomain
    diffing always runs regardless.

    Service diffing uses two separate checks on the same svc_baseline dict:
      • Key absent  → new service
      • Key present, product+version changed → version change
    This avoids a separate SQL query for version detection.
    """
    diff = ScanDiff()

    # ── Subdomain diff ────────────────────────────────────────────────────────
    diff.new_subs = sorted(set(current_subs) - baseline_subs)

    if sd is None:
        return diff

    # ── IP diff ───────────────────────────────────────────────────────────────
    diff.new_ips = sorted(set(sd.ips) - ip_baseline)

    # ── Service diff — split into new services vs version changes ─────────────
    for svc in sd.services:
        key: tuple[str, int, str] = (svc["ip"], svc["port"], svc["proto"])
        stored = svc_baseline.get(key)
        if stored is None:
            diff.new_services.append(svc)
        else:
            old_ver = f"{stored['product']} {stored['version']}".strip()
            new_ver = f"{svc.get('product', '')} {svc.get('version', '')}".strip()
            if new_ver and old_ver != new_ver:
                diff.changed_versions.append(
                    {
                        "ip": svc["ip"],
                        "port": svc["port"],
                        "proto": svc["proto"],
                        "old": old_ver or "(unknown)",
                        "new": new_ver,
                    }
                )

    # ── CVE diff ──────────────────────────────────────────────────────────────
    diff.new_cves = sorted(set(sd.vulns) - vuln_baseline)

    return diff


# ---------------------------------------------------------------------------
# Embed builders
# ---------------------------------------------------------------------------

_FOOTER = "Root AI • Phase 5 Bug Bounty Watchdog  |  Authorised use only"
_FIELD_LIMIT = 1020  # Discord field values cap at 1024 — leave a 4-char buffer


def _truncate_field(lines: list[str], limit: int = _FIELD_LIMIT) -> str:
    """Join *lines* and truncate to *limit* chars on a whole-line boundary."""
    text = "\n".join(lines)
    if len(text) <= limit:
        return text
    truncated = text[:limit]
    last_nl = truncated.rfind("\n")
    if last_nl > 0:
        truncated = truncated[:last_nl]
    return truncated + "\n`…`"


def _build_baseline_embed(
    domain: str,
    sub_count: int,
    ip_count: int,
    service_count: int,
    cve_count: int,
) -> discord.Embed:
    """Embed posted on the very first scan of a newly tracked domain."""
    embed = discord.Embed(
        title=f"📋 Watchdog Baseline Established — `{domain}`",
        description=(
            "First scan complete. Baseline recorded — future scans will diff against this snapshot.\n\n"
            "Run `/recon` or `/autopwn` to investigate further."
        ),
        color=discord.Color.blurple(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="📊 Baseline Snapshot",
        value=(
            f"Subdomains: **{sub_count}**\n"
            f"Shodan IPs: **{ip_count}**\n"
            f"Open services: **{service_count}**\n"
            f"Known CVEs: **{cve_count}**"
        ),
        inline=False,
    )
    embed.set_footer(text=_FOOTER)
    return embed


def _build_alert_embed(
    domain: str,
    diff: ScanDiff,
    enriched_cves: list[CVEDetail] | None = None,
) -> discord.Embed:
    """Alert embed posted to WATCHDOG_CHANNEL_ID when new assets are detected."""
    change_count = (
        len(diff.new_subs)
        + len(diff.new_ips)
        + len(diff.new_services)
        + len(diff.changed_versions)
        + len(diff.new_cves)
    )
    embed = discord.Embed(
        title=f"🚨 Watchdog Alert — `{domain}`",
        description=(
            f"**{change_count}** change(s) detected during routine scan.\n"
            "Run `/recon` or `/autopwn` to investigate."
        ),
        color=discord.Color.from_rgb(255, 80, 0),
        timestamp=datetime.now(timezone.utc),
    )

    if diff.new_subs:
        lines = [f"`{s}`" for s in diff.new_subs[:40]]
        if len(diff.new_subs) > 40:
            lines.append(f"`... +{len(diff.new_subs) - 40} more`")
        embed.add_field(
            name=f"🌐 New Subdomains ({len(diff.new_subs)})",
            value=_truncate_field(lines),
            inline=False,
        )

    if diff.new_ips:
        lines = [f"`{ip}`" for ip in diff.new_ips]
        embed.add_field(
            name=f"🖥️ New IPs ({len(diff.new_ips)})",
            value=_truncate_field(lines),
            inline=False,
        )

    if diff.new_services:
        lines = []
        for svc in diff.new_services[:20]:
            line = f"`{svc['ip']}:{svc['port']}/{svc['proto']}`"
            ver = f"{svc.get('product', '')} {svc.get('version', '')}".strip()
            if ver:
                line += f" — {ver}"
            lines.append(line)
        if len(diff.new_services) > 20:
            lines.append(f"`... +{len(diff.new_services) - 20} more`")
        embed.add_field(
            name=f"🔓 New Services ({len(diff.new_services)})",
            value=_truncate_field(lines),
            inline=False,
        )

    if diff.changed_versions:
        lines = []
        for vc in diff.changed_versions[:10]:
            lines.append(
                f"`{vc['ip']}:{vc['port']}/{vc['proto']}` `{vc['old']}` → `{vc['new']}`"
            )
        if len(diff.changed_versions) > 10:
            lines.append(f"`... +{len(diff.changed_versions) - 10} more`")
        embed.add_field(
            name=f"🔄 Version Changes ({len(diff.changed_versions)})",
            value=_truncate_field(lines),
            inline=False,
        )

    if diff.new_cves:
        if enriched_cves:
            enriched_ids = {d.cve_id for d in enriched_cves}
            lines: list[str] = []
            for detail in enriched_cves:
                score_str = f"{detail.score:.1f}" if detail.score is not None else "N/A"
                desc = detail.description[:120]
                lines.append(
                    f"`{detail.cve_id}` [{detail.severity} {score_str}]: {desc}"
                )
            unenriched = [c for c in diff.new_cves if c not in enriched_ids]
            if unenriched:
                lines.append("Also reported: " + ", ".join(f"`{c}`" for c in unenriched[:10]))
        else:
            lines = [f"`{cve}`" for cve in diff.new_cves[:15]]
            if len(diff.new_cves) > 15:
                lines.append(f"`... +{len(diff.new_cves) - 15} more`")
        embed.add_field(
            name=f"⚠️ New CVEs ({len(diff.new_cves)})",
            value=_truncate_field(lines),
            inline=False,
        )

    embed.set_footer(text=_FOOTER)
    return embed


def _build_scan_embed(
    domain: str,
    diff: ScanDiff,
    current_sub_count: int,
    baseline_sub_count: int,
    enriched_cves: list[CVEDetail] | None = None,
) -> discord.Embed:
    """Ephemeral embed returned to the user for an on-demand /watchdog scan."""
    has_changes = diff.has_changes
    color = discord.Color.from_rgb(220, 50, 50) if has_changes else discord.Color.green()
    new_count = (
        len(diff.new_subs)
        + len(diff.new_ips)
        + len(diff.new_services)
        + len(diff.changed_versions)
        + len(diff.new_cves)
    )
    title = (
        f"🔍 Watchdog Scan — `{domain}` — {new_count} new"
        if has_changes
        else f"✅ Watchdog Scan — `{domain}` — No new assets"
    )
    embed = discord.Embed(title=title, color=color, timestamp=datetime.now(timezone.utc))

    embed.add_field(
        name="📊 Stats",
        value=(
            f"Current subdomains: **{current_sub_count}**\n"
            f"Prior baseline: **{baseline_sub_count}**\n"
            f"New: subs **{len(diff.new_subs)}** | "
            f"IPs **{len(diff.new_ips)}** | "
            f"SVCs **{len(diff.new_services)}** | "
            f"CVEs **{len(diff.new_cves)}**"
        ),
        inline=False,
    )

    if diff.new_subs:
        lines = [f"`{s}`" for s in diff.new_subs[:30]]
        if len(diff.new_subs) > 30:
            lines.append(f"`... +{len(diff.new_subs) - 30} more`")
        embed.add_field(
            name=f"🚨 New Subdomains ({len(diff.new_subs)})",
            value=_truncate_field(lines),
            inline=False,
        )

    if diff.new_ips:
        embed.add_field(
            name=f"🖥️ New IPs ({len(diff.new_ips)})",
            value=_truncate_field([f"`{ip}`" for ip in diff.new_ips]),
            inline=False,
        )

    if diff.new_services:
        lines = []
        for svc in diff.new_services[:10]:
            line = f"`{svc['ip']}:{svc['port']}/{svc['proto']}`"
            ver = f"{svc.get('product', '')} {svc.get('version', '')}".strip()
            if ver:
                line += f" — {ver}"
            lines.append(line)
        if len(diff.new_services) > 10:
            lines.append(f"`... +{len(diff.new_services) - 10} more`")
        embed.add_field(
            name=f"🔓 New Services ({len(diff.new_services)})",
            value=_truncate_field(lines),
            inline=False,
        )

    if diff.changed_versions:
        lines = [
            f"`{vc['ip']}:{vc['port']}/{vc['proto']}` `{vc['old']}` → `{vc['new']}`"
            for vc in diff.changed_versions[:5]
        ]
        if len(diff.changed_versions) > 5:
            lines.append(f"`... +{len(diff.changed_versions) - 5} more`")
        embed.add_field(
            name=f"🔄 Version Changes ({len(diff.changed_versions)})",
            value=_truncate_field(lines),
            inline=False,
        )

    if diff.new_cves:
        if enriched_cves:
            enriched_ids = {d.cve_id for d in enriched_cves}
            cve_lines: list[str] = []
            for detail in enriched_cves:
                score_str = f"{detail.score:.1f}" if detail.score is not None else "N/A"
                desc = detail.description[:120]
                cve_lines.append(
                    f"`{detail.cve_id}` [{detail.severity} {score_str}]: {desc}"
                )
            unenriched = [c for c in diff.new_cves if c not in enriched_ids]
            if unenriched:
                cve_lines.append("Also reported: " + ", ".join(f"`{c}`" for c in unenriched[:10]))
        else:
            cve_lines = [f"`{cve}`" for cve in diff.new_cves[:10]]
            if len(diff.new_cves) > 10:
                cve_lines.append(f"`... +{len(diff.new_cves) - 10} more`")
        embed.add_field(
            name=f"⚠️ New CVEs ({len(diff.new_cves)})",
            value=_truncate_field(cve_lines),
            inline=False,
        )

    embed.set_footer(text="Root AI • Phase 5 Bug Bounty Watchdog")
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class WatchdogCog(commands.Cog, name="Watchdog"):
    """
    Phase 5 — Bug Bounty Watchdog.

    Tracks a set of target domains, periodically rescans them using free
    open-source tools (crt.sh, subfinder, assetfinder) and Shodan host intel,
    then alerts to Discord when new subdomains, IPs, services, version changes,
    or CVEs appear.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.db = WatchdogDB(WATCHDOG_DB_PATH)
        self._watchdog_loop.change_interval(hours=WATCHDOG_INTERVAL_HOURS)

    async def cog_load(self) -> None:
        await self.db.init()
        self._watchdog_loop.start()
        log.info(
            "Watchdog started — interval: %d h, DB: %s",
            WATCHDOG_INTERVAL_HOURS,
            WATCHDOG_DB_PATH,
        )

    async def cog_unload(self) -> None:
        self._watchdog_loop.cancel()

    # ── Background task ───────────────────────────────────────────────────────

    @tasks.loop(hours=6)  # interval overridden in __init__ via change_interval
    async def _watchdog_loop(self) -> None:
        """Periodically scan all tracked targets and alert on new assets."""
        targets = await self.db.list_targets()
        if not targets:
            return
        log.info("Watchdog loop: scanning %d target(s)", len(targets))
        for t in targets:
            await self._scan_and_alert(t["domain"], t["channel_id"], interactive=False)

    @_watchdog_loop.before_loop
    async def _before_watchdog(self) -> None:
        await self.bot.wait_until_ready()

    # ── Shared scan logic ─────────────────────────────────────────────────────

    async def _scan_and_alert(
        self,
        domain: str,
        channel_id: int,
        *,
        interactive: bool = False,
        interaction: Optional[discord.Interaction] = None,
    ) -> None:
        """
        Scan *domain*, diff against baseline, and post results.

        First-scan behaviour (last_scanned IS NULL):
          Posts a "baseline established" embed — no diff alert — to avoid
          flooding the channel when a domain is first added.

        Subsequent scan behaviour:
          - Background: posts alert to channel_id only when diff.has_changes.
          - Interactive: always replies to the slash command interaction (ephemeral).

        Both gather_subdomains and _shodan_host_info run concurrently.
        Shodan failure is non-fatal — subdomain diffing continues regardless.

        IMPORTANT: first-scan detection reads last_scanned BEFORE any upsert
        so that adding and immediately scanning a domain behaves correctly.
        """
        log.info("Watchdog scanning: %s", domain)

        # ── Detect first scan BEFORE any upsert ──────────────────────────────
        last_scanned = await self.db.get_target_last_scanned(domain)
        is_first_scan = last_scanned is None

        # ── Fetch all baselines concurrently ──────────────────────────────────
        baseline_subs, ip_baseline, svc_baseline, vuln_baseline = await asyncio.gather(
            self.db.get_baseline(domain),
            self.db.get_shodan_ip_baseline(domain),
            self.db.get_shodan_service_baseline(domain),
            self.db.get_vuln_baseline(domain),
        )

        # ── Run recon tools concurrently ──────────────────────────────────────
        gather_result, shodan_result = await asyncio.gather(
            gather_subdomains(domain),
            _shodan_host_info(domain),
            return_exceptions=True,
        )

        if isinstance(gather_result, Exception):
            log.error(
                "Watchdog: gather_subdomains failed for %s: %s", domain, gather_result
            )
            if interactive and interaction:
                await interaction.followup.send(
                    f"⚠️ Subdomain scan failed for `{domain}`: {gather_result}",
                    ephemeral=True,
                )
            return

        current_subs: list[str] = gather_result  # type: ignore[assignment]

        sd: Optional[ShodanResult] = None
        if isinstance(shodan_result, Exception):
            log.warning("Watchdog: Shodan failed for %s: %s", domain, shodan_result)
        else:
            sd = shodan_result  # type: ignore[assignment]

        # ── Compute diff BEFORE upserting ─────────────────────────────────────
        diff = _build_diff(
            current_subs=current_subs,
            baseline_subs=baseline_subs,
            sd=sd,
            ip_baseline=ip_baseline,
            svc_baseline=svc_baseline,
            vuln_baseline=vuln_baseline,
        )

        # ── Upsert new baseline (includes last_scanned stamp) ─────────────────
        await self.db.full_upsert(domain, current_subs, sd)

        # ── First scan → baseline embed only (no diff, skip NVD enrichment) ───
        if is_first_scan:
            ip_count = len(sd.ips) if sd else 0
            svc_count = len(sd.services) if sd else 0
            cve_count = len(sd.vulns) if sd else 0
            embed = _build_baseline_embed(
                domain,
                sub_count=len(current_subs),
                ip_count=ip_count,
                service_count=svc_count,
                cve_count=cve_count,
            )
            if interactive and interaction:
                await interaction.followup.send(embed=embed, ephemeral=True)
            else:
                channel = self.bot.get_channel(channel_id)
                if channel:
                    await channel.send(embed=embed)  # type: ignore[union-attr]
            log.info(
                "Watchdog: baseline for %s — %d subs, %d IPs, %d svcs, %d CVEs",
                domain, len(current_subs), ip_count, svc_count, cve_count,
            )
            return

        # ── Enrich new CVEs via NVD (capped at 5; ~32s at free-tier rate) ─────
        # Runs only on subsequent scans — baseline embeds show counts, not IDs.
        enriched_cves: list[CVEDetail] = []
        if diff.new_cves:
            log.info(
                "Watchdog: enriching %d new CVE(s) via NVD for %s",
                min(len(diff.new_cves), 5),
                domain,
            )
            enriched_cves = await enrich_cves(diff.new_cves)

        # ── Interactive: always reply with scan embed ─────────────────────────
        if interactive and interaction:
            embed = _build_scan_embed(
                domain,
                diff=diff,
                current_sub_count=len(current_subs),
                baseline_sub_count=len(baseline_subs),
                enriched_cves=enriched_cves or None,
            )
            await interaction.followup.send(embed=embed, ephemeral=True)

        # ── Background: alert to channel only if changes found ────────────────
        if not interactive and diff.has_changes:
            channel = self.bot.get_channel(channel_id)
            if channel is None:
                log.warning(
                    "Watchdog: channel %d not found for %s", channel_id, domain
                )
                return
            embed = _build_alert_embed(domain, diff, enriched_cves=enriched_cves or None)
            await channel.send(embed=embed)  # type: ignore[union-attr]
            log.info(
                "Watchdog: %s — alerted %d new_subs, %d new_ips, %d new_svcs, "
                "%d ver_changes, %d new_cves",
                domain,
                len(diff.new_subs),
                len(diff.new_ips),
                len(diff.new_services),
                len(diff.changed_versions),
                len(diff.new_cves),
            )

    # ── Slash command group ───────────────────────────────────────────────────

    watchdog = app_commands.Group(
        name="watchdog",
        description="[OWNER] Bug bounty asset watchdog — track and monitor target domains.",
    )

    @watchdog.command(name="add", description="[OWNER] Add a domain to the watchdog.")
    @app_commands.describe(domain="Target domain to monitor (e.g. example.com)")
    async def watchdog_add(self, interaction: discord.Interaction, domain: str) -> None:
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/watchdog` is an owner-only command.", ephemeral=True
            )
            return

        valid, result = _validate_domain(domain)
        if not valid:
            await interaction.response.send_message(f"⚠️ {result}", ephemeral=True)
            return
        clean_domain: str = result

        channel_id = WATCHDOG_CHANNEL_ID or interaction.channel_id or 0
        inserted = await self.db.add_target(clean_domain, channel_id)
        if inserted:
            await interaction.response.send_message(
                f"✅ `{clean_domain}` added to watchdog.\n"
                f"Alerts will post to <#{channel_id}>.\n"
                f"First scan will run within **{WATCHDOG_INTERVAL_HOURS} h**.",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                f"ℹ️ `{clean_domain}` is already tracked.", ephemeral=True
            )

    @watchdog.command(name="remove", description="[OWNER] Remove a domain from the watchdog.")
    @app_commands.describe(domain="Target domain to stop monitoring")
    async def watchdog_remove(self, interaction: discord.Interaction, domain: str) -> None:
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/watchdog` is an owner-only command.", ephemeral=True
            )
            return

        valid, result = _validate_domain(domain)
        clean_domain = result if valid else domain.strip().lower()

        removed = await self.db.remove_target(clean_domain)
        if removed:
            await interaction.response.send_message(
                f"🗑️ `{clean_domain}` removed from watchdog (baseline cleared).",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                f"⚠️ `{clean_domain}` was not in the watchdog.", ephemeral=True
            )

    @watchdog.command(name="list", description="[OWNER] List all tracked watchdog targets.")
    async def watchdog_list(self, interaction: discord.Interaction) -> None:
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/watchdog` is an owner-only command.", ephemeral=True
            )
            return

        targets = await self.db.list_targets()
        if not targets:
            await interaction.response.send_message(
                "📭 No targets currently tracked. Use `/watchdog add <domain>` to start.",
                ephemeral=True,
            )
            return

        embed = discord.Embed(
            title="🎯 Watchdog Targets",
            description=(
                f"Scanning every **{WATCHDOG_INTERVAL_HOURS} h** via "
                "crt.sh + subfinder + assetfinder + Shodan."
            ),
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )
        for t in targets:
            last = t["last_scanned"] or "Never"
            if last != "Never" and "T" in last:
                last = last[:19].replace("T", " ") + " UTC"
            embed.add_field(
                name=f"`{t['domain']}`",
                value=f"Last scanned: {last}\nAlert channel: <#{t['channel_id']}>",
                inline=False,
            )
        embed.set_footer(text=f"Root AI • Phase 5 Watchdog  |  {len(targets)} target(s)")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @watchdog.command(name="scan", description="[OWNER] Immediately scan a tracked domain.")
    @app_commands.describe(domain="Domain to scan right now")
    async def watchdog_scan(self, interaction: discord.Interaction, domain: str) -> None:
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/watchdog` is an owner-only command.", ephemeral=True
            )
            return

        valid, result = _validate_domain(domain)
        if not valid:
            await interaction.response.send_message(f"⚠️ {result}", ephemeral=True)
            return
        clean_domain: str = result

        targets = await self.db.list_targets()
        tracked_domains = {t["domain"] for t in targets}
        if clean_domain not in tracked_domains:
            await interaction.response.send_message(
                f"⚠️ `{clean_domain}` is not in the watchdog. "
                "Add it first with `/watchdog add`.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(thinking=True, ephemeral=True)
        channel_id = next(t["channel_id"] for t in targets if t["domain"] == clean_domain)
        await self._scan_and_alert(
            clean_domain,
            channel_id,
            interactive=True,
            interaction=interaction,
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(WatchdogCog(bot))
