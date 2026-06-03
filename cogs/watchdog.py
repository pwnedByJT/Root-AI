"""
cogs/watchdog.py
Phase 5 — Bug Bounty Watchdog (Persistent Asset Monitor)

Slash commands: /watchdog add <domain>
                /watchdog remove <domain>
                /watchdog list
                /watchdog scan <domain>

Background task (tasks.loop):
  - Runs every WATCHDOG_INTERVAL_HOURS (default 6 h).
  - For every tracked target: runs gather_subdomains() (crt.sh + subfinder + assetfinder).
  - Diffs current results against the stored baseline in SQLite.
  - POSTs a Discord embed to WATCHDOG_CHANNEL_ID when new subdomains are found.
  - Updates the baseline after a successful alert so repeats are suppressed.

Storage:
  - Local SQLite at WATCHDOG_DB_PATH (default data/watchdog.db).
  - Two tables: targets, subdomains.
  - All DB I/O is wrapped in asyncio.to_thread() — no blocking the event loop.

Security boundaries:
  - All /watchdog subcommands are gated to BOT_OWNER_ID.
  - Domain input re-uses recon.py's _validate_domain() — same FQDN regex + private-range guard.
  - No outbound connections beyond what gather_subdomains() already makes.

Tool requirements on Parrot OS:
  - subfinder   (https://github.com/projectdiscovery/subfinder)
  - assetfinder (https://github.com/tomnomnom/assetfinder)
  Both are free / open-source. Graceful degradation if either is missing.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands, tasks

from config import BOT_OWNER_ID, WATCHDOG_CHANNEL_ID, WATCHDOG_DB_PATH, WATCHDOG_INTERVAL_HOURS
from cogs.recon import _validate_domain, gather_subdomains

log = logging.getLogger("root_ai.watchdog")

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
            con.commit()

    async def init(self) -> None:
        await asyncio.to_thread(self._init_db)

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
        """Delete a target (cascade removes its subdomains); return True if found."""
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

    # ── Subdomains / baseline ─────────────────────────────────────────────────

    def _get_baseline(self, domain: str) -> set[str]:
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
        return await asyncio.to_thread(self._get_baseline, domain)

    def _upsert_subdomains(self, domain: str, subdomains: list[str]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._path) as con:
            row = con.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
            if row is None:
                return
            target_id = row[0]
            for sub in subdomains:
                con.execute(
                    """
                    INSERT INTO subdomains (target_id, subdomain, first_seen, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(target_id, subdomain) DO UPDATE SET last_seen = excluded.last_seen
                    """,
                    (target_id, sub, now, now),
                )
            con.execute(
                "UPDATE targets SET last_scanned = ? WHERE id = ?",
                (now, target_id),
            )
            con.commit()

    async def upsert_subdomains(self, domain: str, subdomains: list[str]) -> None:
        await asyncio.to_thread(self._upsert_subdomains, domain, subdomains)


# ---------------------------------------------------------------------------
# Alert embed builder
# ---------------------------------------------------------------------------


def _build_alert_embed(domain: str, new_subs: list[str], total_known: int) -> discord.Embed:
    embed = discord.Embed(
        title=f"🚨 New Assets Detected — `{domain}`",
        description=(
            f"**{len(new_subs)}** new subdomain(s) discovered during routine watchdog scan.\n"
            f"Total tracked baseline: **{total_known}** subdomains.\n\n"
            "Run `/recon` or `/autopwn` to investigate."
        ),
        color=discord.Color.from_rgb(255, 80, 0),
        timestamp=datetime.now(timezone.utc),
    )
    sub_text = "\n".join(f"`{s}`" for s in new_subs[:40])
    if len(new_subs) > 40:
        sub_text += f"\n`... +{len(new_subs) - 40} more`"
    embed.add_field(name="🌐 New Subdomains", value=sub_text[:1020], inline=False)
    embed.set_footer(text="Root AI • Phase 5 Bug Bounty Watchdog  |  Authorised use only")
    return embed


def _build_scan_embed(domain: str, current: list[str], new_subs: list[str], baseline_size: int) -> discord.Embed:
    """Embed for the on-demand /watchdog scan result (ephemeral)."""
    color = discord.Color.from_rgb(220, 50, 50) if new_subs else discord.Color.green()
    title = (
        f"🔍 Watchdog Scan — `{domain}` — {len(new_subs)} new"
        if new_subs
        else f"✅ Watchdog Scan — `{domain}` — No new assets"
    )
    embed = discord.Embed(
        title=title,
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="📊 Stats",
        value=(
            f"Current scan: **{len(current)}** subdomains\n"
            f"Prior baseline: **{baseline_size}** subdomains\n"
            f"New this scan: **{len(new_subs)}**"
        ),
        inline=False,
    )
    if new_subs:
        sub_text = "\n".join(f"`{s}`" for s in new_subs[:30])
        if len(new_subs) > 30:
            sub_text += f"\n`... +{len(new_subs) - 30} more`"
        embed.add_field(name="🚨 New Subdomains", value=sub_text[:1020], inline=False)
    embed.set_footer(text="Root AI • Phase 5 Bug Bounty Watchdog")
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class WatchdogCog(commands.Cog, name="Watchdog"):
    """
    Phase 5 — Bug Bounty Watchdog.

    Tracks a set of target domains, periodically rescans them using free
    open-source tools (crt.sh, subfinder, assetfinder), and alerts to Discord
    when new subdomains appear.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.db = WatchdogDB(WATCHDOG_DB_PATH)
        self._watchdog_loop.change_interval(hours=WATCHDOG_INTERVAL_HOURS)

    async def cog_load(self) -> None:
        await self.db.init()
        self._watchdog_loop.start()
        log.info("Watchdog started — interval: %d h, DB: %s", WATCHDOG_INTERVAL_HOURS, WATCHDOG_DB_PATH)

    async def cog_unload(self) -> None:
        self._watchdog_loop.cancel()

    # ── Background task ───────────────────────────────────────────────────────

    @tasks.loop(hours=6)  # interval overridden in __init__ via change_interval
    async def _watchdog_loop(self) -> None:
        """Periodically scan all tracked targets and alert on new subdomains."""
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
        Scan *domain*, diff against baseline, alert if new subdomains found.

        If *interactive* is True and *interaction* is provided, the result is
        sent as an ephemeral followup to the slash command interaction.
        Otherwise the result is posted to *channel_id* (background mode).
        """
        log.info("Watchdog scanning: %s", domain)
        try:
            current = await gather_subdomains(domain)
        except Exception as exc:  # pylint: disable=broad-except
            log.error("Watchdog: gather_subdomains failed for %s: %s", domain, exc)
            if interactive and interaction:
                await interaction.followup.send(
                    f"⚠️ Scan failed for `{domain}`: {exc}", ephemeral=True
                )
            return

        baseline = await self.db.get_baseline(domain)
        new_subs = sorted(set(current) - baseline)

        if interactive and interaction:
            embed = _build_scan_embed(domain, current, new_subs, len(baseline))
            await interaction.followup.send(embed=embed, ephemeral=True)

        # Always update the baseline (upsert new + refresh last_seen)
        await self.db.upsert_subdomains(domain, current)

        # Post alert to watch channel only for background scans with new findings
        if not interactive and new_subs:
            channel = self.bot.get_channel(channel_id)
            if channel is None:
                log.warning("Watchdog: channel %d not found for %s", channel_id, domain)
                return
            embed = _build_alert_embed(domain, new_subs, len(current))
            await channel.send(embed=embed)  # type: ignore[union-attr]
            log.info("Watchdog: alerted %d new subdomains for %s", len(new_subs), domain)

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
            description=f"Scanning every **{WATCHDOG_INTERVAL_HOURS} h** via crt.sh + subfinder + assetfinder.",
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )
        for t in targets:
            last = t["last_scanned"] or "Never"
            # Truncate ISO timestamp to readable date+time
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

        # Verify target is tracked
        targets = await self.db.list_targets()
        tracked_domains = {t["domain"] for t in targets}
        if clean_domain not in tracked_domains:
            await interaction.response.send_message(
                f"⚠️ `{clean_domain}` is not in the watchdog. Add it first with `/watchdog add`.",
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
