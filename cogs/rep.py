"""
cogs/rep.py
Community Rep System — prefix commands for giving and tracking reputation points.

Commands
--------
.rep @user       — Give one reputation point to a member (24-hour cooldown per giver)
.myrep           — Show your own reputation count
.leaderboard     — Show the top 10 most-reputed community members (alias: .top)

Design notes
------------
* All disk access is serialised through a single ``asyncio.Lock`` to prevent
  concurrent read/write races on the JSON file.
* File I/O is offloaded to a thread pool via ``asyncio.to_thread`` so the event
  loop is never blocked.
* The 24-hour cooldown is per-giver (one rep given every 24 h, regardless of target).
* Auto-role thresholds are not implemented; this is a pure point tracker.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import discord
from discord.ext import commands

log = logging.getLogger("root_ai.rep")

# ---------------------------------------------------------------------------
# Persistence paths
# ---------------------------------------------------------------------------

DATA_DIR = Path("data")
REP_FILE = DATA_DIR / "rep.json"

REP_COOLDOWN_HOURS: int = 24


# ---------------------------------------------------------------------------
# Blocking file-I/O helpers (executed in thread pool via asyncio.to_thread)
# ---------------------------------------------------------------------------


def _load_rep_data() -> dict:
    """Load rep data from disk.  Returns a fresh empty structure if the file is missing."""
    if not REP_FILE.exists():
        return {"rep_counts": {}, "last_given": {}}
    with REP_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_rep_data(data: dict) -> None:
    """Persist rep data to disk, ensuring the data directory exists."""
    DATA_DIR.mkdir(exist_ok=True)
    with REP_FILE.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class RepCog(commands.Cog, name="Rep"):
    """
    Community reputation system driven entirely by prefix commands.

    Not wired into the LLM tool registry — rep actions are always explicit,
    user-initiated commands rather than AI-inferred operations.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._lock: asyncio.Lock = asyncio.Lock()

    async def cog_load(self) -> None:
        """Ensure the data directory and file exist before any command runs."""
        DATA_DIR.mkdir(exist_ok=True)
        if not REP_FILE.exists():
            await asyncio.to_thread(_save_rep_data, {"rep_counts": {}, "last_given": {}})
        log.info("RepCog loaded — data file: %s", REP_FILE.resolve())

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    @commands.command(name="rep")
    async def give_rep(self, ctx: commands.Context, member: discord.Member) -> None:
        """Give one reputation point to a community member. One per 24 hours."""
        giver_id = str(ctx.author.id)
        target_id = str(member.id)

        # No self-rep
        if giver_id == target_id:
            await ctx.reply("🚫 You cannot give rep to yourself.")
            return

        async with self._lock:
            data = await asyncio.to_thread(_load_rep_data)

            # Cooldown check — has this user given rep in the last 24 hours?
            last_str: str | None = data["last_given"].get(giver_id)
            if last_str:
                last_dt = datetime.fromisoformat(last_str)
                elapsed = datetime.now(timezone.utc) - last_dt
                if elapsed < timedelta(hours=REP_COOLDOWN_HOURS):
                    remaining = timedelta(hours=REP_COOLDOWN_HOURS) - elapsed
                    hours, rem = divmod(int(remaining.total_seconds()), 3600)
                    minutes = rem // 60
                    await ctx.reply(
                        f"⏳ You can give rep again in **{hours}h {minutes}m**."
                    )
                    return

            # Credit the target and stamp the giver's last-given time
            data["rep_counts"][target_id] = data["rep_counts"].get(target_id, 0) + 1
            data["last_given"][giver_id] = datetime.now(timezone.utc).isoformat()

            await asyncio.to_thread(_save_rep_data, data)

        new_total: int = data["rep_counts"][target_id]
        log.info("Rep given: %s → %s (new total: %d)", ctx.author, member, new_total)
        await ctx.reply(
            f"⭐ {ctx.author.mention} gave rep to {member.mention}! "
            f"They now have **{new_total}** rep."
        )

    @commands.command(name="myrep")
    async def my_rep(self, ctx: commands.Context) -> None:
        """Display your current reputation count."""
        user_id = str(ctx.author.id)

        async with self._lock:
            data = await asyncio.to_thread(_load_rep_data)

        rep: int = data["rep_counts"].get(user_id, 0)
        s = "" if rep == 1 else "s"
        await ctx.reply(f"⭐ You have **{rep}** reputation point{s}.")

    @commands.command(name="leaderboard", aliases=["top"])
    async def leaderboard(self, ctx: commands.Context) -> None:
        """Show the top 10 community members by reputation."""
        async with self._lock:
            data = await asyncio.to_thread(_load_rep_data)

        rep_counts: dict = data.get("rep_counts", {})
        if not rep_counts:
            await ctx.reply(
                "📭 No reputation data yet — start giving rep with `.rep @user`!"
            )
            return

        top_ten = sorted(rep_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        medals = ["🥇", "🥈", "🥉"]
        lines = []
        for i, (uid, points) in enumerate(top_ten):
            prefix = medals[i] if i < 3 else f"**{i + 1}.**"
            lines.append(f"{prefix} <@{uid}> — **{points}** rep")

        embed = discord.Embed(
            title="🏆 Rep Leaderboard — Top 10",
            description="\n".join(lines),
            color=discord.Color.gold(),
        )
        embed.set_footer(text="Give rep with .rep @user")
        await ctx.send(embed=embed)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @give_rep.error
    async def give_rep_error(self, ctx: commands.Context, error: Exception) -> None:
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.reply("Usage: `.rep @user`")
        elif isinstance(error, commands.MemberNotFound):
            await ctx.reply("❌ User not found. Mention a valid server member.")
        else:
            log.exception("Unexpected error in .rep command")
            await ctx.reply(f"An error occurred: {error}")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(RepCog(bot))
