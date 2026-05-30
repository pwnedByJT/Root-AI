"""
cogs/rep.py
Community Rep System — slash commands for giving and tracking reputation points.

Commands
--------
/rep @user       — Give one reputation point to a member (24-hour cooldown per giver)
/myrep           — Show your own reputation count
/leaderboard     — Show the top 10 most-reputed community members
/top             — Alias for /leaderboard

Design notes
------------
* All disk access is serialised through the shared module-level lock from
  ``services.storage`` so that ``cogs/shop.py`` (which writes cooldown waivers
  into the same file) never races with this cog.
* File I/O is offloaded to a thread pool via ``asyncio.to_thread`` so the event
  loop is never blocked.
* The 24-hour cooldown is per-giver (one rep given every 24 h, regardless of target).
* Cooldown waivers: if the buyer's ID appears in ``data["cooldown_waivers"]``, the
  cooldown check is skipped and that entry is consumed (removed) atomically within
  the same lock acquisition.
* /leaderboard and /top are separate app_commands entries pointing to a shared
  implementation — app_commands has no aliases concept.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands
from discord.ext import commands

from services.storage import init_rep_file, load_rep_data, rep_lock, save_rep_data

log = logging.getLogger("root_ai.rep")

REP_COOLDOWN_HOURS: int = 24


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class RepCog(commands.Cog, name="Rep"):
    """
    Community reputation system driven entirely by slash commands.

    Not wired into the LLM tool registry — rep actions are always explicit,
    user-initiated commands rather than AI-inferred operations.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        """Ensure the data directory and rep file exist before any command runs."""
        from services.storage import REP_FILE  # noqa: PLC0415

        await init_rep_file()
        log.info("RepCog loaded — data file: %s", REP_FILE.resolve())

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    @app_commands.command(name="rep", description="Give one reputation point to a community member (24-hour cooldown).")
    async def give_rep(self, interaction: discord.Interaction, member: discord.Member) -> None:
        """Give one reputation point to a community member. One per 24 hours."""
        # Defer so we have time for lock + I/O without hitting Discord's 3-second ack limit
        await interaction.response.defer()

        giver_id = str(interaction.user.id)
        target_id = str(member.id)

        # No self-rep
        if giver_id == target_id:
            await interaction.followup.send("🚫 You cannot give rep to yourself.")
            return

        try:
            async with rep_lock():
                data = await load_rep_data()

                # Cooldown check — skip if a waiver token is present for this user
                waivers: list = data.setdefault("cooldown_waivers", [])
                if giver_id in waivers:
                    # Consume the waiver atomically within this lock acquisition
                    waivers.remove(giver_id)
                    log.info("Cooldown waiver consumed for %s.", interaction.user)
                else:
                    last_str: str | None = data["last_given"].get(giver_id)
                    if last_str:
                        last_dt = datetime.fromisoformat(last_str)
                        elapsed = datetime.now(timezone.utc) - last_dt
                        if elapsed < timedelta(hours=REP_COOLDOWN_HOURS):
                            remaining = timedelta(hours=REP_COOLDOWN_HOURS) - elapsed
                            hours, rem = divmod(int(remaining.total_seconds()), 3600)
                            minutes = rem // 60
                            await interaction.followup.send(
                                f"⏳ You can give rep again in **{hours}h {minutes}m**.\n"
                                f"💡 Buy a **Cooldown Waiver** in the shop with `/shop`!"
                            )
                            return

                # Credit the target and stamp the giver's last-given time
                data["rep_counts"][target_id] = data["rep_counts"].get(target_id, 0) + 1
                data["last_given"][giver_id] = datetime.now(timezone.utc).isoformat()

                await save_rep_data(data)

            new_total: int = data["rep_counts"][target_id]
            log.info("Rep given: %s → %s (new total: %d)", interaction.user, member, new_total)
            await interaction.followup.send(
                f"⭐ {interaction.user.mention} gave rep to {member.mention}! "
                f"They now have **{new_total}** rep."
            )

        except Exception as exc:  # pylint: disable=broad-except
            log.exception("Unexpected error in /rep command")
            await interaction.followup.send(f"❌ An error occurred: {exc}")

    @app_commands.command(name="myrep", description="Show your current reputation count.")
    async def my_rep(self, interaction: discord.Interaction) -> None:
        """Display your current reputation count."""
        await interaction.response.defer(ephemeral=True)

        user_id = str(interaction.user.id)

        async with rep_lock():
            data = await load_rep_data()

        rep: int = data["rep_counts"].get(user_id, 0)
        s = "" if rep == 1 else "s"
        await interaction.followup.send(f"⭐ You have **{rep}** reputation point{s}.")

    async def _leaderboard_impl(self, interaction: discord.Interaction) -> None:
        """Shared implementation for /leaderboard and /top."""
        await interaction.response.defer()

        async with rep_lock():
            data = await load_rep_data()

        rep_counts: dict = data.get("rep_counts", {})
        if not rep_counts:
            await interaction.followup.send(
                "📭 No reputation data yet — start giving rep with `/rep @user`!"
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
        embed.set_footer(text="Give rep with /rep @user  •  Spend rep in the shop with /shop")
        await interaction.followup.send(embed=embed)

    @app_commands.command(name="leaderboard", description="Show the top 10 community members by reputation.")
    async def leaderboard(self, interaction: discord.Interaction) -> None:
        """Show the top 10 community members by reputation."""
        await self._leaderboard_impl(interaction)

    @app_commands.command(name="top", description="Show the top 10 community members by reputation.")
    async def top(self, interaction: discord.Interaction) -> None:
        """Alias for /leaderboard."""
        await self._leaderboard_impl(interaction)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(RepCog(bot))
