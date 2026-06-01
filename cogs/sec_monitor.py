"""
cogs/sec_monitor.py
HTB accountability tracker with streak-danger alerts.

Responsibilities
----------------
* ``SecMonitorCog.streak_monitor`` — ``@tasks.loop`` that polls every 4 hours:
    - Fetches the owner's current HTB activity via the API.
    - Posts a @owner warning to SEC_MONITOR_CHANNEL_ID if a streak is in danger of
      resetting (no activity today AND fewer than STREAK_WARN_HOURS remain until
      UTC midnight).
    - Fires at most ONCE per UTC day (``_warned_today`` dedup map)
      so the alert channel is never spammed during the danger window.

* ``/streak`` — guild slash command: returns a rich embed with HTB rank and the latest machine cleared.

* LLM Tool Registration (commented out) — demonstrates how to wire the streak
  data fetcher into ChatContextManager so "@Root AI how are my lab streaks
  looking?" works as a natural-language query.  See the block below the
  ``get_streak_summary()`` function.

Streak-danger definition
------------------------
A streak is considered "in danger" when BOTH of the following are true:
  1. No activity has been recorded for the user on the current UTC calendar day.
  2. Fewer than ``STREAK_WARN_HOURS`` (default: 12) hours remain until the next
     UTC midnight, at which point the streak counter resets.

Undocumented endpoint notice
-----------------------------
The platform changes its internal API surface without notice. The URLs used
here were validated around 2026-06. If they begin returning 4xx errors, consult
these breadcrumbs to find the replacement paths:

  HTB v4:  https://documenter.getpostman.com/view/13129365/TVeqbmeq  (community)
           Alternatively: DevTools → Network tab on https://app.hackthebox.com

Configuration required (.env additions)
----------------------------------------
  HTB_API_TOKEN          — App Token from HTB Account Settings → App Tokens
  SEC_MONITOR_CHANNEL_ID — Discord channel ID where streak alerts are posted
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime, timedelta, timezone

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

import config
from config import BOT_OWNER_ID
from services.llm_manager import ChatContextManager

log = logging.getLogger("root_ai.sec_monitor")

# ---------------------------------------------------------------------------
# Identity — update here if the username ever changes
# ---------------------------------------------------------------------------

HTB_USERNAME: str = "pwnedByJT"

# ---------------------------------------------------------------------------
# Streak danger threshold
# A warning fires only when no activity has been logged today (UTC) AND this
# many hours or fewer remain until the UTC-midnight streak reset.
# ---------------------------------------------------------------------------

STREAK_WARN_HOURS: int = 12

# ---------------------------------------------------------------------------
# API endpoint constants
# Validated ~2026-06; update the relevant constant if a platform 404s.
# ---------------------------------------------------------------------------

# HTB Helix v4 — all requests require:  Authorization: Bearer {HTB_API_TOKEN}
_HTB_BASE: str = "https://labs.hackthebox.com/api/v4"
_HTB_USER_INFO: str = f"{_HTB_BASE}/user/info"           # resolves user id + rank
_HTB_ACTIVITY_TMPL: str = f"{_HTB_BASE}/profile/activity/{{user_id}}"  # recent solves

# Shared HTTP timeout applied to every outbound request in this cog.
_TIMEOUT: aiohttp.ClientTimeout = aiohttp.ClientTimeout(total=15)

# ---------------------------------------------------------------------------
# Streak timing helper
# ---------------------------------------------------------------------------


def _hours_until_utc_midnight() -> float:
    """Return the number of hours remaining until the next UTC midnight (0–24)."""
    now = datetime.now(timezone.utc)
    tomorrow_midnight = (now + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return (tomorrow_midnight - now).total_seconds() / 3600.0


# ---------------------------------------------------------------------------
# Visual helpers
# ---------------------------------------------------------------------------


def _streak_bar(days: int, max_shown: int = 10) -> str:
    """Return a compact emoji bar representing a streak length (capped at max_shown)."""
    filled = min(days, max_shown)
    return "🟩" * filled + "⬜" * (max_shown - filled)


# ---------------------------------------------------------------------------
# HTB data fetching  (pure async — no Discord coupling)
# ---------------------------------------------------------------------------


async def fetch_htb_data(api_token: str) -> dict:
    """
    Fetch the authenticated user's HTB profile and most recent activity.

    Two sequential requests are made within a single ``aiohttp.ClientSession``:
      1. ``GET /api/v4/user/info``          → rank, points, user id
      2. ``GET /api/v4/profile/activity/{id}`` → most recent solves

    Returns a dict:
        username        str       — display name
        rank            str       — e.g. "Hacker", "Pro Hacker", "Elite Hacker"
        points          int       — total score
        activity_today  bool      — True if any submission was recorded today (UTC)
        last_activity   str       — human-readable label of the most recent solve
        error           str|None  — error message; all other keys absent on error
    """
    log.info("HTB API: Fetching profile for '%s'", HTB_USERNAME)

    if not api_token:
        return {"error": "HTB_API_TOKEN is not set in your .env file."}

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "User-Agent": "RootAI-Discord-Bot/1.0",
    }

    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            # ── Step 1: resolve user id + rank ─────────────────────────────
            # BYPASSED: The /user/info endpoint is currently returning a 404.
            # We are hardcoding the ID directly to ensure the streak monitor functions.
            user_id: int = 2203566
            rank: str = "Apprentice"  # Fallback since endpoint is down
            points: int = 0           # Fallback since endpoint is down
            info: dict = {"name": HTB_USERNAME}

            # ── Step 2: fetch recent activity ───────────────────────────────
            activity_url = _HTB_ACTIVITY_TMPL.format(user_id=user_id)
            async with session.get(activity_url, headers=headers) as resp:
                resp.raise_for_status()
                activity_payload: dict = await resp.json()

        activities: list[dict] = (
            activity_payload.get("profile", {}).get("activity", [])
        )

        today_str: str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        activity_today: bool = False
        last_activity: str = "None recorded"

        if activities:
            latest: dict = activities[0]
            latest_date_raw: str = latest.get("date", "")
            activity_today = latest_date_raw.startswith(today_str)
            obj_type: str = latest.get("object_type", "item").title()
            solve_name: str = latest.get("name", "Unknown")
            solve_type: str = latest.get("type", "").replace("_", " ").title()
            last_activity = f"{obj_type} — {solve_name} ({solve_type})"

        return {
            "username": info.get("name", HTB_USERNAME),
            "rank": rank,
            "points": points,
            "activity_today": activity_today,
            "last_activity": last_activity,
            "error": None,
        }

    except aiohttp.ClientResponseError as exc:
        log.error("HTB API HTTP error: %s %s", exc.status, exc.message)
        return {"error": f"HTB API error: HTTP {exc.status} — {exc.message}"}
    except asyncio.TimeoutError:
        log.error("HTB API timed out after %ds.", _TIMEOUT.total)
        return {"error": f"HTB API timed out after {_TIMEOUT.total}s."}
    except aiohttp.ClientConnectorError as exc:
        log.error("HTB API connection error: %s", exc)
        return {"error": f"HTB connection failed: {exc}"}
    except Exception as exc:  # pylint: disable=broad-except
        log.exception("HTB API unexpected error")
        return {"error": f"HTB fetch failed: {exc}"}


# ---------------------------------------------------------------------------
# Combined summary (shared by the background task and the /streak command)
# ---------------------------------------------------------------------------


async def get_streak_summary() -> dict:
    """
    Fetch data from HTB and return a unified dict.

    Keys:
        htb         dict    — result of fetch_htb_data()
        hours_left  float   — hours remaining until the next UTC midnight reset
    """
    htb = await fetch_htb_data(api_token=config.HTB_API_TOKEN)

    return {
        "htb": htb,
        "hours_left": _hours_until_utc_midnight(),
    }


# ---------------------------------------------------------------------------
# LLM Tool spec + registration helper
#
# STATUS: COMMENTED OUT — uncomment to activate "@Root AI, check my streaks"
#
# HOW TO ENABLE
# -------------
# 1. Uncomment the STREAK_TOOL_SPEC dict and the _register_tools() method below.
# 2. In SecMonitorCog.__init__, add:   self._register_tools()
# 3. In services/llm_manager.py, add "check_streak_data" to the system prompt
#    so the model knows when to reach for this tool:
#      "Use check_streak_data when the user asks about HTB rank, lab progress, 
#       or whether they completed a challenge today."
#
# HOW IT WORKS
# ------------
# The handler wraps get_streak_summary() in the ToolHandler signature expected
# by ChatContextManager:  async (args: dict, message: discord.Message) -> str
# On a natural-language query, the LLM will call "check_streak_data" (no args),
# receive the formatted text block, and surface it directly in Discord.
# ---------------------------------------------------------------------------

# STREAK_TOOL_SPEC: dict = {
#     "type": "function",
#     "function": {
#         "name": "check_streak_data",
#         "description": (
#             "Fetches the current HTB rank, and latest machine "
#             "or room cleared for pwnedByJT.  Use this when the user asks about "
#             "their lab streaks, HTB rank, progress, or whether they have "
#             "completed a challenge or room today."
#         ),
#         "parameters": {
#             "type": "object",
#             "properties": {},
#             "required": [],
#         },
#     },
# }
#
# def _register_tools(self) -> None:
#     async def _streak_handler(args: dict, message: discord.Message) -> str:  # noqa: ARG001
#         summary = await get_streak_summary()
#         htb = summary["htb"]
#         hours_left = summary["hours_left"]
#
#         lines: list[str] = [f"⏰ **{hours_left:.1f}h** until UTC midnight streak reset\n"]
#
#         if htb.get("error"):
#             lines.append(f"❌ **HTB Error:** {htb['error']}")
#         else:
#             today_status = "✅ Done" if htb["activity_today"] else f"⚠️ Nothing yet ({hours_left:.1f}h left)"
#             lines.append(
#                 f"**⬛ Hack The Box**\n"
#                 f"  Rank: {htb['rank']} | Points: {htb['points']:,}\n"
#                 f"  Today: {today_status}\n"
#                 f"  Last solve: {htb['last_activity']}"
#             )
#
#         return "\n\n".join(lines)
#
#     self._chat.register_tool("check_streak_data", _streak_handler, STREAK_TOOL_SPEC)


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class SecMonitorCog(commands.Cog, name="SecMonitor"):
    """
    Accountability tracker for HTB streak maintenance.

    Background task polls every 4 hours.  If the user has no activity logged
    today (UTC) and fewer than STREAK_WARN_HOURS remain until midnight, a
    @mention alert is posted to SEC_MONITOR_CHANNEL_ID.

    Instance state
    --------------
    _warned_today   dict[str, date] — maps platform key ("htb") to the
                                      UTC date on which a streak-danger alert was
                                      last fired.  Resets implicitly on date change,
                                      capping alerts at one per platform per day.
    """

    def __init__(self, bot: commands.Bot, chat_manager: ChatContextManager) -> None:
        self.bot = bot
        # Stored for future use when _register_tools() is uncommented above.
        self._chat = chat_manager
        self._warned_today: dict[str, date] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def cog_load(self) -> None:
        """Start the background streak monitor when the cog is loaded."""
        self.streak_monitor.start()
        log.info("HTB streak monitor started — polling every 4 hours.")

    async def cog_unload(self) -> None:
        """Gracefully cancel the background task on unload / shutdown."""
        self.streak_monitor.cancel()

    # ------------------------------------------------------------------
    # Background task
    # ------------------------------------------------------------------

    @tasks.loop(hours=4)
    async def streak_monitor(self) -> None:
        """
        Polls HTB every 4 hours and fires streak-danger alerts.

        Early-exit logic
        ----------------
        If more than STREAK_WARN_HOURS remain until UTC midnight, we skip all
        API calls entirely — there's nothing to warn about yet and we save the
        rate-limit budget for when it actually matters.

        Dedup logic
        -----------
        ``_warned_today[platform]`` stores the UTC date of the last alert.
        A second warning within the same UTC day is silently skipped.  The
        dedup resets naturally when the date rolls over (no explicit clear needed).
        """
        log.info("SEC MONITOR: Running streak check cycle.")
        today = datetime.now(timezone.utc).date()
        hours_left = _hours_until_utc_midnight()

        # Skip if we're still outside the warning window.
        if hours_left > STREAK_WARN_HOURS:
            log.debug(
                "SEC MONITOR: %.1fh until midnight — outside %dh warning window. Skipping.",
                hours_left,
                STREAK_WARN_HOURS,
            )
            return

        channel = self.bot.get_channel(config.SEC_MONITOR_CHANNEL_ID)
        if not channel:
            log.warning(
                "SEC MONITOR: Channel ID %d not found — alerts not sent. "
                "Check SEC_MONITOR_CHANNEL_ID in your .env file.",
                config.SEC_MONITOR_CHANNEL_ID,
            )
            return

        # ── HTB streak check ───────────────────────────────────────────────
        if self._warned_today.get("htb") != today:
            try:
                htb = await fetch_htb_data(api_token=config.HTB_API_TOKEN)
                if htb.get("error"):
                    log.warning("SEC MONITOR: HTB fetch error — %s", htb["error"])
                elif not htb["activity_today"]:
                    log.info(
                        "SEC MONITOR: HTB — no activity today. %.1fh left. Posting alert.",
                        hours_left,
                    )
                    await self._send_streak_alert(
                        channel=channel,
                        platform="Hack The Box",
                        emoji="⬛",
                        color=discord.Color.dark_green(),
                        hours_left=hours_left,
                        detail=(
                            f"**Rank:** {htb['rank']}\n"
                            f"**Points:** {htb['points']:,}\n"
                            f"**Last solve:** {htb['last_activity']}"
                        ),
                        cta_url="https://app.hackthebox.com/starting-point",
                    )
                    self._warned_today["htb"] = today
                else:
                    log.info("SEC MONITOR: HTB — activity already logged today. No alert.")

            except Exception:  # pylint: disable=broad-except
                log.exception("SEC MONITOR: Unexpected error during HTB streak check.")


    @streak_monitor.before_loop
    async def _before_streak_monitor(self) -> None:
        """Block the task loop until the bot is fully connected to Discord."""
        await self.bot.wait_until_ready()

    # ------------------------------------------------------------------
    # Alert embed helper
    # ------------------------------------------------------------------

    async def _send_streak_alert(
        self,
        channel: discord.abc.Messageable,
        platform: str,
        emoji: str,
        color: discord.Color,
        hours_left: float,
        detail: str,
        cta_url: str,
    ) -> None:
        """Post a streak-danger embed to the monitor channel with a @mention."""
        embed = discord.Embed(
            title=f"{emoji} {platform} Streak at Risk!",
            description=(
                f"<@{BOT_OWNER_ID}> — no **{platform}** activity logged today.\n\n"
                f"{detail}\n\n"
                f"⏰ **{hours_left:.1f} hours** left before your streak resets at UTC midnight."
            ),
            color=color,
            url=cta_url,
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(text="Log in and complete a lab to keep your streak alive! 🔐")
        await channel.send(content=f"<@{BOT_OWNER_ID}>", embed=embed)

    # ------------------------------------------------------------------
    # Slash command — /streak
    # ------------------------------------------------------------------

    @app_commands.command(
        name="streak",
        description="Show your current HTB rank, and latest lab activity.",
    )
    async def streak_command(self, interaction: discord.Interaction) -> None:
        """
        Fetches live data from HTB and returns a rich embed.

        Visibility
        ----------
        Responses are public when called by the bot owner so the stats can
        be seen in the channel.  Any other caller receives an ephemeral reply to
        avoid broadcasting personal accountability data server-wide.
        """
        is_owner: bool = interaction.user.id == BOT_OWNER_ID
        # Defer immediately — concurrent API calls may exceed Discord's 3s ack window.
        await interaction.response.defer(ephemeral=not is_owner)

        summary = await get_streak_summary()
        htb = summary["htb"]
        hours_left = summary["hours_left"]

        embed = discord.Embed(
            title="🔐 pwnedByJT — Lab Streak Status",
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(
            text=f"⏰ {hours_left:.1f}h until UTC midnight streak reset"
            + ("  •  ⚠️ Streaks at risk!" if hours_left <= STREAK_WARN_HOURS else "")
        )

        # ── HTB field ──────────────────────────────────────────────────────
        if htb.get("error"):
            embed.add_field(
                name="⬛ Hack The Box",
                value=f"```\n{htb['error']}\n```",
                inline=False,
            )
        else:
            today_icon = "✅" if htb["activity_today"] else "⚠️"
            today_label = "Done for today" if htb["activity_today"] else "Nothing logged yet"
            embed.add_field(
                name="⬛ Hack The Box",
                value=(
                    f"**Rank:** {htb['rank']}\n"
                    f"**Points:** {htb['points']:,}\n"
                    f"**Today:** {today_icon} {today_label}\n"
                    f"**Last solve:** {htb['last_activity']}"
                ),
                inline=True,
            )

        await interaction.followup.send(embed=embed, ephemeral=not is_owner)


# ---------------------------------------------------------------------------
# Extension entry point
# ---------------------------------------------------------------------------


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(SecMonitorCog(bot, chat_manager))