"""
cogs/twitch.py
Twitch live-status tool + background monitor + Hype Train milestone alerts.

Responsibilities
----------------
* ``check_twitch_status`` — on-demand Helix API query (registered as an LLM tool).
* ``TwitchCog.twitch_monitor`` — ``@tasks.loop`` that polls every 3 minutes:
    - Posts a @everyone alert to the configured channel when the stream goes live.
    - Fires a viewer-milestone embed (Hype Train) each time the live viewer count
      crosses a threshold in VIEWER_MILESTONES for the first time in that stream.
    - Resets milestone tracking when the stream ends so thresholds can fire again
      on the next broadcast.

Hype Train design
-----------------
* Milestones are one-shot per stream: once fired they are added to
  ``_milestones_fired`` and never re-fire, even if viewer count dips then
  re-crosses the threshold.
* The milestone set is reset on the live → offline transition.
* If the bot restarts mid-stream, historical milestones will re-fire once
  (acceptable trade-off for a home-lab bot; persist the set to disk if undesired).
* Milestone embeds do NOT include @everyone — the initial live alert already
  handles the broadcast ping.
"""

from __future__ import annotations

import logging
import time

import aiohttp
import discord
from discord.ext import commands, tasks

from config import (
    BOT_OWNER_ID,
    TWITCH_BROADCASTER_LOGIN,
    TWITCH_CLIENT_ID,
    TWITCH_CLIENT_SECRET,
    TWITCH_NOTIFY_CHANNEL_ID,
)
from services.llm_manager import ChatContextManager

log = logging.getLogger("root_ai.twitch")

# ---------------------------------------------------------------------------
# Hype Train — viewer-count milestones (fires once per stream per threshold)
# Kept intentionally low for a new/small streamer.
# ---------------------------------------------------------------------------

VIEWER_MILESTONES: list[int] = [5, 10, 15, 25, 35, 50, 75, 100]

# ---------------------------------------------------------------------------
# Token cache (module-level so it survives Cog reloads within a session)
# ---------------------------------------------------------------------------

_token_cache: dict = {"access_token": None, "expires_at": 0.0}


async def _get_twitch_app_token() -> str:
    """
    Returns a cached Twitch App Access Token, refreshing via Client Credentials
    if it has expired.  Tokens are valid for ~60 days; a 60-second safety buffer
    is subtracted from the reported expiry.
    """
    if _token_cache["access_token"] and time.time() < _token_cache["expires_at"]:
        return _token_cache["access_token"]

    if not TWITCH_CLIENT_ID or not TWITCH_CLIENT_SECRET:
        raise ValueError(
            "TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET must be set in your .env file."
        )

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://id.twitch.tv/oauth2/token",
            params={
                "client_id": TWITCH_CLIENT_ID,
                "client_secret": TWITCH_CLIENT_SECRET,
                "grant_type": "client_credentials",
            },
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()

    _token_cache["access_token"] = data["access_token"]
    _token_cache["expires_at"] = time.time() + data.get("expires_in", 3600) - 60
    log.info("Twitch app token refreshed. Expires in ~%d seconds.", data.get("expires_in", 3600))
    return _token_cache["access_token"]


# ---------------------------------------------------------------------------
# Core tool logic
# ---------------------------------------------------------------------------


async def check_twitch_status() -> str:
    """
    Queries the Twitch Helix API to check whether the broadcaster is live.
    Returns a human-readable status string suitable for direct Discord output.
    """
    log.info("TWITCH API: Checking live status for '%s'", TWITCH_BROADCASTER_LOGIN)
    try:
        token = await _get_twitch_app_token()

        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.twitch.tv/helix/streams",
                params={"user_login": TWITCH_BROADCASTER_LOGIN},
                headers={
                    "Client-ID": TWITCH_CLIENT_ID,
                    "Authorization": f"Bearer {token}",
                },
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

        streams = data.get("data", [])

        if not streams:
            return (
                f"📴 **{TWITCH_BROADCASTER_LOGIN}** is currently **offline**.\n"
                f"Channel: https://www.twitch.tv/{TWITCH_BROADCASTER_LOGIN}"
            )

        stream = streams[0]
        title = stream.get("title", "No title set")
        game = stream.get("game_name", "Unknown")
        viewers = stream.get("viewer_count", 0)
        started = stream.get("started_at", "Unknown")

        return (
            f"🟢 **{TWITCH_BROADCASTER_LOGIN}** is **LIVE!**\n"
            f"📺 **Title:** {title}\n"
            f"🎮 **Game:** {game}\n"
            f"👁️ **Viewers:** {viewers:,}\n"
            f"⏱️ **Started at:** {started} (UTC)\n"
            f"🔗 https://www.twitch.tv/{TWITCH_BROADCASTER_LOGIN}"
        )

    except ValueError as exc:
        log.error("Twitch config error: %s", exc)
        return f"Configuration Error: {exc}"
    except aiohttp.ClientResponseError as exc:
        log.error("Twitch API HTTP error: %s %s", exc.status, exc.message)
        return f"Twitch API Error: HTTP {exc.status} — {exc.message}"
    except Exception as exc:  # pylint: disable=broad-except
        log.exception("Unexpected error checking Twitch status")
        return f"Twitch check failed: {exc}"


# ---------------------------------------------------------------------------
# Tool spec
# ---------------------------------------------------------------------------

TWITCH_STATUS_TOOL_SPEC: dict = {
    "type": "function",
    "function": {
        "name": "check_twitch_status",
        "description": (
            "Checks whether the pwnedByJT Twitch channel is currently live. "
            "Use this when the user asks if the stream is live, if they are streaming, "
            "or anything about the Twitch channel status."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
}


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class TwitchCog(commands.Cog, name="Twitch"):
    """
    Registers the Twitch status tool and runs the background live monitor
    with Hype Train viewer-milestone alerts.

    Instance state
    --------------
    _was_live       — last known live state; resets on Cog reload (acceptable).
    _milestones_fired — milestones that have already been announced this stream;
                       cleared on live → offline transition.
    """

    def __init__(self, bot: commands.Bot, chat_manager: ChatContextManager) -> None:
        self.bot = bot
        self._chat = chat_manager
        self._was_live: bool = False
        self._milestones_fired: set[int] = set()
        self._register_tools()

    def _register_tools(self) -> None:
        async def _twitch_handler(args: dict, message: discord.Message) -> str:  # noqa: ARG001
            return await check_twitch_status()

        self._chat.register_tool("check_twitch_status", _twitch_handler, TWITCH_STATUS_TOOL_SPEC)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def cog_load(self) -> None:
        """Start the background task when the cog is loaded."""
        self.twitch_monitor.start()
        log.info("Twitch live monitor started — polling every 3 minutes.")

    async def cog_unload(self) -> None:
        """Gracefully cancel the task on unload / shutdown."""
        self.twitch_monitor.cancel()

    # ------------------------------------------------------------------
    # Background task
    # ------------------------------------------------------------------

    @tasks.loop(minutes=3)
    async def twitch_monitor(self) -> None:
        """
        Polls the Twitch Helix API every 3 minutes.

        - Fires a @everyone embed alert on the offline → live transition.
        - Fires a Hype Train milestone embed each time viewer count first crosses
          a threshold in VIEWER_MILESTONES (no @everyone — broadcast already done).
        - Resets ``_milestones_fired`` on the live → offline transition so
          thresholds can fire again next stream.
        """
        log.info("TWITCH MONITOR: Polling live status for '%s'", TWITCH_BROADCASTER_LOGIN)

        try:
            token = await _get_twitch_app_token()

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.twitch.tv/helix/streams",
                    params={"user_login": TWITCH_BROADCASTER_LOGIN},
                    headers={
                        "Client-ID": TWITCH_CLIENT_ID,
                        "Authorization": f"Bearer {token}",
                    },
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()

            stream_data = data.get("data", [])
            is_live: bool = bool(stream_data)

            # ── offline → live: post @everyone alert ────────────────────
            if is_live and not self._was_live:
                log.info(
                    "TWITCH MONITOR: '%s' just went live — posting alert.",
                    TWITCH_BROADCASTER_LOGIN,
                )
                channel = self.bot.get_channel(TWITCH_NOTIFY_CHANNEL_ID)
                if channel:
                    embed = discord.Embed(
                        title="🔴 pwnedByJT is LIVE!",
                        description=(
                            "**Watch the stream:**\n"
                            "[🟣 Twitch](https://twitch.tv/pwnedByJT)  •  "
                            "[🟩 Kick](https://kick.com/pwnedbyjt)  •  "
                            "[🔴 YouTube](https://www.youtube.com/@pwnedByJT)  •  "
                            "[🎵 TikTok](https://www.tiktok.com/@pwnedbyjt)"
                        ),
                        color=discord.Color.purple(),
                    )
                    await channel.send(
                        content=f"@everyone <@{BOT_OWNER_ID}>",
                        embed=embed,
                    )
                else:
                    log.warning(
                        "TWITCH MONITOR: Could not find channel ID %d — alert not sent.",
                        TWITCH_NOTIFY_CHANNEL_ID,
                    )

            # ── live → offline: reset milestone tracking ─────────────────
            if not is_live and self._was_live:
                log.info(
                    "TWITCH MONITOR: '%s' went offline — resetting Hype Train milestones.",
                    TWITCH_BROADCASTER_LOGIN,
                )
                self._milestones_fired = set()

            # ── Hype Train: check viewer milestones while live ───────────
            if is_live and stream_data:
                viewer_count: int = stream_data[0].get("viewer_count", 0)
                log.debug(
                    "TWITCH MONITOR: Live viewer count = %d (milestones fired: %s)",
                    viewer_count,
                    self._milestones_fired,
                )

                channel = self.bot.get_channel(TWITCH_NOTIFY_CHANNEL_ID)
                for milestone in VIEWER_MILESTONES:
                    if viewer_count >= milestone and milestone not in self._milestones_fired:
                        self._milestones_fired.add(milestone)
                        log.info(
                            "TWITCH HYPE TRAIN: Milestone %d viewers reached (%d live).",
                            milestone,
                            viewer_count,
                        )
                        if channel:
                            await self._post_hype_milestone(channel, milestone, viewer_count)

            self._was_live = is_live

        except aiohttp.ClientResponseError as exc:
            log.error(
                "TWITCH MONITOR: HTTP error %s %s — will retry next cycle.",
                exc.status,
                exc.message,
            )
        except Exception:  # pylint: disable=broad-except
            log.exception("TWITCH MONITOR: Unexpected error — will retry next cycle.")

    @twitch_monitor.before_loop
    async def _before_twitch_monitor(self) -> None:
        """Block the task until the bot is fully connected."""
        await self.bot.wait_until_ready()

    # ------------------------------------------------------------------
    # Hype Train helper
    # ------------------------------------------------------------------

    @staticmethod
    async def _post_hype_milestone(
        channel: discord.abc.Messageable,
        milestone: int,
        current_viewers: int,
    ) -> None:
        """Post a Hype Train milestone embed to the notification channel."""
        # Pick a flavour string that scales with the milestone
        if milestone < 15:
            flavor = "The stream is heating up! 🔥"
        elif milestone < 35:
            flavor = "Things are getting spicy — keep it rolling! 🌶️"
        elif milestone < 75:
            flavor = "The Hype Train has left the station! 🚂"
        else:
            flavor = "MAXIMUM HYPE — this is incredible! 🎉🎉🎉"

        embed = discord.Embed(
            title=f"🚂 Hype Train — {milestone} Viewers!",
            description=(
                f"**{TWITCH_BROADCASTER_LOGIN}** just hit **{milestone} concurrent viewers**!\n\n"
                f"👁️ **Current viewers:** {current_viewers:,}\n\n"
                f"{flavor}\n\n"
                f"[🟣 Watch on Twitch](https://twitch.tv/pwnedByJT)"
            ),
            color=discord.Color.orange(),
        )
        await channel.send(embed=embed)


async def setup(bot: commands.Bot) -> None:
    chat_manager: ChatContextManager = bot.chat_manager  # type: ignore[attr-defined]
    await bot.add_cog(TwitchCog(bot, chat_manager))
