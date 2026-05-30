"""
cogs/shop.py
Root AI Community Shop — spend rep points on cosmetic perks via Discord UI.

V1 Items
--------
| ID         | Name              | Cost | Duration  | Notes                          |
|------------|-------------------|------|-----------|--------------------------------|
| nickname   | Custom Nickname   |  30  | 7 days    | Bot sets your server nickname  |
| colour     | Role Colour       |  50  | Permanent | Cosmetic colour role           |
| vip        | VIP Badge         | 100  | 30 days   | Cosmetic VIP role              |
| waiver     | Cooldown Waiver   |  20  | One-use   | Skip next .rep cooldown        |
| pwned      | pwned             | 300  | Permanent | Ultimate prestige role 💀      |

Design notes
------------
* All roles created by the shop have ``discord.Permissions(permissions=0)`` —
  zero server permissions, purely cosmetic.
* Cooldown waivers are stored in ``rep.json`` (not shop.json) so the waiver
  purchase only needs ``rep_lock``, eliminating any risk of deadlock.
* Lock ordering: rep_lock → (release) → shop_lock.  The two locks are NEVER
  held simultaneously — each is acquired, used, and released independently.
* The NicknameModal uses ``interaction.response.send_modal()`` directly
  (cannot defer before opening a modal).  All other items defer first, then
  use a ConfirmView sent as an ephemeral followup.
* Colour roles are named with a fixed prefix so the bot can find and remove
  an existing colour role before assigning a new one (no stacking).
* The ``expire_perks`` task runs every 10 minutes and removes expired VIP
  roles and restores original nicknames when their timer lapses.
* Each View subclass implements ``interaction_check`` so only the member who
  opened the shop session can interact with it — prevents cross-user rep theft.
* ``PurchaseError`` is raised from apply helpers when a perk is already owned;
  it produces a friendly message and triggers a full refund.
"""

from __future__ import annotations

import dataclasses
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands, tasks

from services.storage import (
    init_shop_file,
    load_rep_data,
    load_shop_data,
    rep_lock,
    save_rep_data,
    save_shop_data,
    shop_lock,
)

log = logging.getLogger("root_ai.shop")

# ---------------------------------------------------------------------------
# Custom exception for user-facing purchase failures (triggers refund)
# ---------------------------------------------------------------------------


class PurchaseError(Exception):
    """Raised inside _apply_* helpers to signal a user-facing failure.

    The message is shown directly to the buyer and rep is refunded.
    """


# ---------------------------------------------------------------------------
# Shop catalogue
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ShopItem:
    id: str
    name: str
    cost: int
    description: str
    emoji: str
    category: str
    duration_days: Optional[int] = None  # None = permanent / one-use


SHOP_ITEMS: list[ShopItem] = [
    ShopItem("nickname", "Custom Nickname",  30,  "Set your server nickname for 7 days",    "🎭", "cosmetic",  7),
    ShopItem("colour",   "Role Colour",      50,  "Pick a cosmetic colour role (permanent)", "🎨", "cosmetic",  None),
    ShopItem("vip",      "VIP Badge",       100,  "VIP cosmetic role for 30 days",          "👑", "cosmetic",  30),
    ShopItem("waiver",   "Cooldown Waiver",  20,  "Skip your next /rep cooldown (one-use)", "⚡", "economy",   None),
    ShopItem("pwned",    "pwned",           300,  "Ultimate prestige role — permanently 💀","💀", "prestige",  None),
]

ITEMS_BY_ID: dict[str, ShopItem] = {item.id: item for item in SHOP_ITEMS}

COLOUR_OPTIONS: dict[str, tuple[discord.Color, str]] = {
    "Red":    (discord.Color.red(),    "🔴"),
    "Blue":   (discord.Color.blue(),   "🔵"),
    "Green":  (discord.Color.green(),  "🟢"),
    "Gold":   (discord.Color.gold(),   "🟡"),
    "Purple": (discord.Color.purple(), "🟣"),
    "Cyan":   (discord.Color.teal(),   "🩵"),
}

# Role-name prefixes used to locate bot-created roles
COLOUR_ROLE_PREFIX = "🎨 "
VIP_ROLE_NAME = "👑 VIP"
PWNED_ROLE_NAME = "💀 pwned"


# ---------------------------------------------------------------------------
# Helper: build the shop embed for a given category
# ---------------------------------------------------------------------------


def _shop_category_embed(category: str) -> discord.Embed:
    items = [i for i in SHOP_ITEMS if i.category == category]
    lines = []
    for item in items:
        if item.id == "waiver":
            dur = "One-use"
        elif item.duration_days:
            dur = f"{item.duration_days}d"
        else:
            dur = "Permanent"
        lines.append(
            f"{item.emoji} **{item.name}** — `{item.cost}` rep\n"
            f"  ↳ {item.description} *(duration: {dur})*"
        )
    embed = discord.Embed(
        title=f"🛍️ Shop — {category.capitalize()}",
        description="\n\n".join(lines) or "No items in this category.",
        color=discord.Color.blurple(),
    )
    embed.set_footer(text="Use /myrep to check your balance")
    return embed


def _shop_main_embed() -> discord.Embed:
    embed = discord.Embed(
        title="🛍️ Root AI Community Shop",
        description=(
            "Spend your hard-earned rep points on cosmetic perks!\n\n"
            "Pick a category below to browse and buy items.\n\n"
            "**Categories**\n"
            "🎭👑🎨 **Cosmetic** — nicknames, colours, badges\n"
            "⚡ **Economy** — cooldown waivers\n"
            "💀 **Prestige** — ultimate flex"
        ),
        color=discord.Color.blurple(),
    )
    embed.set_footer(text="Use /myrep to check your rep balance")
    return embed


# ---------------------------------------------------------------------------
# View base class — gates all interactions to the session owner
# ---------------------------------------------------------------------------


class _OwnedView(discord.ui.View):
    """Base View that rejects interactions from users other than the session owner."""

    def __init__(self, member: discord.Member, timeout: float = 120) -> None:
        super().__init__(timeout=timeout)
        self._member = member

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self._member.id:
            await interaction.response.send_message(
                "❌ This isn't your shop session! Open your own with `/shop`.",
                ephemeral=True,
            )
            return False
        return True

    async def on_timeout(self) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Nickname Modal
# ---------------------------------------------------------------------------


class NicknameModal(discord.ui.Modal, title="Set Your Nickname"):
    nickname: discord.ui.TextInput = discord.ui.TextInput(
        label="New Nickname",
        placeholder="Enter your desired nickname (max 32 chars)",
        min_length=1,
        max_length=32,
        required=True,
    )

    def __init__(self, cog: "ShopCog", member: discord.Member) -> None:
        super().__init__()
        self._cog = cog
        self._member = member

    # Modals are submitted only by the user who opened them — no interaction_check needed.
    async def on_submit(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        chosen = self.nickname.value.strip()
        result = await self._cog.process_purchase(
            interaction=interaction,
            member=self._member,
            item=ITEMS_BY_ID["nickname"],
            extra={"nickname": chosen},
        )
        await interaction.followup.send(result, ephemeral=True)


# ---------------------------------------------------------------------------
# Colour picker view
# ---------------------------------------------------------------------------


class ColourPickerView(_OwnedView):
    def __init__(self, cog: "ShopCog", member: discord.Member) -> None:
        super().__init__(member=member, timeout=60)
        self._cog = cog
        for colour_name, (_, emoji) in COLOUR_OPTIONS.items():
            btn = discord.ui.Button(
                label=colour_name,
                emoji=emoji,
                style=discord.ButtonStyle.secondary,
                custom_id=f"colour_{colour_name.lower()}",
            )
            btn.callback = self._make_callback(colour_name)
            self.add_item(btn)

    def _make_callback(self, colour_name: str):
        async def callback(interaction: discord.Interaction) -> None:
            await interaction.response.defer(ephemeral=True)
            result = await self._cog.process_purchase(
                interaction=interaction,
                member=self._member,
                item=ITEMS_BY_ID["colour"],
                extra={"colour_name": colour_name},
            )
            await interaction.followup.send(result, ephemeral=True)
            self.stop()
        return callback


# ---------------------------------------------------------------------------
# Confirm / cancel view (for non-modal purchases)
# ---------------------------------------------------------------------------


class ConfirmView(_OwnedView):
    def __init__(
        self,
        cog: "ShopCog",
        member: discord.Member,
        item: ShopItem,
        extra: dict | None = None,
    ) -> None:
        super().__init__(member=member, timeout=60)
        self._cog = cog
        self._item = item
        self._extra = extra or {}

    @discord.ui.button(label="✅ Confirm Purchase", style=discord.ButtonStyle.success)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        for child in self.children:
            child.disabled = True  # type: ignore[union-attr]
        result = await self._cog.process_purchase(
            interaction=interaction,
            member=self._member,
            item=self._item,
            extra=self._extra,
        )
        await interaction.followup.send(result, ephemeral=True)
        self.stop()

    @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.danger)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.edit_message(content="Purchase cancelled.", view=None, embed=None)
        self.stop()


# ---------------------------------------------------------------------------
# Items view — shown after the user picks a category
# ---------------------------------------------------------------------------


class ItemsView(_OwnedView):
    def __init__(self, cog: "ShopCog", member: discord.Member, category: str) -> None:
        super().__init__(member=member, timeout=120)
        self._cog = cog
        self._category = category
        items = [i for i in SHOP_ITEMS if i.category == category]
        for item in items:
            btn = discord.ui.Button(
                label=f"{item.emoji} {item.name} ({item.cost} rep)",
                style=discord.ButtonStyle.primary,
                custom_id=f"buy_{item.id}",
            )
            btn.callback = self._make_buy_callback(item)
            self.add_item(btn)

        back_btn = discord.ui.Button(label="← Back", style=discord.ButtonStyle.secondary, row=4)
        back_btn.callback = self._back_callback
        self.add_item(back_btn)

    def _make_buy_callback(self, item: ShopItem):
        async def callback(interaction: discord.Interaction) -> None:
            # Nickname: open a modal (cannot defer before modal)
            if item.id == "nickname":
                modal = NicknameModal(cog=self._cog, member=self._member)
                await interaction.response.send_modal(modal)
                return

            # Colour: show colour picker
            if item.id == "colour":
                await interaction.response.defer(ephemeral=True)
                view = ColourPickerView(cog=self._cog, member=self._member)
                await interaction.followup.send(
                    "🎨 Pick your colour:", view=view, ephemeral=True
                )
                return

            # All other items: show confirm/cancel
            await interaction.response.defer(ephemeral=True)
            if item.id == "waiver":
                dur_str = "one-use"
            elif item.duration_days:
                dur_str = f"{item.duration_days} days"
            else:
                dur_str = "permanently"
            confirm_embed = discord.Embed(
                title=f"Confirm: {item.emoji} {item.name}",
                description=(
                    f"**Cost:** `{item.cost}` rep\n"
                    f"**Duration:** {dur_str}\n\n"
                    f"{item.description}\n\n"
                    "Are you sure?"
                ),
                color=discord.Color.orange(),
            )
            view = ConfirmView(cog=self._cog, member=self._member, item=item)
            await interaction.followup.send(embed=confirm_embed, view=view, ephemeral=True)

        return callback

    async def _back_callback(self, interaction: discord.Interaction) -> None:
        await interaction.response.edit_message(
            embed=_shop_main_embed(),
            view=ShopView(cog=self._cog, member=self._member),
        )
        self.stop()


# ---------------------------------------------------------------------------
# Top-level shop view — category selector
# ---------------------------------------------------------------------------


class ShopView(_OwnedView):
    def __init__(self, cog: "ShopCog", member: discord.Member) -> None:
        super().__init__(member=member, timeout=120)
        self._cog = cog

        select = discord.ui.Select(
            placeholder="🛍️ Choose a category…",
            options=[
                discord.SelectOption(label="Cosmetic",  value="cosmetic",  emoji="🎭", description="Nicknames, colours, badges"),
                discord.SelectOption(label="Economy",   value="economy",   emoji="⚡", description="Cooldown waivers"),
                discord.SelectOption(label="Prestige",  value="prestige",  emoji="💀", description="Ultimate prestige role"),
            ],
        )
        select.callback = self._on_category_select
        self.add_item(select)

    async def _on_category_select(self, interaction: discord.Interaction) -> None:
        category = interaction.data["values"][0]  # type: ignore[index]
        embed = _shop_category_embed(category)
        view = ItemsView(cog=self._cog, member=self._member, category=category)
        await interaction.response.edit_message(embed=embed, view=view)
        self.stop()


# ---------------------------------------------------------------------------
# ShopCog
# ---------------------------------------------------------------------------


class ShopCog(commands.Cog, name="Shop"):
    """
    Manages the rep-powered community shop, Discord UI navigation, perk
    application, and timed-perk expiry.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def cog_load(self) -> None:
        from services.storage import SHOP_FILE  # noqa: PLC0415

        await init_shop_file()
        self.expire_perks.start()
        log.info("ShopCog loaded — perk expiry task started. Data file: %s", SHOP_FILE.resolve())

    async def cog_unload(self) -> None:
        self.expire_perks.cancel()

    # ------------------------------------------------------------------
    # /shop command
    # ------------------------------------------------------------------

    @app_commands.command(name="shop", description="Open the community shop to spend your rep points.")
    async def shop(self, interaction: discord.Interaction) -> None:
        """Open the community shop to spend your rep points."""
        if not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message(
                "❌ This command must be used inside a server.", ephemeral=True
            )
            return
        member = interaction.user
        view = ShopView(cog=self, member=member)
        await interaction.response.send_message(embed=_shop_main_embed(), view=view)

    # ------------------------------------------------------------------
    # Central purchase processor
    # ------------------------------------------------------------------

    async def process_purchase(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
        item: ShopItem,
        extra: dict | None = None,
    ) -> str:
        """
        Validates rep balance, deducts cost, then applies the perk.

        Returns a human-readable result string (ephemeral to the buyer).

        Lock order: rep_lock (deduct) → release → shop_lock (apply perk) → release.
        On discord.Forbidden or PurchaseError: re-acquire rep_lock, refund, release.
        The two locks are NEVER held simultaneously.
        """
        extra = extra or {}
        user_id = str(member.id)

        # ── Step 1: validate + deduct rep (rep_lock only) ──────────────
        async with rep_lock():
            rep_data = await load_rep_data()
            balance: int = rep_data["rep_counts"].get(user_id, 0)

            if balance < item.cost:
                short = item.cost - balance
                return (
                    f"❌ Not enough rep! You need **{item.cost}** rep but only have **{balance}**.\n"
                    f"You're **{short}** rep short. Keep contributing to earn more! ⭐"
                )

            rep_data["rep_counts"][user_id] = balance - item.cost
            await save_rep_data(rep_data)
            log.info(
                "SHOP: %s purchased '%s' for %d rep (balance: %d → %d).",
                member, item.id, item.cost, balance, balance - item.cost,
            )

        # ── Step 2: apply the perk ──────────────────────────────────────
        try:
            result = await self._apply_perk(member, item, extra)
        except PurchaseError as exc:
            # User-facing rejection (e.g. already owns the perk) — refund
            log.info("SHOP: PurchaseError for '%s' on %s — refunding. %s", item.id, member, exc)
            async with rep_lock():
                rep_data = await load_rep_data()
                rep_data["rep_counts"][user_id] = rep_data["rep_counts"].get(user_id, 0) + item.cost
                await save_rep_data(rep_data)
            return f"❌ {exc}\nYour **{item.cost}** rep has been refunded."
        except discord.Forbidden as exc:
            log.warning("SHOP: Discord Forbidden applying '%s' for %s — refunding. %s", item.id, member, exc)
            async with rep_lock():
                rep_data = await load_rep_data()
                rep_data["rep_counts"][user_id] = rep_data["rep_counts"].get(user_id, 0) + item.cost
                await save_rep_data(rep_data)
            return (
                f"❌ Couldn't apply **{item.name}** — Discord permission error.\n"
                f"Your **{item.cost}** rep has been refunded."
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.exception("SHOP: Unexpected error applying '%s' for %s.", item.id, member)
            async with rep_lock():
                rep_data = await load_rep_data()
                rep_data["rep_counts"][user_id] = rep_data["rep_counts"].get(user_id, 0) + item.cost
                await save_rep_data(rep_data)
            return (
                f"❌ An unexpected error occurred: {exc}\n"
                f"Your **{item.cost}** rep has been refunded."
            )

        return result

    # ------------------------------------------------------------------
    # Perk application helpers
    # ------------------------------------------------------------------

    async def _apply_perk(self, member: discord.Member, item: ShopItem, extra: dict) -> str:
        """Dispatch to the correct apply_* method."""
        dispatch = {
            "nickname": self._apply_nickname,
            "colour":   self._apply_colour,
            "vip":      self._apply_vip,
            "waiver":   self._apply_waiver,
            "pwned":    self._apply_pwned,
        }
        handler = dispatch.get(item.id)
        if handler is None:
            raise ValueError(f"Unknown item id: {item.id!r}")
        return await handler(member, item, extra)

    async def _apply_nickname(self, member: discord.Member, item: ShopItem, extra: dict) -> str:
        chosen_nick = extra.get("nickname", "").strip()
        if not chosen_nick:
            raise PurchaseError("No nickname provided.")

        original_nick = member.nick  # may be None (uses display name)

        # May raise discord.Forbidden if member is server owner
        await member.edit(nick=chosen_nick, reason="Shop: nickname perk purchased")

        expires_at = (datetime.now(timezone.utc) + timedelta(days=item.duration_days)).isoformat()

        async with shop_lock():
            shop_data = await load_shop_data()
            perks: list = shop_data["active_perks"].setdefault(str(member.id), [])
            # Replace any existing nickname perk
            shop_data["active_perks"][str(member.id)] = [p for p in perks if p.get("type") != "nickname"]
            shop_data["active_perks"][str(member.id)].append({
                "type": "nickname",
                "expires_at": expires_at,
                "original_nick": original_nick,
            })
            await save_shop_data(shop_data)

        return (
            f"🎭 Nickname set to **{chosen_nick}** for **{item.duration_days} days**!\n"
            f"It will revert automatically when the timer expires."
        )

    async def _apply_colour(self, member: discord.Member, item: ShopItem, extra: dict) -> str:
        colour_name: str = extra.get("colour_name", "")
        if colour_name not in COLOUR_OPTIONS:
            raise PurchaseError(f"Unknown colour: {colour_name!r}")

        colour_obj, emoji = COLOUR_OPTIONS[colour_name]
        guild = member.guild

        # Remove any existing colour role (prevent stacking)
        existing_colour_roles = [r for r in member.roles if r.name.startswith(COLOUR_ROLE_PREFIX)]
        if existing_colour_roles:
            await member.remove_roles(*existing_colour_roles, reason="Shop: replacing old colour role")

        role_name = f"{COLOUR_ROLE_PREFIX}{colour_name}"
        role = await self._get_or_create_role(guild, role_name, colour_obj)
        await member.add_roles(role, reason="Shop: colour perk purchased")

        async with shop_lock():
            shop_data = await load_shop_data()
            perks: list = shop_data["active_perks"].setdefault(str(member.id), [])
            shop_data["active_perks"][str(member.id)] = [p for p in perks if p.get("type") != "colour"]
            shop_data["active_perks"][str(member.id)].append({
                "type": "colour",
                "colour_name": colour_name,
                "role_id": role.id,
            })
            await save_shop_data(shop_data)

        return f"{emoji} Colour role **{colour_name}** applied permanently! Enjoy the flex."

    async def _apply_vip(self, member: discord.Member, item: ShopItem, extra: dict) -> str:
        guild = member.guild
        role = await self._get_or_create_role(guild, VIP_ROLE_NAME, discord.Color.gold())
        await member.add_roles(role, reason="Shop: VIP perk purchased")

        expires_at = (datetime.now(timezone.utc) + timedelta(days=item.duration_days)).isoformat()

        async with shop_lock():
            shop_data = await load_shop_data()
            perks: list = shop_data["active_perks"].setdefault(str(member.id), [])
            shop_data["active_perks"][str(member.id)] = [p for p in perks if p.get("type") != "vip"]
            shop_data["active_perks"][str(member.id)].append({
                "type": "vip",
                "expires_at": expires_at,
                "role_id": role.id,
            })
            await save_shop_data(shop_data)

        return (
            f"👑 **VIP Badge** granted for **{item.duration_days} days**!\n"
            f"Role will be removed automatically when it expires."
        )

    async def _apply_waiver(self, member: discord.Member, item: ShopItem, extra: dict) -> str:
        """Cooldown waiver: write the user ID into rep.json (under rep_lock only).

        Raises PurchaseError if the user already has an unused waiver — prevents
        silent rep drain from double-buying.
        """
        user_id = str(member.id)

        async with rep_lock():
            rep_data = await load_rep_data()
            waivers: list = rep_data.setdefault("cooldown_waivers", [])

            if user_id in waivers:
                raise PurchaseError(
                    "You already have an unused Cooldown Waiver! "
                    "Use it with `/rep @user` before buying another."
                )

            waivers.append(user_id)
            await save_rep_data(rep_data)

        return (
            "⚡ **Cooldown Waiver** activated!\n"
            "Your next `/rep` will skip the 24-hour cooldown. Use it wisely!"
        )

    async def _apply_pwned(self, member: discord.Member, item: ShopItem, extra: dict) -> str:
        """Grant the prestige pwned role permanently.

        Raises PurchaseError if the member already owns the role — prevents
        silent rep drain from re-purchasing.
        """
        guild = member.guild

        # Check if member already has the pwned role (by name)
        already_has = any(r.name == PWNED_ROLE_NAME for r in member.roles)
        if already_has:
            raise PurchaseError(
                "You already have the **pwned** prestige role! "
                "You cannot buy it twice."
            )

        role = await self._get_or_create_role(guild, PWNED_ROLE_NAME, discord.Color.dark_red())
        await member.add_roles(role, reason="Shop: pwned prestige role purchased")

        async with shop_lock():
            shop_data = await load_shop_data()
            perks: list = shop_data["active_perks"].setdefault(str(member.id), [])
            perks.append({"type": "pwned", "role_id": role.id})
            await save_shop_data(shop_data)

        return (
            "💀 You are now **pwned**. The ultimate prestige is yours — permanently.\n"
            "Flex responsibly."
        )

    # ------------------------------------------------------------------
    # Role factory
    # ------------------------------------------------------------------

    @staticmethod
    async def _get_or_create_role(
        guild: discord.Guild,
        name: str,
        colour: discord.Color,
    ) -> discord.Role:
        """
        Return an existing guild role by name, or create it with zero permissions
        and the given colour.  Created roles are cosmetic-only (no server perms).
        """
        existing = discord.utils.get(guild.roles, name=name)
        if existing:
            return existing
        role = await guild.create_role(
            name=name,
            color=colour,
            permissions=discord.Permissions(permissions=0),
            mentionable=False,
            reason="Root AI Shop — cosmetic role (zero permissions)",
        )
        log.info("SHOP: Created new role '%s' (id=%d) in guild '%s'.", name, role.id, guild.name)
        return role

    # ------------------------------------------------------------------
    # Perk expiry background task
    # ------------------------------------------------------------------

    @tasks.loop(minutes=10)
    async def expire_perks(self) -> None:
        """
        Scans active_perks in shop.json every 10 minutes and:
        - Removes expired VIP roles from members.
        - Reverts expired nicknames.
        - Purges the expired perk entry from shop.json.
        Permanent perks (colour, pwned, waiver) are skipped.
        """
        now = datetime.now(timezone.utc)
        log.debug("SHOP: Running perk expiry check at %s.", now.isoformat())

        async with shop_lock():
            shop_data = await load_shop_data()
            dirty = False

            for guild in self.bot.guilds:
                for user_id in list(shop_data["active_perks"].keys()):
                    perks: list = shop_data["active_perks"][user_id]
                    surviving: list = []

                    for perk in perks:
                        expires_str: str | None = perk.get("expires_at")
                        if not expires_str:
                            # Permanent perk — keep it
                            surviving.append(perk)
                            continue

                        expires_dt = datetime.fromisoformat(expires_str)
                        if now < expires_dt:
                            surviving.append(perk)
                            continue

                        # ── Perk has expired — take action ────────────
                        perk_type = perk.get("type")
                        log.info("SHOP: Perk '%s' expired for user %s.", perk_type, user_id)
                        dirty = True

                        member = guild.get_member(int(user_id))
                        if member is None:
                            continue  # Left the server — just drop the record

                        try:
                            if perk_type == "vip":
                                role_id: int | None = perk.get("role_id")
                                if role_id:
                                    vip_role = guild.get_role(role_id)
                                    if vip_role and vip_role in member.roles:
                                        await member.remove_roles(vip_role, reason="Shop: VIP perk expired")
                                        log.info("SHOP: Removed VIP role from %s.", member)

                            elif perk_type == "nickname":
                                original = perk.get("original_nick")  # None = no custom nick
                                await member.edit(nick=original, reason="Shop: nickname perk expired")
                                log.info("SHOP: Reverted nickname for %s to %r.", member, original)

                        except discord.Forbidden:
                            log.warning("SHOP: Forbidden reverting '%s' for %s.", perk_type, member)
                        except Exception:  # pylint: disable=broad-except
                            log.exception("SHOP: Error reverting '%s' for %s.", perk_type, member)

                    shop_data["active_perks"][user_id] = surviving

            if dirty:
                await save_shop_data(shop_data)

    @expire_perks.before_loop
    async def _before_expire_perks(self) -> None:
        await self.bot.wait_until_ready()


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ShopCog(bot))
