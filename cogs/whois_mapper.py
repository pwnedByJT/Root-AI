"""
cogs/whois_mapper.py
Phase 14 — WHOIS & ASN Mapper

Public API:    lookup_whois(target) -> WhoisResult
Slash command: /whois <target>
Button:        ReconView → "🌍 WHOIS" → WhoisMapperCog.start_whois()

Data sources:
  - RDAP (rdap.org)  — domain registration, IP network blocks
  - ipinfo.io        — ASN, org, country, city (50k req/month free; optional token)

Design notes:
  - target can be a domain (FQDN) or an IPv4/IPv6 address.
  - SSRF guard blocks private/loopback IPs before any outbound HTTP call.
  - vCard fields parsed by property name (prop[0]), never by position — registries
    return fields in different orders; positional indexing silently returns garbage.
  - GDPR/ICANN post-2018: most registrant fields are redacted; embed omits empty
    lines and appends a GDPR footnote when no registrant data is rendered.
  - All HTTP calls share one aiohttp.ClientSession per lookup_whois() invocation.
  - asyncio.Semaphore(2) throttles concurrent HTTP fan-out.
  - No watchdog integration — domain registration changes are not usefully alertable.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID, IPINFO_TOKEN

log = logging.getLogger("root_ai.whois_mapper")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RDAP_DOMAIN_URL = "https://rdap.org/domain/{}"
_RDAP_IP_URL = "https://rdap.org/ip/{}"
_IPINFO_URL = "https://ipinfo.io/{}/json"

_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=20)
_SEM = asyncio.Semaphore(2)  # max concurrent outbound HTTP calls

# ---------------------------------------------------------------------------
# Input validation — SSRF guard
# ---------------------------------------------------------------------------

_PRIVATE_RANGE_RE = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|0\.0\.0\.0)"
)

_FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _ssrf_guard(ip: str) -> bool:
    """Return True if *ip* is a globally-routable (safe) address."""
    if _PRIVATE_RANGE_RE.match(ip):
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# vCard helpers
# ---------------------------------------------------------------------------


def _vcard_get(vcard_array: list, prop_name: str) -> str:
    """
    Extract the first value of *prop_name* from a jCard/vCard array.

    vCard entries are [name, params, type, value] but registries may omit or
    reorder fields — always iterate by prop[0], never by index.
    Strips the ``tel:`` URI prefix from telephone values.
    """
    for prop in vcard_array:
        if not isinstance(prop, list) or not prop:
            continue
        if prop[0] == prop_name:
            val = prop[3] if len(prop) > 3 else ""
            if not isinstance(val, str):
                val = str(val) if val else ""
            if prop_name == "tel":
                val = val.removeprefix("tel:")
            return val.strip()
    return ""


# ---------------------------------------------------------------------------
# Country flag emoji
# ---------------------------------------------------------------------------


def _country_flag(cc: str) -> str:
    """Convert a 2-letter ISO 3166-1 alpha-2 code to the Unicode flag emoji."""
    if not cc or len(cc) < 2:
        return ""
    cc = cc.upper()
    try:
        return (
            chr(0x1F1E6 + ord(cc[0]) - ord("A"))
            + chr(0x1F1E6 + ord(cc[1]) - ord("A"))
        )
    except (ValueError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# RDAP entity traversal
# ---------------------------------------------------------------------------


def _find_entity_by_role(entities: list[dict], role: str) -> Optional[dict]:
    """Recursively search an RDAP entity list for the first entity with *role*."""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if role in entity.get("roles", []):
            return entity
        nested = entity.get("entities", [])
        if nested:
            found = _find_entity_by_role(nested, role)
            if found:
                return found
    return None


def _entity_vcard_field(entity: Optional[dict], prop_name: str) -> str:
    """Pull a vCard field value from an RDAP entity's vcardArray."""
    if entity is None:
        return ""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    return _vcard_get(vcard[1], prop_name)


# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------


@dataclass
class DomainWhoisResult:
    """Registration data extracted from an RDAP domain lookup."""

    registrar: str = ""
    registrar_abuse_email: str = ""
    created: str = ""
    expires: str = ""
    last_changed: str = ""
    status: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    dnssec: bool = False
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_country: str = ""
    registrant_email: str = ""
    error: str = ""


@dataclass
class IPInfoResult:
    """ASN + geolocation data for a single IP (ipinfo.io merged with RDAP IP)."""

    ip: str = ""
    asn: str = ""
    org_name: str = ""
    network_name: str = ""
    cidr: str = ""
    country: str = ""
    city: str = ""
    abuse_email: str = ""
    error: str = ""


@dataclass
class WhoisResult:
    """Top-level result returned by lookup_whois()."""

    target: str = ""
    is_ip: bool = False
    domain_whois: Optional[DomainWhoisResult] = None
    ip_infos: list[IPInfoResult] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


def _ipinfo_headers() -> dict[str, str]:
    h: dict[str, str] = {"Accept": "application/json"}
    if IPINFO_TOKEN:
        h["Authorization"] = f"Bearer {IPINFO_TOKEN}"
    return h


async def _rdap_domain(domain: str, session: aiohttp.ClientSession) -> DomainWhoisResult:
    """Fetch and parse an RDAP domain record."""
    result = DomainWhoisResult()
    url = _RDAP_DOMAIN_URL.format(domain)
    try:
        async with _SEM:
            async with session.get(url, timeout=_HTTP_TIMEOUT) as resp:
                if resp.status != 200:
                    result.error = f"RDAP HTTP {resp.status}"
                    return result
                data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        result.error = "RDAP domain timeout"
        return result
    except Exception as exc:  # pylint: disable=broad-except
        result.error = f"RDAP domain error: {exc}"
        return result

    # Events
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")[:10]
        if action == "registration":
            result.created = date
        elif action == "expiration":
            result.expires = date
        elif action == "last changed":
            result.last_changed = date

    result.status = data.get("status", [])
    result.nameservers = [
        ns.get("ldhName", "").lower()
        for ns in data.get("nameservers", [])
        if ns.get("ldhName")
    ]
    result.dnssec = bool(data.get("secureDNS", {}).get("delegationSigned", False))

    entities = data.get("entities", [])
    registrar_entity = _find_entity_by_role(entities, "registrar")
    registrant_entity = _find_entity_by_role(entities, "registrant")

    result.registrar = _entity_vcard_field(registrar_entity, "fn")
    result.registrar_abuse_email = _entity_vcard_field(registrar_entity, "email")
    result.registrant_name = _entity_vcard_field(registrant_entity, "fn")
    result.registrant_org = _entity_vcard_field(registrant_entity, "org")
    result.registrant_email = _entity_vcard_field(registrant_entity, "email")

    # Country lives inside the 'adr' vCard property as a 7-element list
    if registrant_entity:
        vcard = registrant_entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and prop and prop[0] == "adr":
                    adr_val = prop[3] if len(prop) > 3 else []
                    if isinstance(adr_val, list) and len(adr_val) >= 7:
                        result.registrant_country = str(adr_val[6] or "")
                    break

    log.info("RDAP domain: %s → registrar=%r created=%r", domain, result.registrar, result.created)
    return result


async def _ipinfo(ip: str, session: aiohttp.ClientSession) -> IPInfoResult:
    """Query ipinfo.io for ASN, org, country, and city for a single IP."""
    result = IPInfoResult(ip=ip)
    url = _IPINFO_URL.format(ip)
    try:
        async with _SEM:
            async with session.get(url, headers=_ipinfo_headers(), timeout=_HTTP_TIMEOUT) as resp:
                if resp.status != 200:
                    result.error = f"ipinfo.io HTTP {resp.status}"
                    return result
                data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        result.error = "ipinfo.io timeout"
        return result
    except Exception as exc:  # pylint: disable=broad-except
        result.error = f"ipinfo.io error: {exc}"
        return result

    org_raw = data.get("org", "")
    if org_raw and " " in org_raw:
        result.asn, result.org_name = org_raw.split(" ", 1)
    else:
        result.org_name = org_raw

    result.country = data.get("country", "")
    result.city = data.get("city", "")
    abuse_obj = data.get("abuse", {})
    result.abuse_email = abuse_obj.get("email", "") if isinstance(abuse_obj, dict) else ""

    log.info("ipinfo: %s → asn=%r org=%r country=%r", ip, result.asn, result.org_name, result.country)
    return result


async def _rdap_ip(ip: str, session: aiohttp.ClientSession) -> dict:
    """
    Fetch RDAP IP record for network name, CIDR block, and abuse contact.

    Returns a plain dict (never raises) — merged into IPInfoResult by callers.
    """
    out: dict = {"network_name": "", "cidr": "", "abuse_email": ""}
    url = _RDAP_IP_URL.format(ip)
    try:
        async with _SEM:
            async with session.get(url, timeout=_HTTP_TIMEOUT) as resp:
                if resp.status != 200:
                    return out
                data = await resp.json(content_type=None)
    except Exception:  # pylint: disable=broad-except
        return out

    out["network_name"] = data.get("name", "")

    # cidr0_cidrs is a common RDAP extension; fall back to 'handle' (e.g. "1.2.3.0/24")
    cidr_ext = data.get("cidr0_cidrs", [])
    if cidr_ext and isinstance(cidr_ext[0], dict):
        first = cidr_ext[0]
        prefix = first.get("v4prefix", "") or first.get("v6prefix", "")
        length = first.get("length", "")
        if prefix and length != "":
            out["cidr"] = f"{prefix}/{length}"
    if not out["cidr"]:
        handle = data.get("handle", "")
        if "/" in handle:
            out["cidr"] = handle

    abuse_entity = _find_entity_by_role(data.get("entities", []), "abuse")
    out["abuse_email"] = _entity_vcard_field(abuse_entity, "email")

    log.info("RDAP IP: %s → name=%r cidr=%r", ip, out["network_name"], out["cidr"])
    return out


def _resolve_ips(domain: str) -> list[str]:
    """Resolve *domain* to a deduplicated list of globally-routable IPs (max 3, sync)."""
    try:
        infos = socket.getaddrinfo(domain, None)
        seen: set[str] = set()
        results: list[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in seen and _ssrf_guard(ip):
                seen.add(ip)
                results.append(ip)
                if len(results) >= 3:
                    break
        return results
    except Exception:  # pylint: disable=broad-except
        return []


async def _gather_ip_info(ip: str, session: aiohttp.ClientSession) -> IPInfoResult:
    """Run ipinfo.io + RDAP IP concurrently for *ip* and merge into one IPInfoResult."""
    ipinfo_r, rdap_extra = await asyncio.gather(
        _ipinfo(ip, session),
        _rdap_ip(ip, session),
        return_exceptions=True,
    )
    result = (
        ipinfo_r
        if isinstance(ipinfo_r, IPInfoResult)
        else IPInfoResult(ip=ip, error=str(ipinfo_r))
    )
    extra = rdap_extra if isinstance(rdap_extra, dict) else {}

    if not result.network_name:
        result.network_name = extra.get("network_name", "")
    if not result.cidr:
        result.cidr = extra.get("cidr", "")
    if not result.abuse_email:
        result.abuse_email = extra.get("abuse_email", "")

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def lookup_whois(target: str) -> WhoisResult:
    """
    WHOIS + ASN lookup for *target* (domain FQDN or IPv4/IPv6 address).

    Domain:  RDAP registration + ipinfo.io per resolved IP (concurrent).
    IP:      ipinfo.io + RDAP IP block (concurrent), SSRF-guarded.

    Never raises — all errors are captured in the result dataclasses.
    """
    target = target.strip().lower()

    async with aiohttp.ClientSession() as session:
        if _is_ip(target):
            if not _ssrf_guard(target):
                return WhoisResult(
                    target=target,
                    is_ip=True,
                    error="Private/loopback IP addresses are not allowed.",
                )
            ip_info = await _gather_ip_info(target, session)
            return WhoisResult(
                target=target,
                is_ip=True,
                ip_infos=[ip_info],
                resolved_ips=[target],
            )

        # Domain path
        if not _FQDN_RE.match(target):
            return WhoisResult(
                target=target,
                is_ip=False,
                error=f"`{target}` is not a valid fully-qualified domain name.",
            )

        resolved = await asyncio.to_thread(_resolve_ips, target)

        # Fan out: RDAP domain + ipinfo per resolved IP
        tasks: list = [_rdap_domain(target, session)]
        for ip in resolved[:3]:
            tasks.append(_gather_ip_info(ip, session))

        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        domain_whois_raw = gathered[0]
        ip_results_raw = gathered[1:]

        domain_whois = (
            domain_whois_raw
            if isinstance(domain_whois_raw, DomainWhoisResult)
            else DomainWhoisResult(error=str(domain_whois_raw))
        )

        ip_infos: list[IPInfoResult] = []
        for r in ip_results_raw:
            if isinstance(r, IPInfoResult):
                ip_infos.append(r)
            else:
                log.warning("IP info gather error: %s", r)

        return WhoisResult(
            target=target,
            is_ip=False,
            domain_whois=domain_whois,
            ip_infos=ip_infos,
            resolved_ips=resolved,
        )


# ---------------------------------------------------------------------------
# Embed builder
# ---------------------------------------------------------------------------


def _build_whois_embed(result: WhoisResult) -> discord.Embed:
    """Build a rich Discord embed from a WhoisResult."""
    if result.error:
        return discord.Embed(
            title=f"🌍 WHOIS — `{result.target}`",
            description=f"⚠️ {result.error}",
            color=discord.Color.red(),
        )

    embed = discord.Embed(
        title=f"🌍 WHOIS — `{result.target}`",
        color=discord.Color.from_rgb(30, 120, 200),
    )

    gdpr_note = False

    # ── Domain registration section ──────────────────────────────────────────
    if result.domain_whois is not None:
        dw = result.domain_whois
        if dw.error:
            embed.add_field(name="📋 Domain Registration", value=f"⚠️ {dw.error}", inline=False)
        else:
            lines: list[str] = []
            if dw.registrar:
                lines.append(f"**Registrar:** {dw.registrar}")
            if dw.registrar_abuse_email:
                lines.append(f"**Registrar Abuse:** `{dw.registrar_abuse_email}`")
            if dw.created:
                lines.append(f"**Created:** {dw.created}")
            if dw.expires:
                lines.append(f"**Expires:** {dw.expires}")
            if dw.last_changed:
                lines.append(f"**Updated:** {dw.last_changed}")
            if dw.status:
                lines.append("**Status:** " + ", ".join(f"`{s}`" for s in dw.status[:5]))
            if dw.dnssec:
                lines.append("**DNSSEC:** ✅ signed")
            if dw.nameservers:
                lines.append(
                    "**Nameservers:** " + ", ".join(f"`{ns}`" for ns in dw.nameservers[:6])
                )
            embed.add_field(
                name="📋 Domain Registration",
                value="\n".join(lines)[:1020] if lines else "No registration data returned.",
                inline=False,
            )

            # Registrant — omit entirely if all fields are empty (GDPR redacted)
            reg_lines: list[str] = []
            if dw.registrant_name:
                reg_lines.append(f"**Name:** {dw.registrant_name}")
            if dw.registrant_org:
                reg_lines.append(f"**Org:** {dw.registrant_org}")
            if dw.registrant_email:
                reg_lines.append(f"**Email:** `{dw.registrant_email}`")
            if dw.registrant_country:
                flag = _country_flag(dw.registrant_country)
                reg_lines.append(f"**Country:** {flag} {dw.registrant_country}".strip())

            if reg_lines:
                embed.add_field(
                    name="👤 Registrant",
                    value="\n".join(reg_lines)[:1020],
                    inline=False,
                )
            else:
                gdpr_note = True  # no registrant data — GDPR footnote warranted

    # ── IP / ASN section(s) ──────────────────────────────────────────────────
    for ip_info in result.ip_infos[:3]:
        lines2: list[str] = []
        if ip_info.asn:
            lines2.append(f"**ASN:** `{ip_info.asn}`")
        if ip_info.org_name:
            lines2.append(f"**Org:** {ip_info.org_name}")
        if ip_info.network_name:
            lines2.append(f"**Network:** {ip_info.network_name}")
        if ip_info.cidr:
            lines2.append(f"**CIDR:** `{ip_info.cidr}`")
        if ip_info.country:
            flag = _country_flag(ip_info.country)
            lines2.append(f"**Country:** {flag} {ip_info.country}".strip())
        if ip_info.city:
            lines2.append(f"**City:** {ip_info.city}")
        if ip_info.abuse_email:
            lines2.append(f"**Abuse:** `{ip_info.abuse_email}`")
        if ip_info.error:
            lines2.append(f"⚠️ {ip_info.error}")

        embed.add_field(
            name=f"🌐 IP / ASN — `{ip_info.ip}`",
            value="\n".join(lines2)[:1020] if lines2 else "No data returned.",
            inline=False,
        )

    footer = "Root AI • Phase 14 WHOIS & ASN Mapper  |  Authorised use only"
    if gdpr_note:
        footer += "\n⚠️ Registrant data redacted under GDPR / ICANN policy."
    embed.set_footer(text=footer)
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class WhoisMapperCog(commands.Cog, name="WhoisMapper"):
    """
    Phase 14 — WHOIS & ASN Mapper.

    Resolves domain registration data via RDAP (rdap.org) and IP/ASN
    intelligence via ipinfo.io.  Exposes /whois for manual lookups and
    provides start_whois() as a public API consumed by ReconView.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def start_whois(
        self, interaction: discord.Interaction, target: str
    ) -> None:
        """
        Public API for the ReconView "🌍 WHOIS" button.

        Caller must have already consumed the interaction response (e.g. via
        edit_message to disable the button).  All Discord output goes through
        interaction.followup.
        """
        log.info("WhoisMapper: start_whois target=%r user=%s", target, interaction.user)
        result = await lookup_whois(target)
        embed = _build_whois_embed(result)
        await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="whois",
        description="[OWNER] WHOIS & ASN lookup for a domain or IP address.",
    )
    @app_commands.describe(
        target="Domain (e.g. example.com) or IP (e.g. 8.8.8.8)",
    )
    async def whois(
        self,
        interaction: discord.Interaction,
        target: str,
    ) -> None:
        """Phase 14 entry point — manual WHOIS + ASN lookup."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/whois` is an owner-only command.", ephemeral=True
            )
            return

        target_clean = target.strip()
        if not target_clean:
            await interaction.response.send_message(
                "⚠️ Please provide a domain name or IP address.", ephemeral=True
            )
            return

        await interaction.response.defer(thinking=True)
        log.info("WhoisMapper: /whois target=%r user=%s", target_clean, interaction.user)

        result = await lookup_whois(target_clean)
        embed = _build_whois_embed(result)
        await interaction.followup.send(embed=embed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(WhoisMapperCog(bot))
