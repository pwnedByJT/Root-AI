"""
cogs/recon.py
Phase 1 — Autonomous OSINT & Attack Surface Mapping

Slash command: /recon <target_domain>

Pipeline (runs concurrently):
  1. crt.sh Certificate Transparency log query — passive subdomain enumeration
  2. subfinder (Parrot OS SSH) — active subdomain enumeration
  3. assetfinder (Parrot OS SSH) — active subdomain enumeration
  4. Shodan host intel — api.host(ip) per resolved IP (free tier, sequential)
  5. Nmap scan via the existing SSH→Parrot OS tunnel (reuses run_parrot_nmap_scan)

Output:
  - Rich Discord Embed: subdomains, Shodan services/CVEs, open ports, scan metadata
  - ReconView: "Send to Auto-Pwn" button (Phase 2 stub — result cached in View)

Security boundaries:
  - /recon is restricted to the bot owner (BOT_OWNER_ID) at the code level.
  - FQDN regex validation runs before any network call to prevent injection/SSRF.
  - Resolved IPs are re-validated against _PRIVATE_RANGE_RE before Shodan lookup.
  - crt.sh is read-only passive recon — no active probing on that path.
  - Nmap is rate-limited to T4 timing; target is validated before SSH dispatch.
  - Shodan api.host() is called sequentially (1 req/s free-tier limit).
  - Shodan is skipped entirely when SHODAN_API_KEY is not set.

Phase 2 integration point:
  - ReconResult dataclass is the contract between Phase 1 and Phase 2.
  - When Phase 2 (auto-pwn) is implemented, ReconView.autopwn_button should
    call the AutoPwnCog pipeline and pass result.domain + result.open_ports.
  - ShodanResult is included in ReconResult and seeded into the AutoPwn LLM context.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID, NVD_API_KEY, SHODAN_API_KEY
from cogs.security import run_parrot_command, run_parrot_nmap_scan

log = logging.getLogger("root_ai.recon")

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# Strict FQDN regex — must match before any outbound request is made.
# Prevents command injection, SSRF against internal IPs, and malformed input.
_FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Block private/loopback ranges from being targeted — belt-and-suspenders SSRF guard.
_PRIVATE_RANGE_RE = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


def _validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate *domain* as a public FQDN.

    Returns (True, cleaned_domain) on success or (False, error_message) on failure.
    """
    clean = domain.strip().lower()
    if _PRIVATE_RANGE_RE.match(clean):
        return False, f"`{domain}` resolves to a private/loopback range — not allowed."
    if not _FQDN_RE.match(clean):
        return False, f"`{domain}` is not a valid fully-qualified domain name."
    if len(clean) > 253:
        return False, "Domain name exceeds the 253-character FQDN limit."
    return True, clean


# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------


@dataclass
class ShodanResult:
    """
    Shodan host intelligence snapshot for all IPs resolved from a domain.

    services entries have shape:
        {"port": int, "proto": str, "product": str, "version": str,
         "cpe": str, "banner": str}   (banner truncated to 200 chars)
    """

    ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)  # CVE IDs


@dataclass
class CVEDetail:
    """
    Enriched CVE data from the NVD 2.0 API.

    score    — CVSS base score (v3.1 preferred, v3.0 fallback, v2 last resort)
    severity — CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    description — first 200 chars of the English description
    """

    cve_id: str
    score: Optional[float]
    severity: str
    description: str


@dataclass
class ReconResult:
    """
    Immutable snapshot of a completed recon run.
    Passed to ReconView so the "Send to Auto-Pwn" button can hand it to Phase 2.
    """

    domain: str
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    raw_nmap: str = ""
    shodan_data: Optional[ShodanResult] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OSINT helpers
# ---------------------------------------------------------------------------

# Maximum subdomains to display in the embed (crt.sh can return thousands)
_MAX_DISPLAY_SUBS = 30


async def _crtsh_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains of *domain*.

    Returns a deduplicated, sorted list of subdomains (wildcards excluded).
    Returns an empty list on any network or parse error.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=25),
            ) as resp:
                if resp.status != 200:
                    log.warning("crt.sh returned HTTP %d for %s", resp.status, domain)
                    return []
                data = await resp.json(content_type=None)

        seen: set[str] = set()
        results: list[str] = []
        apex = domain.lower()

        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                # Skip wildcards, the apex domain itself, and duplicates
                if (
                    not name
                    or name.startswith("*.")
                    or name == apex
                    or name in seen
                ):
                    continue
                # Only keep names that are subdomains of the target
                if name.endswith(f".{apex}"):
                    seen.add(name)
                    results.append(name)

        log.info("crt.sh: %d unique subdomains for %s", len(results), domain)
        return sorted(results)

    except asyncio.TimeoutError:
        log.warning("crt.sh timed out for %s", domain)
        return []
    except Exception as exc:  # pylint: disable=broad-except
        log.error("crt.sh error for %s: %s", domain, exc)
        return []


async def _subfinder_subdomains(domain: str) -> list[str]:
    """
    Run subfinder on Parrot OS via SSH and return discovered subdomains.

    Requires subfinder to be installed on the Parrot host (free / open-source).
    Returns [] gracefully if the binary is missing or the SSH call fails.
    """
    try:
        cmd = f"subfinder -d '{domain}' -silent -all 2>/dev/null | head -500"
        output = await run_parrot_command(cmd, timeout=60)
        if "command not found" in output or not output.strip():
            return []
        results = [
            line.strip().lower()
            for line in output.splitlines()
            if line.strip() and line.strip().endswith(f".{domain.lower()}")
        ]
        log.info("subfinder: %d subdomains for %s", len(results), domain)
        return sorted(set(results))
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("subfinder failed for %s: %s", domain, exc)
        return []


async def _assetfinder_subdomains(domain: str) -> list[str]:
    """
    Run assetfinder on Parrot OS via SSH and return discovered subdomains.

    Requires assetfinder to be installed on the Parrot host (free / open-source).
    Returns [] gracefully if the binary is missing or the SSH call fails.
    """
    try:
        cmd = f"assetfinder --subs-only '{domain}' 2>/dev/null | head -200"
        output = await run_parrot_command(cmd, timeout=45)
        if "command not found" in output or not output.strip():
            return []
        results = [
            line.strip().lower()
            for line in output.splitlines()
            if line.strip() and line.strip().endswith(f".{domain.lower()}")
        ]
        log.info("assetfinder: %d subdomains for %s", len(results), domain)
        return sorted(set(results))
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("assetfinder failed for %s: %s", domain, exc)
        return []


async def gather_subdomains(domain: str) -> list[str]:
    """
    Combine crt.sh + subfinder + assetfinder results into a single deduplicated list.

    Public API — importable by ``cogs.watchdog`` to avoid code duplication.
    All three sources run concurrently; any that fail are silently skipped.
    """
    results = await asyncio.gather(
        _crtsh_subdomains(domain),
        _subfinder_subdomains(domain),
        _assetfinder_subdomains(domain),
        return_exceptions=True,
    )
    merged: set[str] = set()
    for r in results:
        if isinstance(r, list):
            merged.update(r)
    return sorted(merged)


def _resolve_ips(domain: str) -> list[str]:
    """Resolve *domain* to a deduplicated list of public IPv4 addresses (sync)."""
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        seen: set[str] = set()
        results: list[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in seen and not _PRIVATE_RANGE_RE.match(ip):
                seen.add(ip)
                results.append(ip)
        return results[:3]  # cap at 3 — conserve free-tier credits
    except Exception:  # pylint: disable=broad-except
        return []


async def _shodan_host_info(domain: str) -> Optional[ShodanResult]:
    """
    Query Shodan for host intel on all public IPs resolved from *domain*.

    Uses only ``api.host(ip)`` — free tier, no query credits consumed.
    IPs are queried **sequentially** to respect the 1 req/s free-tier rate limit.

    Returns None if SHODAN_API_KEY is not set.
    Returns a (possibly empty) ShodanResult on any other outcome so the caller
    can always distinguish "not configured" from "no results".
    """
    if not SHODAN_API_KEY:
        return None

    try:
        import shodan  # local import — only required when key is configured
    except ImportError:
        log.warning("Shodan library not installed — run: pip install shodan")
        return None

    api = shodan.Shodan(SHODAN_API_KEY)
    ips = await asyncio.to_thread(_resolve_ips, domain)

    if not ips:
        log.info("Shodan: no public IPs resolved for %s", domain)
        return ShodanResult()

    result = ShodanResult(ips=ips)

    for ip in ips:
        try:
            host = await asyncio.to_thread(api.host, ip)
        except shodan.APIError as exc:
            msg = str(exc).lower()
            if "no information available" in msg:
                log.debug("Shodan: no data for %s (%s)", ip, domain)
                continue  # normal — host not indexed
            if "invalid api key" in msg or "access denied" in msg:
                log.error("Shodan: API key rejected — %s", exc)
                result  # return whatever we have so far
                break
            log.warning("Shodan: API error for %s: %s", ip, exc)
            continue
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("Shodan: unexpected error for %s: %s", ip, exc)
            continue

        # Collect unique hostnames
        for hn in host.get("hostnames", []):
            if hn not in result.hostnames:
                result.hostnames.append(hn)

        # Collect CVEs
        for cve in host.get("vulns", {}).keys():
            if cve not in result.vulns:
                result.vulns.append(cve)

        # Collect services — include 'ip' so consumers can track per-IP port state
        for item in host.get("data", []):
            service: dict = {
                "ip": ip,
                "port": item.get("port", 0),
                "proto": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "cpe": (item.get("cpe", [""])[0] if item.get("cpe") else ""),
                "banner": (item.get("data", "") or "")[:200].strip(),
            }
            result.services.append(service)

    log.info(
        "Shodan: %s — %d IP(s), %d service(s), %d CVE(s)",
        domain, len(ips), len(result.services), len(result.vulns),
    )
    return result


async def enrich_cves(cve_ids: list[str]) -> list[CVEDetail]:
    """
    Fetch CVSS scores and descriptions for *cve_ids* from the NVD 2.0 API.

    Rate limits (rolling 30-second window):
      - No key (NVD_API_KEY unset): 5 req / 30 s → 6.5 s inter-request sleep
      - With NVD_API_KEY:          50 req / 30 s → 0.6 s inter-request sleep

    Caps at 5 CVEs regardless of key status to bound total wait time.
    Returns a (possibly shorter) list of CVEDetail; gracefully skips any
    CVE unknown to NVD (HTTP 404) or that times out.
    Public API — importable by ``cogs.autopwn`` and ``cogs.watchdog``.
    """
    if not cve_ids:
        return []

    # Authenticated tier: 50 req/30s (0.6s sleep); unauthenticated: 5 req/30s (6.5s sleep)
    _sleep = 0.6 if NVD_API_KEY else 6.5
    _headers: dict[str, str] = {"Accept": "application/json"}
    if NVD_API_KEY:
        _headers["apiKey"] = NVD_API_KEY

    results: list[CVEDetail] = []
    async with aiohttp.ClientSession() as session:
        for i, cve_id in enumerate(cve_ids[:5]):  # hard cap at 5
            if i > 0:
                await asyncio.sleep(_sleep)
            try:
                async with session.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id},
                    headers=_headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 404:
                        log.debug("NVD: %s not yet indexed (404)", cve_id)
                        continue
                    if resp.status != 200:
                        log.warning("NVD: unexpected HTTP %d for %s", resp.status, cve_id)
                        continue
                    data = await resp.json(content_type=None)

                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    continue

                cve_obj = vulns[0]["cve"]
                score: Optional[float] = None
                severity: str = "UNKNOWN"
                metrics = cve_obj.get("metrics", {})

                # CVSS priority: v3.1 → v3.0 → v2
                for mk in ("cvssMetricV31", "cvssMetricV30"):
                    if mk in metrics and metrics[mk]:
                        cd = metrics[mk][0]["cvssData"]
                        score = cd.get("baseScore")
                        severity = cd.get("baseSeverity", "UNKNOWN")
                        break

                if score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cd = metrics["cvssMetricV2"][0]["cvssData"]
                    score = cd.get("baseScore")
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

                descs = cve_obj.get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
                results.append(
                    CVEDetail(
                        cve_id=cve_id,
                        score=score,
                        severity=severity,
                        description=desc[:200],
                    )
                )
                log.debug("NVD: enriched %s — score=%s severity=%s", cve_id, score, severity)

            except asyncio.TimeoutError:
                log.warning("NVD: timeout for %s", cve_id)
                continue
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("NVD: error for %s: %s", cve_id, exc)
                continue

    log.info("NVD: enriched %d/%d CVE(s)", len(results), min(len(cve_ids), 5))
    return results


def _parse_open_ports(nmap_output: str) -> list[str]:
    """
    Extract open port lines from nmap stdout.

    Example input line:
        ``80/tcp   open  http    nginx 1.18.0``
    Returns lines as-is, stripped of leading whitespace.
    """
    ports = []
    for line in nmap_output.splitlines():
        stripped = line.strip()
        if ("open" in stripped) and ("/" in stripped):
            # Match lines like "80/tcp open ..."
            if re.match(r"^\d+/(tcp|udp)\s+open", stripped):
                ports.append(stripped)
    return ports


# ---------------------------------------------------------------------------
# Discord UI — Embed builder
# ---------------------------------------------------------------------------


def _build_recon_embed(
    result: ReconResult,
    enriched_cves: list[CVEDetail] | None = None,
) -> discord.Embed:
    """Build the main recon report embed from a completed ReconResult."""
    embed = discord.Embed(
        title=f"🔍 Recon Report — `{result.domain}`",
        description=(
            "Passive enumeration via **crt.sh** + **subfinder** + **assetfinder** + **Shodan** "
            "& active port scan via **Parrot OS / nmap**.\n\n"
            "⚠️ *Use only on targets you own or have explicit written permission to test.*"
        ),
        color=discord.Color.from_rgb(220, 50, 50),
        timestamp=result.timestamp,
    )

    # ── Subdomains field ─────────────────────────────────────────────────────
    total_subs = len(result.subdomains)
    if result.subdomains:
        display = result.subdomains[:_MAX_DISPLAY_SUBS]
        sub_text = "\n".join(f"`{s}`" for s in display)
        if total_subs > _MAX_DISPLAY_SUBS:
            sub_text += f"\n`... +{total_subs - _MAX_DISPLAY_SUBS} more`"
        embed.add_field(
            name=f"🌐 Subdomains  ({total_subs} discovered)",
            value=sub_text[:1020],
            inline=False,
        )
    else:
        embed.add_field(
            name="🌐 Subdomains",
            value="None discovered via passive CT log recon.",
            inline=False,
        )

    # ── Open ports field ─────────────────────────────────────────────────────
    total_ports = len(result.open_ports)
    if result.open_ports:
        ports_text = "\n".join(f"`{p}`" for p in result.open_ports[:20])
        if total_ports > 20:
            ports_text += f"\n`... +{total_ports - 20} more`"
        embed.add_field(
            name=f"🔓 Open Ports  ({total_ports} found)",
            value=ports_text[:1020],
            inline=False,
        )
    else:
        embed.add_field(
            name="🔓 Open Ports",
            value=(
                "No open ports detected in the top-500 scan.\n"
                "`Run /recon again with a deeper scan flag for full coverage.`"
            ),
            inline=False,
        )

    # ── Shodan Intel field ───────────────────────────────────────────────────
    sd = result.shodan_data
    if sd is not None:
        if sd.services or sd.vulns or sd.hostnames:
            lines: list[str] = []
            if sd.ips:
                lines.append(f"**IPs:** {', '.join(f'`{ip}`' for ip in sd.ips)}")
            if sd.hostnames:
                hn_display = sd.hostnames[:5]
                lines.append("**Hostnames:** " + ", ".join(f"`{h}`" for h in hn_display))
            if sd.services:
                svc_lines = []
                for svc in sd.services[:10]:
                    parts = f"`{svc['port']}/{svc['proto']}`"
                    if svc["product"]:
                        parts += f" {svc['product']}"
                        if svc["version"]:
                            parts += f" {svc['version']}"
                    svc_lines.append(parts)
                if len(sd.services) > 10:
                    svc_lines.append(f"`... +{len(sd.services) - 10} more`")
                lines.append("**Services:**\n" + "\n".join(svc_lines))
            # CVEs shown here only when not enriched — enriched path uses its own field below
            if sd.vulns and not enriched_cves:
                cve_text = " ".join(f"`{v}`" for v in sd.vulns[:10])
                if len(sd.vulns) > 10:
                    cve_text += f" `+{len(sd.vulns) - 10} more`"
                lines.append(f"**⚠️ CVEs ({len(sd.vulns)}):** {cve_text}")
            embed.add_field(
                name="🔭 Shodan Intel",
                value="\n".join(lines)[:1020],
                inline=False,
            )
        else:
            embed.add_field(
                name="🔭 Shodan Intel",
                value="Host not indexed or no open services recorded.",
                inline=False,
            )

    # ── CVE Enrichment field (separate field when NVD data available) ────────
    if sd and sd.vulns and enriched_cves:
        enriched_ids = {d.cve_id for d in enriched_cves}
        cve_lines: list[str] = []
        for detail in enriched_cves:
            score_str = f"{detail.score:.1f}" if detail.score is not None else "N/A"
            desc = detail.description[:120]
            cve_lines.append(
                f"`{detail.cve_id}` **[{detail.severity} {score_str}]**\n{desc}"
            )
        unenriched = [v for v in sd.vulns if v not in enriched_ids]
        if unenriched:
            cve_lines.append(
                "Also reported: " + " ".join(f"`{v}`" for v in unenriched[:10])
                + (f" `+{len(unenriched) - 10} more`" if len(unenriched) > 10 else "")
            )
        embed.add_field(
            name=f"⚠️ CVEs — Enriched  ({len(sd.vulns)} total, {len(enriched_cves)} scored)",
            value="\n".join(cve_lines)[:1020],
            inline=False,
        )
    # sd is None → SHODAN_API_KEY not set; omit the field entirely

    # ── Error notes (if any partial failures occurred) ───────────────────────
    if result.error_notes:
        embed.add_field(
            name="⚠️ Scan Notes",
            value="\n".join(f"• {n}" for n in result.error_notes)[:512],
            inline=False,
        )

    embed.set_footer(text="Root AI • Phase 1 OSINT Engine  |  Authorised use only")
    return embed


# ---------------------------------------------------------------------------
# Discord UI — Button View
# ---------------------------------------------------------------------------


class ReconView(discord.ui.View):
    """
    Interactive view attached to the recon embed.

    Holds the ReconResult so the button callback can pass it to Phase 2
    without needing a global cache or database lookup.
    """

    def __init__(self, result: ReconResult) -> None:
        super().__init__(timeout=300)  # 5-minute window
        self.result = result

    @discord.ui.button(
        label="Send to Auto-Pwn",
        style=discord.ButtonStyle.danger,
        emoji="⚡",
    )
    async def autopwn_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Phase 2 integration point — stub until Auto-Pwn pipeline is built."""
        # Hard owner check on every button press
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ **Auto-Pwn** is restricted to the server administrator.",
                ephemeral=True,
            )
            return

        # Disable the button to prevent double-fire
        button.disabled = True
        button.label = "⏳ Running Auto-Pwn..."
        button.emoji = discord.PartialEmoji(name="⏳")
        await interaction.response.edit_message(view=self)

        # ── Phase 2 handoff ───────────────────────────────────────────────
        # edit_message() has consumed the interaction response; all further
        # Discord messages in start_autopwn() use interaction.followup.
        autopwn_cog = interaction.client.get_cog("AutoPwn")
        if autopwn_cog is None:
            await interaction.followup.send(
                "⚠️ AutoPwn cog is not loaded — check bot startup logs.",
                ephemeral=True,
            )
            return
        await autopwn_cog.start_autopwn(interaction, self.result)

    @discord.ui.button(
        label="Brute Subs",
        style=discord.ButtonStyle.secondary,
        emoji="🔨",
    )
    async def brute_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Phase 12 integration point — active DNS brute-force via gobuster."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ **Brute Subs** is restricted to the server administrator.",
                ephemeral=True,
            )
            return

        button.disabled = True
        button.label = "⏳ Bruting..."
        button.emoji = discord.PartialEmoji(name="⏳")
        await interaction.response.edit_message(view=self)

        brute_cog = interaction.client.get_cog("SubdomainBrute")
        if brute_cog is None:
            await interaction.followup.send(
                "⚠️ SubdomainBrute cog is not loaded — check bot startup logs.",
                ephemeral=True,
            )
            return
        await brute_cog.start_brute(
            interaction, self.result.domain, passive_known=self.result.subdomains
        )

    @discord.ui.button(
        label="WHOIS",
        style=discord.ButtonStyle.secondary,
        emoji="🌍",
    )
    async def whois_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Phase 14 integration point — WHOIS & ASN lookup for the recon domain."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ **WHOIS** is restricted to the server administrator.",
                ephemeral=True,
            )
            return

        button.disabled = True
        button.label = "⏳ Looking up..."
        button.emoji = discord.PartialEmoji(name="⏳")
        await interaction.response.edit_message(view=self)

        whois_cog = interaction.client.get_cog("WhoisMapper")
        if whois_cog is None:
            await interaction.followup.send(
                "⚠️ WhoisMapper cog is not loaded — check bot startup logs.",
                ephemeral=True,
            )
            return
        await whois_cog.start_whois(interaction, self.result.domain)

    @discord.ui.button(
        label="SSL",
        style=discord.ButtonStyle.secondary,
        emoji="🔒",
    )
    async def ssl_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Phase 15 integration point — SSL/TLS inspection for the recon domain."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ **SSL Inspector** is restricted to the server administrator.",
                ephemeral=True,
            )
            return

        button.disabled = True
        button.label = "⏳ Scanning..."
        button.emoji = discord.PartialEmoji(name="⏳")
        await interaction.response.edit_message(view=self)

        ssl_cog = interaction.client.get_cog("SSLInspector")
        if ssl_cog is None:
            await interaction.followup.send(
                "⚠️ SSLInspector cog is not loaded — check bot startup logs.",
                ephemeral=True,
            )
            return
        await ssl_cog.start_ssl_check(interaction, self.result.domain)

    async def on_timeout(self) -> None:
        """Disable all buttons when the view expires to prevent stale interactions."""
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                item.disabled = True


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class ReconCog(commands.Cog, name="Recon"):
    """
    Phase 1 — OSINT & Attack Surface Mapping.

    Orchestrates passive subdomain enumeration (crt.sh) and active port
    scanning (Nmap via Parrot OS SSH) behind a single Discord slash command.
    Results are surfaced as a rich Embed with a Phase 2 integration button.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(
        name="recon",
        description="[OWNER] Run OSINT recon on a bug bounty / authorised target domain.",
    )
    @app_commands.describe(
        target_domain="Fully-qualified domain name to recon (e.g. example.com)",
    )
    async def recon(
        self, interaction: discord.Interaction, target_domain: str
    ) -> None:
        """
        Phase 1 entry point.

        Runs crt.sh subdomain enum and nmap concurrently, then renders
        a rich Discord embed with an Auto-Pwn hand-off button.
        """
        # ── Owner gate ────────────────────────────────────────────────────────
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/recon` is an owner-only command.",
                ephemeral=True,
            )
            return

        # ── Input validation ─────────────────────────────────────────────────
        valid, clean_domain_or_err = _validate_domain(target_domain)
        if not valid:
            await interaction.response.send_message(
                f"⚠️ Invalid target: {clean_domain_or_err}", ephemeral=True
            )
            return

        clean_domain: str = clean_domain_or_err

        # ── Defer immediately — pipeline takes > 3 seconds ───────────────────
        await interaction.response.defer(thinking=True)
        log.info("RECON: Starting recon on '%s' for user %s", clean_domain, interaction.user)

        # ── Run OSINT tools concurrently ─────────────────────────────────────
        # gather_subdomains (crt.sh + subfinder + assetfinder, ~5–60 s),
        # _shodan_host_info (sequential per IP, ~5–15 s), and
        # nmap (active, ~15–60 s) all run concurrently at the top level.
        # Note: Shodan IPs are queried sequentially *within* _shodan_host_info
        # to honour the 1 req/s free-tier rate limit.
        nmap_args = "-T4 --top-ports 500 --open"
        results = await asyncio.gather(
            gather_subdomains(clean_domain),
            run_parrot_nmap_scan(clean_domain, nmap_args),
            _shodan_host_info(clean_domain),
            return_exceptions=True,
        )
        subdomains_raw, nmap_output_raw, shodan_raw = results

        # Gracefully degrade if any task failed
        error_notes: list[str] = []
        subdomains: list[str] = []
        nmap_output: str = ""
        shodan_data: Optional[ShodanResult] = None

        if isinstance(subdomains_raw, Exception):
            log.error("RECON: subdomain gather failed: %s", subdomains_raw)
            error_notes.append(f"Subdomain enumeration failed: {subdomains_raw}")
        else:
            subdomains = subdomains_raw  # type: ignore[assignment]

        if isinstance(nmap_output_raw, Exception):
            log.error("RECON: nmap failed: %s", nmap_output_raw)
            error_notes.append(f"Nmap scan failed: {nmap_output_raw}")
        else:
            nmap_output = nmap_output_raw  # type: ignore[assignment]

        if isinstance(shodan_raw, Exception):
            log.error("RECON: Shodan failed: %s", shodan_raw)
            error_notes.append(f"Shodan lookup failed: {shodan_raw}")
        else:
            shodan_data = shodan_raw  # type: ignore[assignment]

        open_ports = _parse_open_ports(nmap_output)
        log.info(
            "RECON: %s — %d subdomains, %d open ports",
            clean_domain,
            len(subdomains),
            len(open_ports),
        )

        # ── Build result ──────────────────────────────────────────────────────
        result = ReconResult(
            domain=clean_domain,
            subdomains=subdomains,
            open_ports=open_ports,
            raw_nmap=nmap_output,
            shodan_data=shodan_data,
            error_notes=error_notes,
        )

        # ── Enrich CVEs via NVD (cap 5; ~32s at free-tier rate) ──────────────
        enriched_cves: list[CVEDetail] = []
        if shodan_data and shodan_data.vulns:
            log.info(
                "RECON: enriching %d CVE(s) via NVD for %s",
                min(len(shodan_data.vulns), 5),
                clean_domain,
            )
            enriched_cves = await enrich_cves(shodan_data.vulns)

        embed = _build_recon_embed(result, enriched_cves=enriched_cves or None)
        view = ReconView(result)

        await interaction.followup.send(embed=embed, view=view)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ReconCog(bot))
