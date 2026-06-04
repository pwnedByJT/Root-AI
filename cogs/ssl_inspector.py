"""
cogs/ssl_inspector.py
Phase 15 — SSL/TLS Certificate Inspector

Public API:    check_ssl(target, port=443) -> SSLResult
Slash command: /ssl <target> [port]
Button:        ReconView → "🔒 SSL" → SSLInspectorCog.start_ssl_check()

Checks performed (concurrently where possible):
  1. Certificate info — Python ssl module (direct connection from bot host)
       Subject CN/O, Issuer CN/O, validity window, days-to-expiry, SANs,
       negotiated TLS version, negotiated cipher + strength
  2. HSTS header check — aiohttp HTTPS GET to /
       Strict-Transport-Security: max-age, includeSubDomains, preload
  3. TLS cipher suite analysis — nmap --script ssl-enum-ciphers via Parrot SSH
       Supported TLS versions, weak/deprecated ciphers, least cipher grade

Grade (A+ / A / B / C / F):
  F  — cert expired  OR  SSLv2/SSLv3 enabled
  C  — TLS 1.0 or TLS 1.1 enabled  OR  cert expiring within 30 days
  B  — TLS 1.2 max, no HSTS  OR  weak ciphers present
  A  — TLS 1.2+, HSTS present
  A+ — TLS 1.3 supported, HSTS max-age ≥ 31 536 000, no weak ciphers

Security boundaries:
  - FQDN regex + SSRF guard (same pattern as Phase 1 / Phase 14) before any I/O.
  - Private/loopback IPs are rejected before any outbound call.
  - /ssl is restricted to the bot owner (BOT_OWNER_ID).
  - HSTS check uses ssl=False (skips cert verification intentionally — we want
    the header even when the cert is the one under test).
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID
from cogs.security import run_parrot_command

log = logging.getLogger("root_ai.ssl_inspector")

# ---------------------------------------------------------------------------
# Input validation — SSRF guard (same pattern as recon / whois_mapper)
# ---------------------------------------------------------------------------

_FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_PRIVATE_RANGE_RE = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|0\.0\.0\.0)"
)

_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)


def _validate_target(target: str) -> tuple[bool, str]:
    """Validate as public FQDN. Returns (ok, cleaned_host_or_error_message)."""
    clean = target.strip().lower()
    if _PRIVATE_RANGE_RE.match(clean):
        return False, f"`{target}` is a private/loopback address — not allowed."
    if not _FQDN_RE.match(clean):
        return False, f"`{target}` is not a valid fully-qualified domain name."
    return True, clean


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class CertInfo:
    """X.509 certificate metadata extracted via Python's ssl module."""

    subject_cn: str = ""
    subject_org: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_expiring_soon: bool = False       # True when < 30 days remain
    san_domains: list[str] = field(default_factory=list)
    tls_version_negotiated: str = ""     # e.g. "TLSv1.3"
    cipher_negotiated: str = ""          # e.g. "TLS_AES_256_GCM_SHA384"
    cipher_bits: int = 0                 # symmetric cipher strength (not RSA/ECDSA key size)
    error: str = ""


@dataclass
class TLSAnalysis:
    """Cipher suite and TLS version data from nmap ssl-enum-ciphers."""

    tls_versions_enabled: list[str] = field(default_factory=list)   # ["TLSv1.2", "TLSv1.3"]
    tls_versions_weak: list[str] = field(default_factory=list)       # ["TLSv1.0", "TLSv1.1"]
    ciphers_weak: list[str] = field(default_factory=list)            # names graded B or lower
    least_cipher_grade: str = ""                                      # "A" / "B" / "C" / "F"
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    hsts_includesubdomains: bool = False
    hsts_preload: bool = False
    nmap_raw: str = ""                   # raw nmap output (first 500 chars) for debug
    error: str = ""


@dataclass
class SSLResult:
    """Aggregated SSL/TLS inspection result."""

    target: str = ""
    port: int = 443
    cert: Optional[CertInfo] = None
    tls: Optional[TLSAnalysis] = None
    grade: str = "?"                     # A+ / A / B / C / F
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    error: str = ""


# ---------------------------------------------------------------------------
# Certificate info — direct Python ssl connection from bot host
# ---------------------------------------------------------------------------


def _cert_rdns_field(rdns_seq: tuple, field_name: str) -> str:
    """Extract a named field from an ssl.getpeercert() RDNS tuple-of-tuples."""
    for rdn in rdns_seq:
        for attr in rdn:
            if attr[0] == field_name:
                return attr[1]
    return ""


def _parse_cert_dict(cert: dict, cipher_tuple: tuple | None, tls_ver: str) -> CertInfo:
    """Convert ssl.getpeercert() → CertInfo."""
    info = CertInfo()
    info.subject_cn = _cert_rdns_field(cert.get("subject", ()), "commonName")
    info.subject_org = _cert_rdns_field(cert.get("subject", ()), "organizationName")
    info.issuer_cn = _cert_rdns_field(cert.get("issuer", ()), "commonName")
    info.issuer_org = _cert_rdns_field(cert.get("issuer", ()), "organizationName")
    info.serial = cert.get("serialNumber", "")
    info.tls_version_negotiated = tls_ver or ""

    # cipher_tuple is (name, protocol_version, bits) — bits = symmetric cipher strength
    if cipher_tuple:
        info.cipher_negotiated = cipher_tuple[0] or ""
        info.cipher_bits = cipher_tuple[2] or 0

    # Dates — ssl module returns "Jan  1 00:00:00 2025 GMT"
    _fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_after_dt = datetime.strptime(cert.get("notAfter", ""), _fmt).replace(
            tzinfo=timezone.utc
        )
        info.not_after = not_after_dt.strftime("%Y-%m-%d")
        delta = not_after_dt - datetime.now(timezone.utc)
        info.days_until_expiry = delta.days
        info.is_expired = delta.days < 0
        info.is_expiring_soon = 0 <= delta.days < 30
    except ValueError:
        info.not_after = cert.get("notAfter", "")

    try:
        not_before_dt = datetime.strptime(cert.get("notBefore", ""), _fmt)
        info.not_before = not_before_dt.strftime("%Y-%m-%d")
    except ValueError:
        info.not_before = cert.get("notBefore", "")

    # Subject Alternative Names
    info.san_domains = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]

    return info


def _get_cert_sync(host: str, port: int) -> CertInfo:
    """Blocking SSL connect — must be run via executor (see _get_cert_info)."""
    info = CertInfo()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                raw_cert = ssock.getpeercert()
                cipher = ssock.cipher()
                ver = ssock.version() or ""
        return _parse_cert_dict(raw_cert, cipher, ver)
    except ssl.SSLCertVerificationError as exc:
        info.error = f"Certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        info.error = f"SSL error: {exc}"
    except (socket.timeout, TimeoutError):
        info.error = "Connection timed out."
    except OSError as exc:
        info.error = f"Connection failed: {exc}"
    return info


async def _get_cert_info(host: str, port: int) -> CertInfo:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_cert_sync, host, port)


# ---------------------------------------------------------------------------
# HSTS header check
# ---------------------------------------------------------------------------


async def _check_hsts(host: str, port: int) -> tuple[bool, int, bool, bool]:
    """
    GET https://host:port/ and inspect Strict-Transport-Security header.

    Uses ssl=False so we get the header even when the cert is expired/self-signed
    (exactly the case we're testing). Returns (enabled, max_age, includeSubDomains, preload).
    """
    url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector, timeout=_HTTP_TIMEOUT
        ) as session:
            async with session.get(url, allow_redirects=True, max_redirects=5) as resp:
                hsts = resp.headers.get("Strict-Transport-Security", "")
    except Exception:
        return False, 0, False, False

    if not hsts:
        return False, 0, False, False

    max_age = 0
    m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    if m:
        max_age = int(m.group(1))

    incl_sub = "includesubdomains" in hsts.lower()
    preload = "preload" in hsts.lower()
    return True, max_age, incl_sub, preload


# ---------------------------------------------------------------------------
# TLS cipher suite analysis — nmap ssl-enum-ciphers via Parrot SSH
# ---------------------------------------------------------------------------

# Matches TLS version subheaders in nmap ssl-enum-ciphers output, e.g.:
#   |   TLSv1.2:
#   |   TLSv1.3:
#   |   SSLv3:
_TLS_VER_RE = re.compile(r"\|\s+((?:TLS|SSL)v[\w.]+)\s*:", re.IGNORECASE)

# Matches cipher name + grade lines, e.g.:
#   |       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - A
#   |       TLS_RSA_WITH_3DES_EDE_CBC_SHA - C
_CIPHER_LINE_RE = re.compile(
    r"\|\s+((?:TLS|SSL)_\w+|\w{10,})\s+-\s+([A-F])\s*$", re.MULTILINE
)

# Matches the summary line: "|_  least strength: A"
_LEAST_STRENGTH_RE = re.compile(r"least strength\s*:\s*([A-F])", re.IGNORECASE)

# TLS versions we consider weak/deprecated
_WEAK_TLS_VERSIONS = frozenset({"sslv2", "sslv3", "tlsv1.0", "tlsv1.1"})


async def _run_nmap_ssl(host: str, port: int) -> TLSAnalysis:
    """Run nmap ssl-enum-ciphers via Parrot SSH and parse the output."""
    analysis = TLSAnalysis()

    try:
        cmd = (
            f"nmap --script ssl-enum-ciphers -p {port} {host} "
            f"--script-timeout 30 -T4 2>/dev/null"
        )
        raw = await asyncio.wait_for(
            run_parrot_command(cmd, timeout=65), timeout=70
        )
    except asyncio.TimeoutError:
        analysis.error = "nmap ssl-enum-ciphers timed out."
        return analysis
    except Exception as exc:
        analysis.error = f"nmap error: {exc}"
        return analysis

    analysis.nmap_raw = raw[:500]

    # ── TLS versions ──────────────────────────────────────────────────────────
    # Track which version a cipher line belongs to by recording the last seen header
    current_ver = ""
    for line in raw.splitlines():
        ver_match = _TLS_VER_RE.search(line)
        if ver_match:
            current_ver = ver_match.group(1)
            if current_ver.lower() in _WEAK_TLS_VERSIONS:
                if current_ver not in analysis.tls_versions_weak:
                    analysis.tls_versions_weak.append(current_ver)
            else:
                if current_ver not in analysis.tls_versions_enabled:
                    analysis.tls_versions_enabled.append(current_ver)
            continue

        cipher_match = _CIPHER_LINE_RE.search(line)
        if cipher_match:
            cipher_name = cipher_match.group(1)
            grade = cipher_match.group(2)
            if grade in ("B", "C", "F"):
                label = f"{cipher_name} (grade {grade})"
                if label not in analysis.ciphers_weak:
                    analysis.ciphers_weak.append(label)

    # ── Least cipher grade ────────────────────────────────────────────────────
    lm = _LEAST_STRENGTH_RE.search(raw)
    if lm:
        analysis.least_cipher_grade = lm.group(1)

    return analysis


# ---------------------------------------------------------------------------
# Grade calculator
# ---------------------------------------------------------------------------


def _compute_grade(
    cert: CertInfo, tls: TLSAnalysis
) -> tuple[str, list[str], list[str]]:
    """
    Return (grade, issues, recommendations) from cert and TLS analysis data.
    Grade scale: A+ > A > B > C > F (only downgrade, never upgrade once lowered).
    """
    issues: list[str] = []
    recs: list[str] = []
    grade = "A+"

    def _degrade(new: str) -> None:
        nonlocal grade
        _order = {"F": 0, "C": 1, "B": 2, "A": 3, "A+": 4}
        if _order.get(new, 4) < _order.get(grade, 4):
            grade = new

    # ── Certificate checks ────────────────────────────────────────────────────
    if cert.is_expired:
        issues.append("❌ Certificate is **EXPIRED**")
        recs.append("Renew the TLS certificate immediately.")
        _degrade("F")
    elif cert.is_expiring_soon:
        issues.append(f"⚠️ Certificate expires in **{cert.days_until_expiry} days**")
        recs.append("Schedule certificate renewal before expiry.")
        _degrade("C")

    if cert.error:
        issues.append(f"❌ Certificate error: {cert.error}")

    # ── TLS version checks ────────────────────────────────────────────────────
    for ver in (tls.tls_versions_weak if tls else []):
        lower = ver.lower()
        if "sslv2" in lower or "sslv3" in lower:
            issues.append(f"❌ **{ver}** is enabled — critically insecure")
            recs.append(f"Disable {ver} immediately on your server.")
            _degrade("F")
        else:
            issues.append(f"⚠️ **{ver}** is enabled — deprecated protocol")
            recs.append(f"Disable {ver}; only TLS 1.2 and TLS 1.3 should be allowed.")
            _degrade("C")

    # ── Weak ciphers ──────────────────────────────────────────────────────────
    if tls and tls.ciphers_weak:
        issues.append(f"⚠️ {len(tls.ciphers_weak)} weak cipher(s) in server offer")
        recs.append("Remove weak/deprecated cipher suites from your TLS configuration.")
        _degrade("B")

    # ── TLS 1.3 availability ──────────────────────────────────────────────────
    has_tls13 = tls and any("tlsv1.3" in v.lower() for v in tls.tls_versions_enabled)
    has_tls12 = tls and any("tlsv1.2" in v.lower() for v in tls.tls_versions_enabled)

    if not has_tls13 and tls and (tls.tls_versions_enabled or tls.tls_versions_weak):
        if has_tls12:
            issues.append("ℹ️ TLS 1.3 not detected — only TLS 1.2 observed")
        _degrade("B")

    # ── HSTS ─────────────────────────────────────────────────────────────────
    if tls and not tls.hsts_enabled:
        issues.append("⚠️ HSTS header not present")
        recs.append(
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to your server."
        )
        _degrade("A")
    elif tls and tls.hsts_enabled and tls.hsts_max_age < 31_536_000:
        issues.append(
            f"ℹ️ HSTS max-age `{tls.hsts_max_age:,}s` is below recommended 31,536,000s (1 year)"
        )
        recs.append("Increase HSTS max-age to at least 31,536,000 seconds.")
        _degrade("A")

    if not issues:
        issues.append("✅ No issues detected")

    return grade, issues, recs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_ssl(target: str, port: int = 443) -> SSLResult:
    """
    Run a full SSL/TLS inspection against *target:port*.

    Validates input, runs cert fetch + HSTS check + nmap cipher scan
    concurrently, grades the result, and returns an ``SSLResult``.

    Consumed by ``/ssl`` slash command and ``ReconView``'s SSL button.
    """
    result = SSLResult(target=target, port=port)

    ok, val = _validate_target(target)
    if not ok:
        result.error = val
        return result

    host = val

    # ── Run all three checks concurrently ────────────────────────────────────
    cert_task = asyncio.create_task(_get_cert_info(host, port))
    hsts_task = asyncio.create_task(_check_hsts(host, port))
    nmap_task = asyncio.create_task(_run_nmap_ssl(host, port))

    cert_info, hsts_data, tls_analysis = await asyncio.gather(
        cert_task, hsts_task, nmap_task, return_exceptions=True
    )

    # Coerce any unexpected exceptions into safe fallbacks
    if isinstance(cert_info, Exception):
        cert_info = CertInfo(error=str(cert_info))
    if isinstance(hsts_data, Exception):
        hsts_data = (False, 0, False, False)
    if isinstance(tls_analysis, Exception):
        tls_analysis = TLSAnalysis(error=str(tls_analysis))

    # Merge HSTS data into TLS analysis struct
    if isinstance(tls_analysis, TLSAnalysis) and isinstance(hsts_data, tuple):
        (
            tls_analysis.hsts_enabled,
            tls_analysis.hsts_max_age,
            tls_analysis.hsts_includesubdomains,
            tls_analysis.hsts_preload,
        ) = hsts_data

    result.cert = cert_info
    result.tls = tls_analysis

    grade, issues, recs = _compute_grade(cert_info, tls_analysis)
    result.grade = grade
    result.issues = issues
    result.recommendations = recs

    return result


# ---------------------------------------------------------------------------
# Discord embed builder
# ---------------------------------------------------------------------------

_GRADE_COLOUR = {
    "A+": 0x00C853,
    "A":  0x64DD17,
    "B":  0xFFD600,
    "C":  0xFF6D00,
    "F":  0xD50000,
    "?":  0x607D8B,
}

_GRADE_EMOJI = {
    "A+": "🟢",
    "A":  "🟢",
    "B":  "🟡",
    "C":  "🟠",
    "F":  "🔴",
    "?":  "⚫",
}


def _build_ssl_embed(result: SSLResult) -> discord.Embed:
    grade_emoji = _GRADE_EMOJI.get(result.grade, "⚫")
    colour = _GRADE_COLOUR.get(result.grade, 0x607D8B)

    embed = discord.Embed(
        title=f"🔒 SSL/TLS Inspector — {result.target}:{result.port}",
        colour=colour,
    )
    embed.set_footer(
        text=f"Grade: {grade_emoji} {result.grade}  •  Root AI Phase 15  •  SSL/TLS Inspector"
    )

    if result.error:
        embed.description = f"❌ **Error:** {result.error}"
        return embed

    cert = result.cert
    tls = result.tls

    # ── Certificate ───────────────────────────────────────────────────────────
    if cert:
        if cert.error:
            embed.add_field(
                name="📜 Certificate", value=f"❌ {cert.error}", inline=False
            )
        else:
            expiry_flag = ""
            if cert.is_expired:
                expiry_flag = "  🔴 **EXPIRED**"
            elif cert.is_expiring_soon:
                expiry_flag = f"  ⚠️ expires in **{cert.days_until_expiry}d**"

            cert_lines = [
                f"**Subject CN:** `{cert.subject_cn or '—'}`",
                f"**Issuer:** `{cert.issuer_cn or '—'}`",
                f"**Valid until:** `{cert.not_after}`{expiry_flag}",
                f"**TLS negotiated:** `{cert.tls_version_negotiated or '—'}`",
                f"**Cipher:** `{cert.cipher_negotiated or '—'}`",
            ]
            if cert.cipher_bits:
                cert_lines.append(f"**Cipher strength:** `{cert.cipher_bits} bits`")

            embed.add_field(
                name="📜 Certificate", value="\n".join(cert_lines), inline=False
            )

            if cert.san_domains:
                sans = cert.san_domains[:12]
                more = len(cert.san_domains) - 12
                san_text = "  ".join(f"`{s}`" for s in sans)
                if more > 0:
                    san_text += f"\n_+{more} more_"
                embed.add_field(
                    name="🌐 Subject Alternative Names", value=san_text, inline=False
                )

    # ── TLS Versions ──────────────────────────────────────────────────────────
    if tls:
        tls_lines = []
        for ver in tls.tls_versions_enabled:
            tls_lines.append(f"✅ `{ver}` — enabled")
        for ver in tls.tls_versions_weak:
            tls_lines.append(f"❌ `{ver}` — **deprecated**")
        if not tls_lines:
            if tls.error:
                tls_lines.append(f"⚠️ {tls.error}")
            else:
                tls_lines.append("_No TLS version data (port may be filtered via SSH)_")
        elif tls.error:
            tls_lines.append(f"⚠️ {tls.error}")

        embed.add_field(
            name="🔐 TLS Versions (nmap)", value="\n".join(tls_lines), inline=True
        )

        # ── HSTS ─────────────────────────────────────────────────────────────
        if tls.hsts_enabled:
            age_ok = tls.hsts_max_age >= 31_536_000
            hsts_lines = [
                "✅ **Enabled**",
                f"max-age: `{tls.hsts_max_age:,}s` {'✅' if age_ok else '⚠️'}",
                f"includeSubDomains: `{'yes' if tls.hsts_includesubdomains else 'no'}`",
                f"preload: `{'yes' if tls.hsts_preload else 'no'}`",
            ]
        else:
            hsts_lines = ["❌ **Not present**"]

        embed.add_field(
            name="🛡️ HSTS", value="\n".join(hsts_lines), inline=True
        )

        # ── Weak ciphers ──────────────────────────────────────────────────────
        if tls.ciphers_weak:
            display = tls.ciphers_weak[:8]
            more = len(tls.ciphers_weak) - 8
            weak_text = "\n".join(f"⚠️ `{c}`" for c in display)
            if more > 0:
                weak_text += f"\n_+{more} more_"
            embed.add_field(
                name="⚡ Weak / Deprecated Ciphers", value=weak_text, inline=False
            )

    # ── Grade + issues ────────────────────────────────────────────────────────
    embed.add_field(
        name=f"{grade_emoji} Grade {result.grade} — Findings",
        value="\n".join(result.issues) or "✅ No issues detected",
        inline=False,
    )

    if result.recommendations:
        embed.add_field(
            name="🔧 Recommendations",
            value="\n".join(f"• {r}" for r in result.recommendations),
            inline=False,
        )

    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class SSLInspectorCog(commands.Cog, name="SSLInspector"):
    """
    Phase 15 — SSL/TLS Certificate Inspector.

    Inspects the TLS configuration of a target host: certificate chain, expiry,
    HSTS enforcement, supported TLS protocol versions, and cipher suite grades.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def start_ssl_check(
        self,
        interaction: discord.Interaction,
        target: str,
        port: int = 443,
    ) -> None:
        """
        Public API consumed by ReconView's SSL button.

        *interaction* must already be responded to (or deferred) by the caller.
        Posts a progress followup, then the result embed as a second followup.
        """
        await interaction.followup.send(
            f"🔒 Inspecting `{target}:{port}` — running cert check, HSTS, "
            f"and nmap cipher scan concurrently..."
        )
        result = await check_ssl(target, port)
        embed = _build_ssl_embed(result)
        await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="ssl",
        description="[OWNER] Inspect SSL/TLS certificate and cipher configuration of a host.",
    )
    @app_commands.describe(
        target="Domain name to inspect (e.g. example.com)",
        port="Port to check (default: 443)",
    )
    async def ssl_command(
        self,
        interaction: discord.Interaction,
        target: str,
        port: int = 443,
    ) -> None:
        """Phase 15 entry point — full SSL/TLS inspection."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/ssl` is an owner-only command.",
                ephemeral=True,
            )
            return

        if not 1 <= port <= 65535:
            await interaction.response.send_message(
                "❌ Port must be between 1 and 65535.",
                ephemeral=True,
            )
            return

        await interaction.response.defer()
        await interaction.followup.send(
            f"🔒 Inspecting `{target}:{port}` — running cert check, HSTS, "
            f"and nmap cipher scan concurrently..."
        )

        result = await check_ssl(target, port)
        embed = _build_ssl_embed(result)
        await interaction.followup.send(embed=embed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SSLInspectorCog(bot))
