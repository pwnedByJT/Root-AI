"""
cogs/web_fingerprinter.py
Phase 16 — Web Technology Fingerprinter

Public API:    fingerprint_target(target) -> FingerprintResult
Slash command: /fingerprint <target>
Button:        ReconView → "🔍 Stack" → WebFingerprinterCog.start_fingerprint()

Detection pipeline (run concurrently):
  1. whatweb -a 3 via Parrot SSH
       CMS, web server, frameworks, JS libraries, CDN/WAF, analytics, OS,
       email addresses, IP. Falls back gracefully if whatweb is not installed
       (surfaces install instructions; header analysis still runs independently).
  2. aiohttp HTTPS → HTTP GET for response headers
       Security header analysis: CSP, X-Frame-Options, X-Content-Type-Options,
       Referrer-Policy, Permissions-Policy, X-Powered-By, Server version exposure.

Design notes:
  - whatweb text output is parsed with a bracket-aware state machine so that
    multi-bracket plugins like HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]
    and Country[UNITED STATES][US] are handled correctly; positional or naive
    split-on-comma logic silently drops the second bracket group.
  - command -v whatweb is checked first; "not installed" is surfaced explicitly
    rather than surfacing empty plugin output.
  - FQDN validation + SSRF guard (same pattern as Phases 1, 14, 15) blocks
    private/loopback targets before any outbound I/O.
  - /fingerprint is restricted to the bot owner (BOT_OWNER_ID).
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID
from cogs.security import run_parrot_command

log = logging.getLogger("root_ai.web_fingerprinter")

# ---------------------------------------------------------------------------
# Input validation — SSRF guard (shared pattern with Phases 1, 14, 15)
# ---------------------------------------------------------------------------

_FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_PRIVATE_RANGE_RE = re.compile(
    r"^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|0\.0\.0\.0)"
)

_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)


def _validate_target(target: str) -> tuple[bool, str]:
    """Validate as public FQDN. Returns (ok, cleaned_host_or_error)."""
    clean = target.strip().lower()
    if _PRIVATE_RANGE_RE.match(clean):
        return False, f"`{target}` is a private/loopback address — not allowed."
    if not _FQDN_RE.match(clean):
        return False, f"`{target}` is not a valid fully-qualified domain name."
    return True, clean


# ---------------------------------------------------------------------------
# Tech category lookups
# ---------------------------------------------------------------------------

_SERVER_PLUGINS: frozenset[str] = frozenset({
    "Apache", "Nginx", "IIS", "LiteSpeed", "Caddy", "OpenResty", "HTTPServer",
    "Cowboy", "Jetty", "Tomcat", "WebLogic", "WebSphere", "Lighttpd", "Cherokee",
    "Gunicorn", "Uvicorn", "Puma", "Thin", "WEBrick",
})

_LANG_PLUGINS: frozenset[str] = frozenset({
    "PHP", "Python", "Ruby", "ASP.NET", "Java", "Perl", "Go", "Node.js",
    "ColdFusion", "Erlang",
})

_CMS_PLUGINS: frozenset[str] = frozenset({
    "WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix", "Ghost",
    "Typo3", "Craft", "Concrete5", "DotNetNuke", "SilverStripe", "Umbraco",
    "MODX", "Prestashop", "OpenCart", "WooCommerce", "ExpressionEngine",
    "Kentico", "Sitecore", "Squarespace",
})

_FRAMEWORK_PLUGINS: frozenset[str] = frozenset({
    "Laravel", "Django", "Rails", "Express", "Symfony", "CodeIgniter", "Yii",
    "CakePHP", "Flask", "FastAPI", "Spring", "Struts", "Zend", "Phalcon",
    "FuelPHP", "Slim", "Lumen", "Next.js", "Nuxt.js", "Gatsby",
})

_JS_PLUGINS: frozenset[str] = frozenset({
    "jQuery", "JQuery", "Bootstrap", "React", "Vue", "Angular", "Lodash",
    "Moment", "Backbone", "Ember", "Mootools", "Prototype", "Underscore",
    "Handlebars", "Mustache", "Knockout", "Polymer", "Lit", "Alpine",
})

_CDN_WAF_PLUGINS: frozenset[str] = frozenset({
    "Cloudflare", "Akamai", "Fastly", "Sucuri", "Incapsula", "CloudFront",
    "StackPath", "Imperva", "F5", "Varnish", "KeyCDN", "MaxCDN", "BunnyCDN",
    "Edgecast", "Limelight", "Zscaler",
})

_ANALYTICS_PLUGINS: frozenset[str] = frozenset({
    "Google-Analytics", "Hotjar", "Mixpanel", "Segment", "Amplitude", "Piwik",
    "Matomo", "Heap", "FullStory", "Facebook-Pixel", "HubSpot", "Intercom",
    "Optimizely", "Crazy-Egg", "Lucky-Orange",
})

_OS_PLUGINS: frozenset[str] = frozenset({
    "Ubuntu", "CentOS", "Debian", "RedHat", "Windows-Server", "FreeBSD",
    "Fedora", "AlmaLinux", "Rocky-Linux", "Amazon-Linux",
})

# Plugins whose bracket values are email addresses or IPs — captured separately
_META_PLUGINS: frozenset[str] = frozenset({"Email", "IP", "Country", "Title"})

# ---------------------------------------------------------------------------
# whatweb output parser — bracket-aware state machine
# ---------------------------------------------------------------------------


def _parse_whatweb_line(line: str) -> tuple[str, list[tuple[str, list[str]]]]:
    """
    Parse one whatweb text-output line.

    Format:  ``URL [STATUS CODE] Plugin1[val1][val2], Plugin2, Plugin3[val]``

    Handles consecutive bracket groups correctly:
      ``HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]``
      → ("HTTPServer", ["Ubuntu Linux", "Apache/2.4.41 (Ubuntu)"])

      ``Country[UNITED STATES][US]``
      → ("Country", ["UNITED STATES", "US"])

    Returns (status_str, [(plugin_name, [value, ...]), ...]).
    """
    m = re.match(r"https?://\S+\s+\[([^\]]+)\]\s+(.*)", line.strip())
    if not m:
        return "", []

    status = m.group(1)
    plugins_str = m.group(2)

    plugins: list[tuple[str, list[str]]] = []
    name_chars: list[str] = []
    values: list[str] = []
    val_chars: list[str] = []
    depth = 0

    for ch in plugins_str:
        if ch == "[":
            if depth == 0:
                val_chars = []
            else:
                val_chars.append(ch)
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                values.append("".join(val_chars))
                val_chars = []
            else:
                val_chars.append(ch)
        elif ch == "," and depth == 0:
            name = "".join(name_chars).strip()
            if name:
                plugins.append((name, values))
            name_chars = []
            values = []
        else:
            if depth > 0:
                val_chars.append(ch)
            else:
                name_chars.append(ch)

    # Flush last plugin
    name = "".join(name_chars).strip()
    if name:
        plugins.append((name, values))

    return status, plugins


def _extract_server_name(values: list[str]) -> str:
    """
    For HTTPServer plugins the last bracket group is typically the most specific
    server string (e.g., "Apache/2.4.41 (Ubuntu)"). Return the last non-empty value.
    """
    for v in reversed(values):
        v = v.strip()
        if v:
            return v
    return ""


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class TechStack:
    """Technology components detected by whatweb."""

    web_server: str = ""
    language: str = ""
    cms: str = ""
    frameworks: list[str] = field(default_factory=list)
    js_libraries: list[str] = field(default_factory=list)
    cdn_waf: str = ""
    analytics: list[str] = field(default_factory=list)
    os_hint: str = ""
    emails: list[str] = field(default_factory=list)
    page_title: str = ""
    raw_plugins: list[str] = field(default_factory=list)  # full plugin list for debug
    http_status: str = ""
    whatweb_error: str = ""


@dataclass
class HeaderAnalysis:
    """HTTP response header security audit."""

    # Present / absent security headers
    has_csp: bool = False
    has_xfo: bool = False                # X-Frame-Options
    has_xcto: bool = False               # X-Content-Type-Options: nosniff
    has_rp: bool = False                 # Referrer-Policy
    has_pp: bool = False                 # Permissions-Policy
    has_hsts: bool = False               # Strict-Transport-Security

    # Tech-disclosure headers
    server_header: str = ""
    x_powered_by: str = ""
    x_generator: str = ""

    # Collected issues
    issues: list[str] = field(default_factory=list)

    error: str = ""


@dataclass
class FingerprintResult:
    """Aggregated web technology fingerprint."""

    target: str = ""
    url: str = ""
    tech: Optional[TechStack] = None
    headers: Optional[HeaderAnalysis] = None
    error: str = ""


# ---------------------------------------------------------------------------
# whatweb via Parrot SSH
# ---------------------------------------------------------------------------


async def _run_whatweb(host: str) -> TechStack:
    """
    Run whatweb on Parrot OS, check it is installed, parse output.

    Tries HTTPS first then HTTP (whatweb follows redirects automatically
    when given both URLs, but running one at a time gives cleaner output).
    """
    stack = TechStack()

    # ── Check whatweb is installed ────────────────────────────────────────────
    try:
        check = await asyncio.wait_for(
            run_parrot_command("command -v whatweb 2>&1 || echo WHATWEB_NOT_FOUND"),
            timeout=10,
        )
    except Exception as exc:
        stack.whatweb_error = f"Parrot SSH unavailable: {exc}"
        return stack

    if "WHATWEB_NOT_FOUND" in check or not check.strip():
        stack.whatweb_error = (
            "whatweb is not installed on Parrot OS. "
            "Install with: `sudo apt install whatweb`"
        )
        return stack

    # ── Run whatweb (HTTPS first, then HTTP) ──────────────────────────────────
    raw = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            out = await asyncio.wait_for(
                run_parrot_command(
                    f"whatweb -a 3 '{url}' --color=never 2>/dev/null | tail -1"
                ),
                timeout=45,
            )
        except asyncio.TimeoutError:
            stack.whatweb_error = "whatweb timed out."
            return stack
        except Exception as exc:
            stack.whatweb_error = f"whatweb error: {exc}"
            return stack

        if out.strip() and "://" in out:
            raw = out.strip()
            break

    if not raw:
        stack.whatweb_error = "whatweb returned no output — target may be down."
        return stack

    # ── Parse ─────────────────────────────────────────────────────────────────
    status, plugins = _parse_whatweb_line(raw)
    stack.http_status = status
    stack.raw_plugins = [f"{n}{'[' + ', '.join(v) + ']' if v else ''}" for n, v in plugins]

    for name, values in plugins:
        val_str = ", ".join(values)

        if name in _META_PLUGINS:
            if name == "Email":
                stack.emails.extend(v for v in values if v)
            elif name == "Title":
                stack.page_title = values[0] if values else ""
            continue

        if name in _SERVER_PLUGINS:
            if not stack.web_server:
                stack.web_server = (
                    _extract_server_name(values) if values else name
                )
        elif name in _LANG_PLUGINS:
            if not stack.language:
                stack.language = f"{name}{'[' + values[0] + ']' if values else ''}"
        elif name in _CMS_PLUGINS:
            if not stack.cms:
                stack.cms = f"{name}{'[' + values[0] + ']' if values else ''}"
        elif name in _FRAMEWORK_PLUGINS:
            entry = f"{name}{'[' + values[0] + ']' if values else ''}"
            if entry not in stack.frameworks:
                stack.frameworks.append(entry)
        elif name in _JS_PLUGINS:
            entry = f"{name}{'[' + values[0] + ']' if values else ''}"
            if entry not in stack.js_libraries:
                stack.js_libraries.append(entry)
        elif name in _CDN_WAF_PLUGINS:
            if not stack.cdn_waf:
                stack.cdn_waf = name
        elif name in _ANALYTICS_PLUGINS:
            if name not in stack.analytics:
                stack.analytics.append(name)
        elif name in _OS_PLUGINS:
            if not stack.os_hint:
                stack.os_hint = name

    return stack


# ---------------------------------------------------------------------------
# HTTP response header security analysis
# ---------------------------------------------------------------------------

_VERSION_IN_SERVER_RE = re.compile(r"/[\d.]+")


async def _analyze_headers(host: str) -> HeaderAnalysis:
    """
    GET https://host (fallback http://host) and audit security headers.
    ssl=False so we get headers even if the cert is expired/self-signed.
    """
    ha = HeaderAnalysis()

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector, timeout=_HTTP_TIMEOUT
            ) as session:
                async with session.get(
                    url, allow_redirects=True, max_redirects=5
                ) as resp:
                    h = resp.headers
        except Exception as exc:
            ha.error = f"Could not reach {url}: {exc}"
            continue

        # ── Tech-disclosure headers ───────────────────────────────────────────
        ha.server_header = h.get("Server", "")
        ha.x_powered_by = h.get("X-Powered-By", "")
        ha.x_generator = h.get("X-Generator", "") or h.get("X-Generator-Engine", "")

        # ── Security headers ──────────────────────────────────────────────────
        ha.has_csp = bool(h.get("Content-Security-Policy"))
        ha.has_xfo = bool(h.get("X-Frame-Options"))
        ha.has_xcto = h.get("X-Content-Type-Options", "").lower() == "nosniff"
        ha.has_rp = bool(h.get("Referrer-Policy"))
        ha.has_pp = bool(h.get("Permissions-Policy") or h.get("Feature-Policy"))
        ha.has_hsts = bool(h.get("Strict-Transport-Security"))
        ha.error = ""
        break

    # ── Build issue list ──────────────────────────────────────────────────────
    if not ha.has_csp:
        ha.issues.append("❌ `Content-Security-Policy` missing — XSS risk")
    if not ha.has_xfo:
        ha.issues.append("⚠️ `X-Frame-Options` missing — clickjacking risk")
    if not ha.has_xcto:
        ha.issues.append("⚠️ `X-Content-Type-Options: nosniff` missing")
    if not ha.has_rp:
        ha.issues.append("ℹ️ `Referrer-Policy` missing — referrer leakage possible")
    if not ha.has_pp:
        ha.issues.append("ℹ️ `Permissions-Policy` missing")

    if ha.x_powered_by:
        ha.issues.append(f"ℹ️ `X-Powered-By: {ha.x_powered_by}` — tech stack disclosed")
    if ha.server_header and _VERSION_IN_SERVER_RE.search(ha.server_header):
        ha.issues.append(
            f"ℹ️ `Server: {ha.server_header}` — version number disclosed"
        )

    return ha


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fingerprint_target(target: str) -> FingerprintResult:
    """
    Run a full web technology fingerprint against *target*.

    Runs whatweb (via Parrot SSH) and HTTP header analysis concurrently.
    Returns a ``FingerprintResult`` suitable for embed rendering or export.
    """
    result = FingerprintResult(target=target)

    ok, val = _validate_target(target)
    if not ok:
        result.error = val
        return result

    host = val
    result.url = f"https://{host}"

    # ── Run both checks concurrently ──────────────────────────────────────────
    whatweb_task = asyncio.create_task(_run_whatweb(host))
    headers_task = asyncio.create_task(_analyze_headers(host))

    tech, headers = await asyncio.gather(
        whatweb_task, headers_task, return_exceptions=True
    )

    if isinstance(tech, Exception):
        tech = TechStack(whatweb_error=str(tech))
    if isinstance(headers, Exception):
        headers = HeaderAnalysis(error=str(headers))

    result.tech = tech
    result.headers = headers
    return result


# ---------------------------------------------------------------------------
# Discord embed builder
# ---------------------------------------------------------------------------


def _build_fingerprint_embed(result: FingerprintResult) -> discord.Embed:
    embed = discord.Embed(
        title=f"🔍 Web Tech Fingerprint — {result.target}",
        colour=0x7B68EE,
    )
    embed.set_footer(text="Root AI Phase 16  •  Web Technology Fingerprinter")

    if result.error:
        embed.description = f"❌ **Error:** {result.error}"
        return embed

    tech = result.tech
    headers = result.headers

    # ── Technology Stack ──────────────────────────────────────────────────────
    if tech:
        if tech.whatweb_error:
            embed.add_field(
                name="🕸️ whatweb",
                value=f"⚠️ {tech.whatweb_error}",
                inline=False,
            )
        else:
            stack_lines = []
            if tech.http_status:
                stack_lines.append(f"**HTTP Status:** `{tech.http_status}`")
            if tech.web_server:
                stack_lines.append(f"**Web Server:** `{tech.web_server}`")
            if tech.os_hint:
                stack_lines.append(f"**OS:** `{tech.os_hint}`")
            if tech.language:
                stack_lines.append(f"**Language:** `{tech.language}`")
            if tech.cms:
                stack_lines.append(f"**CMS:** `{tech.cms}`")
            if tech.cdn_waf:
                stack_lines.append(f"**CDN / WAF:** `{tech.cdn_waf}`")
            if tech.page_title:
                title_trunc = tech.page_title[:60]
                stack_lines.append(f"**Page Title:** {title_trunc}")

            if stack_lines:
                embed.add_field(
                    name="🕸️ Technology Stack",
                    value="\n".join(stack_lines),
                    inline=False,
                )

            # Frameworks & JS
            fw_js_lines = []
            if tech.frameworks:
                fw_js_lines.append("**Frameworks:** " + ", ".join(f"`{f}`" for f in tech.frameworks))
            if tech.js_libraries:
                fw_js_lines.append("**JS Libs:** " + ", ".join(f"`{j}`" for j in tech.js_libraries[:8]))
            if tech.analytics:
                fw_js_lines.append("**Analytics:** " + ", ".join(f"`{a}`" for a in tech.analytics))
            if fw_js_lines:
                embed.add_field(
                    name="📦 Libraries & Analytics",
                    value="\n".join(fw_js_lines),
                    inline=False,
                )

            # Emails discovered
            if tech.emails:
                embed.add_field(
                    name="📧 Emails Discovered",
                    value=", ".join(f"`{e}`" for e in tech.emails[:10]),
                    inline=False,
                )

    # ── Security Headers ──────────────────────────────────────────────────────
    if headers:
        if headers.error:
            embed.add_field(
                name="🛡️ Security Headers",
                value=f"⚠️ {headers.error}",
                inline=False,
            )
        else:
            def _tick(present: bool) -> str:
                return "✅" if present else "❌"

            header_lines = [
                f"{_tick(headers.has_csp)} `Content-Security-Policy`",
                f"{_tick(headers.has_xfo)} `X-Frame-Options`",
                f"{_tick(headers.has_xcto)} `X-Content-Type-Options: nosniff`",
                f"{_tick(headers.has_rp)} `Referrer-Policy`",
                f"{_tick(headers.has_pp)} `Permissions-Policy`",
                f"{_tick(headers.has_hsts)} `Strict-Transport-Security`",
            ]
            embed.add_field(
                name="🛡️ Security Headers",
                value="\n".join(header_lines),
                inline=True,
            )

            # Disclosure
            disc_lines = []
            if headers.server_header:
                disc_lines.append(f"Server: `{headers.server_header}`")
            if headers.x_powered_by:
                disc_lines.append(f"X-Powered-By: `{headers.x_powered_by}`")
            if headers.x_generator:
                disc_lines.append(f"X-Generator: `{headers.x_generator}`")
            if not disc_lines:
                disc_lines.append("_No tech-disclosure headers found_ ✅")
            embed.add_field(
                name="🔎 Disclosure Headers",
                value="\n".join(disc_lines),
                inline=True,
            )

            # Issues
            if headers.issues:
                embed.add_field(
                    name="⚠️ Findings",
                    value="\n".join(headers.issues),
                    inline=False,
                )

    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class WebFingerprinterCog(commands.Cog, name="WebFingerprinter"):
    """
    Phase 16 — Web Technology Fingerprinter.

    Identifies the CMS, web server, programming language, frameworks,
    JavaScript libraries, CDN/WAF, and security header posture of a target.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    async def start_fingerprint(
        self, interaction: discord.Interaction, target: str
    ) -> None:
        """
        Public API consumed by ReconView's "🔍 Stack" button.

        *interaction* must already be responded to (deferred) by the caller.
        Posts a progress followup then the result embed.
        """
        await interaction.followup.send(
            f"🔍 Fingerprinting `{target}` — running whatweb and header analysis..."
        )
        result = await fingerprint_target(target)
        embed = _build_fingerprint_embed(result)
        await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="fingerprint",
        description="[OWNER] Detect the web technology stack and security headers of a target.",
    )
    @app_commands.describe(
        target="Domain name to fingerprint (e.g. example.com)",
    )
    async def fingerprint_command(
        self, interaction: discord.Interaction, target: str
    ) -> None:
        """Phase 16 entry point — web technology fingerprinter."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/fingerprint` is an owner-only command.",
                ephemeral=True,
            )
            return

        await interaction.response.defer()
        await interaction.followup.send(
            f"🔍 Fingerprinting `{target}` — running whatweb and header analysis..."
        )

        result = await fingerprint_target(target)
        embed = _build_fingerprint_embed(result)
        await interaction.followup.send(embed=embed)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(WebFingerprinterCog(bot))
