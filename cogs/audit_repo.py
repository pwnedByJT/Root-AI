"""
cogs/audit_repo.py
Phase 4 — Repository Security Audit & HackerOne Report Generator

Slash command: /audit_repo <github_url> <vulnerability_type>
Public API:    AuditRepoCog.export_report(interaction, autopwn_result)
               └─ Called by Phase 2 AutoPwnView "Export Report" button.

Pipeline (/audit_repo):
  1. Validate GitHub URL (strict regex — no SSRF into internal hosts)
  2. SSH to Parrot OS: git clone --depth=1 <url> /tmp/audit_<uuid>/
  3. Repo size guard (>100 MB → abort before grep)
  4. grep -E <vuln_pattern> for the chosen vulnerability type
  5. Read top 5 hit-files (≤80 lines / ≤2 KB each)
  6. LLM: analyse grep evidence + code slices → structured findings JSON
  7. Render HackerOne-format markdown report
  8. try/finally cleanup: rm -rf /tmp/audit_<uuid>/
  9. Upload report as discord.File + summary embed

Pipeline (export_report from AutoPwnResult):
  1. LLM: convert Phase 2 executive summary + cycle observations → structured JSON
  2. Render HackerOne-format markdown report
  3. Upload report as discord.File + summary embed (ephemeral)

Security boundaries:
  - /audit_repo and export_report are gated to BOT_OWNER_ID.
  - GitHub URL validated against strict regex before any SSH dispatch.
  - Temp dir uses uuid4().hex — no collisions, no path traversal.
  - try/finally guarantees cleanup even on SSH errors or exceptions.
  - asyncio.Lock prevents concurrent audits (Parrot OS protection).
  - Repo size checked (100 MB cap) before grepping.
  - LLM receives only curated grep output + truncated file slices — not raw
    user input.  All shell commands are built from controlled constants.

Phase 5 integration point:
  - AuditRepoCog is the report-generation backend.  A future /watchdog cog
    can call export_report() when persistent monitoring detects new findings.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands
from openai import AsyncOpenAI

from config import BOT_OWNER_ID, GITHUB_PAT, LOCAL_LLM_URL, LOCAL_MODEL_NAME
from cogs.security import run_parrot_command

if TYPE_CHECKING:
    from cogs.autopwn import AutoPwnResult

log = logging.getLogger("root_ai.audit")

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_audit_lock = asyncio.Lock()  # one audit at a time — Parrot OS SSH protection

_ollama_client = AsyncOpenAI(base_url=LOCAL_LLM_URL, api_key="ollama")

# ---------------------------------------------------------------------------
# Vulnerability configurations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VulnConfig:
    display: str                  # Human-readable name for embeds / report titles
    severity: str                 # Default severity if LLM doesn't specify
    grep_expr: str                # -E pattern (no single-quote chars — SSH-safe)
    file_globs: tuple[str, ...]   # --include patterns passed to grep
    description: str              # One-line description of the vulnerability class


VULN_CONFIGS: dict[str, VulnConfig] = {
    "sql_injection": VulnConfig(
        display="SQL Injection",
        severity="Critical",
        grep_expr=(
            r"(execute\(|cursor\.execute|db\.query|\.raw\(|"
            r"SELECT.*\+|INSERT.*\+|UPDATE.*\+|mysql_query|pg_query)"
        ),
        file_globs=("*.py", "*.php", "*.js", "*.rb", "*.go", "*.java"),
        description="Unsanitised user input concatenated into SQL queries.",
    ),
    "xss": VulnConfig(
        display="Cross-Site Scripting (XSS)",
        severity="High",
        grep_expr=(
            r"(innerHTML|document\.write\(|eval\(|\.html\(|"
            r"dangerouslySetInnerHTML|v-html=|render_template_string|mark_safe)"
        ),
        file_globs=("*.js", "*.ts", "*.jsx", "*.tsx", "*.html", "*.py", "*.php"),
        description="Unescaped user input reflected into HTML or JavaScript output.",
    ),
    "ssrf": VulnConfig(
        display="Server-Side Request Forgery (SSRF)",
        severity="Critical",
        grep_expr=(
            r"(requests\.get\(|requests\.post\(|urllib\.request|"
            r"fetch\(|http\.get\(|axios\.|curl_exec|file_get_contents)"
        ),
        file_globs=("*.py", "*.js", "*.ts", "*.php", "*.rb", "*.go", "*.java"),
        description="User-controlled URLs passed to server-side HTTP requests.",
    ),
    "cmd_injection": VulnConfig(
        display="Command Injection",
        severity="Critical",
        grep_expr=(
            r"(os\.system|subprocess\.call|exec\(|shell=True|"
            r"popen\(|system\(|passthru|shell_exec|proc_open)"
        ),
        file_globs=("*.py", "*.php", "*.js", "*.rb", "*.go", "*.java"),
        description="Unsanitised user input executed as an OS shell command.",
    ),
    "path_traversal": VulnConfig(
        display="Path Traversal / LFI",
        severity="High",
        grep_expr=(
            r"(open\(|file_get_contents\(|include\(|require\(|"
            r"readFile\(|\.\.\/|join\(request|join\(user)"
        ),
        file_globs=("*.py", "*.php", "*.js", "*.ts", "*.rb", "*.go"),
        description="User-controlled file paths allowing directory traversal.",
    ),
    "hardcoded_secrets": VulnConfig(
        display="Hardcoded Secrets",
        severity="High",
        grep_expr=(
            r"(password=[^\s,]{6,}|api_key=[^\s]{3,}|secret=[^\s]{3,}|"
            r"AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|private_key\s*=)"
        ),
        file_globs=(
            "*.py", "*.js", "*.ts", "*.rb", "*.go", "*.java",
            "*.env", "*.yml", "*.yaml", "*.json", "*.conf",
        ),
        description="Credentials, API keys, or secrets committed to source code.",
    ),
    "insecure_deser": VulnConfig(
        display="Insecure Deserialization",
        severity="Critical",
        grep_expr=(
            r"(pickle\.loads|yaml\.load\(|marshal\.loads|"
            r"unserialize\(|ObjectInputStream|readObject)"
        ),
        file_globs=("*.py", "*.php", "*.java", "*.rb", "*.js"),
        description="Unsafe deserialization of user-controlled data.",
    ),
    "open_redirect": VulnConfig(
        display="Open Redirect",
        severity="Medium",
        grep_expr=(
            r"(HttpResponseRedirect\(|res\.redirect\(|"
            r"next=|return_url=|redirect_to=|url=request)"
        ),
        file_globs=("*.py", "*.php", "*.js", "*.ts", "*.rb", "*.go"),
        description="Unvalidated URL parameters used in server-side HTTP redirects.",
    ),
}

# ---------------------------------------------------------------------------
# GitHub URL validation
# ---------------------------------------------------------------------------

_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[a-zA-Z0-9._-]{1,100}/[a-zA-Z0-9._-]{1,100}(?:\.git)?/?$"
)


def _validate_github_url(url: str) -> tuple[bool, str]:
    """
    Validate *url* as a public GitHub repository URL.

    Returns (True, clean_url) on success or (False, error_message) on failure.
    The clean_url has trailing slashes stripped and no whitespace.
    """
    clean = url.strip().rstrip("/")
    if not _GITHUB_URL_RE.match(clean):
        return False, (
            f"`{url}` is not a valid GitHub repository URL.\n"
            "Expected format: `https://github.com/owner/repo`"
        )
    return True, clean


# ---------------------------------------------------------------------------
# HackerOne-format markdown renderer
# ---------------------------------------------------------------------------

_CVSS_RANGES: dict[str, str] = {
    "Critical": "9.0 – 10.0",
    "High":     "7.0 – 8.9",
    "Medium":   "4.0 – 6.9",
    "Low":      "1.0 – 3.9",
    "Info":     "0.0",
}


def _render_h1_markdown(
    title: str,
    severity: str,
    vuln_type: str,
    affected: str,
    summary: str,
    steps: str,
    impact: str,
    poc: str,
    remediation: str,
    timestamp: datetime,
    metadata: dict[str, str],
    cve_section: str = "",
    exploit_section: str = "",
    nuclei_section: str = "",
) -> str:
    """Return a HackerOne-compatible vulnerability report in Markdown."""
    cvss = _CVSS_RANGES.get(severity, "N/A")
    meta_rows = "\n".join(f"| {k} | {v} |" for k, v in metadata.items())
    _cve_block = f"\n\n---\n\n## CVE Analysis\n\n{cve_section}" if cve_section else ""
    _exploit_block = f"\n\n---\n\n## Known Exploits\n\n{exploit_section}" if exploit_section else ""
    _nuclei_block = f"\n\n---\n\n## Nuclei Findings\n\n{nuclei_section}" if nuclei_section else ""
    return f"""# {title}

**Report Date:** {timestamp.strftime("%Y-%m-%d %H:%M UTC")}
**Severity:** {severity}
**CVSS Score Range:** {cvss}
**Vulnerability Type:** {vuln_type}
**Affected Component:** {affected}

---

## Summary

{summary}

---

## Steps to Reproduce

{steps}

---

## Impact

{impact}

---

## Proof of Concept

{poc}

---

## Recommended Remediation

{remediation}{_cve_block}{_exploit_block}{_nuclei_block}

---

## Metadata

| Field | Value |
|-------|-------|
{meta_rows}

---
*Report generated by Root AI \u2022 Phase 4 Audit Engine \u2022 {timestamp.strftime("%Y-%m-%d")}*
"""


# ---------------------------------------------------------------------------
# LLM prompts & JSON extraction
# ---------------------------------------------------------------------------

_AUDIT_SYSTEM = """\
You are a professional penetration tester writing a vulnerability disclosure report for HackerOne.
You will receive grep output and code snippets from a security audit of a GitHub repository.
Analyse the evidence and identify real vulnerabilities.

RESPONSE FORMAT \u2014 reply with ONLY valid JSON, no markdown, no prose:
{
  "has_vulnerability": true,
  "severity": "Critical|High|Medium|Low|Info",
  "affected_components": ["path/to/file.py:42"],
  "summary": "2-3 sentence description of the finding",
  "steps_to_reproduce": "1. Clone the repo\\n2. Run...\\n3. Observe...",
  "impact": "Business and technical impact if exploited",
  "proof_of_concept": "Code snippet, curl command, or payload demonstrating the issue",
  "remediation": "Specific code-level fix with before/after examples where possible"
}

If grep returned no matches or the code appears safe for the specified vulnerability type,
set has_vulnerability to false and explain in the summary field.
"""

_EXPORT_SYSTEM = """\
You are a professional penetration tester converting network scan results into a HackerOne report.
You will receive an executive summary and tool observations from a penetration test.

RESPONSE FORMAT \u2014 reply with ONLY valid JSON, no markdown, no prose:
{
  "severity": "Critical|High|Medium|Low|Info",
  "vulnerability_types": ["SQL Injection", "Open Port Exposure"],
  "affected_components": ["domain.com:80", "api.domain.com:8443"],
  "summary": "2-3 sentence executive summary of all findings",
  "steps_to_reproduce": "1. ...\\n2. ...\\n3. ...",
  "impact": "Business and technical impact description",
  "proof_of_concept": "Specific attack commands, payloads, or curl demonstrating the issues",
  "remediation": "Prioritised remediation steps with specific hardening recommendations"
}
"""

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def _extract_json(text: str) -> dict | None:
    """Extract first valid JSON object from LLM output (handles fences + bare JSON)."""
    for candidate in (
        text.strip(),
        *(m.group(1).strip() for m in _JSON_FENCE_RE.finditer(text)),
    ):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    # Last resort: outermost { … }
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass
    return None


# ---------------------------------------------------------------------------
# Parrot OS SSH pipeline
# ---------------------------------------------------------------------------


async def _clone_and_grep(
    github_url: str,
    vuln: VulnConfig,
    work_dir: str,
) -> tuple[str, str, str]:
    """
    Clone the repo on Parrot, enforce size limit, grep for patterns, read
    the top 5 hit-files.

    Returns (clone_status, grep_output, file_contents).
      - clone_status == "ok" means the clone succeeded and the caller may continue.
      - Any other value is a human-readable failure message.

    The caller is responsible for cleanup via try/finally.
    """
    # ── Clone ─────────────────────────────────────────────────────────────────
    # Embed PAT in URL for private-repo access; never log the raw auth URL.
    if GITHUB_PAT:
        auth_url = github_url.replace("https://", f"https://{GITHUB_PAT}@")
    else:
        auth_url = github_url
    log.info("Audit: cloning %s into %s", github_url, work_dir)
    clone_out = await run_parrot_command(
        f"git clone --depth=1 '{auth_url}' '{work_dir}' 2>&1",
        timeout=90,
    )
    # Scrub PAT from any error output before it touches Discord or logs
    if GITHUB_PAT:
        clone_out = clone_out.replace(GITHUB_PAT, "***")
    lower = clone_out.lower()
    if "fatal:" in lower or ("error:" in lower and "warning:" not in lower):
        return f"Clone failed:\n{clone_out}", "", ""

    # ── Size guard (100 MB) ───────────────────────────────────────────────────
    size_out = await run_parrot_command(
        f"du -sm '{work_dir}' 2>/dev/null | cut -f1", timeout=10
    )
    try:
        size_mb = int(size_out.strip())
        if size_mb > 100:
            return (
                f"Repository is too large ({size_mb} MB). "
                "The 100 MB limit exists to prevent Parrot OS storage issues.",
                "", "",
            )
    except ValueError:
        pass  # du output unparseable — proceed

    # ── Grep for vulnerability patterns ───────────────────────────────────────
    include_flags = " ".join(f"--include='{g}'" for g in vuln.file_globs)
    grep_cmd = (
        f"grep -rn -E '{vuln.grep_expr}' {include_flags} '{work_dir}' "
        f"2>/dev/null | head -100"
    )
    grep_out = await run_parrot_command(grep_cmd, timeout=30)

    # ── Read top 5 most-hit files ─────────────────────────────────────────────
    files_cmd = (
        f"grep -rln -E '{vuln.grep_expr}' {include_flags} '{work_dir}' "
        f"2>/dev/null | head -5"
    )
    files_out = await run_parrot_command(files_cmd, timeout=15)

    file_contents = ""
    for raw_path in files_out.strip().splitlines()[:5]:
        fpath = raw_path.strip()
        if not fpath:
            continue
        rel = fpath[len(work_dir):].lstrip("/")
        content = await run_parrot_command(f"head -80 '{fpath}' 2>/dev/null", timeout=10)
        file_contents += f"\n=== {rel} ===\n{content[:2000]}\n"

    return "ok", grep_out or "(no pattern matches)", file_contents


# ---------------------------------------------------------------------------
# LLM analysis helpers
# ---------------------------------------------------------------------------

_LLM_TIMEOUT = 120  # seconds for each LLM call


async def _llm_analyze_repo(
    github_url: str,
    vuln: VulnConfig,
    grep_output: str,
    file_contents: str,
) -> dict:
    """
    Feed grep evidence + code slices to the LLM and return structured findings.
    Falls back to a minimal dict built from raw grep output on any failure.
    """
    user_msg = (
        f"TARGET REPOSITORY: {github_url}\n"
        f"VULNERABILITY TYPE: {vuln.display}\n"
        f"DESCRIPTION: {vuln.description}\n\n"
        f"=== GREP OUTPUT ===\n{grep_output[:3000]}\n\n"
        f"=== RELEVANT FILE CONTENTS ===\n{file_contents[:4000]}\n\n"
        "Analyse this evidence and produce the structured vulnerability report JSON."
    )
    try:
        resp = await asyncio.wait_for(
            _ollama_client.chat.completions.create(
                model=LOCAL_MODEL_NAME,
                messages=[
                    {"role": "system", "content": _AUDIT_SYSTEM},
                    {"role": "user",   "content": user_msg},
                ],
                temperature=0.2,
                top_p=0.9,
            ),
            timeout=_LLM_TIMEOUT,
        )
        parsed = _extract_json(resp.choices[0].message.content or "")
        if parsed:
            return parsed
    except Exception as exc:
        log.error("Audit: LLM repo analysis failed: %s", exc)

    # Fallback — build a minimal findings dict from raw grep output
    has_matches = bool(grep_output.strip() and "(no pattern matches)" not in grep_output)
    return {
        "has_vulnerability": has_matches,
        "severity": vuln.severity,
        "affected_components": [],
        "summary": (
            f"Grep found {grep_output.count(chr(10))} potential {vuln.display} pattern "
            "matches but LLM analysis was unavailable. Review the raw grep output below."
            if has_matches else
            f"No {vuln.display} patterns detected in the audited file types."
        ),
        "steps_to_reproduce": (
            f"1. Clone the repository.\n"
            f"2. Review the flagged locations in the Proof of Concept section.\n"
            f"3. Trace user-controlled input to the identified sinks."
        ),
        "impact": (
            f"Potential {vuln.display} if user input flows into the identified sinks "
            "without sanitisation."
        ),
        "proof_of_concept": grep_output[:1500] or "(no matches found)",
        "remediation": (
            f"Sanitise and validate all user inputs before they reach "
            f"{vuln.description.lower()}"
        ),
    }


async def _llm_analyze_autopwn(result: "AutoPwnResult") -> dict:
    """
    Convert a Phase 2 AutoPwnResult into structured H1 report fields via LLM.
    Includes Phase 7/8 enriched CVE and exploit data when present.
    Falls back to minimal dict on failure.
    """
    obs_block = "\n\n".join(
        f"[{c.action} — cycle {c.cycle_num}]\n{c.observation[:500]}"
        for c in result.cycles
    ) or "(no tool observations recorded)"

    # Phase 7/8 enrichment data — included when available
    cve_ctx = ""
    enriched_cves = getattr(result, "enriched_cves", [])
    if enriched_cves:
        lines = []
        for d in enriched_cves:
            score_str = f"{d.score:.1f}" if d.score is not None else "N/A"
            lines.append(f"  {d.cve_id} [{d.severity} {score_str}]: {d.description}")
        cve_ctx = "\n\n=== ENRICHED CVE DATA ===\n" + "\n".join(lines)

    exploit_ctx = ""
    exploit_suggestions = getattr(result, "exploit_suggestions", [])
    if exploit_suggestions:
        lines = []
        for e in exploit_suggestions:
            lines.append(f"  EDB-{e.edb_id} [{e.exploit_type}/{e.platform}] {e.title}")
        exploit_ctx = "\n\n=== KNOWN EXPLOITS (searchsploit) ===\n" + "\n".join(lines)

    nuclei_ctx = ""
    nuclei_findings = getattr(result, "nuclei_findings", [])
    if nuclei_findings:
        lines = []
        for f in nuclei_findings[:10]:
            score_str = f" (CVSS {f.cvss_score:.1f})" if f.cvss_score is not None else ""
            lines.append(
                f"  [{f.severity.upper()}] {f.template_id} — {f.name}{score_str}"
            )
        nuclei_ctx = "\n\n=== NUCLEI SCAN FINDINGS ===\n" + "\n".join(lines)

    user_msg = (
        f"TARGET: {result.domain}\n"
        f"TOOLS USED: {', '.join(result.tools_used) or 'none'}\n"
        f"AGGRESSIVENESS: {result.aggressiveness}\n\n"
        f"=== EXECUTIVE SUMMARY ===\n{result.executive_summary}\n\n"
        f"=== TOOL OBSERVATIONS ===\n{obs_block[:3000]}"
        f"{cve_ctx[:1500]}"
        f"{exploit_ctx[:1000]}"
        f"{nuclei_ctx[:800]}\n\n"
        "Convert these penetration test findings into the structured report JSON."
    )
    try:
        resp = await asyncio.wait_for(
            _ollama_client.chat.completions.create(
                model=LOCAL_MODEL_NAME,
                messages=[
                    {"role": "system", "content": _EXPORT_SYSTEM},
                    {"role": "user",   "content": user_msg},
                ],
                temperature=0.2,
                top_p=0.9,
            ),
            timeout=_LLM_TIMEOUT,
        )
        parsed = _extract_json(resp.choices[0].message.content or "")
        if parsed:
            return parsed
    except Exception as exc:
        log.error("Audit: LLM autopwn export failed: %s", exc)

    # Fallback
    return {
        "severity": "High",
        "vulnerability_types": result.tools_used or ["Network Vulnerability"],
        "affected_components": [result.domain],
        "summary": (
            result.executive_summary[:500]
            if result.executive_summary
            else "No executive summary available."
        ),
        "steps_to_reproduce": "See tool observations in the exported report.",
        "impact": "Review the executive summary for full impact assessment.",
        "proof_of_concept": obs_block[:500],
        "remediation": (
            "Apply vendor security patches, harden exposed services, "
            "and restrict access to sensitive ports."
        ),
    }


# ---------------------------------------------------------------------------
# Discord UI — embed builders
# ---------------------------------------------------------------------------


def _build_progress_embed(status: str, repo: str, vuln_display: str) -> discord.Embed:
    return discord.Embed(
        title=f"🔍 Repository Audit — `{repo}`",
        description=f"**Vulnerability:** {vuln_display}\n**Status:** {status}",
        color=discord.Color.orange(),
        timestamp=datetime.now(timezone.utc),
    ).set_footer(text="Root AI \u2022 Phase 4 Audit Engine  |  Authorised use only")


def _build_summary_embed(
    findings: dict,
    repo: str,
    vuln_display: str,
    filename: str,
    duration_s: float,
) -> discord.Embed:
    severity = findings.get("severity", "High")
    has_vuln = findings.get("has_vulnerability", True)
    color = (
        discord.Color.red()    if severity == "Critical" else
        discord.Color.orange() if severity == "High"     else
        discord.Color.yellow() if severity == "Medium"   else
        discord.Color.green()  if not has_vuln            else
        discord.Color.greyple()
    )
    embed = discord.Embed(
        title=f"📋 Audit Report — `{repo}`",
        description=findings.get("summary", "No summary produced.")[:2048],
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="🎯 Vulnerability Type", value=vuln_display, inline=True)
    embed.add_field(name="⚠️ Severity",           value=severity,    inline=True)

    affected = findings.get("affected_components", [])
    embed.add_field(
        name="📁 Affected Components",
        value="\n".join(f"`{c}`" for c in affected[:5]) or "None identified",
        inline=False,
    )
    embed.add_field(name="⏱️ Duration", value=f"{duration_s:.0f}s", inline=True)
    embed.add_field(name="📄 Report",   value=f"`{filename}`",        inline=True)
    embed.set_footer(text="Root AI \u2022 Phase 4 Audit Engine  |  Authorised use only")
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class AuditRepoCog(commands.Cog, name="Audit"):
    """
    Phase 4 — Repository Security Audit & HackerOne Report Generator.

    /audit_repo clones a GitHub repo on Parrot OS, runs vulnerability-specific
    grep patterns, feeds the curated evidence slice to the LLM, and uploads a
    HackerOne-format markdown report as a Discord file.

    export_report() is the public API consumed by Phase 2's AutoPwnView
    "Export Report" button to convert network scan findings into a report.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ------------------------------------------------------------------
    # Public API — called by Phase 2 AutoPwnView "Export Report" button
    # ------------------------------------------------------------------

    async def export_report(
        self,
        interaction: discord.Interaction,
        result: "AutoPwnResult",
    ) -> None:
        """
        Generate a HackerOne-format report from a Phase 2 AutoPwnResult.

        interaction.response has already been consumed by edit_message()
        in autopwn.py — use followup throughout.
        """
        now = datetime.now(timezone.utc)
        log.info("Audit: export_report | target=%s", result.domain)

        status_msg = await interaction.followup.send(
            embed=discord.Embed(
                title="📄 Generating HackerOne Report...",
                description=f"Analysing findings for `{result.domain}` via LLM...",
                color=discord.Color.orange(),
            ),
            wait=True,
            ephemeral=True,
        )

        findings = await _llm_analyze_autopwn(result)

        # ── Render markdown ───────────────────────────────────────────────────
        vuln_types = ", ".join(findings.get("vulnerability_types", ["Network Vulnerability"]))
        affected = ", ".join(findings.get("affected_components", [result.domain])[:3])
        severity = findings.get("severity", "High")

        # ── Build Phase 7/8/10 report sections (rendered directly — no LLM reformatting) ─
        enriched_cves = getattr(result, "enriched_cves", [])
        exploit_suggestions = getattr(result, "exploit_suggestions", [])
        nuclei_findings = getattr(result, "nuclei_findings", [])

        cve_section = ""
        if enriched_cves:
            rows = [
                "| CVE ID | Severity | CVSS | Description |",
                "|--------|----------|------|-------------|",
            ]
            for d in enriched_cves:
                score = f"{d.score:.1f}" if d.score is not None else "N/A"
                desc = (d.description or "")[:80].replace("|", "\\|")
                rows.append(f"| {d.cve_id} | {d.severity} | {score} | {desc} |")
            cve_section = "\n".join(rows)

        exploit_section = ""
        if exploit_suggestions:
            rows = [
                "| EDB-ID | Type | Platform | Title |",
                "|--------|------|----------|-------|",
            ]
            for e in exploit_suggestions:
                title_safe = e.title[:60].replace("|", "\\|")
                rows.append(f"| {e.edb_id} | {e.exploit_type} | {e.platform} | {title_safe} |")
            exploit_section = "\n".join(rows)

        nuclei_section = ""
        if nuclei_findings:
            rows = [
                "| Template ID | Severity | CVSS | Name | Matched URL |",
                "|-------------|----------|------|------|-------------|",
            ]
            for f in nuclei_findings:
                score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
                name_safe = f.name[:50].replace("|", "\\|")
                url_safe = f.matched_url[:60].replace("|", "\\|")
                rows.append(
                    f"| `{f.template_id}` | {f.severity} | {score} | {name_safe} | {url_safe} |"
                )
            nuclei_section = "\n".join(rows)

        metadata = {
            "Target":           result.domain,
            "Scan Date":        result.timestamp.strftime("%Y-%m-%d"),
            "Tools Used":       ", ".join(result.tools_used) or "None",
            "Aggressiveness":   result.aggressiveness,
            "Cycles Run":       str(len(result.cycles)),
            "Duration":         f"{result.total_duration_s:.0f}s",
            "CVEs Analysed":    str(len(enriched_cves)),
            "Exploits Found":   str(len(exploit_suggestions)),
            "Nuclei Findings":  str(len(nuclei_findings)),
            "Generated By":     "Root AI \u2022 Phase 4",
        }

        report_md = _render_h1_markdown(
            title=f"Penetration Test Report \u2014 {result.domain}",
            severity=severity,
            vuln_type=vuln_types,
            affected=affected,
            summary=findings.get("summary", result.executive_summary[:500]),
            steps=findings.get("steps_to_reproduce", "See tool observations in report body."),
            impact=findings.get("impact", "Review executive summary for impact assessment."),
            poc=findings.get("proof_of_concept", "See raw observations in report body."),
            remediation=findings.get(
                "remediation",
                "Apply vendor patches and harden all exposed services.",
            ),
            timestamp=now,
            metadata=metadata,
            cve_section=cve_section,
            exploit_section=exploit_section,
            nuclei_section=nuclei_section,
        )

        filename = (
            f"report_{result.domain.replace('.', '_')}"
            f"_{now.strftime('%Y%m%d_%H%M%S')}.md"
        )
        file_obj = discord.File(io.BytesIO(report_md.encode("utf-8")), filename=filename)

        summary_embed = discord.Embed(
            title=f"📋 Report Ready \u2014 `{result.domain}`",
            description=findings.get("summary", "")[:1024],
            color=discord.Color.green(),
            timestamp=now,
        )
        summary_embed.add_field(name="\u26a0\ufe0f Severity",        value=severity,             inline=True)
        summary_embed.add_field(name="\ud83d\udee0\ufe0f Vuln Types", value=vuln_types[:256],     inline=True)
        if enriched_cves:
            critical_count = sum(
                1 for d in enriched_cves
                if (d.severity or "").upper() in ("CRITICAL", "HIGH")
            )
            summary_embed.add_field(
                name="\ud83d\udd2c CVE Analysis",
                value=f"{len(enriched_cves)} enriched \u00b7 {critical_count} Critical/High",
                inline=True,
            )
        if exploit_suggestions:
            summary_embed.add_field(
                name="\ud83d\udca3 Known Exploits",
                value=f"{len(exploit_suggestions)} via searchsploit",
                inline=True,
            )
        if nuclei_findings:
            nuclei_crit = sum(
                1 for f in nuclei_findings if f.severity in ("critical", "high")
            )
            summary_embed.add_field(
                name="\ud83d\udd2c Nuclei Scan",
                value=f"{len(nuclei_findings)} finding(s) \u00b7 {nuclei_crit} Critical/High",
                inline=True,
            )
        summary_embed.add_field(name="\ud83d\udcc4 File",            value=f"`{filename}`",       inline=False)
        summary_embed.set_footer(
            text="Root AI \u2022 Phase 4 Audit Engine  |  Authorised use only"
        )

        try:
            await status_msg.edit(
                embed=discord.Embed(
                    title="\u2705 Report Generated \u2014 Uploading...",
                    color=discord.Color.green(),
                )
            )
        except Exception:
            pass

        await interaction.followup.send(embed=summary_embed, file=file_obj, ephemeral=True)
        log.info(
            "Audit: export complete | target=%s | severity=%s",
            result.domain, severity,
        )

    # ------------------------------------------------------------------
    # Slash command
    # ------------------------------------------------------------------

    @app_commands.command(
        name="audit_repo",
        description="[OWNER] Audit a GitHub repo for vulnerabilities and export a HackerOne report.",
    )
    @app_commands.describe(
        github_url="GitHub repository URL (https://github.com/owner/repo)",
        vulnerability_type="Vulnerability class to audit for",
    )
    @app_commands.choices(vulnerability_type=[
        app_commands.Choice(
            name="SQL Injection \u2014 database query tampering",         value="sql_injection"),
        app_commands.Choice(
            name="XSS \u2014 cross-site scripting",                       value="xss"),
        app_commands.Choice(
            name="SSRF \u2014 server-side request forgery",               value="ssrf"),
        app_commands.Choice(
            name="Command Injection \u2014 OS shell execution",           value="cmd_injection"),
        app_commands.Choice(
            name="Path Traversal \u2014 LFI / directory traversal",      value="path_traversal"),
        app_commands.Choice(
            name="Hardcoded Secrets \u2014 credentials & API keys",       value="hardcoded_secrets"),
        app_commands.Choice(
            name="Insecure Deserialization \u2014 pickle/YAML/XML",       value="insecure_deser"),
        app_commands.Choice(
            name="Open Redirect \u2014 unvalidated URL redirects",        value="open_redirect"),
    ])
    async def audit_repo(
        self,
        interaction: discord.Interaction,
        github_url: str,
        vulnerability_type: str,
    ) -> None:
        """Phase 4 entry point — repo clone, grep, LLM analysis, H1 report upload."""

        # ── Owner gate ────────────────────────────────────────────────────────
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "\u26d4 `/audit_repo` is an owner-only command.", ephemeral=True
            )
            return

        # ── URL validation ───────────────────────────────────────────────────
        valid, clean_url_or_err = _validate_github_url(github_url)
        if not valid:
            await interaction.response.send_message(
                f"\u26a0\ufe0f Invalid URL: {clean_url_or_err}", ephemeral=True
            )
            return
        clean_url: str = clean_url_or_err

        vuln = VULN_CONFIGS.get(vulnerability_type)
        if vuln is None:
            await interaction.response.send_message(
                f"\u26a0\ufe0f Unknown vulnerability type: `{vulnerability_type}`",
                ephemeral=True,
            )
            return

        # ── Concurrency guard ────────────────────────────────────────────────
        if _audit_lock.locked():
            await interaction.response.send_message(
                "\u26a0\ufe0f An audit is already running. Please wait for it to finish.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(thinking=True)
        repo_name = clean_url.split("/")[-1].removesuffix(".git")
        log.info(
            "Audit: /audit_repo | url=%s | vuln=%s | user=%s",
            clean_url, vulnerability_type, interaction.user,
        )

        async with _audit_lock:
            work_dir = f"/tmp/audit_{uuid.uuid4().hex}"
            t0 = time.monotonic()
            findings: dict | None = None
            grep_out: str = ""

            try:
                # ── Initial progress embed ────────────────────────────────────
                progress_msg = await interaction.followup.send(
                    embed=_build_progress_embed(
                        "\u23f3 Cloning repository on Parrot OS...",
                        repo_name, vuln.display,
                    ),
                    wait=True,
                )

                # ── Clone + size-check + grep ─────────────────────────────────
                clone_status, grep_out, file_contents = await _clone_and_grep(
                    clean_url, vuln, work_dir
                )

                if clone_status != "ok":
                    await progress_msg.edit(
                        embed=discord.Embed(
                            title="\u274c Audit Failed",
                            description=clone_status[:2000],
                            color=discord.Color.red(),
                        )
                    )
                    return  # finally block runs cleanup

                await progress_msg.edit(
                    embed=_build_progress_embed(
                        f"\ud83e\udd16 Analysing {vuln.display} patterns with LLM...",
                        repo_name, vuln.display,
                    )
                )

                # ── LLM analysis ──────────────────────────────────────────────
                findings = await _llm_analyze_repo(
                    clean_url, vuln, grep_out, file_contents
                )

                await progress_msg.edit(
                    embed=_build_progress_embed(
                        "\ud83d\udcc4 Rendering HackerOne report...",
                        repo_name, vuln.display,
                    )
                )

            finally:
                # ── Cleanup (always runs — even on exception or early return) ─
                try:
                    await run_parrot_command(
                        f"rm -rf '{work_dir}' 2>/dev/null", timeout=15
                    )
                    log.info("Audit: cleaned up %s", work_dir)
                except Exception:
                    log.warning("Audit: cleanup failed for %s", work_dir)

        # ── Render & upload report (outside SSH lock) ─────────────────────────
        if findings is None:
            return  # error was already sent above

        now = datetime.now(timezone.utc)
        duration = time.monotonic() - t0

        # Extract affected components from grep output if LLM didn't provide them
        affected_components: list[str] = findings.get("affected_components", [])
        if not affected_components:
            for line in grep_out.splitlines()[:5]:
                part = line.split(":")[0].replace(work_dir, "").lstrip("/")
                if part:
                    affected_components.append(f"{repo_name}/{part}")

        severity = findings.get("severity", vuln.severity)
        affected_str = ", ".join(affected_components[:3]) or repo_name

        metadata = {
            "Repository":        clean_url,
            "Vulnerability Type": vuln.display,
            "Audit Date":        now.strftime("%Y-%m-%d"),
            "Pattern Matches":   str(max(0, grep_out.count("\n"))),
            "Severity":          severity,
            "Generated By":      "Root AI \u2022 Phase 4",
        }

        report_md = _render_h1_markdown(
            title=f"Security Audit Report \u2014 {repo_name}",
            severity=severity,
            vuln_type=vuln.display,
            affected=affected_str,
            summary=findings.get("summary", "No summary produced."),
            steps=findings.get(
                "steps_to_reproduce",
                "1. Clone the repository.\n"
                "2. Review the flagged code sections.\n"
                "3. Trace user input through the identified sinks.",
            ),
            impact=findings.get(
                "impact",
                f"Potential {vuln.display} if user-controlled input "
                f"reaches the identified sinks without sanitisation.",
            ),
            poc=findings.get(
                "proof_of_concept",
                grep_out[:1000] or "(no pattern matches found)",
            ),
            remediation=findings.get(
                "remediation",
                f"Sanitise and validate all user inputs before "
                f"they reach {vuln.description.lower()}.",
            ),
            timestamp=now,
            metadata=metadata,
        )

        filename = (
            f"audit_{repo_name}_{vulnerability_type}"
            f"_{now.strftime('%Y%m%d_%H%M%S')}.md"
        )
        file_obj = discord.File(io.BytesIO(report_md.encode("utf-8")), filename=filename)
        summary_embed = _build_summary_embed(
            findings=findings,
            repo=repo_name,
            vuln_display=vuln.display,
            filename=filename,
            duration_s=duration,
        )

        # Mark progress as done
        try:
            await progress_msg.edit(
                embed=_build_progress_embed(
                    "\u2705 Complete \u2014 report ready below.",
                    repo_name, vuln.display,
                )
            )
        except Exception:
            pass

        await interaction.followup.send(embed=summary_embed, file=file_obj)
        log.info(
            "Audit: complete | repo=%s | vuln=%s | severity=%s | duration=%.1fs",
            repo_name, vulnerability_type, severity, duration,
        )


# ---------------------------------------------------------------------------
# Extension setup
# ---------------------------------------------------------------------------


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AuditRepoCog(bot))
