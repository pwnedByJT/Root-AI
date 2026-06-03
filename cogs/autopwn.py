"""
cogs/autopwn.py
Phase 2 — Autonomous ReAct Penetration Testing Agent

Slash command: /autopwn <target_domain> <aggressiveness>
Public API:    AutoPwnCog.start_autopwn(interaction, recon_result)
               └─ Called by the Phase 1 ReconView "Send to Auto-Pwn" button.

Pipeline (ReAct loop — Reason → Act → Observe):
  Tools: run_nmap, run_gobuster, run_nikto, synthesize
  Max cycles capped by aggressiveness profile (2 / 3 / 4).
  Final step: LLM synthesises an executive summary embed.

Security boundaries:
  - /autopwn and the Phase 1 button are both restricted to BOT_OWNER_ID.
  - asyncio.Lock prevents concurrent runs (single Parrot OS SSH protection).
  - Target FQDN is validated upstream; _sanitize_host() strips residual chars.
  - Per-tool SSH timeout: 60–120 s (profile-dependent).
  - Total wall-clock cap: 5–10 minutes (profile-dependent).
  - Each tool observation is truncated to 2 000 chars before LLM re-ingestion.
  - LLM emits JSON action selection in message content (NOT OpenAI tool-calls);
    parse failure triggers immediate synthesis rather than an exception.

Phase 4 integration point:
  - AutoPwnResult is the typed contract between Phase 2 and Phase 4 (audit/report).
  - AutoPwnView.export_button is the handoff stub for the HackerOne-format exporter.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Coroutine

import discord
from discord import app_commands
from discord.ext import commands
from openai import AsyncOpenAI

from config import BOT_OWNER_ID, LOCAL_LLM_URL, LOCAL_MODEL_NAME
from cogs.exploit_suggester import ExploitMatch, search_exploits
from cogs.recon import CVEDetail, ReconResult, _validate_domain, enrich_cves
from cogs.security import run_parrot_command, run_parrot_nmap_scan

log = logging.getLogger("root_ai.autopwn")

# ---------------------------------------------------------------------------
# Aggressiveness presets
# ---------------------------------------------------------------------------


@dataclass
class AggressivenessProfile:
    max_cycles: int
    nmap_flags: str
    gobuster_wordlist: str
    allow_nikto: bool
    tool_timeout: int   # seconds per SSH command
    total_timeout: int  # seconds total wall-clock cap


PROFILES: dict[str, AggressivenessProfile] = {
    "low": AggressivenessProfile(
        max_cycles=2,
        nmap_flags="-T2 --top-ports 100 --open",
        gobuster_wordlist="/usr/share/wordlists/dirb/small.txt",
        allow_nikto=False,
        tool_timeout=60,
        total_timeout=300,
    ),
    "medium": AggressivenessProfile(
        max_cycles=3,
        nmap_flags="-T3 --top-ports 1000 --open",
        gobuster_wordlist="/usr/share/wordlists/dirb/common.txt",
        allow_nikto=True,
        tool_timeout=90,
        total_timeout=480,
    ),
    "high": AggressivenessProfile(
        max_cycles=4,
        nmap_flags="-T4 -p- --open",
        gobuster_wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        allow_nikto=True,
        tool_timeout=120,
        total_timeout=600,
    ),
}

# ---------------------------------------------------------------------------
# Input sanitisation (target is already FQDN-validated; this strips residuals)
# ---------------------------------------------------------------------------

_SAFE_HOST_RE = re.compile(r"[^a-zA-Z0-9.\-]")


def _sanitize_host(host: str) -> str:
    return _SAFE_HOST_RE.sub("", host)[:253]


# ---------------------------------------------------------------------------
# ReAct system prompt
# ---------------------------------------------------------------------------

_REACT_SYSTEM = """\
You are an autonomous penetration testing agent assessing an authorised target domain.
Methodically enumerate the attack surface using the tools available to you.

AVAILABLE ACTIONS:
  run_nmap     — Run nmap port scan against the target
  run_gobuster — Run gobuster directory enumeration against http://<target>
  run_nikto    — Run nikto web vulnerability scanner against the target
  synthesize   — Stop scanning and write the final executive summary

RESPONSE FORMAT — reply with ONLY valid JSON, no markdown, no prose:
{
  "reasoning": "<one-sentence explanation of your next step>",
  "action": "<run_nmap|run_gobuster|run_nikto|synthesize>",
  "args": {}
}

For the "synthesize" action, write the full executive summary in the "reasoning" field.
The summary MUST include:
  • Key findings from each tool observation
  • Severity assessment (Critical / High / Medium / Low / Info)
  • Attack vectors identified and how they could be exploited
  • Recommended next steps for a bug bounty submission

RULES:
  1. Do NOT repeat an action you have already taken.
  2. If nikto is not in the available tools, do not choose it.
  3. Choose "synthesize" when you have collected sufficient data OR exhausted all tools.
  4. Keep "reasoning" to 1–2 sentences for non-synthesize actions.
"""

_OBS_MAX_CHARS = 2_000  # truncate observations before re-feeding to LLM

# ---------------------------------------------------------------------------
# JSON extraction (LLM may wrap output in markdown fences)
# ---------------------------------------------------------------------------

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def _extract_json(text: str) -> dict | None:
    """Extract the first valid JSON object from LLM output."""
    for candidate in (
        text.strip(),
        *(m.group(1).strip() for m in _JSON_FENCE_RE.finditer(text)),
    ):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Last resort: find outermost { … }
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass

    return None


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass
class CycleResult:
    """Record of a single Reason → Act → Observe iteration."""

    cycle_num: int
    action: str
    reasoning: str
    observation: str
    duration_s: float


@dataclass
class AutoPwnResult:
    """
    Typed snapshot of a completed Auto-Pwn run.
    Passed to AutoPwnView so the Phase 4 export button can hand it to the
    report-generation pipeline without a global cache or database lookup.
    """

    domain: str
    aggressiveness: str
    cycles: list[CycleResult] = field(default_factory=list)
    executive_summary: str = ""
    tools_used: list[str] = field(default_factory=list)
    total_duration_s: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str = ""
    # Phase 7/8 enrichment — populated by _run_react_agent; consumed by Phase 4 export
    enriched_cves: list[CVEDetail] = field(default_factory=list)
    exploit_suggestions: list[ExploitMatch] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Autonomous ReAct agent (no Discord coupling)
# ---------------------------------------------------------------------------

_ollama_client = AsyncOpenAI(
    base_url=LOCAL_LLM_URL,
    api_key="ollama",
)


async def _run_react_agent(
    target: str,
    aggressiveness: str,
    profile: AggressivenessProfile,
    initial_recon: ReconResult | None,
    progress_cb: Callable[[str], Coroutine],
) -> AutoPwnResult:
    """
    Execute the ReAct loop for *target*.

    Parameters
    ----------
    target:
        Validated FQDN — no further validation needed inside this function.
    aggressiveness:
        Human-readable preset label stored in the result for display/export.
    profile:
        Resolved AggressivenessProfile controlling cycle count, tools, timeouts.
    initial_recon:
        Optional Phase 1 ReconResult used to seed the initial LLM context.
    progress_cb:
        ``async (status: str) -> None`` callback for live Discord embed updates.
    """
    result = AutoPwnResult(domain=target, aggressiveness=aggressiveness)
    wall_start = time.monotonic()

    # ── Seed LLM history ────────────────────────────────────────────────────
    messages: list[dict] = [{"role": "system", "content": _REACT_SYSTEM}]

    if initial_recon:
        seed_lines = [f"TARGET: {target}"]
        if initial_recon.subdomains:
            seed_lines.append(
                f"KNOWN SUBDOMAINS ({len(initial_recon.subdomains)} from crt.sh):\n"
                + "\n".join(initial_recon.subdomains[:20])
            )
        if initial_recon.open_ports:
            seed_lines.append(
                f"KNOWN OPEN PORTS ({len(initial_recon.open_ports)} from nmap):\n"
                + "\n".join(initial_recon.open_ports[:20])
            )
        sd = initial_recon.shodan_data
        if sd and sd.services:
            svc_summary = "\n".join(
                f"  {s['port']}/{s['proto']} {s.get('product','')} {s.get('version','')}".strip()
                for s in sd.services[:20]
            )
            seed_lines.append(f"SHODAN SERVICES ({len(sd.services)} indexed):\n{svc_summary}")
        if sd and sd.vulns:
            await progress_cb("🔍 Enriching CVE data via NVD (free tier — may take ~30s)...")
            enriched: list[CVEDetail] = await enrich_cves(sd.vulns)
            result.enriched_cves = enriched
            if enriched:
                enriched_ids = {d.cve_id for d in enriched}
                cve_lines: list[str] = []
                for detail in enriched:
                    score_str = f"{detail.score:.1f}" if detail.score is not None else "N/A"
                    cve_lines.append(
                        f"  {detail.cve_id} [{detail.severity} {score_str}]: {detail.description}"
                    )
                unenriched = [c for c in sd.vulns[:10] if c not in enriched_ids]
                block = "\n".join(cve_lines)
                if unenriched:
                    block += "\n  Also reported (no NVD data): " + ", ".join(unenriched)
                seed_lines.append(
                    f"SHODAN CVEs — ENRICHED ({len(enriched)}/{min(len(sd.vulns), 5)} looked up):\n{block}"
                )
            else:
                seed_lines.append("SHODAN CVEs (bare): " + ", ".join(sd.vulns[:10]))

        # ── Exploit suggester — search ExploitDB for high/critical CVEs + products ──
        exploit_queries: list[str] = []
        if sd and sd.vulns:
            # Prefer high/critical enriched CVEs; fall back to bare CVE IDs
            if enriched:
                exploit_queries.extend(
                    d.cve_id for d in enriched if d.score is not None and d.score >= 7.0
                )
            if not exploit_queries:
                exploit_queries.extend(sd.vulns[:3])
        # Also add Shodan product names for broader exploit coverage
        if sd and sd.services:
            for svc in sd.services[:3]:
                product = svc.get("product", "").strip()
                if product and product not in exploit_queries:
                    exploit_queries.append(product)

        if exploit_queries:
            await progress_cb("💣 Searching ExploitDB for known exploits...")
            exploits: list[ExploitMatch] = await search_exploits(exploit_queries[:5])
            result.exploit_suggestions = exploits
            if exploits:
                exploit_lines: list[str] = []
                for e in exploits[:10]:
                    exploit_lines.append(
                        f"  [{e.exploit_type}/{e.platform}] {e.title} (EDB-{e.edb_id})"
                    )
                seed_lines.append(
                    f"KNOWN EXPLOITS ({len(exploits)} found via searchsploit):\n"
                    + "\n".join(exploit_lines)
                )

        first_msg = (
            "Phase 1 recon data is available — use it as your starting context:\n\n"
            + "\n\n".join(seed_lines)
            + "\n\nBegin the autonomous assessment. Choose your first action."
        )
    else:
        first_msg = f"TARGET: {target}\n\nBegin the autonomous assessment. Choose your first action."

    messages.append({"role": "user", "content": first_msg})

    # ── Available action set (profile-controlled) ────────────────────────────
    available: set[str] = {"run_nmap", "run_gobuster", "synthesize"}
    if profile.allow_nikto:
        available.add("run_nikto")
    taken: set[str] = set()

    # ── ReAct loop ───────────────────────────────────────────────────────────
    for cycle in range(1, profile.max_cycles + 1):
        if time.monotonic() - wall_start > profile.total_timeout:
            log.warning("AutoPwn: total_timeout hit at cycle %d — breaking", cycle)
            await progress_cb(f"⏱️ Time cap reached — synthesizing findings...")
            break

        await progress_cb(f"🧠 Cycle {cycle}/{profile.max_cycles} — Reasoning...")

        # ── Reason ──────────────────────────────────────────────────────────
        llm_text = ""
        try:
            resp = await asyncio.wait_for(
                _ollama_client.chat.completions.create(
                    model=LOCAL_MODEL_NAME,
                    messages=messages,
                    temperature=0.2,
                    top_p=0.9,
                ),
                timeout=60,
            )
            llm_text = resp.choices[0].message.content or ""
        except asyncio.TimeoutError:
            log.warning("AutoPwn: LLM timed out at cycle %d", cycle)
            await progress_cb(f"⚠️ Cycle {cycle}: LLM timeout — synthesizing...")
            break
        except Exception as exc:
            log.error("AutoPwn: LLM error at cycle %d: %s", cycle, exc)
            result.error = str(exc)
            await progress_cb(f"⚠️ Cycle {cycle}: LLM error — synthesizing...")
            break

        parsed = _extract_json(llm_text)

        # Retry once with an explicit synthesize prompt on parse failure
        if not parsed:
            log.warning("AutoPwn: JSON parse failed at cycle %d. Raw: %r", cycle, llm_text[:200])
            messages.append({"role": "assistant", "content": llm_text})
            messages.append({
                "role": "user",
                "content": (
                    "Your last response was not valid JSON. "
                    'Respond immediately with: {"reasoning": "<summary of all findings>", '
                    '"action": "synthesize", "args": {}}'
                ),
            })
            try:
                resp2 = await asyncio.wait_for(
                    _ollama_client.chat.completions.create(
                        model=LOCAL_MODEL_NAME,
                        messages=messages,
                        temperature=0.1,
                        top_p=0.9,
                    ),
                    timeout=60,
                )
                parsed = _extract_json(resp2.choices[0].message.content or "")
            except Exception:
                pass

            if not parsed:
                result.error = "LLM failed to produce valid JSON after retry"
                await progress_cb("⚠️ LLM output unreadable — aborting loop")
                break

        action: str = parsed.get("action", "synthesize")
        reasoning: str = parsed.get("reasoning", "")

        # Guard: unknown or already-taken action → synthesize
        if action not in available or action in taken:
            log.info(
                "AutoPwn: action '%s' %s — forcing synthesize",
                action,
                "already taken" if action in taken else "not available",
            )
            action = "synthesize"
            reasoning = parsed.get("reasoning", reasoning)

        messages.append({"role": "assistant", "content": json.dumps(parsed)})

        # ── Synthesize (terminal) ────────────────────────────────────────────
        if action == "synthesize":
            result.executive_summary = reasoning
            await progress_cb("📋 Synthesizing executive summary...")
            break

        # ── Act ──────────────────────────────────────────────────────────────
        taken.add(action)
        t0 = time.monotonic()
        safe_host = _sanitize_host(target)
        observation = ""

        if action == "run_nmap":
            await progress_cb(f"🔍 Cycle {cycle}/{profile.max_cycles} — Running nmap...")
            try:
                observation = await asyncio.wait_for(
                    run_parrot_nmap_scan(target, profile.nmap_flags),
                    timeout=profile.tool_timeout,
                )
            except asyncio.TimeoutError:
                observation = f"nmap timed out after {profile.tool_timeout}s."
            if "nmap" not in result.tools_used:
                result.tools_used.append("nmap")

        elif action == "run_gobuster":
            await progress_cb(f"📂 Cycle {cycle}/{profile.max_cycles} — Running gobuster...")
            cmd = (
                f"gobuster dir -u http://{safe_host} "
                f"-w {profile.gobuster_wordlist} -t 50 -q --no-error 2>/dev/null | head -100"
            )
            try:
                observation = await asyncio.wait_for(
                    run_parrot_command(cmd, timeout=profile.tool_timeout),
                    timeout=profile.tool_timeout + 10,
                )
            except asyncio.TimeoutError:
                observation = f"gobuster timed out after {profile.tool_timeout}s."
            if "gobuster" not in result.tools_used:
                result.tools_used.append("gobuster")

        elif action == "run_nikto":
            await progress_cb(f"🕷️ Cycle {cycle}/{profile.max_cycles} — Running nikto...")
            nikto_time = min(profile.tool_timeout, 90)
            cmd = f"nikto -h {safe_host} -maxtime {nikto_time} -nointeractive 2>/dev/null"
            try:
                observation = await asyncio.wait_for(
                    run_parrot_command(cmd, timeout=nikto_time + 15),
                    timeout=nikto_time + 20,
                )
            except asyncio.TimeoutError:
                observation = f"nikto timed out after {nikto_time}s."
            if "nikto" not in result.tools_used:
                result.tools_used.append("nikto")

        else:
            observation = f"Unknown action '{action}' — skipped."

        cycle_duration = time.monotonic() - t0
        log.info("AutoPwn: cycle %d (%s) complete in %.1fs", cycle, action, cycle_duration)

        # Truncate before re-feeding to LLM
        if len(observation) > _OBS_MAX_CHARS:
            observation = observation[:_OBS_MAX_CHARS] + f"\n[... truncated to {_OBS_MAX_CHARS} chars]"

        result.cycles.append(
            CycleResult(
                cycle_num=cycle,
                action=action,
                reasoning=reasoning,
                observation=observation,
                duration_s=cycle_duration,
            )
        )

        # ── Observe ──────────────────────────────────────────────────────────
        messages.append({
            "role": "user",
            "content": (
                f"OBSERVATION from {action}:\n```\n{observation}\n```\n\n"
                "Choose your next action."
            ),
        })

    result.total_duration_s = time.monotonic() - wall_start

    # ── Fallback synthesis if loop exited without a summary ──────────────────
    if not result.executive_summary:
        if result.cycles:
            await progress_cb("📋 Generating summary from collected observations...")
            obs_block = "\n\n".join(
                f"[{c.action} — cycle {c.cycle_num}]\n{c.observation[:500]}"
                for c in result.cycles
            )
            synth_messages = [
                {"role": "system", "content": _REACT_SYSTEM},
                {
                    "role": "user",
                    "content": (
                        f"TARGET: {target}\n\nCollected tool observations:\n{obs_block}\n\n"
                        "Write the full executive summary as plain text (not JSON). "
                        "Include findings, severity, attack vectors, and next steps."
                    ),
                },
            ]
            try:
                synth_resp = await asyncio.wait_for(
                    _ollama_client.chat.completions.create(
                        model=LOCAL_MODEL_NAME,
                        messages=synth_messages,
                        temperature=0.3,
                        top_p=0.9,
                    ),
                    timeout=90,
                )
                result.executive_summary = (
                    synth_resp.choices[0].message.content or "No summary generated."
                )
            except Exception as exc:
                result.executive_summary = f"Summary generation failed: {exc}"
        else:
            result.executive_summary = (
                "No findings collected — verify Parrot OS SSH connectivity and try again."
            )

    return result


# ---------------------------------------------------------------------------
# Discord UI — Embed builders
# ---------------------------------------------------------------------------


def _fmt_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s" if m else f"{s}s"


def _build_progress_embed(
    domain: str,
    aggressiveness: str,
    status_line: str,
    cycles: list[CycleResult],
    max_cycles: int,
) -> discord.Embed:
    embed = discord.Embed(
        title=f"⚡ Auto-Pwn Pipeline — `{domain}`",
        description=f"**Status:** {status_line}",
        color=discord.Color.orange(),
        timestamp=datetime.now(timezone.utc),
    )

    if cycles:
        lines = ""
        for c in cycles[-5:]:  # show last 5 completed cycles
            lines += f"✅ **Cycle {c.cycle_num}** — `{c.action}` ({c.duration_s:.1f}s)\n"
        embed.add_field(
            name=f"📊 Cycles Complete  ({len(cycles)}/{max_cycles})",
            value=lines,
            inline=False,
        )

    embed.set_footer(
        text=f"Root AI • Phase 2 ReAct Agent  |  Aggressiveness: {aggressiveness}"
    )
    return embed


def _build_summary_embed(result: AutoPwnResult) -> discord.Embed:
    embed = discord.Embed(
        title=f"📋 Executive Summary — `{result.domain}`",
        description=(result.executive_summary or "No summary produced.")[:4000],
        color=discord.Color.green() if not result.error else discord.Color.red(),
        timestamp=result.timestamp,
    )

    embed.add_field(name="🎯 Target", value=f"`{result.domain}`", inline=True)
    embed.add_field(name="🔄 Cycles Run", value=str(len(result.cycles)), inline=True)
    embed.add_field(
        name="🛠️ Tools Used",
        value=(
            ", ".join(f"`{t}`" for t in result.tools_used)
            if result.tools_used
            else "None"
        ),
        inline=True,
    )
    embed.add_field(name="⏱️ Duration", value=_fmt_duration(result.total_duration_s), inline=True)
    embed.add_field(name="🎯 Aggressiveness", value=f"`{result.aggressiveness}`", inline=True)

    if result.error:
        embed.add_field(name="⚠️ Pipeline Error", value=result.error[:512], inline=False)

    embed.set_footer(text="Root AI • Phase 2 ReAct Agent  |  Authorised use only")
    return embed


# ---------------------------------------------------------------------------
# Discord UI — AutoPwn View (Phase 4 export stub)
# ---------------------------------------------------------------------------


class AutoPwnView(discord.ui.View):
    """
    Attached to the final executive summary embed.

    Holds the AutoPwnResult so the Phase 4 export button can pass it to the
    HackerOne-format report generator without a global cache or DB lookup.
    """

    def __init__(self, result: AutoPwnResult) -> None:
        super().__init__(timeout=300)
        self.result = result

    @discord.ui.button(
        label="Export Report",
        style=discord.ButtonStyle.secondary,
        emoji="📄",
    )
    async def export_button(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        """Phase 4 integration point — HackerOne-format report export."""
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ Report export is restricted to the server administrator.",
                ephemeral=True,
            )
            return

        button.disabled = True
        button.label = "⏳ Generating Report..."
        await interaction.response.edit_message(view=self)

        # ── Phase 4 handoff ───────────────────────────────────────────────
        audit_cog = interaction.client.get_cog("Audit")
        if audit_cog is None:
            await interaction.followup.send(
                "⚠️ Audit cog is not loaded — check bot startup logs.",
                ephemeral=True,
            )
            return
        await audit_cog.export_report(interaction, self.result)

    async def on_timeout(self) -> None:
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                item.disabled = True


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class AutoPwnCog(commands.Cog, name="AutoPwn"):
    """
    Phase 2 — Autonomous ReAct Penetration Testing Agent.

    Orchestrates an LLM-driven Reason → Act → Observe loop over the target
    domain, executing nmap, gobuster, and nikto via the Parrot OS SSH tunnel.
    Produces a rich executive summary embed with a Phase 4 export integration
    point.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._lock = asyncio.Lock()  # one autopwn at a time — Parrot OS protection

    # ------------------------------------------------------------------
    # Public API — called by Phase 1 ReconView button
    # ------------------------------------------------------------------

    async def start_autopwn(
        self,
        interaction: discord.Interaction,
        recon_result: ReconResult,
        aggressiveness: str = "medium",
    ) -> None:
        """
        Entry point called from ReconView.autopwn_button.

        The interaction response has already been consumed by the button's
        edit_message() call, so we use interaction.followup throughout.
        """
        await self._run_pipeline(
            interaction=interaction,
            target=recon_result.domain,
            aggressiveness=aggressiveness,
            initial_recon=recon_result,
        )

    # ------------------------------------------------------------------
    # Slash command
    # ------------------------------------------------------------------

    @app_commands.command(
        name="autopwn",
        description="[OWNER] Run autonomous ReAct pentest pipeline on an authorised target.",
    )
    @app_commands.describe(
        target_domain="Fully-qualified domain name to assess (e.g. example.com)",
        aggressiveness="Scan intensity: low / medium / high",
    )
    @app_commands.choices(aggressiveness=[
        app_commands.Choice(name="low — light nmap, 2 cycles, no nikto", value="low"),
        app_commands.Choice(name="medium — nmap + gobuster + nikto, 3 cycles", value="medium"),
        app_commands.Choice(name="high — deep nmap + gobuster + nikto, 4 cycles", value="high"),
    ])
    async def autopwn(
        self,
        interaction: discord.Interaction,
        target_domain: str,
        aggressiveness: str = "medium",
    ) -> None:
        """
        Phase 2 entry point (slash command path).

        Validates the target, defers the interaction, then delegates to the
        shared pipeline runner.
        """
        # ── Owner gate ────────────────────────────────────────────────────────
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/autopwn` is an owner-only command.", ephemeral=True
            )
            return

        # ── FQDN validation ──────────────────────────────────────────────────
        valid, clean_or_err = _validate_domain(target_domain)
        if not valid:
            await interaction.response.send_message(
                f"⚠️ Invalid target: {clean_or_err}", ephemeral=True
            )
            return
        clean_domain: str = clean_or_err

        await interaction.response.defer(thinking=True)
        log.info(
            "AutoPwn: /autopwn invoked | target=%s | aggressiveness=%s | user=%s",
            clean_domain, aggressiveness, interaction.user,
        )

        await self._run_pipeline(
            interaction=interaction,
            target=clean_domain,
            aggressiveness=aggressiveness,
            initial_recon=None,
        )

    # ------------------------------------------------------------------
    # Shared pipeline runner
    # ------------------------------------------------------------------

    async def _run_pipeline(
        self,
        interaction: discord.Interaction,
        target: str,
        aggressiveness: str,
        initial_recon: ReconResult | None,
    ) -> None:
        """
        Core pipeline — handles both slash command and Phase 1 button flows.

        In both cases the interaction response is already consumed upstream
        (defer or edit_message), so we use interaction.followup exclusively.
        """
        profile = PROFILES.get(aggressiveness, PROFILES["medium"])

        # ── Concurrency guard ────────────────────────────────────────────────
        if self._lock.locked():
            await interaction.followup.send(
                "⚠️ An Auto-Pwn scan is already running. "
                "Please wait for it to finish before starting another.",
                ephemeral=True,
            )
            return

        async with self._lock:
            log.info(
                "AutoPwn: pipeline start | target=%s | aggressiveness=%s",
                target, aggressiveness,
            )

            # ── Send initial progress embed ───────────────────────────────────
            progress_embed = _build_progress_embed(
                domain=target,
                aggressiveness=aggressiveness,
                status_line="🔄 Initialising ReAct agent...",
                cycles=[],
                max_cycles=profile.max_cycles,
            )
            progress_msg = await interaction.followup.send(embed=progress_embed, wait=True)

            completed: list[CycleResult] = []

            async def _progress_cb(status: str) -> None:
                """Push a live status update to the progress embed."""
                try:
                    embed = _build_progress_embed(
                        domain=target,
                        aggressiveness=aggressiveness,
                        status_line=status,
                        cycles=completed,
                        max_cycles=profile.max_cycles,
                    )
                    await progress_msg.edit(embed=embed)
                except Exception as exc:
                    log.warning("AutoPwn: progress embed edit failed: %s", exc)

            # ── Run the ReAct agent ───────────────────────────────────────────
            try:
                result = await _run_react_agent(
                    target=target,
                    aggressiveness=aggressiveness,
                    profile=profile,
                    initial_recon=initial_recon,
                    progress_cb=_progress_cb,
                )
                completed = result.cycles
            except Exception as exc:
                log.exception("AutoPwn: unhandled exception in react agent")
                result = AutoPwnResult(
                    domain=target,
                    aggressiveness=aggressiveness,
                    executive_summary="Pipeline failed due to an internal error.",
                    error=str(exc),
                )

            # ── Mark progress embed as done ───────────────────────────────────
            try:
                done_embed = _build_progress_embed(
                    domain=target,
                    aggressiveness=aggressiveness,
                    status_line="✅ Pipeline complete — see summary below.",
                    cycles=completed,
                    max_cycles=profile.max_cycles,
                )
                await progress_msg.edit(embed=done_embed)
            except Exception:
                pass  # non-critical

            # ── Post executive summary ────────────────────────────────────────
            summary_embed = _build_summary_embed(result)
            view = AutoPwnView(result)
            await interaction.followup.send(embed=summary_embed, view=view)

            log.info(
                "AutoPwn: pipeline complete | target=%s | cycles=%d | duration=%.1fs",
                target, len(result.cycles), result.total_duration_s,
            )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AutoPwnCog(bot))
