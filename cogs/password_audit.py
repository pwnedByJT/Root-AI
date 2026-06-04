"""
cogs/password_audit.py
Phase 11 — Password Hash Auditor

Slash command: /password_audit <hashes> [hash_type]
Public API:    crack_hashes(hashes, hash_type="auto") -> list[CrackResult]
               └─ Called by future integration points (audit_repo hash discovery).

Pipeline (/password_audit):
  1. Parse + validate hash input (1–5 hashes, newline or comma separated)
  2. Auto-detect hash type via format-specific regex (or use explicit override)
  3. Resolve wordlist path on Parrot OS (supports both .txt and .gz variants)
  4. For each hash: write isolated temp file → run john → run john --show → cleanup
  5. Post EPHEMERAL embed with cracked passwords behind spoiler tags

Security boundaries:
  - /password_audit gated to BOT_OWNER_ID.
  - asyncio.Lock prevents concurrent cracking (one at a time — Parrot OS protection).
  - Hash input validated by format-specific regex — reject, not strip.
    Characters allowed: [a-zA-Z0-9$./:*+\\-]
  - john session/pot file isolated per-run via uuid4() — no ~/.john/john.pot pollution.
  - Cracked passwords posted EPHEMERAL-only — spoiler-tagged to require deliberate reveal.
  - Max 5 hashes per run; --max-run-time=60 per john invocation (quick wordlist check).
  - Cleanup of temp files in finally — guaranteed even on SSH error or timeout.

john prerequisites on Parrot OS:
  sudo apt install john  (or johntheripper)
  gunzip -k /usr/share/wordlists/rockyou.txt.gz   (if only .gz is present)
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

from config import BOT_OWNER_ID
from cogs.security import run_parrot_command

log = logging.getLogger("root_ai.password_audit")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_HASHES = 5

# --max-run-time passed to john per invocation.
# Short intentionally: this is a quick wordlist check, not an exhaustive crack.
# 5 hashes × 60 s = 300 s max — safely within Discord's 15-min followup window.
_JOHN_MAX_RUN_TIME = 60

# SSH command timeout = run-time + 30 s for startup/cleanup overhead
_JOHN_SSH_TIMEOUT = _JOHN_MAX_RUN_TIME + 30

# Wordlist paths to try in order (some Parrot installs ship gzipped)
_WORDLIST_PATHS = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
)

_crack_lock = asyncio.Lock()  # one john session at a time — Parrot OS protection

# ---------------------------------------------------------------------------
# Hash format table
# ---------------------------------------------------------------------------
# Each entry: (john_format_flag, display_name, detection_regex)
# Order matters: more-specific patterns listed before generic hex patterns.
# For MD5/NTLM ambiguity: auto-detect picks raw-md5 only.  User may override
# with hash_type="ntlm" to force --format=nt explicitly.
# ---------------------------------------------------------------------------

_HASH_FORMATS: list[tuple[str, str, re.Pattern]] = [
    (
        "bcrypt",
        "bcrypt",
        re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
    ),
    (
        "sha512crypt",
        "sha512crypt (Linux $6$)",
        re.compile(r"^\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$"),
    ),
    (
        "md5crypt",
        "md5crypt (Linux $1$)",
        re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
    ),
    (
        "raw-sha512",
        "SHA-512",
        re.compile(r"^[a-fA-F0-9]{128}$"),
    ),
    (
        "raw-sha256",
        "SHA-256",
        re.compile(r"^[a-fA-F0-9]{64}$"),
    ),
    (
        "raw-sha1",
        "SHA-1",
        re.compile(r"^[a-fA-F0-9]{40}$"),
    ),
    (
        "raw-md5",
        "MD5",
        re.compile(r"^[a-fA-F0-9]{32}$"),
    ),
]

# Explicit hash_type override aliases → john format flag
_FORMAT_ALIASES: dict[str, str] = {
    "md5":           "raw-md5",
    "raw-md5":       "raw-md5",
    "sha1":          "raw-sha1",
    "raw-sha1":      "raw-sha1",
    "sha256":        "raw-sha256",
    "raw-sha256":    "raw-sha256",
    "sha512":        "raw-sha512",
    "raw-sha512":    "raw-sha512",
    "ntlm":          "nt",
    "nt":            "nt",
    "bcrypt":        "bcrypt",
    "sha512crypt":   "sha512crypt",
    "sha512-crypt":  "sha512crypt",
    "md5crypt":      "md5crypt",
    "md5-crypt":     "md5crypt",
}

# Hash input character allowlist — validate-or-reject (NOT strip)
# bcrypt includes $, ., / ; crypt hashes may include * ; all are safe in single-quotes
_SAFE_HASH_RE = re.compile(r"^[a-zA-Z0-9$./:*+\-]+$")

# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------


@dataclass
class CrackResult:
    """Result for a single hash cracking attempt."""

    hash_str: str           # original hash string submitted
    cracked: bool           # True if a plaintext password was found
    password: str = ""      # plaintext password (empty when cracked=False)
    hash_type: str = ""     # john format flag used (e.g. "raw-md5", "bcrypt")
    display_type: str = ""  # human-readable type (e.g. "MD5", "bcrypt")
    duration_s: float = 0.0


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def _parse_hashes(raw: str) -> list[str]:
    """
    Parse newline- or comma-separated hashes from user input.

    Returns up to _MAX_HASHES validated hash strings.
    Raises ValueError describing the problem on invalid input.
    """
    candidates = [h.strip() for h in re.split(r"[,\n]+", raw) if h.strip()]
    if not candidates:
        raise ValueError("No hashes provided.")
    if len(candidates) > _MAX_HASHES:
        raise ValueError(
            f"Too many hashes — max {_MAX_HASHES} per run. Got {len(candidates)}."
        )
    validated: list[str] = []
    for h in candidates:
        if len(h) > 256:
            raise ValueError(
                f"Hash is too long (max 256 chars): `{h[:40]}...`"
            )
        if not _SAFE_HASH_RE.match(h):
            raise ValueError(
                f"Hash contains invalid characters: `{h[:40]!r}`\n"
                "Allowed: `[a-zA-Z0-9$./:*+-]`"
            )
        validated.append(h)
    return validated


def _detect_hash_type(hash_str: str) -> Optional[tuple[str, str]]:
    """
    Auto-detect the john format for *hash_str*.

    Returns ``(john_format_flag, display_name)`` for the first matching entry,
    or ``None`` if no pattern matches.
    MD5 / NTLM ambiguity: auto-detect picks raw-md5. Use hash_type="ntlm" to override.
    """
    for fmt, display, pattern in _HASH_FORMATS:
        if pattern.match(hash_str):
            return fmt, display
    return None


# ---------------------------------------------------------------------------
# Wordlist resolver
# ---------------------------------------------------------------------------


async def _resolve_wordlist() -> Optional[str]:
    """
    Return the first existing rockyou wordlist path on Parrot OS, or None.

    Checks _WORDLIST_PATHS in order.  Only the uncompressed .txt variant is
    directly usable by john — the .gz check exists to surface a clear error.
    """
    for path in _WORDLIST_PATHS:
        result = await run_parrot_command(f"test -f '{path}' && echo ok", timeout=10)
        if "ok" in result:
            if path.endswith(".gz"):
                log.warning(
                    "PasswordAudit: rockyou.txt.gz found but john requires uncompressed. "
                    "Run: gunzip -k /usr/share/wordlists/rockyou.txt.gz"
                )
                return None  # don't return .gz — john can't use it directly
            return path
    return None


# ---------------------------------------------------------------------------
# Per-hash cracker (isolated john session)
# ---------------------------------------------------------------------------


async def _crack_single(
    hash_str: str,
    john_format: str,
    display_type: str,
    wordlist_path: str,
) -> CrackResult:
    """
    Crack one hash via john on Parrot OS using an isolated session + pot file.

    Each call generates a fresh uuid4 run_id so:
      - Hash file, pot file, and session name are unique per attempt.
      - ~/.john/john.pot is never touched — no cross-run contamination.
      - finally block always cleans up temp files.

    Never raises — any failure (SSH down, john missing, timeout) returns
    CrackResult(cracked=False) so callers can proceed.
    """
    run_id = uuid.uuid4().hex[:14]
    hash_file = f"/tmp/pwaudit_{run_id}.hash"
    pot_file = f"/tmp/pwaudit_{run_id}.pot"
    session_name = f"pwaudit_{run_id}"

    t0 = time.monotonic()

    # Build shell commands — hash is written via printf (not echo) to avoid
    # trailing newlines that could confuse some john format parsers.
    write_cmd = f"printf '%s' '{hash_str}' > '{hash_file}'"

    crack_cmd = (
        f"john --session='{session_name}' "
        f"--pot='{pot_file}' "
        f"--format='{john_format}' "
        f"--wordlist='{wordlist_path}' "
        f"--max-run-time={_JOHN_MAX_RUN_TIME} "
        f"'{hash_file}' 2>/dev/null"
    )

    # john --show reads the pot file to display cracked entries
    show_cmd = (
        f"john --show "
        f"--pot='{pot_file}' "
        f"--format='{john_format}' "
        f"'{hash_file}' 2>/dev/null"
    )

    # Cleanup: remove hash file, pot file, john session files
    cleanup_cmd = (
        f"rm -f '{hash_file}' '{pot_file}' "
        f"'/root/.john/{session_name}.log' '/root/.john/{session_name}.rec' "
        f"2>/dev/null; true"
    )

    try:
        # Write hash to isolated temp file
        await run_parrot_command(write_cmd, timeout=10)

        # Run john wordlist attack — bounded by --max-run-time internally
        await asyncio.wait_for(
            run_parrot_command(crack_cmd, timeout=_JOHN_SSH_TIMEOUT),
            timeout=_JOHN_MAX_RUN_TIME + 60,
        )

        # Read results from pot file via --show
        show_output = await run_parrot_command(show_cmd, timeout=15)

        # Parse john --show output.
        # Line format: "hash:password" (or "?:password" for some raw formats)
        # Followed by summary: "N password hashes cracked, M left"
        password = ""
        for line in show_output.splitlines():
            line = line.strip()
            if not line or re.match(r"^\d+ password", line):
                continue
            colon_idx = line.find(":")
            if colon_idx == -1:
                continue
            # Second field is the password; strip any trailing john gecos fields
            candidate = line[colon_idx + 1:].split(":")[0]
            if candidate:
                password = candidate
                break

        return CrackResult(
            hash_str=hash_str,
            cracked=bool(password),
            password=password,
            hash_type=john_format,
            display_type=display_type,
            duration_s=time.monotonic() - t0,
        )

    except asyncio.TimeoutError:
        log.warning(
            "PasswordAudit: john timed out | format=%s | hash=%s...",
            john_format, hash_str[:20],
        )
        return CrackResult(
            hash_str=hash_str,
            cracked=False,
            hash_type=john_format,
            display_type=display_type,
            duration_s=time.monotonic() - t0,
        )
    except Exception as exc:
        log.error(
            "PasswordAudit: crack error | format=%s | hash=%s... | %s",
            john_format, hash_str[:20], exc,
        )
        return CrackResult(
            hash_str=hash_str,
            cracked=False,
            hash_type=john_format,
            display_type=display_type,
            duration_s=time.monotonic() - t0,
        )
    finally:
        # Guaranteed cleanup — runs even on CancelledError
        try:
            await run_parrot_command(cleanup_cmd, timeout=10)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def crack_hashes(
    hashes: list[str],
    hash_type: str = "auto",
) -> list[CrackResult]:
    """
    Crack a list of password hashes via john on Parrot OS.

    Parameters
    ----------
    hashes:
        List of validated hash strings (up to _MAX_HASHES).
        Each must pass _SAFE_HASH_RE validation before calling this function.
    hash_type:
        ``"auto"`` to detect format automatically, or an alias from
        _FORMAT_ALIASES (e.g. ``"md5"``, ``"bcrypt"``, ``"ntlm"``).

    Returns
    -------
    list[CrackResult]
        One entry per input hash, in the same order.
        cracked=False when not found, format unrecognised, or any error.
        Returns [] when hashes is empty or no wordlist is found on Parrot OS.

    Notes
    -----
    - All hashes are cracked sequentially under _crack_lock (one at a time).
    - MD5 and NTLM both produce 32-char hex strings; auto-detect picks MD5.
      Pass hash_type="ntlm" explicitly when NTLM is known.
    - Use a 60-second wall-clock budget per hash (quick check, not exhaustive).
    """
    if not hashes:
        return []

    wordlist = await _resolve_wordlist()
    if not wordlist:
        log.error(
            "PasswordAudit: no usable rockyou.txt found on Parrot OS. "
            "Run: gunzip -k /usr/share/wordlists/rockyou.txt.gz"
        )
        return [
            CrackResult(
                hash_str=h,
                cracked=False,
                hash_type="unknown",
                display_type="unknown",
            )
            for h in hashes
        ]

    results: list[CrackResult] = []

    async with _crack_lock:
        for hash_str in hashes[:_MAX_HASHES]:
            if hash_type == "auto":
                detected = _detect_hash_type(hash_str)
                if detected is None:
                    log.warning(
                        "PasswordAudit: unrecognised hash format — %r", hash_str[:40]
                    )
                    results.append(
                        CrackResult(
                            hash_str=hash_str,
                            cracked=False,
                            hash_type="unknown",
                            display_type="unknown",
                        )
                    )
                    continue
                john_format, display = detected
            else:
                john_format = _FORMAT_ALIASES.get(hash_type.lower())
                if not john_format:
                    log.warning(
                        "PasswordAudit: unknown hash_type alias %r", hash_type
                    )
                    results.append(
                        CrackResult(
                            hash_str=hash_str,
                            cracked=False,
                            hash_type=hash_type,
                            display_type=hash_type,
                        )
                    )
                    continue
                # Find display name for explicit override
                display = next(
                    (d for f, d, _ in _HASH_FORMATS if f == john_format),
                    john_format,
                )
                if john_format == "nt":
                    display = "NTLM"

            result = await _crack_single(hash_str, john_format, display, wordlist)
            results.append(result)

    log.info(
        "PasswordAudit: complete | hashes=%d | cracked=%d",
        len(results),
        sum(1 for r in results if r.cracked),
    )
    return results


# ---------------------------------------------------------------------------
# Embed builder
# ---------------------------------------------------------------------------


def _build_crack_embed(
    results: list[CrackResult],
    duration_s: float,
) -> discord.Embed:
    """
    Build a Discord embed summarising crack results.

    Cracked passwords are wrapped in Discord spoiler tags (||password||) to
    require a deliberate click to reveal — mitigating accidental screenshot exposure.
    Results are always posted ephemeral; this embed is a secondary safety layer.
    """
    cracked_count = sum(1 for r in results if r.cracked)

    if cracked_count > 0:
        color = discord.Color.orange()
        title = f"🔓 Password Audit — {cracked_count}/{len(results)} Hash(es) Cracked"
    else:
        color = discord.Color.green()
        title = f"🔒 Password Audit — No Hashes Cracked"

    embed = discord.Embed(
        title=title,
        description=(
            f"Quick wordlist check via `john` + `rockyou.txt` on Parrot OS.\n"
            "⚠️ *Results are **ephemeral** — only you can see this message.*"
        ),
        color=color,
        timestamp=datetime.now(timezone.utc),
    )

    for r in results:
        hash_display = (
            r.hash_str[:28] + "…" if len(r.hash_str) > 28 else r.hash_str
        )
        type_label = r.display_type or r.hash_type or "unknown"

        if r.cracked:
            value = (
                f"✅ **Cracked** (`{type_label}`)\n"
                f"🔑 Password: ||`{r.password}`||\n"
                f"⏱️ {r.duration_s:.0f}s"
            )
        elif r.hash_type == "unknown":
            value = (
                "❓ **Unrecognised format**\n"
                "Auto-detect found no matching hash type.\n"
                "Try specifying `hash_type` explicitly."
            )
        else:
            value = (
                f"❌ **Not cracked** (`{type_label}`)\n"
                "Not in rockyou.txt top-60s.\n"
                f"⏱️ {r.duration_s:.0f}s"
            )

        embed.add_field(
            name=f"`{hash_display}`",
            value=value,
            inline=False,
        )

    embed.set_footer(
        text=(
            f"Root AI • Phase 11 Password Auditor  |  "
            f"{duration_s:.0f}s total  |  Authorised use only"
        )
    )
    return embed


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------


class PasswordAuditCog(commands.Cog, name="PasswordAudit"):
    """
    Phase 11 — Password Hash Auditor.

    Submits hashes to john the Ripper on the Parrot OS SSH workstation for a
    quick rockyou.txt wordlist attack.  Supports MD5, SHA-1, SHA-256, SHA-512,
    NTLM, bcrypt, MD5crypt, and SHA-512crypt hashes.

    Results are posted EPHEMERAL only — cracked passwords are additionally
    wrapped in Discord spoiler tags to require a deliberate click to reveal.

    The public crack_hashes() function is available as an integration API for
    future pipeline consumers (e.g. audit_repo hash discovery).
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(
        name="password_audit",
        description="[OWNER] Crack password hashes via john + rockyou.txt on Parrot OS.",
    )
    @app_commands.describe(
        hashes=(
            "Hash(es) to crack — comma or newline separated, max 5. "
            "e.g. 5f4dcc3b5aa765d61d8327deb882cf99"
        ),
        hash_type="Hash format (default: auto-detect)",
    )
    @app_commands.choices(hash_type=[
        app_commands.Choice(name="auto — detect automatically",          value="auto"),
        app_commands.Choice(name="MD5 — 32-char hex",                   value="md5"),
        app_commands.Choice(name="SHA-1 — 40-char hex",                 value="sha1"),
        app_commands.Choice(name="SHA-256 — 64-char hex",               value="sha256"),
        app_commands.Choice(name="SHA-512 — 128-char hex",              value="sha512"),
        app_commands.Choice(name="NTLM — Windows password hash",        value="ntlm"),
        app_commands.Choice(name="bcrypt — $2y$/$2a$ format",           value="bcrypt"),
        app_commands.Choice(name="MD5crypt — Linux $1$ format",         value="md5crypt"),
        app_commands.Choice(name="SHA-512crypt — Linux $6$ format",     value="sha512crypt"),
    ])
    async def password_audit(
        self,
        interaction: discord.Interaction,
        hashes: str,
        hash_type: str = "auto",
    ) -> None:
        """Phase 11 entry point — password hash cracking via slash command."""

        # ── Owner gate ────────────────────────────────────────────────────────
        if interaction.user.id != BOT_OWNER_ID:
            await interaction.response.send_message(
                "⛔ `/password_audit` is an owner-only command.", ephemeral=True
            )
            return

        # ── Parse + validate hashes ──────────────────────────────────────────
        try:
            hash_list = _parse_hashes(hashes)
        except ValueError as exc:
            await interaction.response.send_message(
                f"⚠️ {exc}", ephemeral=True
            )
            return

        # ── Concurrency guard ────────────────────────────────────────────────
        if _crack_lock.locked():
            await interaction.response.send_message(
                "⚠️ A password cracking job is already running. "
                "Please wait for it to finish.",
                ephemeral=True,
            )
            return

        await interaction.response.defer(thinking=True, ephemeral=True)

        log.info(
            "PasswordAudit: /password_audit | hashes=%d | hash_type=%s | user=%s",
            len(hash_list), hash_type, interaction.user,
        )

        t0 = time.monotonic()
        results = await crack_hashes(hash_list, hash_type=hash_type)
        duration = time.monotonic() - t0

        embed = _build_crack_embed(results, duration)

        # ALWAYS ephemeral — cracked passwords must not appear in channel history
        await interaction.followup.send(embed=embed, ephemeral=True)

        log.info(
            "PasswordAudit: complete | hashes=%d | cracked=%d | duration=%.1fs",
            len(results),
            sum(1 for r in results if r.cracked),
            duration,
        )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(PasswordAuditCog(bot))
