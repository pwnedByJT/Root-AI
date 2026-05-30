"""
services/storage.py
Shared persistence layer for Root AI runtime data files.

Why this module exists
----------------------
Multiple cogs (``cogs/rep.py``, ``cogs/shop.py``) read and write the same
JSON files.  Each cog used to own its own ``asyncio.Lock`` instance, which
meant two different lock objects were guarding the same file — no mutual
exclusion at all.

This module creates a **single, module-level lock per file** that every
importer shares.  Because Python modules are singletons within a process,
any cog that does ``from services.storage import rep_lock`` receives the
same ``asyncio.Lock`` object.

Lock-ordering contract (to prevent deadlocks)
---------------------------------------------
If code ever needs to hold more than one lock simultaneously, it MUST
acquire them in this fixed order:

    rep_lock → shop_lock

In practice, the current implementation avoids holding two locks at the
same time altogether:
* ``cogs/rep.py``  — acquires ``rep_lock`` only.
* ``cogs/shop.py`` — acquires ``rep_lock`` (deduct/refund), releases it,
                     then acquires ``shop_lock`` (apply perk), releases it.
  Cooldown waivers are stored in ``rep.json`` so the shop never needs to
  acquire both locks concurrently.

File I/O
--------
All disk reads/writes are synchronous helpers meant to be run via
``asyncio.to_thread`` so the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

log = logging.getLogger("root_ai.storage")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_DIR: Path = Path("data")
REP_FILE: Path = DATA_DIR / "rep.json"
SHOP_FILE: Path = DATA_DIR / "shop.json"

# ---------------------------------------------------------------------------
# Module-level locks — ONE instance per file, shared across all cogs
# ---------------------------------------------------------------------------

_REP_LOCK: asyncio.Lock = asyncio.Lock()
_SHOP_LOCK: asyncio.Lock = asyncio.Lock()


def rep_lock() -> asyncio.Lock:
    """Return the shared asyncio.Lock for rep.json."""
    return _REP_LOCK


def shop_lock() -> asyncio.Lock:
    """Return the shared asyncio.Lock for shop.json."""
    return _SHOP_LOCK


# ---------------------------------------------------------------------------
# Default data structures
# ---------------------------------------------------------------------------

_REP_DEFAULT: dict = {"rep_counts": {}, "last_given": {}, "cooldown_waivers": []}
_SHOP_DEFAULT: dict = {"active_perks": {}}


# ---------------------------------------------------------------------------
# Sync I/O helpers (run via asyncio.to_thread — never call from async context)
# ---------------------------------------------------------------------------


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(exist_ok=True)


def _load_rep_sync() -> dict:
    """Load rep.json from disk.  Returns a fresh default structure if missing."""
    if not REP_FILE.exists():
        return dict(_REP_DEFAULT)
    try:
        with REP_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Back-fill any keys added in newer versions
        for key, default_val in _REP_DEFAULT.items():
            if key not in data:
                data[key] = type(default_val)()
        return data
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to load %s — returning default. Error: %s", REP_FILE, exc)
        return dict(_REP_DEFAULT)


def _save_rep_sync(data: dict) -> None:
    """Persist rep data to disk."""
    _ensure_data_dir()
    with REP_FILE.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _load_shop_sync() -> dict:
    """Load shop.json from disk.  Returns a fresh default structure if missing."""
    if not SHOP_FILE.exists():
        return dict(_SHOP_DEFAULT)
    try:
        with SHOP_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        for key, default_val in _SHOP_DEFAULT.items():
            if key not in data:
                data[key] = type(default_val)()
        return data
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Failed to load %s — returning default. Error: %s", SHOP_FILE, exc)
        return dict(_SHOP_DEFAULT)


def _save_shop_sync(data: dict) -> None:
    """Persist shop data to disk."""
    _ensure_data_dir()
    with SHOP_FILE.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# Initialisation helpers (safe to call from cog_load)
# ---------------------------------------------------------------------------


async def init_rep_file() -> None:
    """Ensure rep.json exists with the default structure. Safe to call on startup."""
    DATA_DIR.mkdir(exist_ok=True)
    if not REP_FILE.exists():
        await asyncio.to_thread(_save_rep_sync, dict(_REP_DEFAULT))
        log.info("storage: initialised %s with default structure.", REP_FILE)


async def init_shop_file() -> None:
    """Ensure shop.json exists with the default structure. Safe to call on startup."""
    DATA_DIR.mkdir(exist_ok=True)
    if not SHOP_FILE.exists():
        await asyncio.to_thread(_save_shop_sync, dict(_SHOP_DEFAULT))
        log.info("storage: initialised %s with default structure.", SHOP_FILE)


# ---------------------------------------------------------------------------
# Async wrappers (safe to await from cog methods)
# ---------------------------------------------------------------------------


async def load_rep_data() -> dict:
    """Thread-safe async load of rep.json.  Caller must already hold rep_lock()."""
    return await asyncio.to_thread(_load_rep_sync)


async def save_rep_data(data: dict) -> None:
    """Thread-safe async save of rep.json.  Caller must already hold rep_lock()."""
    await asyncio.to_thread(_save_rep_sync, data)


async def load_shop_data() -> dict:
    """Thread-safe async load of shop.json.  Caller must already hold shop_lock()."""
    return await asyncio.to_thread(_load_shop_sync)


async def save_shop_data(data: dict) -> None:
    """Thread-safe async save of shop.json.  Caller must already hold shop_lock()."""
    await asyncio.to_thread(_save_shop_sync, data)
