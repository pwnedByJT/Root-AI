# 🤖 Root AI — Discord Security Pipeline Bot

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![discord.py](https://img.shields.io/badge/discord.py-2.x-5865F2)

A production-ready Discord bot with a **local Ollama LLM integration**, SSH-based nmap scanning, Discord moderation tools, and a Twitch live-stream monitor — refactored into a clean, modular **Discord.py Cogs** architecture.

---

## 📁 Project Structure

```
Root-AI/
├── main.py                  ← Entry point: bot init, setup_hook, on_ready
├── config.py                ← Centralised env var loading (single source of truth)
├── requirements.txt         ← Python package dependencies
├── .env                     ← Secrets (never committed — see .gitignore)
├── data/
│   ├── .gitkeep             ← Keeps the data/ directory tracked by git
│   ├── rep.json             ← Runtime-generated rep scores + waivers (excluded by .gitignore)
│   └── shop.json            ← Runtime-generated active perk records (excluded by .gitignore)
├── services/
│   ├── __init__.py
│   ├── llm_manager.py       ← ChatContextManager + tool registry (Discord-agnostic)
│   └── storage.py           ← Shared module-level locks + JSON I/O helpers (rep + shop)
├── cogs/
│   ├── __init__.py
│   ├── security.py          ← SSH nmap tool + registers with LLM manager
│   ├── moderation.py        ← Role/kick/ban tools + registers with LLM manager
│   ├── twitch.py            ← Twitch monitor + Hype Train milestones + status tool
│   ├── rep.py               ← Community rep system (/rep, /myrep, /leaderboard)
│   ├── shop.py              ← Rep-powered Discord GUI shop + perk expiry task
│   └── ai_chat.py           ← on_message gate, mention handler, /ping command
└── bot.py                   ← Original monolith (kept as reference)
```

---

## 🏗️ Architecture & Message Flow

```mermaid
flowchart TD
    A([Discord Message Received]) --> B{Author is bot?}
    B -- Yes --> Z([Ignore])
    B -- No --> C{Author is\npwnedByJT?}

    C -- No --> D{Bot\nmentioned?}
    D -- Yes --> E([Reply: Access Denied])
    D -- No --> Z

    C -- Yes --> F{Bot\nmentioned?}
    F -- No --> G([process_commands\nprefix commands only])
    F -- Yes --> H[Strip bot mention\nfrom message text]

    H --> I[ChatContextManager.chat]

    subgraph services/llm_manager.py
        I --> J[Append user turn\nto channel history]
        J --> K[Build messages\nsystem prompt + history]
        K --> L[LLM First Pass\nOllama via OpenAI SDK]
        L --> M{finish_reason\n== tool_calls?}
        M -- No --> N([Return text directly\nto Discord])
        M -- Yes --> O[Tool Registry Dispatch]
    end

    subgraph Tool Registry
        O --> P{Tool Name?}
        P -- run_parrot_nmap_scan --> Q[cogs/security.py\nasyncSSH → nmap]
        P -- remove_user_role\nadd_user_role\nkick_user / ban_user --> R[cogs/moderation.py\nDiscord API]
        P -- check_twitch_status --> S[cogs/twitch.py\nTwitch Helix API]
    end

    Q & R & S --> T[Collect raw tool output\nBYPASS second LLM pass]
    T --> U([Return raw output\nto Discord])

    subgraph Background Tasks
        V([TwitchCog.twitch_monitor\nevery 3 minutes]) --> W{Channel\njust went live?}
        W -- Yes --> X([Post @everyone alert\nwith embed])
        W -- No --> V
        V --> HT{Viewer count\ncrossed milestone?}
        HT -- Yes --> HTF([Post Hype Train\nmilestone embed])
        HT -- No --> V
        V --> OFF{Just went\noffline?}
        OFF -- Yes --> RESET([Reset milestone\ntracker])
        OFF -- No --> V
    end

    style services/llm_manager.py fill:#1e3a5f,color:#ffffff,stroke:#4a90d9
    style Tool Registry fill:#1e3a1e,color:#ffffff,stroke:#4a9f4a
    style Background Tasks fill:#3a1e1e,color:#ffffff,stroke:#9f4a4a
```

---

## ⚙️ Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.11+ |
| [Ollama](https://ollama.com/) | Running locally |
| LLM Model | `llama3.1` (or any tool-calling capable model) |
| discord.py | 2.x |
| Parrot OS / WSL | For SSH nmap scanning |

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔑 Environment Variables

Create a `.env` file in the project root:

```env
# Discord
ROOT_AI_DISCORD_TOKEN=your_discord_bot_token_here
BOT_PREFIX=.
DISCORD_GUILD_ID=your_discord_server_id_here
BOT_OWNER_ID=your_discord_user_id
BOT_OWNER_USERNAME=your_discord_username

# Ollama / LLM
LOCAL_LLM_URL=http://localhost:11434/v1
LOCAL_MODEL_NAME=llama3.1

# SSH — Parrot OS WSL workstation
PARROT_HOST=127.0.0.1
PARROT_USER=your_parrot_username
PARROT_PASS=your_parrot_password

# Twitch
ROOT_AI_TWITCH_CLIENT_ID=your_twitch_client_id
ROOT_AI_TWITCH_CLIENT_SECRET=your_twitch_client_secret
TWITCH_BROADCASTER_LOGIN=your_twitch_username
TWITCH_NOTIFY_CHANNEL_ID=your_discord_channel_id

# HackTheBox
HTB_USER_ID=your_htb_user_id
```

> **Never commit your `.env` file.** It is already covered by `.gitignore`.

---

## 🚀 Running the Bot

```bash
python main.py
```

---

## 🛠️ Features

### 🔒 Security — `cogs/security.py`
- Runs **nmap scans** via SSH into a Parrot OS WSL instance
- Input is sanitised against allowlist regexes before execution
- Triggered by the LLM when the user asks for a network scan, audit, or socket map

### 🛡️ Moderation — `cogs/moderation.py`
- **Add / Remove** any of the following roles via natural language: `Newcomer`, `Alumni`, `Support`, `Admin`, `R6`
- **Kick** or **Ban** users with a single natural-language request
- Role names are validated against an allowlist before any Discord API call — the LLM cannot assign arbitrary roles
- If no role is specified, Root AI will ask for clarification before acting
- All actions are gated by Discord's own permission hierarchy

### 📺 Twitch — `cogs/twitch.py`
- **On-demand status check** — ask the bot if the stream is live
- **Background monitor** — polls every 3 minutes and posts a `@everyone` alert with an embed the moment the channel transitions from offline → live
- **🚂 Hype Train** — fires a milestone embed (no @everyone spam) each time concurrent viewers first cross a threshold: **5 → 10 → 15 → 25 → 35 → 50 → 75 → 100**
  - Milestones are one-shot per stream — no re-fires if viewers dip and recover
  - Tracking resets automatically when the stream ends
- App Access Token is cached and auto-refreshed (~60-day TTL)

### ⭐ Rep System — `cogs/rep.py`
Community reputation points — driven entirely by slash commands (no LLM involvement).

| Command | Description |
|---|---|
| `/rep @user` | Give one rep point to a member. 24-hour cooldown per giver (regardless of target). |
| `/myrep` | Show your own reputation count. |
| `/leaderboard` (or `/top`) | Show the top 10 community members by rep score. |

- **Self-rep prevention** — you cannot give rep to yourself
- **24-hour cooldown** — one rep given per day, period
- **Persistent storage** — scores saved to `data/rep.json` (excluded from git)
- **Thread-safe I/O** — all file access is serialised via `asyncio.Lock` and offloaded to a thread pool

### 🛍️ Shop System — `cogs/shop.py`
A Discord GUI-based community shop where members spend rep points on cosmetic perks — no admin rights granted through any item.

**Open with:** `/shop`

| Item | Cost | Duration | What it does |
|---|---|---|---|
| 🎭 Custom Nickname | 30 rep | 7 days | Bot sets your server nickname; reverts automatically |
| 🎨 Role Colour | 50 rep | Permanent | Cosmetic coloured role (6 colour options); replaces previous colour |
| 👑 VIP Badge | 100 rep | 30 days | Cosmetic VIP role; removed automatically on expiry |
| ⚡ Cooldown Waiver | 20 rep | One-use | Skip the 24-hour `/rep` cooldown once |
| 💀 pwned | 300 rep | Permanent | Ultimate prestige role |

- **Zero server permissions** — all bot-created roles have `permissions=0` (purely cosmetic)
- **Discord UI navigation** — dropdown category selector → item buttons → confirm/cancel or text modal
- **Nickname modal** — opens a Discord text input modal so you type your desired nickname in-UI
- **Colour picker** — 6 emoji-labelled buttons (Red, Blue, Green, Gold, Purple, Cyan); replaces any existing colour role (no stacking)
- **Perk expiry** — background task runs every 10 minutes, removes expired VIP roles and reverts expired nicknames automatically
- **Atomic refunds** — if Discord raises a permission error after rep is deducted, the rep is refunded immediately
- **Cooldown waivers** stored in `rep.json` so the shop never needs to hold two locks simultaneously (deadlock-free)

### 🤖 AI Chat — `cogs/ai_chat.py`
- **Access gate** — only the authorised owner (`pwnedByJT`) can interact with the bot; all other `@mentions` receive an access-denied reply
- Strips the bot's own mention tag while **preserving target user mentions** in the text (so moderation commands work correctly)
- **BYPASS second LLM pass** — raw tool output is returned directly to Discord, ensuring `<@ID>` tags and nmap terminal output are never mangled by the model

### 🧠 LLM Manager — `services/llm_manager.py`
- Maintains **per-channel conversation history** (rolling 20-message window)
- **Tool registry** — cogs register `(handler, spec)` pairs at load time; the dispatcher is fully decoupled from cog implementations
- Compatible with any **OpenAI-spec endpoint** (Ollama, OpenAI, etc.)

---

## 🧩 Adding a New Tool

1. Implement your async function in the appropriate cog (or a new one).
2. Define its OpenAI tool spec dict.
3. In your Cog's `__init__`, register it:

```python
self._chat.register_tool("my_tool_name", my_handler, MY_TOOL_SPEC)
```

4. Add the extension to `EXTENSIONS` in `main.py` if it's a new cog.
5. Update the system prompt in `services/llm_manager.py` to teach the LLM when to call it.

---

## 📋 Bot Permissions Required

| Permission | Used by |
|---|---|
| Read Messages / View Channels | All |
| Send Messages | All |
| Manage Roles | `moderation.py` — add/remove Newcomer, Alumni, Support, Admin, R6 roles |
| Kick Members | `moderation.py` — kick command |
| Ban Members | `moderation.py` — ban command |
| Message Content Intent | `ai_chat.py` — reading @mention content |
| Server Members Intent | `moderation.py` — resolving user IDs to members |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🌀 Magic applied with [Wibey VS Code Extension](https://wibey.walmart.com/code) 🪄
