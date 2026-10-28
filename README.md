# 浮生角色馆 · Fusheng Roleplay Lounge

> A single-file, self-hosted roleplay chat lounge. Bring your own API key, pick a character, and talk all night.

**Live site (GitHub Pages):** `https://<your-username>.github.io/fusheng-roleplay/`

## What problem this solves

Most roleplay / character-chat sites lock you in: they host the model, log your chats, charge a subscription, and give you no control over prompts. Fusheng flips that:

- **You bring your own API key** (OpenAI / DeepSeek / Zhipu GLM / Kimi / Qwen / Gemini / any OpenAI-compatible endpoint) — the site is just a front end that talks directly from your browser to the provider you choose.
- **Your data never leaves your browser.** Characters, sessions, and keys live in `localStorage`. There is no backend, no account, no telemetry.
- **The prompts are open.** Every character card is plain text you can read, copy, and rewrite.

Think of it as "a local chat UI for your own API key" — similar in spirit to self-hosted front ends, but as one `index.html` you can open by double-clicking.

## Main features

| Category | Details |
|---|---|
| API access | 7 presets (OpenAI, DeepSeek, Zhipu GLM, Kimi/Moonshot, Qwen, Gemini, Custom) + any OpenAI-compatible base URL; connection tester built in |
| Streaming chat | SSE streaming replies with typewriter cursor, stop/resume, retry on error |
| Message tools | Edit-and-regenerate any user message, rewrite last reply, "continue" button, copy, delete, quick chips (continue / elaborate / rephrase) |
| Roleplay engine | Shared "performance rules" system prompt (anti-AI-speak, stay in character, action descriptions, conversation hooks), toggleable |
| Characters | 5 hand-tuned builtin characters with persona / greeting / example dialogues; character workshop to create or fork-edit cards (emoji + theme color pickers) |
| Session | Multiple sessions per character, session titles, plot memo injected into every request, clear chat, export to TXT |
| Data | Full backup/restore via JSON export/import |
| UI | Dark "midnight lounge" theme + light theme, mobile drawer layout, no external dependencies |

## Installation

No build, no dependencies, no server.

1. Download `index.html` (or clone this repo).
2. Open it in any modern browser. Done.

To run it from GitHub Pages, just visit the live site URL above — the page itself contains zero secrets.

## Usage

1. Click **设置 API (Set API)** in the bottom-left corner.
2. Pick a provider preset, paste your API key, choose a model, hit **测试连接 (Test)**.
3. Pick a character from the sidebar — or open **角色工坊 (Character Workshop)** to write your own card.
4. Chat. Use the quick chips above the input box to steer the conversation.

> Privacy note: your API key is stored only in your browser's `localStorage` and sent only to the provider endpoint you configure. The page makes no other network requests.

## Quick start example

A character card is just structured text. This is the actual format used by the workshop:

```text
角色设定 (persona):
  你是林晚秋，26岁，中文系研究生……
  性格与说话方式：
  - 声音温柔，爱用「嗯？」开头，但能温和地拆穿借口
  - 例句：「（把毯子往你那边挪了挪）……又熬夜。说吧，这次是睡不着，还是不想睡？」
  在乎与忌讳：
  - 忌讳：敷衍的「我没事」。听到会安静两秒，然后盯着你。

开场白 (greeting):
  （阳台的串灯还亮着，小桌上给你留了半杯还温着的桂花乌龙）回来啦。

示例对话 (examples, one per line):
  我今天过得糟透了|||（没追问，先把你面前那杯推近了些）先喝口热的。……
```

The shared performance rules (roleplay constitution) are prepended automatically. Every reply, the model receives: rules + persona + your plot memo + example dialogues + recent history.

## License

MIT
