# 浮生角色馆 · Fusheng Roleplay Lounge

> A single-file, browser-only roleplay chat lounge. Bring your own API key, pick a character, and talk all night — your data stays local.

**Live site (GitHub Pages):** https://azdezhishijiangtang.github.io/fusheng-roleplay/

> **© 2026 azdezhishijiangtang · 保留所有权利 / All Rights Reserved**
> 本仓库全部内容——源代码、角色设定、提示词、界面文案——均为原创作品，受版权保护。未经作者事先书面许可，禁止复制、转载、克隆、镜像、二次分发或用于任何衍生作品（无论商业或非商业用途）。详见 [LICENSE](./LICENSE)。
> All content in this repository (code, character cards, prompts, and copy) is original work protected by copyright. No copying, redistribution, mirroring, or derivative use without the author's prior written permission. See [LICENSE](./LICENSE).

## What problem this solves

Most roleplay / character-chat sites lock you in: they host the model, log your chats, charge a subscription, and give you no control over your data. Fusheng flips that:

- **You bring your own API key** (OpenAI / DeepSeek / Zhipu GLM / Kimi / Qwen / Gemini / any OpenAI-compatible endpoint) — the site is just a front end that talks directly from your browser to the provider you choose.
- **Your data never leaves your browser.** Characters, sessions, and keys live in `localStorage`. There is no backend, no account, no telemetry.
- **Private by design.** Nothing you write is ever uploaded to anyone except the model provider you configure.

Think of it as "a local chat UI for your own API key" — lightweight, private, and free of platform lock-in.

## Main features

| Category | Details |
|---|---|
| API access | 7 presets (OpenAI, DeepSeek, Zhipu GLM, Kimi/Moonshot, Qwen, Gemini, Custom) + any OpenAI-compatible base URL; connection tester built in |
| Streaming chat | SSE streaming replies with typewriter cursor, stop/resume, retry on error |
| Message tools | Edit-and-regenerate any user message, rewrite last reply, "continue" button, quick chips (continue / elaborate / rephrase) |
| Roleplay engine | Built-in shared performance-rules layer, toggleable |
| Characters | 5 hand-tuned builtin characters; character workshop to create or fork-edit your own cards (emoji + theme color pickers) |
| Session | Multiple sessions per character, session titles, plot memo injected into every request, clear chat, export to TXT |
| Data | Full backup/restore via JSON export/import |
| UI | Dark "midnight lounge" theme + light theme, mobile drawer layout, no external dependencies |

## Getting started

The project runs as a hosted site — there is nothing to download, install, or deploy.

1. Open the live site: **https://azdezhishijiangtang.github.io/fusheng-roleplay/**
2. Click **设置 API (Set API)** in the bottom-left corner.
3. Pick a provider preset, paste your API key, choose a model, hit **测试连接 (Test)**.
4. Pick a character from the sidebar — or open **角色工坊 (Character Workshop)** to write your own card.
5. Chat. Use the quick chips above the input box to steer the conversation.

> Privacy note: your API key is stored only in your browser's `localStorage` and sent only to the provider endpoint you configure. The page makes no other network requests.

## Character card format

Cards are structured plain text built from four fields:

| Field | Purpose |
|---|---|
| 角色设定 (persona) | Identity, personality, speech habits, what the character cares about or avoids |
| 开场白 (greeting) | The opening scene the character enters with |
| 示例对话 (examples) | Sample exchanges that anchor tone and rhythm |
| 剧情备忘 (plot memo) | Optional context injected into every request |

The full text of the builtin characters — persona, greetings, and example dialogues — is original creative work and is intentionally not reproduced here. Explore them on the live site. Anything you write in the workshop belongs to you and stays in your browser.

An optional shared performance-rules layer is applied automatically to every conversation — no configuration needed.
