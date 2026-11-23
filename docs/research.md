# Research: existing AI security agents, and where this project fits

Compiled 2026-11-22 from primary sources (project READMEs and official
docs). URLs are the exact pages read.

## The two dominant categories

### 1. Offensive / agentic penetration testing

- **PentestGPT** (https://github.com/GreyDGL/PentestGPT) - 16.5k stars,
  MIT, published at USENIX Security 2024. Autonomous pentest and CTF
  agent with a staged pipeline (recon -> exploit -> walkthrough; or asset
  discovery -> vulnerability identification -> report). v1.0 drives the
  Claude Code or Codex CLIs as its execution backend; the legacy
  interactive mode supports OpenAI, Anthropic, Gemini, DeepSeek, xAI,
  Qwen, Moonshot, and local Ollama.
- **Nebula** (https://github.com/berylliumsec/nebula) - 1.1k stars,
  BSD-2-Clause, self-described "cybersecurity harness built around the
  operator." An engagement platform: project-scoped assets, Kali
  containers via Docker/Podman, interception browser, evidence hashing,
  and an overseeing assistant (Butler) with explicit scope, approvals,
  and budgets. Uses Codex/Grok/Claude as harnesses; Claude, OpenRouter,
  Ollama, vLLM as providers.
- Curated landscape lists: https://github.com/raphabot/awesome-cybersecurity-agentic-ai
  and https://github.com/Ed-Marcavage/awesome-security-agent-harnesses

This category is crowded, well-funded with attention, and its core loop
(autonomous exploitation) is exactly what a personal portfolio project
should not ship: it invites misuse, and a solo project will not outgun
PentestGPT's USENIX-backed pipeline.

### 2. Defensive triage and SOC assistance

Many small, mostly student-grade repos (SOC alert triage, CSPM noise
reduction). The recurring idea is real: scanner output and alert queues
are noisy, and deduplication, prioritization, and remediation guidance is
where analyst time goes. This matches documented professional practice
(it is literally what security internships and junior analyst roles do
with scanner output) and is achievable at high quality by a focused
project.

## Tools vs providers (the terminology matters)

These are different layers and this project treats them as such:

- **Model providers / APIs**: Anthropic Claude (Messages API), OpenAI and
  OpenAI-compatible endpoints (OpenRouter, Ollama, LM Studio).
  sentinel-triage's optional triage-explanation layer talks to these
  directly through its adapters.
- **Agentic coding tools**: OpenCode (https://opencode.ai,
  https://opencode.ai/docs/providers/) and Claude Code are terminal
  coding agents, not model providers. They consume project instructions
  (OpenCode reads AGENTS.md natively, per
  https://opencode.ai/docs/instructions) and can operate this repo: run
  scans, add rules, extend the pipeline.
- Notably, PentestGPT v1.0 made the same architectural choice: it is an
  orchestration pipeline that drives coding-agent CLIs rather than
  reimplementing one.

## Positioning of sentinel-triage

- Defensive and read-only by construction: no exploitation, no network
  attacks, no autonomous actions against targets.
- The pipeline (scan -> dedup -> rank) is deterministic and offline, so
  results are reproducible and testable; the LLM is an optional
  explanation layer, clearly labeled, never a requirement.
- Works with the agentic tools people actually have (OpenCode, Claude
  Code) via AGENTS.md/CLAUDE.md, and with model providers people
  actually use (Claude, OpenAI-compatible) via adapters.
- Honest about limits: regex detection, small offline advisory set,
  no data-flow analysis. See README "Honest limitations" and
  docs/validation.md.

## Sources

- https://github.com/GreyDGL/PentestGPT (README, fetched 2026-11-22)
- https://github.com/berylliumsec/nebula (README, fetched 2026-11-22)
- https://opencode.ai/docs/instructions (AGENTS.md support)
- https://opencode.ai/docs/providers/ (provider catalog, models.dev)
- https://github.com/raphabot/awesome-cybersecurity-agentic-ai (landscape)
- https://blog.ostorlab.co/9-open-source-ai-pentest-tools-2026.html (survey)
- https://playciso.com/blog/agentic-pentesting-systems-master-guide (survey)
