# Third-party notices

## PentestGPT (forked core)

- Upstream: https://github.com/GreyDGL/PentestGPT
- License: MIT, Copyright (c) 2023 Grey_D
- License text: `third_party/pentestgpt/LICENSE.md` (byte-identical to
  upstream, verified against the upstream file)
- Upstream revision: `e8b1bb77d1ac00329675cec3b060aba971ec1ac8`
  (2026-07-14, latest main at fork time)
- Used in: `src/sentinel_triage/ptree/`

What was taken: the Penetration Testing Tree (PTT) concept and text format
(layered task tree, statuses to-do / completed / not applicable), and the
role of the prompt templates in the reasoning flow.

Substantive changes in this fork:

1. The PTT is a real, tested data model with a strict parser and renderer
   (`ptree/model.py`); upstream shipped it as prompt text plus an
   interactive REPL. The parser/renderer implementation here is original.
2. Upstream prompt text asserted the tester had "valid certificates and
   approval" for a "certified experiment". Those claims are removed.
   Authorization in this project comes from a machine-checked scope file
   (`sentinel_triage.scope`), and the adapted prompts
   (`ptree/prompts.py`) state the loaded scope instead.
3. Task creation is scope-gated: a task acting on an out-of-scope target
   is refused in code (`ptree/planner.py`), including tasks proposed by an
   LLM, whose revisions are parsed and validated before acceptance.
4. A deterministic offline planner is the default; upstream required a
   paid LLM API for any reasoning pass.
5. Non-reconnaissance stages (exploitation, post-exploitation, brute
   force, persistence, evasion) are excluded by design and rejected by the
   gate if proposed.

## Recon plugin tools (invoked, not vendored)

The `recon` command builds allowlisted command lines for these external
open-source tools when the operator installs them; they remain the work
and license of their authors:

- subfinder, httpx, katana, nuclei - ProjectDiscovery (MIT)
- OWASP Amass - OWASP (Apache-2.0)
- nmap - Nmap Project (NPSL)
- dig - ISC (MPL-2.0)
- whois - Marco d'Itri (GPL-2.0-or-later)

Only the safe, allowlisted flag subsets in `sentinel_triage/recon.py` are
used; consult each tool's own documentation and license before relying on
its output.

## Design references (no code taken)

Surveyed while choosing this architecture: CAI (aliasrobotics), Strix
(usestrix), hexstrike-ai (0x4m4). No code was copied from these projects;
CAI's license in particular does not permit reuse. They are credited as
prior art for the agentic-security design space.
