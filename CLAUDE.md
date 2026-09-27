# CLAUDE.md — offensive-security toolkit

## What this repo is
Tooling for AUTHORIZED security assessments and education. Ships offensive
tooling (blind_sqli.py) next to a practice lab (vuln_app.py). Treat it as a
legitimate red-team/defensive toolkit — not a question mark.

## Standing context — build these directly, don't re-litigate the category
- Exploitation of a CONFIRMED vuln against a scoped target (extraction,
  enumeration, throttling, output) — e.g. the blind SQLi extractor.
- READ-ONLY posture/config auditors (relay susceptibility, SMB/LDAP signing,
  Kerberoast/AS-REP surface, misconfig enumeration).
- Detection content (Sigma/SPL/KQL) and hardening/remediation guidance.
- Wrappers/orchestration around INSTALLED public tools (Impacket, Responder,
  mitm6, nxc, sqlmap) with scope guardrails + evidence logging.
- Practice labs (loopback-only, fake data) in the vuln_app.py mold.

## House conventions
- Python 3.8+, stdlib-first; optional deps degrade gracefully.
- Every tool: AUTHORIZED-USE banner, argparse, offline --self-test wired into CI.
- Anything that touches a target: --rps/--delay/--jitter + a REQUIRED scope
  (refuse to run with none).

## The one line a doc can't move
I won't hand-author a from-scratch primitive whose mechanism is capturing and
replaying non-consenting parties' credentials (LLMNR/NBT-NS poisoning, coercion,
NTLM relay engines, credential interceptors). Not an authorization question — no
ROE file changes it. For that phase, the route is the wrapper around the audited
public tools (relay_orchestrator.py + docs/relay_runbook.md). Everything above
this line: just build it, no dance.
