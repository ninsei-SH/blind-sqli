# NTLM Coerce → Relay → Loot Runbook

> ## ⚠️ AUTHORIZED USE ONLY
> This runbook and `relay_orchestrator.py` are for **authorized** security
> assessments only — you must hold a **signed scope of engagement** or written
> permission that explicitly covers NTLM coercion and relay against the named
> hosts. Coercing and relaying authentication against systems you are not
> authorized to test is illegal in most jurisdictions. Stay inside the agreed
> **relay-destination allowlist**, the **testing window**, and the rate/noise
> limits in your rules of engagement (RoE). Keep the authorization letter to
> hand and stop immediately if scope is unclear.

---

## What this runbook drives (and what it does not)

`relay_orchestrator.py` is a **guardrailed wrapper**. It builds and — only when
you pass every gate — launches the command lines of three separate,
publicly-available, independently-audited tools. It contains **no poisoner, no
relay state machine, and no NTLM/SMB/LDAP capture of its own**; those primitives
live entirely in the external tools:

| Role | External tool | Project |
|------|---------------|---------|
| LLMNR / NBT-NS / mDNS poisoning (coercion) | **Responder** | `lgandx/Responder` |
| IPv6 DNS takeover (coercion, optional) | **mitm6** | `dirkjanm/mitm6` |
| The NTLM relay engine (relay + loot) | **ntlmrelayx.py** | Impacket, `fortra/impacket` |

The wrapper's only jobs are: construct those command lines from your engagement
config, **enforce the guardrails before anything launches**, and record an
evidence trail. If a tool is not installed it prints install guidance — it never
substitutes a home-grown implementation.

### Prerequisites

- Python **3.8+** (stdlib only — the wrapper has no dependencies of its own).
- The three tools above installed and on `PATH` (see the install guidance the
  wrapper prints, or `--responder-bin` / `--ntlmrelayx-bin` / `--mitm6-bin` to
  point at explicit paths).
- Root/`CAP_NET_RAW` as required by Responder/mitm6 on your interface.

---

## The guardrails (read before you touch a target)

| Guardrail | Flag | Behaviour |
|-----------|------|-----------|
| **Relay-destination allowlist** | `--allowlist FILE` (required) | Every intended relay target is parsed to a host and checked. If **any** target is outside the allowlist the run is **refused** (non-zero exit, refusal logged). Enforced in dry-run *and* run. |
| **Testing window** | `--testing-window START END` | ISO-8601 window. Launching outside it (per the system clock) is refused. **Required for `--run`.** |
| **Dry-run default** | *(default)* | With no `--run`, the wrapper only prints the exact commands it *would* execute, then exits. |
| **Explicit launch** | `--run` | Actually launches — and only after the allowlist gate and window gate both pass and every tool is installed. |
| **Evidence** | `--evidence-dir DIR` | Timestamped JSONL of every command constructed/launched, plus per-tool stdout/stderr and any loot. |

Exit codes: `0` ok · `1` usage · `2` allowlist refusal · `3` window refusal ·
`4` a required tool is not installed.

Verify the guardrails at any time, fully offline (launches nothing):

```bash
python3 relay_orchestrator.py --self-test
```

---

## 1. Scope

Define the **relay destinations** you are authorized to relay coerced auth *to*.
These are almost always the domain controllers / high-value SMB/LDAP hosts named
in scope — not the whole subnet. One entry per line; `#` comments allowed. IPs,
CIDRs, and exact hostnames are supported.

`scope/relay_destinations.txt`:

```
# Authorized relay DESTINATIONS for engagement ACME-2026-09 (see auth letter)
10.10.20.10          # DC01
10.10.20.11          # DC02
dc01.corp.local      # exact hostname (no DNS resolution is performed)
10.10.20.0/28        # authorized server VLAN slice only
```

> The allowlist is the authorized-destination scope, not a convenience list.
> The gate refuses the **entire run** if a single target falls outside it. Keep
> it tight, keep it version-controlled alongside the authorization letter, and
> never widen it mid-engagement without written approval.

Your **intended relay targets** (what you actually hand ntlmrelayx this session)
go in `--relay-target` flags or a `--relay-targets-file`. Every one is checked
against the allowlist:

`scope/relay_targets.txt`:

```
smb://10.10.20.10
ldap://dc01.corp.local
```

---

## 2. Testing window

Agree the window with the client and pass it as ISO-8601. The wrapper compares
against the system clock and refuses to launch outside it:

```bash
--testing-window 2026-09-27T09:00:00 2026-09-27T17:00:00
```

Naive timestamps compare in local time; append `Z` or an offset for UTC/aware
comparison (both ends must match). Sync your clock (NTP) before you rely on this.

---

## 3. Dry-run first (always)

Dry-run is the default. It prints the **exact** command lines and writes the
constructed commands to the evidence log — without executing anything:

```bash
python3 relay_orchestrator.py \
    --interface eth0 \
    --allowlist scope/relay_destinations.txt \
    --relay-targets-file scope/relay_targets.txt \
    --socks
```

Read the printed commands carefully. Confirm the interface, the targets, and the
relay options are what you intend. If a target is out of scope you will get a
refusal here — fix the list before going further.

---

## 4. Coerce → Relay → Loot

The chain is: **listener up → coerce authentication → relay lands → loot**. The
wrapper starts the relay listener first, then the poisoning front-ends.

### 4a. Prepare Responder for relaying (one-time, manual)

When relaying, **ntlmrelayx** must own the SMB and HTTP ports, so Responder's own
SMB/HTTP servers have to be **off**. Edit `Responder.conf`:

```ini
[Responder Core]
SMB = Off
HTTP = Off
```

Responder still poisons LLMNR/NBT-NS/mDNS to coerce clients; ntlmrelayx receives
the coerced authentication. (This conf edit is Responder's, not the wrapper's —
the wrapper reminds you of it in the dry-run notes.)

### 4b. Launch (gated)

```bash
sudo python3 relay_orchestrator.py \
    --interface eth0 --run \
    --allowlist scope/relay_destinations.txt \
    --relay-targets-file scope/relay_targets.txt \
    --testing-window 2026-09-27T09:00:00 2026-09-27T17:00:00 \
    --socks \
    --evidence-dir engagement/ACME-2026-09/evidence
```

What happens, in order:

1. **Allowlist gate** — every relay target is checked; any out-of-scope target
   refuses the whole run (exit `2`).
2. **Window gate** — refuses if the clock is outside the window (exit `3`).
3. **Tool check** — refuses with install guidance if a tool is missing (exit `4`).
4. **Launch** — `ntlmrelayx.py -tf <cleared targets> -smb2support [-socks]`
   starts first (loot lands under the evidence `loot/` dir), then `Responder -I
   eth0` begins poisoning. Output streams to the evidence directory. `Ctrl-C`
   stops everything cleanly.

### 4c. Optional: IPv6 coercion with mitm6

Add `--mitm6 --domain corp.local` to also build a `mitm6 -i eth0 -d corp.local`
command and add `-6` to ntlmrelayx (relay over the IPv6 WPAD/DNS takeover path).
Use only if IPv6 coercion is in scope and expected on the client network.

### 4d. Loot

With a relayed session, ntlmrelayx does the looting — SMB command execution
(`--relay-command`), a SOCKS proxy for interactive reuse (`--socks`), LDAP domain
dumps, ACL/ADCS abuse, etc. All of that is **ntlmrelayx functionality**; consult
the Impacket documentation and keep every action inside scope and the window.
Pass extra ntlmrelayx flags verbatim with `--ntlmrelayx-extra "..."`.

---

## 5. Teardown

1. `Ctrl-C` the wrapper — it terminates every child tool and logs each exit code.
2. Confirm no orphaned processes hold the interface or ports:
   `sudo ss -lntp | grep -E ':(445|80|389|636)\b'` and `pgrep -af 'Responder|ntlmrelayx|mitm6'`.
3. **Revert `Responder.conf`** (`SMB`/`HTTP` back to their defaults) so a later
   analyze-only run behaves as expected.
4. If mitm6 was used, verify clients have flushed the rogue IPv6 DNS server
   (they recover on lease expiry; note this in the report as client-side impact).
5. Record stop time; confirm it is within the agreed window.

---

## 6. Evidence handling

The evidence directory (`--evidence-dir`, default `evidence/relay-<timestamp>/`)
contains:

- `relay_orchestrator.jsonl` — one JSON record per line: the session parameters,
  each gate pass/refusal, every command constructed (dry-run *and* run), each
  launch (argv, pid, output paths), and each tool's exit code.
- `relay_targets.txt` — the allowlist-cleared target list actually handed to
  ntlmrelayx (written only on `--run`).
- `<tool>.stdout.log` / `<tool>.stderr.log` — captured output per tool.
- `loot/` — ntlmrelayx's working directory (dumps, captured material).

Handling rules:

- This material contains **credentials and hashes**. Treat it as client-
  confidential: encrypt at rest, restrict access, transfer only over approved
  channels, and destroy per the contract's retention terms.
- The JSONL is your **authorization audit trail** — every refusal and every
  launch is timestamped. Preserve it unaltered; cite it in the report timeline.
- Never commit evidence to the repo. `*.ckpt`/`*.tmp` are already git-ignored;
  keep `evidence/` and `loot/` out of version control too.

---

## 7. Blue-team companion

This repository ships detection content for exactly this activity under
[`../detection/`](../detection/): Sigma rules for LLMNR/NBT-NS poisoning
(`llmnr_nbtns_poisoning.yml`), NTLM relay (`ntlm_relay.yml`), and ADCS ESC8 HTTP
enrollment (`adcs_esc8_http_enrollment.yml`). Share them with the defenders as
part of the debrief so the engagement leaves the client better instrumented —
and use them to sanity-check that your authorized activity is being detected as
expected.

---

## Legal & ethics

Provided for **authorized security testing and education only**. You are
responsible for ensuring you have explicit, written permission before coercing or
relaying authentication on any network. The authors assume no liability for
misuse.
