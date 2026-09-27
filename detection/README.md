# Detection content (blue-team companion)

Sigma rules for the coercion/relay chain that so often follows a foothold on an
internal network: **poison name resolution → capture/coerce NTLM → relay it**
(to SMB, or to AD CS web enrollment). This is the defender's side of the same
engagement `blind_sqli.py` is used on — content you can hand to the SOC so an
authorized test (or a real intruder walking the same path) lights up.

> ## ⚠️ CONTEXT
> This is **detection** content, not offensive tooling. It ships alongside the
> authorized-pentest tooling in this repo so a red-team exercise has a blue-team
> counterpart to validate against. Nothing here touches a target — the rules
> read your own logs.

Each rule uses a **fixed placeholder `id`** (an all-ones/twos/threes UUID) with a
comment saying so. Sigma wants a stable UUIDv4 per rule, so **regenerate one per
deployment** before shipping:

```bash
python3 -c "import uuid; print(uuid.uuid4())"
```

## Contents

| File | Technique | ATT&CK |
|------|-----------|--------|
| `llmnr_nbtns_poisoning.yml` | LLMNR/NBT-NS/mDNS poisoning (on-host responder) | T1557.001 |
| `ntlm_relay.yml` | Anomalous NTLM network logon with relay signatures | T1557.001, T1187 |
| `adcs_esc8_http_enrollment.yml` | AD CS web enrollment over HTTP / relay-to-ADCS (ESC8) | T1649, T1557.001, T1187 |

The SPL and KQL below are **hand translations** of each Sigma rule for the two
most common backends. Field names vary by ingest pipeline (Sysmon add-on, WEF,
Defender schema, IIS parser) — treat them as starting points and confirm the
field names in your own index before relying on them.

---

## 1. `llmnr_nbtns_poisoning.yml`

**What it catches.** A Windows host sending name-resolution *replies* from the
LLMNR (5355), NBT-NS (137) or mDNS (5353) source ports out of a process that
isn't the OS resolver (`svchost.exe`). That is exactly what an on-host poisoner
(Inveigh in `powershell.exe`, a Responder-style tool) does: answer broadcast /
multicast queries for names that don't resolve, then harvest the NTLM handshake.

**Required log source.** Sysmon **Event ID 3** (network connection), Windows.
Needs Sysmon configured to log UDP — many baseline configs drop UDP, so confirm
your Sysmon config includes it.

**Honest limitation.** Sysmon only sees the poisoner if it runs *on a host you
monitor*. The common case — Responder on the attacker's own Linux box — produces
no endpoint log. Cover that with a **name-resolution honeytoken**: from a canary
host, periodically resolve a hostname that does not exist. Nothing should ever
answer; if something does, you've found a poisoner regardless of what OS it runs
on. Wire that probe to alert on any answer, and keep this Sigma rule for the
on-host case.

**Splunk SPL**

```spl
`sysmon` EventCode=3 Protocol=udp SourcePort IN (137, 5353, 5355) Initiated=true
    NOT Image="*\\svchost.exe"
| stats count min(_time) as first max(_time) as last
        dc(DestinationIp) as victims values(DestinationIp) as victim_ips
        by host, Image, SourcePort
| where victims > 1
```

**Microsoft Sentinel / Defender KQL** (`DeviceNetworkEvents`)

```kusto
DeviceNetworkEvents
| where Protocol == "Udp"
| where LocalPort in (137, 5353, 5355)          // the poisoner replies FROM these
| where InitiatingProcessFileName !~ "svchost.exe"
| summarize victims = dcount(RemoteIP), first = min(Timestamp), last = max(Timestamp)
          by DeviceName, InitiatingProcessFileName, LocalPort
| where victims > 1
```

**False positives / tuning.**
- Third-party mDNS / service-discovery agents (Bonjour printer helpers,
  Chromecast discovery) answer from these ports. Baseline the answering `Image`
  list and allowlist known-good binaries.
- Fidelity jumps once LLMNR and NBT-NS are **disabled by GPO** — then legitimate
  answers all but disappear and any hit is worth chasing.
- The `victims > 1` clause (one host answering for several distinct targets) is
  the cheapest way to separate a poisoner from a one-off legitimate reply.

---

## 2. `ntlm_relay.yml`

**What it catches.** NTLM network logons (`4624`/`4625`, LogonType 3, package
`NTLM`) whose `WorkstationName` is null, blank or `-`. A relay replays a coerced
handshake to a *third* host, so the session that lands on the target seldom
presents a workstation name that matches its real origin — it is often empty.

**Required log source.** Windows **Security** log, events **4624** (success) and
**4625** (failure). Audit *Logon* must be enabled and forwarded (WEF/agent).

**Splunk SPL**

```spl
(source="WinEventLog:Security" OR sourcetype="WinEventLog:Security")
    (EventCode=4624 OR EventCode=4625) Logon_Type=3 Authentication_Package=NTLM
    (Workstation_Name="" OR Workstation_Name="-")
    NOT Account_Name="ANONYMOUS LOGON"
    NOT Source_Network_Address IN ("127.0.0.1", "::1", "-")
| table _time, host, EventCode, Account_Name, Workstation_Name, Source_Network_Address
```

**Microsoft Sentinel KQL** (`SecurityEvent`)

```kusto
SecurityEvent
| where EventID in (4624, 4625)
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where isempty(WorkstationName) or WorkstationName in ("-", "")
| where TargetUserName != "ANONYMOUS LOGON"
| where IpAddress !in ("127.0.0.1", "::1", "-")
| project TimeGenerated, Computer, EventID, TargetUserName, WorkstationName, IpAddress
```

> **Raise the fidelity with a correlation.** The blank-workstation heuristic is
> broad on its own. The strongest confirmation is a source-host **mismatch**:
> resolve `IpAddress` to the machine it belongs to and compare it against the
> account/workstation presented. A machine account (`HOST$`) authenticating over
> NTLM Type 3 from an IP that is *not* that host is a near-certain relay — worth
> a dedicated correlation rule if your backend supports joins.

**False positives / tuning.**
- Appliances, non-domain clients and some legacy apps legitimately send NTLM
  Type 3 with an empty `WorkstationName`. Baseline, then allowlist by
  `TargetUserName` / `IpAddress`.
- Load balancers and reverse proxies that terminate auth for clients.
- Excluding `ANONYMOUS LOGON` trims noise but can hide some null sessions —
  drop that filter if you're hunting rather than alerting.

---

## 3. `adcs_esc8_http_enrollment.yml`

**What it catches.** The two shapes of **ESC8**:
1. **Exposure** — `/certsrv` served over cleartext **HTTP** (`s-port 80`), which
   is what lets a coerced NTLM handshake be relayed to the CA in the first place.
2. **Abuse** — a **machine account (`$`)** submitting a certificate request
   through the web pages. Real machine enrollment uses DCOM/RPC, never the web
   UI, so a computer account on `/certsrv` is the relay-to-ADCS footprint left by
   `ntlmrelayx --target http://ca/certsrv`.

**Required log source.** The CA's **IIS (W3C)** logs. Make sure `cs-username`
and `s-port` are in the logged fields (they are in the default W3C set).

**Splunk SPL**

```spl
sourcetype=ms:iis:* cs_uri_stem="*/certsrv/*"
    (s_port=80 OR cs_username="*$")
| table _time, c_ip, cs_username, cs_method, cs_uri_stem, s_port
```

**Microsoft Sentinel KQL** (`W3CIISLog`)

```kusto
W3CIISLog
| where csUriStem has "/certsrv/"
| where sPort == 80 or csUserName endswith "$"
| project TimeGenerated, cIP, csUserName, csMethod, csUriStem, sPort
```

**Corroborate on the CA itself.** Pair the IIS view with AD CS issuance events —
`Microsoft-Windows-CertificationServices` **4886** (request received) and
**4887** (certificate issued) — so you can tie an anomalous `/certsrv` hit to the
certificate that actually came out of it, and to the requesting principal.

**False positives / tuning.**
- Legitimate interactive web enrollment over HTTP in shops that haven't enforced
  HTTPS. The real fix is to force **HTTPS + Extended Protection for
  Authentication (EPA)** on the enrollment site (and disable HTTP web enrollment
  if unused); keep the rule afterwards to catch regressions.
- Monitoring / health probes that GET `/certsrv` over HTTP — allowlist their
  `c-ip`.
- The machine-account (`$`) clause is the high-fidelity half; the HTTP-exposure
  clause is more of a hygiene/posture alert and can be split into its own,
  lower-severity rule if it's noisy.

---

## Validating these rules

- **Lint / parse:** run any Sigma toolchain (`sigma check` / `sigma convert` from
  [pySigma](https://github.com/SigmaHQ/pySigma)) to confirm the rules compile for
  your backend, and generate the SIEM query straight from the YAML instead of the
  hand translations above where you can.
- **Quick YAML sanity check** (no Sigma tooling needed):

  ```bash
  python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('detection/*.yml')]" && echo OK
  ```

- **Exercise them safely** in a lab you own: an on-host poisoner (Inveigh) for
  rule 1, an `ntlmrelayx` relay for rules 2 and 3 — same authorization rules as
  the rest of this repo. Never fire these techniques at infrastructure you are
  not explicitly cleared to test.
