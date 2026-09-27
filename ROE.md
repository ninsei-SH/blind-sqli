# Rules of Engagement (ROE) — TEMPLATE

> Fill this out per engagement BEFORE any testing. This file records the
> authorized scope; the tooling in this repo reads from it (or from the
> `scope/` files it points to). Anything not recorded here is out of scope.

## Engagement
- **Client / target org:**
- **Authorizing party (name, title):**
- **Signed authorization ref / SOW #:**
- **Engagement dates:**
- **Assessment type:** internal / external / assumed-breach / red-team

## Testing window
- **Start (ISO 8601):**
- **End (ISO 8601):**
- Feeds `relay_orchestrator.py --testing-window "<start>" "<end>"`.
- Testing outside the window is prohibited.

## In-scope (relay destinations / targets)
List authorized hosts and CIDRs. This is the source for `scope/allowlist.txt`,
consumed by `relay_orchestrator.py --allowlist`.

```
10.0.0.0/24
dc01.corp.local
```

## Explicitly OUT of scope
- Domain controllers? (often out — confirm in writing)
- Production databases / hosts:
- Third-party / cloud-tenant assets:
- Any host not listed in-scope is out of scope by default.

## Rate / impact limits
- Max request rate (feeds `--rps`):
- Segments where coercion/poisoning is permitted (list) — and only via the
  approved public tooling driven by `relay_orchestrator.py` with the allowlist
  gate enforced.
- No DoS, no persistence, no destructive actions.

## Handling captured data
- Credentials/hashes obtained during authorized relay: storage, encryption,
  retention, destruction date.
- Evidence log location (the orchestrator writes JSONL + captured tool output):

## Contacts / escalation
- **Primary POC:**
- **Technical POC:**
- **Emergency stop contact (24/7):**
- **Stop condition / kill-switch:** how testing halts immediately on request.

## Teardown
- Remove tooling, rogue listeners, any planted certs/accounts.
- Confirm no residual config changes on target hosts.
- Sign-off (tester + client):
