#!/usr/bin/env python3
"""
vuln_app.py - INTENTIONALLY VULNERABLE practice target for blind_sqli.py.

============================================================================
 !!! DELIBERATELY INSECURE - DO NOT DEPLOY !!!
----------------------------------------------------------------------------
 This app contains an obvious SQL injection on purpose, as a local practice
 range for the accompanying blind_sqli.py extractor. It binds to 127.0.0.1
 only and serves an in-memory SQLite database seeded with fake data.

 Use it the way you'd use DVWA / a CTF box: on your own machine, to learn and
 to validate tooling. Never expose it to a network or put real data in it.
============================================================================

Zero dependencies (stdlib only).

  Terminal 1:  python3 vuln_app.py --port 8099
  Terminal 2:  python3 blind_sqli.py --url http://127.0.0.1:8099/search --param q \
                   --template "zzz' OR ({cond})-- -" --dbms sqlite \
                   --true-string "MATCH=1" --action dump --db main --table users --unicode

The endpoint runs:  SELECT name, price FROM products WHERE name = '<q>'   (unsanitized)
and renders "MATCH=1" when the query returns rows, "MATCH=0" otherwise -- a
classic boolean-blind content oracle.
"""

import argparse
import html
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB_LOCK = threading.Lock()
DB.executescript("""
    CREATE TABLE products (name TEXT, price TEXT);
    INSERT INTO products VALUES ('widget', '9.99');
    INSERT INTO products VALUES ('gadget', '19.99');

    CREATE TABLE users (id INTEGER, username TEXT, password TEXT, email TEXT);
    INSERT INTO users VALUES (1, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@corp.local');
    INSERT INTO users VALUES (2, 'alice', 'e10adc3949ba59abbe56e057f20f883e', 'alice@corp.local');
    INSERT INTO users VALUES (3, 'José',  'naïve🔑',                          'jose@café.local');
""")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/search":
            self._respond(404, "<h1>Not found</h1> Try /search?q=widget")
            return
        q = parse_qs(parsed.query).get("q", [""])[0]

        # >>> THE VULNERABILITY: raw string concatenation, no parameterization <<<
        sql = "SELECT name, price FROM products WHERE name = '%s'" % q
        try:
            with DB_LOCK:
                rows = DB.execute(sql).fetchall()
            if rows:
                body = "MATCH=1<br>" + "<br>".join(
                    "%s = %s" % (html.escape(str(n)), html.escape(str(p))) for n, p in rows)
            else:
                body = "MATCH=0<br>no products matched"
        except Exception as e:
            # Errors render as a non-matching (false) page, like many real apps.
            body = "MATCH=0<br>query error: %s" % html.escape(str(e))
        self._respond(200, "<h1>Product search</h1>%s" % body)

    def _respond(self, code, body):
        data = ("<!doctype html><html><body>%s</body></html>" % body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser(description="Intentionally vulnerable local SQLi practice target.")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (keep it loopback).")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    base = "http://%s:%d" % (args.host, args.port)
    print("=" * 70)
    print(" INTENTIONALLY VULNERABLE - local practice target (loopback only)")
    print("=" * 70)
    print(" Listening on %s" % base)
    print(" Try:    %s/search?q=widget" % base)
    print(" Inject: %s/search?q=widget' OR '1'='1" % base)
    print("\n Drive the extractor against it:")
    print("   python3 blind_sqli.py --url %s/search --param q \\" % base)
    print("       --template \"zzz' OR ({cond})-- -\" --dbms sqlite \\")
    print("       --true-string \"MATCH=1\" --action dump --db main --table users --unicode")
    print("\n Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        srv.shutdown()


if __name__ == "__main__":
    main()
