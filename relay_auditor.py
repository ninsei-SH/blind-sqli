#!/usr/bin/env python3
"""
relay_auditor.py - Read-only NTLM-relay POSTURE auditor.

============================================================================
 AUTHORIZED USE ONLY
----------------------------------------------------------------------------
 For use during authorized security assessments only (signed scope of
 engagement / written permission). Running this against systems you are not
 explicitly authorized to test is illegal in most jurisdictions. Stay within
 the agreed scope, rate limits, and testing window. Keep your authorization
 letter handy.
============================================================================
 READ-ONLY. THIS IS A POSTURE AUDITOR, NOT AN ATTACK TOOL.
----------------------------------------------------------------------------
 It inspects the configuration each in-scope host advertises about ITSELF and
 reports where that configuration would leave it exposed to an NTLM-relay
 attack. It stays strictly on the safe side of that line. It does NOT, and
 must never be made to:

   * answer / spoof LLMNR, NBT-NS or mDNS queries (no responder behaviour);
   * capture, crack or record NetNTLM / NTLMv1 / NTLMv2 material;
   * coerce authentication (no PetitPotam / PrinterBug / WebDAV tricks);
   * relay, forward or replay anyone's authentication anywhere;
   * collect any third-party credentials of any kind.

 Every check below is either (a) a single benign request to the target that
 asks it to describe its own configuration, or (b) a plain TCP connect. No
 credential material is ever solicited, received, stored or forwarded.
============================================================================

What it checks (per in-scope host)
----------------------------------
  * SMB signing (headline): opens tcp/445, sends a real SMB2 NEGOTIATE and
    parses SecurityMode from the NEGOTIATE response.
        SIGNING_REQUIRED bit (0x02) set  -> signing required     (relay-safe)
        only SIGNING_ENABLED (0x01)      -> not required          (relay-susceptible)
    A relay attack against a host that requires signing fails, so this is the
    single most useful field in a relay-hardening review.
  * LLMNR / NBT-NS / mDNS exposure: PASSIVE. Sends ONE benign name query for a
    random bogus name to each in-scope host and reports whether anything
    answers. It never answers or spoofs queries itself. (See note below on why
    this is unicast-per-target rather than a segment-wide multicast blast.)
  * LDAP signing / channel binding (EPA): best-effort connect to tcp/389 and
    tcp/636. A trustworthy signing/EPA determination is NOT possible with the
    standard library alone (see check_ldap docstring), so this reports
    "unknown / verify manually" rather than guessing.
  * ADCS web enrollment: flags /certsrv reachable over plain HTTP (ESC8 relay
    surface).

Examples
--------
  # Verify the SMB parser end-to-end, fully offline (no network, no target):
  python3 relay_auditor.py --self-test

  # Audit a subnet, gentle rate limit, write JSON:
  python3 relay_auditor.py --targets 10.0.0.0/24 --rps 20 --output posture.json

  # Just the headline SMB signing check against a host list:
  python3 relay_auditor.py --targets hosts.txt --checks smb

Dependencies: none (Python 3 standard library only).
"""

import argparse
import csv
import ipaddress
import json
import os
import random
import socket
import string
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# posture_lab is imported lazily inside self_test() only.


# ==========================================================================
# Logging / colors (mirrors blind_sqli.py).
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


# ==========================================================================
# Token-bucket rate limiter + per-request delay/jitter (same spirit as
# blind_sqli.py). Keeps the audit inside an agreed request budget.
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


class Throttle:
    """One gate in front of every network probe: rate cap, then delay+jitter."""

    def __init__(self, rps=0, delay=0.0, jitter=0.0):
        self.rl = RateLimiter(rps)
        self.delay = delay
        self.jitter = jitter

    def wait(self):
        self.rl.acquire()
        d = self.delay + (random.uniform(0, self.jitter) if self.jitter else 0)
        if d > 0:
            time.sleep(d)


# ==========================================================================
# SMB2 NEGOTIATE: request builder + response parser (struct only).
#
# We speak just enough SMB2 to send a NEGOTIATE and read SecurityMode back.
# We never send SESSION_SETUP, so no authentication is ever attempted.
# ==========================================================================
SMB2_MAGIC = b"\xfeSMB"
SMB2_NEGOTIATE = 0x0000
SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002

DIALECT_NAMES = {
    0x0202: "2.0.2", 0x0210: "2.1.0", 0x0222: "2.2.2", 0x0224: "2.2.4",
    0x02FF: "wildcard", 0x0300: "3.0.0", 0x0302: "3.0.2", 0x0311: "3.1.1",
}

# Signing-posture labels (also the assertion targets in --self-test).
SIGN_REQUIRED = "signing required"
SIGN_NOT_REQUIRED = "signing NOT required / relay-susceptible"
SIGN_UNKNOWN = "unknown"


class SMBParseError(Exception):
    pass


def _smb2_header(command, message_id=0, flags=0, credit=1):
    return (
        SMB2_MAGIC
        + struct.pack("<H", 64)          # StructureSize
        + struct.pack("<H", 0)           # CreditCharge
        + struct.pack("<I", 0)           # Status / ChannelSequence
        + struct.pack("<H", command)     # Command
        + struct.pack("<H", credit)      # CreditRequest
        + struct.pack("<I", flags)       # Flags
        + struct.pack("<I", 0)           # NextCommand
        + struct.pack("<Q", message_id)  # MessageId
        + struct.pack("<I", 0)           # Reserved
        + struct.pack("<I", 0)           # TreeId
        + struct.pack("<Q", 0)           # SessionId
        + b"\x00" * 16                   # Signature
    )


def build_negotiate_request(message_id=0):
    """A valid multi-dialect SMB2 NEGOTIATE request.

    Offers 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1. Because 3.1.1 is offered, the
    request carries the two negotiate contexts a well-behaved 3.1.1 client is
    expected to send (preauth-integrity + encryption), so real Windows servers
    reply with a NEGOTIATE response rather than STATUS_INVALID_PARAMETER.
    """
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]

    fixed_len = 64 + 36 + len(dialects) * 2          # header + fixed body + dialects
    ctx_offset = (fixed_len + 7) & ~7                # negotiate contexts are 8-byte aligned

    header = _smb2_header(SMB2_NEGOTIATE, message_id=message_id)

    body = b""
    body += struct.pack("<H", 36)                                 # StructureSize
    body += struct.pack("<H", len(dialects))                      # DialectCount
    body += struct.pack("<H", SMB2_NEGOTIATE_SIGNING_ENABLED)     # SecurityMode (client)
    body += struct.pack("<H", 0)                                  # Reserved
    body += struct.pack("<I", 0)                                  # Capabilities
    body += os.urandom(16)                                        # ClientGuid
    body += struct.pack("<IHH", ctx_offset, 2, 0)                 # NegCtxOffset, NegCtxCount, Reserved2
    assert len(body) == 36

    msg = header + body + b"".join(struct.pack("<H", d) for d in dialects)
    msg += b"\x00" * ((-len(msg)) % 8)               # pad to first context (== ctx_offset)
    assert len(msg) == ctx_offset

    # SMB2_PREAUTH_INTEGRITY_CAPABILITIES (0x0001): SHA-512, 32-byte salt.
    salt = os.urandom(32)
    pre_data = struct.pack("<HH", 1, len(salt)) + struct.pack("<H", 0x0001) + salt
    msg += struct.pack("<HHI", 0x0001, len(pre_data), 0) + pre_data
    msg += b"\x00" * ((-len(msg)) % 8)

    # SMB2_ENCRYPTION_CAPABILITIES (0x0002): AES-128-GCM, AES-128-CCM.
    enc_data = struct.pack("<H", 2) + struct.pack("<HH", 0x0002, 0x0001)
    msg += struct.pack("<HHI", 0x0002, len(enc_data), 0) + enc_data

    return msg


def parse_negotiate_response(msg):
    """Return (security_mode, dialect_revision) from an SMB2 NEGOTIATE response.

    Reads only fixed-offset fields, so it is independent of any security buffer
    or negotiate contexts the server appends.
    """
    if len(msg) < 4 or msg[0:4] != SMB2_MAGIC:
        raise SMBParseError("not an SMB2 message")
    if len(msg) < 72:
        raise SMBParseError("SMB2 message too short (%d bytes) for a NEGOTIATE response" % len(msg))
    command = struct.unpack_from("<H", msg, 12)[0]
    status = struct.unpack_from("<I", msg, 8)[0]
    if command != SMB2_NEGOTIATE:
        raise SMBParseError("unexpected SMB2 command 0x%04x" % command)
    body_struct_size = struct.unpack_from("<H", msg, 64)[0]
    if body_struct_size == 9:
        raise SMBParseError("server returned SMB2 error status 0x%08x" % status)
    if body_struct_size != 65:
        raise SMBParseError("unexpected NEGOTIATE response StructureSize %d" % body_struct_size)
    security_mode = struct.unpack_from("<H", msg, 66)[0]
    dialect = struct.unpack_from("<H", msg, 68)[0]
    return security_mode, dialect


def _frame(msg):
    """Prepend the 4-byte Direct-TCP / NBSS session header."""
    return struct.pack(">I", len(msg) & 0x00FFFFFF) + msg


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SMBParseError("connection closed after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return buf


def _read_smb2_message(sock):
    hdr = _recv_exact(sock, 4)
    length = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
    if not (0 < length <= 0x1FFFF):
        raise SMBParseError("implausible SMB2 frame length %d" % length)
    return _recv_exact(sock, length)


def _errname(exc):
    return "%s" % (exc if str(exc) else type(exc).__name__)


def check_smb_signing(host, port=445, timeout=5.0, throttle=None):
    """READ-ONLY SMB signing posture: connect, one NEGOTIATE, parse SecurityMode."""
    res = {"smb_port": port, "port_open": False, "signing": SIGN_UNKNOWN,
           "dialect": None, "dialect_name": "", "security_mode": None, "error": None}
    if throttle:
        throttle.wait()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        res["error"] = _errname(e)
        return res
    res["port_open"] = True
    try:
        sock.settimeout(timeout)
        sock.sendall(_frame(build_negotiate_request()))
        msg = _read_smb2_message(sock)
        sec_mode, dialect = parse_negotiate_response(msg)
        res["security_mode"] = sec_mode
        res["dialect"] = dialect
        res["dialect_name"] = DIALECT_NAMES.get(dialect, "0x%04x" % dialect)
        res["signing"] = (SIGN_REQUIRED if (sec_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
                          else SIGN_NOT_REQUIRED)
    except SMBParseError as e:
        res["error"] = str(e)
    except OSError as e:
        res["error"] = _errname(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return res


# ==========================================================================
# Passive name-service exposure (LLMNR / NBT-NS / mDNS).
#
# PASSIVE means: we only ever ASK. We send one benign query for a RANDOM,
# almost-certainly-nonexistent name to the target and note whether anything
# answers. We never answer, spoof or poison a query -- that is the attacker's
# job (Responder/Inveigh) and is explicitly out of scope for this tool.
#
# Why a bogus name? A well-behaved host only answers name queries for names it
# actually owns, so it will stay silent for a random string. A rogue
# name-resolution spoofer answers for ANY name -- so a reply to a bogus name is
# a strong, low-false-positive signal that a poisoning responder is live on the
# path to that target. Silence does NOT prove LLMNR/NBT-NS is disabled on the
# host; confirm the client-side config (GPO / registry) separately.
#
# Why unicast-per-target instead of a segment-wide multicast/broadcast blast?
# Multicast (224.0.0.252 LLMNR, 224.0.0.251 mDNS) and subnet broadcast (NBT-NS)
# would pull answers from EVERY host on the wire, including out-of-scope ones,
# which an authorized, scoped engagement must not touch. Unicast probes keep us
# inside the agreed target list. Responders happily answer unicast queries too.
# ==========================================================================
NAME_ANSWERED = "answered (responder active)"
NAME_SILENT = "no answer"
NAME_ERROR = "error"


def _rand_name(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _dns_query(name, qtype=1, qclass=1, txid=0):
    pkt = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)  # standard query, 1 question
    for label in name.split("."):
        b = label.encode("ascii")
        pkt += bytes([len(b)]) + b
    pkt += b"\x00"
    pkt += struct.pack(">HH", qtype, qclass)
    return pkt


def _encode_netbios_name(name, suffix=0x00):
    name = name.upper()[:15].ljust(15)
    raw = name.encode("ascii") + bytes([suffix])          # 16 bytes
    out = bytearray()
    for byte in raw:
        out.append((byte >> 4) + ord("A"))
        out.append((byte & 0x0F) + ord("A"))
    return bytes(out)                                     # 32 encoded bytes


def _nbtns_query(name, txid=0):
    pkt = struct.pack(">HHHHHH", txid, 0x0110, 1, 0, 0, 0)  # broadcast name query, recursion desired
    enc = _encode_netbios_name(name)
    pkt += bytes([len(enc)]) + enc + b"\x00"               # 0x20 length + 32 bytes + root label
    pkt += struct.pack(">HH", 0x0020, 0x0001)              # QTYPE NB, QCLASS IN
    return pkt


def _udp_probe(host, port, payload, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        s.recvfrom(4096)     # any datagram back == something answered
        return NAME_ANSWERED
    except socket.timeout:
        return NAME_SILENT
    except OSError:
        return NAME_SILENT   # ICMP unreachable etc. -> treat as silent
    finally:
        s.close()


def check_llmnr(host, timeout, throttle=None):
    if throttle:
        throttle.wait()
    return _udp_probe(host, 5355, _dns_query(_rand_name(), qtype=1, qclass=1,
                                             txid=random.randint(0, 0xFFFF)), timeout)


def check_mdns(host, timeout, throttle=None):
    if throttle:
        throttle.wait()
    # QCLASS with the top (unicast-response) bit set => "please answer me unicast".
    return _udp_probe(host, 5353, _dns_query(_rand_name() + ".local", qtype=1,
                                             qclass=0x8001, txid=0), timeout)


def check_nbtns(host, timeout, throttle=None):
    if throttle:
        throttle.wait()
    return _udp_probe(host, 137, _nbtns_query(_rand_name(6),
                                              txid=random.randint(0, 0xFFFF)), timeout)


# ==========================================================================
# LDAP signing / channel binding (EPA).
# ==========================================================================
LDAP_SIGNING_UNKNOWN = "unknown / verify manually"
LDAP_NA = "n/a"


def _tcp_open(host, port, timeout, throttle=None):
    if throttle:
        throttle.wait()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def check_ldap(host, timeout, throttle=None):
    """Best-effort LDAP posture.

    HARD LIMITATION (documented on purpose): whether a DC *enforces* LDAP
    signing, or LDAPS channel binding (EPA), cannot be determined reliably with
    the standard library. A real determination requires attempting an UNSIGNED
    simple/SASL bind (and, for EPA, a TLS bind with and without a channel-
    binding token) and observing whether the server rejects it -- that needs
    credentials plus a full LDAP/SASL/GSS-API stack we intentionally do not
    ship, and attempting binds strays past a read-only posture check anyway.

    So we only report reachability of tcp/389 and tcp/636 and explicitly return
    "unknown / verify manually" for the signing/EPA verdict. Verify manually via
    the DC's event log (2889 / 3039 / 3040), GPO ("Domain controller: LDAP
    server signing requirements" and channel-binding tokens), or a dedicated
    authenticated tool.
    """
    ldap_open = _tcp_open(host, 389, timeout, throttle)
    ldaps_open = _tcp_open(host, 636, timeout, throttle)
    verdict = LDAP_SIGNING_UNKNOWN if (ldap_open or ldaps_open) else LDAP_NA
    return {"ldap_389": "open" if ldap_open else "closed",
            "ldaps_636": "open" if ldaps_open else "closed",
            "ldap_signing": verdict}


# ==========================================================================
# ADCS web enrollment (/certsrv) over plain HTTP -> ESC8 relay surface.
# ==========================================================================
ADCS_HTTP = "reachable over plain HTTP (ESC8 surface)"
ADCS_HTTP_AUTH = "reachable over plain HTTP, auth-gated (ESC8 surface)"
ADCS_ABSENT = "not found / closed"


def check_adcs_http(host, timeout, throttle=None):
    """One plain-HTTP GET to /certsrv/. Reaching it unencrypted is the exposure
    (an attacker can relay coerced auth to it). We only fetch a page; we send no
    credentials and follow no auth challenge."""
    import urllib.request
    import urllib.error
    if throttle:
        throttle.wait()
    url = "http://%s/certsrv/" % host
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "relay-auditor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("latin-1", "replace")
            if "Certificate Services" in body or resp.status in (200, 401, 403):
                return ADCS_HTTP
            return ADCS_ABSENT
    except urllib.error.HTTPError as e:
        # 401/403 == present but auth-gated (still an ESC8 surface over HTTP).
        if e.code in (401, 403):
            return ADCS_HTTP_AUTH
        if e.code == 404:
            return ADCS_ABSENT
        return "http %d" % e.code
    except (urllib.error.URLError, OSError):
        return ADCS_ABSENT


# ==========================================================================
# Target scope expansion. Supports host, host:port, CIDR, comma lists, files.
# ==========================================================================
def _parse_token(token, default_smb_port):
    token = token.strip()
    if not token or token.startswith("#"):
        return []
    if "/" in token:  # CIDR
        net = ipaddress.ip_network(token, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
        return [(str(ip), default_smb_port) for ip in hosts]
    # host or host:port (IPv4 / hostname; IPv6 not handled to keep parsing simple)
    if token.count(":") == 1:
        host, _, port = token.partition(":")
        if port.isdigit():
            return [(host, int(port))]
    return [(token, default_smb_port)]


def expand_targets(spec, default_smb_port):
    tokens = []
    if os.path.isfile(spec):
        with open(spec, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                tokens.append(line)
    else:
        tokens.extend(spec.split(","))

    seen = set()
    targets = []
    for tok in tokens:
        for host, port in _parse_token(tok, default_smb_port):
            key = (host, port)
            if key not in seen:
                seen.add(key)
                targets.append(key)
    return targets


# ==========================================================================
# Per-host audit + output.
# ==========================================================================
FIELDS = ["host", "smb", "signing", "dialect", "llmnr", "nbtns", "mdns",
          "ldap", "ldaps", "ldap_signing", "adcs"]


def audit_host(host, smb_port, checks, throttle, timeout):
    row = {f: "-" for f in FIELDS}
    row["host"] = ("%s:%d" % (host, smb_port)) if smb_port != 445 else host

    if "smb" in checks:
        smb = check_smb_signing(host, smb_port, timeout=timeout, throttle=throttle)
        row["smb"] = "open" if smb["port_open"] else "closed"
        if smb["port_open"]:
            row["signing"] = smb["signing"] if smb["signing"] != SIGN_UNKNOWN \
                else "%s (%s)" % (SIGN_UNKNOWN, smb["error"] or "no parse")
            row["dialect"] = smb["dialect_name"] or "-"
        else:
            row["signing"] = "n/a"

    if "names" in checks:
        row["llmnr"] = check_llmnr(host, timeout, throttle)
        row["nbtns"] = check_nbtns(host, timeout, throttle)
        row["mdns"] = check_mdns(host, timeout, throttle)

    if "ldap" in checks:
        ldap = check_ldap(host, timeout, throttle)
        row["ldap"] = ldap["ldap_389"]
        row["ldaps"] = ldap["ldaps_636"]
        row["ldap_signing"] = ldap["ldap_signing"]

    if "adcs" in checks:
        row["adcs"] = check_adcs_http(host, timeout, throttle)

    return row


def render_table(rows, fields):
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in fields} \
        if rows else {c: len(c) for c in fields}
    line = lambda vals: " | ".join(str(v).ljust(widths[c]) for c, v in zip(fields, vals))
    out = [line(fields), "-+-".join("-" * widths[c] for c in fields)]
    for r in rows:
        out.append(line([r.get(c, "") for c in fields]))
    return "\n".join(out)


def write_results(rows, output):
    if output and output.endswith(".json"):
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2, ensure_ascii=False)
        LOG.ok("Wrote %d host(s) -> %s (json)" % (len(rows), output))
    elif output and output.endswith(".csv"):
        with open(output, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)
        LOG.ok("Wrote %d host(s) -> %s (csv)" % (len(rows), output))
    else:
        text = render_table(rows, FIELDS)
        if output:
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            LOG.ok("Wrote %d host(s) -> %s (tsv)" % (len(rows), output))
        else:
            print(text)


# ==========================================================================
# Offline self-test: drive the SMB signing check against posture_lab's two
# loopback endpoints. Fully hermetic -- no real network, no external hosts,
# no third-party tools.
# ==========================================================================
def self_test():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import posture_lab
    except Exception as e:  # pragma: no cover
        LOG.error("Cannot import posture_lab.py (must sit beside this file): %s" % e)
        return 1

    LOG.info("Self-test: standing up two loopback posture endpoints...")
    ep_req = posture_lab.PostureEndpoint(posture_lab.MODE_REQUIRED, port=0, label="required").start()
    ep_open = posture_lab.PostureEndpoint(posture_lab.MODE_NOT_REQUIRED, port=0, label="not-required").start()

    results = {}

    def check(name, got, expected):
        ok = got == expected
        results[name] = ok
        (LOG.ok if ok else LOG.error)(
            "%-34s %s" % (name, "PASS" if ok else "FAIL got=%r exp=%r" % (got, expected)))

    try:
        r_req = check_smb_signing("127.0.0.1", ep_req.port, timeout=3.0)
        r_open = check_smb_signing("127.0.0.1", ep_open.port, timeout=3.0)

        # Headline oracle: one endpoint required, one relay-susceptible.
        check("required: port open", r_req["port_open"], True)
        check("required: labeled required", r_req["signing"], SIGN_REQUIRED)
        check("required: SecurityMode 0x03", r_req["security_mode"], 0x0003)
        check("required: dialect 3.1.1", r_req["dialect"], 0x0311)

        check("open: port open", r_open["port_open"], True)
        check("open: labeled NOT required", r_open["signing"], SIGN_NOT_REQUIRED)
        check("open: SecurityMode 0x01", r_open["security_mode"], 0x0001)

        # The two must disagree -- that is the whole point of the oracle.
        check("labels differ", r_req["signing"] != r_open["signing"], True)
    finally:
        ep_req.stop()
        ep_open.stop()

    # SecurityMode bit logic (independent of the network path).
    check("bit logic: 0x03 is required",
          bool(0x03 & SMB2_NEGOTIATE_SIGNING_REQUIRED), True)
    check("bit logic: 0x01 not required",
          bool(0x01 & SMB2_NEGOTIATE_SIGNING_REQUIRED), False)
    check("bit logic: 0x00 not required",
          bool(0x00 & SMB2_NEGOTIATE_SIGNING_REQUIRED), False)

    # Parser round-trips a locally built response for every dialect.
    for dialect in (0x0202, 0x0210, 0x0300, 0x0302, 0x0311):
        for mode in (0x0001, 0x0002, 0x0003):
            msg = posture_lab.build_negotiate_response(mode, dialect=dialect)
            sm, dr = parse_negotiate_response(msg)
            check("parse mode 0x%02x dialect %s" % (mode, DIALECT_NAMES[dialect]),
                  (sm, dr), (mode, dialect))

    # Parser rejects non-SMB / truncated / error-response input.
    def raises(fn):
        try:
            fn()
            return False
        except SMBParseError:
            return True
    check("parser rejects non-SMB", raises(lambda: parse_negotiate_response(b"HTTP/1.1 200")), True)
    check("parser rejects short msg", raises(lambda: parse_negotiate_response(SMB2_MAGIC + b"\x00" * 8)), True)

    # Request builder produces a well-formed, 8-byte-aligned NEGOTIATE.
    req = build_negotiate_request()
    check("request magic", req[0:4], SMB2_MAGIC)
    check("request command NEGOTIATE", struct.unpack_from("<H", req, 12)[0], SMB2_NEGOTIATE)
    check("request body StructureSize", struct.unpack_from("<H", req, 64)[0], 36)
    check("request dialect count", struct.unpack_from("<H", req, 66)[0], 5)
    # Negotiate contexts must START at an 8-byte-aligned offset from the SMB2
    # header (the message as a whole need not be a multiple of 8).
    req_ctx_off = struct.unpack_from("<I", req, 64 + 28)[0]
    check("request NegCtxOffset 8-byte aligned", req_ctx_off % 8, 0)
    check("request NegCtxOffset value", req_ctx_off, 112)
    check("request contexts present", req[req_ctx_off:req_ctx_off + 2], struct.pack("<H", 0x0001))

    # Name-service query encoders build sane packets (no network involved).
    check("NetBIOS encoding length", len(_encode_netbios_name("WORKSTATION")), 32)
    check("NetBIOS 'CA' encodes null suffix low nibble",
          _encode_netbios_name("", suffix=0x00)[-2:], b"AA")
    nb = _nbtns_query("TEST", txid=0x1234)
    check("NBT-NS name length prefix", nb[12], 0x20)
    check("NBT-NS QTYPE=NB", struct.unpack_from(">H", nb, len(nb) - 4)[0], 0x0020)
    dq = _dns_query("wpad", qtype=1, qclass=1, txid=0xABCD)
    check("LLMNR qdcount", struct.unpack_from(">H", dq, 4)[0], 1)
    mq = _dns_query("x.local", qclass=0x8001)
    check("mDNS unicast-response bit set",
          struct.unpack_from(">H", mq, len(mq) - 2)[0] & 0x8000, 0x8000)

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
        description="Read-only NTLM-relay posture auditor (authorized testing only). "
                    "Inspects what each host advertises about itself; never poisons, "
                    "captures or relays authentication.",
        epilog="Run --self-test to verify the SMB parser offline against posture_lab.py.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    g = p.add_argument_group("scope")
    g.add_argument("--targets", help="Host, host:port, CIDR, comma-separated list, "
                                     "or a file with one entry per line. REQUIRED.")
    g.add_argument("--smb-port", type=int, default=445, help="Default SMB port for the signing check.")
    g.add_argument("--checks", default="smb,names,ldap,adcs",
                   help="Comma list of checks to run: smb,names,ldap,adcs.")

    g = p.add_argument_group("throttling / performance")
    g.add_argument("--rps", type=float, default=0, help="Global request rate cap (req/s). 0 = unlimited.")
    g.add_argument("--delay", type=float, default=0.0, help="Base delay (s) before each probe.")
    g.add_argument("--jitter", type=float, default=0.0, help="Random extra delay 0..jitter (s).")
    g.add_argument("--threads", type=int, default=1, help="Concurrent hosts (kept low by default).")
    g.add_argument("--timeout", type=float, default=5.0, help="Per-probe socket timeout (s).")

    g = p.add_argument_group("output / misc")
    g.add_argument("--output", help="Write results to file (.csv/.json), else pretty TSV to stdout.")
    g.add_argument("--dry-run", action="store_true", help="Print exactly what would be probed, then exit.")
    g.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug.")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--self-test", action="store_true", help="Run the offline SMB-parser self-test (no network).")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    global LOG
    LOG = Log(level={0: "info", 1: "info", 2: "debug"}.get(args.verbose, "debug"),
              color=not args.no_color)

    if args.self_test:
        return self_test()

    if not args.targets:
        LOG.error("No scope provided. --targets is REQUIRED (host, host:port, CIDR, "
                  "comma list, or file). Refusing to run against an empty scope.")
        return 2

    valid_checks = {"smb", "names", "ldap", "adcs"}
    checks = [c.strip() for c in args.checks.split(",") if c.strip()]
    bad = [c for c in checks if c not in valid_checks]
    if bad:
        LOG.error("Unknown --checks value(s): %s (valid: %s)" % (", ".join(bad), ", ".join(sorted(valid_checks))))
        return 2
    if not checks:
        LOG.error("--checks resolved to nothing to do.")
        return 2

    try:
        targets = expand_targets(args.targets, args.smb_port)
    except ValueError as e:
        LOG.error("Could not parse --targets: %s" % e)
        return 2
    if not targets:
        LOG.error("Scope expanded to zero hosts. Nothing to audit.")
        return 2

    if args.dry_run:
        print("DRY RUN - no packets will be sent. Planned probes:")
        print("  checks : %s" % ", ".join(checks))
        print("  hosts  : %d" % len(targets))
        for host, port in targets:
            plan = []
            if "smb" in checks:
                plan.append("SMB2 NEGOTIATE tcp/%d (read-only signing posture)" % port)
            if "names" in checks:
                plan.append("passive name query udp/5355 (LLMNR), udp/137 (NBT-NS), udp/5353 (mDNS)")
            if "ldap" in checks:
                plan.append("tcp connect 389/636 (LDAP reachability; signing = verify manually)")
            if "adcs" in checks:
                plan.append("http GET /certsrv (ESC8 surface over plain HTTP)")
            print("  - %s" % host)
            for item in plan:
                print("      * %s" % item)
        return 0

    LOG.info("Auditing %d host(s); checks=%s; rps=%s threads=%d"
             % (len(targets), ",".join(checks), args.rps, args.threads))
    throttle = Throttle(args.rps, args.delay, args.jitter)

    def work(t):
        host, port = t
        LOG.debug("probing %s" % host)
        return audit_host(host, port, checks, throttle, args.timeout)

    if args.threads > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            rows = list(ex.map(work, targets))
    else:
        rows = [work(t) for t in targets]

    write_results(rows, args.output)

    # A concise, actionable tail: which hosts are relay-susceptible on SMB.
    if "smb" in checks:
        susceptible = [r["host"] for r in rows if r.get("signing") == SIGN_NOT_REQUIRED]
        if susceptible:
            LOG.warn("SMB signing NOT required (relay-susceptible) on: %s" % ", ".join(susceptible))
        else:
            LOG.ok("No SMB-relay-susceptible hosts found in scope (per signing posture).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        LOG.warn("Interrupted.")
        sys.exit(130)
