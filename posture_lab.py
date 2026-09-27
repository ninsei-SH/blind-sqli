#!/usr/bin/env python3
"""
posture_lab.py - Loopback-only NTLM-relay POSTURE demonstrator for relay_auditor.py.

============================================================================
 !!! CONFIGURATION DEMONSTRATOR - DO NOT DEPLOY !!!
----------------------------------------------------------------------------
 This is a local practice range for the accompanying relay_auditor.py posture
 checker. It binds to 127.0.0.1 only and stands up two tiny TCP endpoints that
 each answer a single SMB2 NEGOTIATE with a DIFFERENT SecurityMode flag:

     endpoint A -> SecurityMode = 0x03 (SIGNING_ENABLED | SIGNING_REQUIRED)
     endpoint B -> SecurityMode = 0x01 (SIGNING_ENABLED, NOT required)

 It exists ONLY to give the auditor a known-good / known-bad oracle for its
 SMB signing check. It is PURELY a posture-flag emitter:

   * It answers exactly one NEGOTIATE response and closes the connection.
   * It NEVER advances to SESSION_SETUP.
   * It performs, accepts and facilitates NO authentication of any kind.
   * It captures nothing, relays nothing, poisons nothing.

 Use it the way you'd use DVWA / a CTF box: on your own machine, to learn and
 to validate tooling. Never expose it to a network or point it at real hosts.
============================================================================

Zero dependencies (stdlib only).

  Terminal 1:  python3 posture_lab.py
  Terminal 2:  (command is printed by terminal 1 on start)

The two NEGOTIATE responses are deliberately wire-accurate SMB2 so that the
auditor's struct-based parser can byte-parse the SecurityMode field out of
them, exactly as it would from a real Windows / Samba server.
"""

import argparse
import ipaddress
import struct
import threading
import time
from socketserver import BaseRequestHandler, ThreadingTCPServer

# --------------------------------------------------------------------------
# SMB2 wire constants (see [MS-SMB2] 2.2.4, SMB2 NEGOTIATE Response).
# --------------------------------------------------------------------------
SMB2_MAGIC = b"\xfeSMB"
SMB2_NEGOTIATE = 0x0000
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001

# SecurityMode bit flags (the whole point of this lab):
SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002

# Named posture presets for clarity at the call site / on the CLI.
MODE_REQUIRED = SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED  # 0x03
MODE_NOT_REQUIRED = SMB2_NEGOTIATE_SIGNING_ENABLED                               # 0x01

DEFAULT_REQUIRED_PORT = 14450
DEFAULT_OPEN_PORT = 14451


# --------------------------------------------------------------------------
# SMB2 message construction.
# --------------------------------------------------------------------------
def _filetime_now():
    """Current time as a Windows FILETIME (100 ns ticks since 1601-01-01)."""
    return int((time.time() + 11644473600) * 10_000_000)


def _smb2_header(command, message_id=0, flags=0, credit=1):
    """A 64-byte synchronous SMB2 packet header."""
    return (
        SMB2_MAGIC
        + struct.pack("<H", 64)          # StructureSize (always 64)
        + struct.pack("<H", 0)           # CreditCharge
        + struct.pack("<I", 0)           # Status (0 = STATUS_SUCCESS)
        + struct.pack("<H", command)     # Command
        + struct.pack("<H", credit)      # CreditRequest/Response
        + struct.pack("<I", flags)       # Flags
        + struct.pack("<I", 0)           # NextCommand
        + struct.pack("<Q", message_id)  # MessageId
        + struct.pack("<I", 0)           # Reserved (ProcessId)
        + struct.pack("<I", 0)           # TreeId
        + struct.pack("<Q", 0)           # SessionId
        + b"\x00" * 16                   # Signature (unsigned: zeros)
    )


def build_negotiate_response(security_mode, dialect=0x0311, message_id=0):
    """Build a complete, wire-accurate SMB2 NEGOTIATE response (no transport
    header) advertising the given SecurityMode.

    This emits ONLY posture metadata (the server's advertised signing policy).
    There is no security buffer / GSS token worth speaking of and no follow-up
    exchange -- it cannot be used to authenticate anything.
    """
    header = _smb2_header(SMB2_NEGOTIATE, message_id=message_id,
                          flags=SMB2_FLAGS_SERVER_TO_REDIR, credit=1)

    neg_ctx_count = 1 if dialect == 0x0311 else 0
    # An empty security buffer sits immediately after the 64-byte fixed body,
    # i.e. at offset 64(header)+64(body) = 128 from the start of the SMB2 msg.
    sec_buf_offset = 128
    sec_buf_len = 0
    neg_ctx_offset = 128 if neg_ctx_count else 0  # 128 is already 8-byte aligned

    body = b""
    body += struct.pack("<H", 65)                # StructureSize (65 = fixed 64 + 1)
    body += struct.pack("<H", security_mode)     # SecurityMode  <-- the posture flag
    body += struct.pack("<H", dialect)           # DialectRevision
    body += struct.pack("<H", neg_ctx_count)     # NegotiateContextCount (Reserved < 3.1.1)
    body += b"\x11" * 16                          # ServerGuid (fixed fake lab GUID)
    body += struct.pack("<I", 0)                  # Capabilities
    body += struct.pack("<I", 0x00100000)         # MaxTransactSize
    body += struct.pack("<I", 0x00100000)         # MaxReadSize
    body += struct.pack("<I", 0x00100000)         # MaxWriteSize
    body += struct.pack("<Q", _filetime_now())    # SystemTime
    body += struct.pack("<Q", 0)                  # ServerStartTime
    body += struct.pack("<H", sec_buf_offset)     # SecurityBufferOffset
    body += struct.pack("<H", sec_buf_len)        # SecurityBufferLength
    body += struct.pack("<I", neg_ctx_offset)     # NegotiateContextOffset
    assert len(body) == 64, "fixed NEGOTIATE response body must be 64 bytes"

    msg = header + body  # 128 bytes, already 8-byte aligned

    if neg_ctx_count:
        # SMB2_PREAUTH_INTEGRITY_CAPABILITIES (mandatory for 3.1.1 well-formedness).
        salt = b"\x22" * 32
        data = struct.pack("<HH", 1, len(salt)) + struct.pack("<H", 0x0001) + salt
        ctx = struct.pack("<HHI", 0x0001, len(data), 0) + data
        msg += ctx

    return msg


def frame(msg):
    """Prepend the 4-byte Direct-TCP / NBSS session header (type 0 + 24-bit len)."""
    return struct.pack(">I", len(msg) & 0x00FFFFFF) + msg


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


# --------------------------------------------------------------------------
# The endpoints.
# --------------------------------------------------------------------------
class _NegotiateHandler(BaseRequestHandler):
    """Reads (and discards) one SMB2 NEGOTIATE request, replies with one
    NEGOTIATE response carrying this endpoint's SecurityMode, then closes.

    Deliberately does nothing else. There is no state machine beyond
    'answer once', so no authentication can occur here."""

    def handle(self):
        sock = self.request
        try:
            sock.settimeout(getattr(self.server, "io_timeout", 5.0))
            # Best-effort read of the client's framed NEGOTIATE request.
            # We do not need it -- we only ever emit a fixed posture reply.
            hdr = _recv_exact(sock, 4)
            if len(hdr) == 4:
                length = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
                if 0 < length <= 0x1FFFF:
                    _recv_exact(sock, length)
        except Exception:
            pass  # a malformed / silent client still gets the posture reply

        try:
            sock.sendall(frame(build_negotiate_response(self.server.security_mode)))
        except Exception:
            pass
        # Connection closes here. No SESSION_SETUP. No auth. Ever.


class PostureEndpoint:
    """One loopback TCP listener that answers SMB2 NEGOTIATE with a fixed
    SecurityMode. Import-friendly so relay_auditor's --self-test can drive it
    fully in-process with no real network."""

    def __init__(self, security_mode, host="127.0.0.1", port=0,
                 label="", io_timeout=5.0):
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("posture_lab endpoints bind loopback only, got %r" % host)
        self.security_mode = security_mode
        self.label = label
        srv = ThreadingTCPServer((host, port), _NegotiateHandler)
        srv.allow_reuse_address = True
        srv.daemon_threads = True
        srv.security_mode = security_mode
        srv.io_timeout = io_timeout
        self.server = srv
        self.host, self.port = srv.server_address[:2]
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        name="posture-%s" % (self.label or self.port),
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self):
        try:
            self.server.shutdown()
        finally:
            self.server.server_close()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Loopback-only SMB signing POSTURE demonstrator for relay_auditor.py "
                    "(configuration oracle only; performs no authentication).")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address (loopback only, enforced).")
    ap.add_argument("--required-port", type=int, default=DEFAULT_REQUIRED_PORT,
                    help="Port for the SIGNING REQUIRED (0x03) endpoint.")
    ap.add_argument("--open-port", type=int, default=DEFAULT_OPEN_PORT,
                    help="Port for the signing-enabled-but-NOT-required (0x01) endpoint.")
    args = ap.parse_args(argv)

    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            raise SystemExit("Refusing to bind non-loopback address %r. This is a "
                             "local demonstrator only." % args.host)
    except ValueError:
        raise SystemExit("--host must be a loopback IP address (e.g. 127.0.0.1).")

    ep_req = PostureEndpoint(MODE_REQUIRED, host=args.host,
                             port=args.required_port, label="required").start()
    ep_open = PostureEndpoint(MODE_NOT_REQUIRED, host=args.host,
                              port=args.open_port, label="not-required").start()

    print("=" * 70)
    print(" SMB SIGNING POSTURE DEMONSTRATOR - loopback only, DO NOT DEPLOY")
    print(" (configuration oracle only - it authenticates nothing)")
    print("=" * 70)
    print(" Endpoint A  %s:%d  SecurityMode=0x%02x  -> signing REQUIRED (relay-safe)"
          % (ep_req.host, ep_req.port, MODE_REQUIRED))
    print(" Endpoint B  %s:%d  SecurityMode=0x%02x  -> signing NOT required (relay-susceptible)"
          % (ep_open.host, ep_open.port, MODE_NOT_REQUIRED))
    print("\n Point the auditor at both:")
    print("   python3 relay_auditor.py --targets %s:%d,%s:%d --checks smb"
          % (ep_req.host, ep_req.port, ep_open.host, ep_open.port))
    print("\n Ctrl-C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nShutting down.")
        ep_req.stop()
        ep_open.stop()


if __name__ == "__main__":
    main()
