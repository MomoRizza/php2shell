#!/usr/bin/env python3
"""
php2shell behavioral assessment — collects signals, not proof of vulnerability.

Can collect heuristic signals when version banners and errors are hidden.
Uses 4-layer behavioral probing:
  1. PHP presence (heuristics)
  2. session.upload_progress feature detection
  3. Optional resource-stress response observations (not CVE-specific)
  4. Worker stability confirmation

The default runs layers 1-2, including small multipart POSTs. --deep explicitly
opts into oversized POSTs that can disrupt service. Network errors, 502 responses,
and recovery do not establish memory corruption, patch status, or either CVE.

Usage:
  python3 detect_behavioral.py https://target.example/
  python3 detect_behavioral.py https://target.example/ --deep      # full 4-layer
  python3 detect_behavioral.py https://target.example/ --quick     # layers 1-2 only
  python3 detect_behavioral.py -f targets.txt -o results.jsonl     # bulk
  python3 detect_behavioral.py https://target.example/ --proxy http://127.0.0.1:8080
"""

import argparse
import json
import os
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── version classification (same as detect_php2shell.py) ──────────────

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}


def classify_version(ver_str):
    """If we DO find a version, classify it."""
    import re
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
    if not m:
        return None, "parse_error"
    maj, mino, pat = int(m.group(1)), int(m.group(2)), int(m.group(3))
    key = (maj, mino)
    if key in FIXED:
        return (maj, mino, pat), "vulnerable" if pat < FIXED[key] else "patched"
    if key < (8, 2):
        return (maj, mino, pat), "eol_vulnerable"  # verify vendor backports separately
    return (maj, mino, pat), "unknown_branch"


# ── Layer 1: PHP presence ─────────────────────────────────────────────

def detect_php_presence(base_url, timeout=10, proxy=None):
    """Heuristic PHP detection without version headers."""
    signals = []
    opener = _build_opener(proxy)

    # Check main page headers
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": UA})
        resp = opener.open(req, timeout=timeout)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        body_snippet = resp.read(4096).decode("latin-1", "replace")

        # X-Powered-By (might still be there)
        xpb = hdrs.get("x-powered-by", "")
        if "php" in xpb.lower():
            signals.append(("x-powered-by", xpb, "strong"))

        # PHPSESSID cookie
        for cookie in hdrs.get("set-cookie", "").split(","):
            if "PHPSESSID" in cookie.upper():
                signals.append(("phpsessid_cookie", cookie.split(";")[0], "strong"))

        # Server header hints
        server = hdrs.get("server", "")
        if server:
            signals.append(("server", server, "info"))

        # PHP-specific response headers
        if "x-litespeed-cache" in hdrs:
            signals.append(("litespeed_cache", hdrs["x-litespeed-cache"], "moderate"))

        # HTML body signals
        if 'wp-content' in body_snippet or 'wp-includes' in body_snippet:
            signals.append(("wordpress", "detected", "strong"))
        if 'laravel' in body_snippet.lower() or 'csrf-token' in body_snippet:
            signals.append(("laravel_hint", "possible", "weak"))

    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        xpb = hdrs.get("x-powered-by", "")
        if "php" in xpb.lower():
            signals.append(("x-powered-by", xpb, "strong"))
    except Exception as e:
        signals.append(("error", str(e), "error"))

    # Probe common PHP paths
    import re
    php_path_hits = 0
    for path in ["/index.php", "/wp-login.php", "/info.php", "/phpinfo.php"]:
        try:
            req = urllib.request.Request(
                base_url.rstrip("/") + path,
                headers={"User-Agent": UA}
            )
            resp = opener.open(req, timeout=timeout)
            code = resp.getcode()
            if code in (200, 301, 302):
                php_path_hits += 1
                # wp-login.php is a strong WordPress/PHP signal
                strength = "strong" if "wp-login" in path and code == 200 else "moderate"
                signals.append(("php_path", f"{path} -> {code}", strength))
                # Check if info.php/phpinfo.php leaks version
                if path in ("/info.php", "/phpinfo.php") and code == 200:
                    body = resp.read(8192).decode("latin-1", "replace")
                    # Check <title> first (e.g. "PHP 8.1.34 - phpinfo()")
                    m = re.search(r"PHP (\d+\.\d+\.\d+)", body)
                    if not m:
                        m = re.search(r"PHP Version (\d+\.\d+\.\d+)", body)
                    if m:
                        signals.append(("phpinfo_version", m.group(1), "definitive"))
        except Exception:
            pass

    # Multiple .php paths responding = strong collective signal
    if php_path_hits >= 2 and not any(s[2] in ("strong", "definitive") for s in signals):
        signals.append(("php_multiple_paths", f"{php_path_hits} .php paths responded", "strong"))

    is_php = any(s[2] in ("strong", "definitive") for s in signals)
    version = next((s[1] for s in signals if s[0] == "phpinfo_version"), None)
    return is_php, signals, version


# ── Layer 2: session.upload_progress detection ────────────────────────

def detect_upload_progress(base_url, timeout=10, proxy=None):
    """
    Test if session.upload_progress is enabled.
    Sends a multipart POST with PHP_SESSION_UPLOAD_PROGRESS field.
    If enabled, PHP processes the callback and may set a session cookie
    even on endpoints that don't call session_start().
    """
    opener = _build_opener(proxy)
    host = base_url.rstrip("/")
    sid = "detectprobe" + secrets.token_hex(8)
    boundary = "----detectuploadprogress" + secrets.token_hex(4)

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"detectprobe\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="probe.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
        f"AAAA\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    results = {"enabled": None, "evidence": []}

    # Try against main page and a PHP endpoint
    for path in ["/", "/index.php"]:
        try:
            req = urllib.request.Request(
                host + path,
                data=body,
                headers={
                    "User-Agent": UA,
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Cookie": f"PHPSESSID={sid}",
                },
                method="POST",
            )
            resp = opener.open(req, timeout=timeout)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check if a session cookie was set/updated
            set_cookie = resp_headers.get("set-cookie", "")
            if "PHPSESSID" in set_cookie.upper():
                results["enabled"] = True
                results["evidence"].append(
                    f"POST {path} with PHP_SESSION_UPLOAD_PROGRESS -> Set-Cookie: PHPSESSID"
                )
                break

            # Even without cookie, a 200 on POST with this field = PHP processed it
            results["evidence"].append(f"POST {path} -> {resp.getcode()} (no session cookie)")

        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            set_cookie = resp_headers.get("set-cookie", "")
            if "PHPSESSID" in set_cookie.upper():
                results["enabled"] = True
                results["evidence"].append(
                    f"POST {path} -> {e.code} but Set-Cookie: PHPSESSID present"
                )
                break
            results["evidence"].append(f"POST {path} -> {e.code}")
        except Exception as e:
            results["evidence"].append(f"POST {path} -> error: {e}")

    if results["enabled"] is None:
        results["enabled"] = False  # couldn't confirm
    return results


# ── Layer 3: OOM behavioral differential ──────────────────────────────

def probe_oom_behavior(base_url, timeout=20, proxy=None):
    """
    Send a multipart POST with a body near memory_limit to observe the
    failure mode:
      - 502 / connection reset = nonspecific transport or upstream failure
      - 500 = nonspecific server error
      - 200/other = no diagnostic conclusion

    Tests at 8M, 16M, 32M (common memory_limit values).
    These probes may disrupt service; none of these observations proves a CVE.
    """
    results = {"oom_crash_detected": False, "probes": [], "verdict": "unknown"}

    for limit_label, size_bytes in [("8M", 9 * 1024 * 1024),
                                      ("16M", 17 * 1024 * 1024),
                                      ("32M", 33 * 1024 * 1024)]:
        probe = _send_oom_probe(base_url, size_bytes, limit_label, timeout, proxy)
        results["probes"].append(probe)

        if probe["crash_signal"]:
            results["oom_crash_detected"] = True
            results["verdict"] = "inconclusive_failure_signal"
            results["crash_at"] = limit_label
            break  # one crash is enough signal

    if not results["oom_crash_detected"]:
        # Could be: patched, memory_limit=-1, or not PHP
        results["verdict"] = "no_crash_observed"

    return results


def _send_oom_probe(base_url, body_size, label, timeout, proxy):
    """Send one oversized multipart POST and observe the response."""
    host = base_url.rstrip("/")
    boundary = "----oomprobe" + secrets.token_hex(4)
    sid = "oomprobe" + secrets.token_hex(8)

    # Build a multipart body with one large field
    header_part = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"probe\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="data"; filename="probe.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n"
        f"\r\n"
    ).encode()
    footer = f"\r\n--{boundary}--\r\n".encode()
    padding_size = max(0, body_size - len(header_part) - len(footer))
    body = header_part + (b"B" * padding_size) + footer

    result = {
        "limit_target": label,
        "body_size": len(body),
        "status_code": None,
        "crash_signal": False,
        "response_time_ms": None,
        "detail": "",
    }

    # Use raw socket for better crash detection (urllib hides connection resets)
    from urllib.parse import urlparse
    u = urlparse(host)
    use_tls = u.scheme == "https"
    h = u.hostname
    p = u.port or (443 if use_tls else 80)
    target_path = "/index.php"

    req_header = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: {h}\r\n"
        f"User-Agent: {UA}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    t0 = time.monotonic()
    try:
        sock = socket.create_connection((h, p), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=h)

        sock.sendall(req_header)
        # Send body in chunks to avoid send buffer issues
        chunk = 65536
        for off in range(0, len(body), chunk):
            sock.sendall(body[off:off + chunk])

        # Read response
        sock.settimeout(timeout)
        resp = b""
        while True:
            try:
                d = sock.recv(65536)
                if not d:
                    break
                resp += d
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                break
        sock.close()
        elapsed = int((time.monotonic() - t0) * 1000)
        result["response_time_ms"] = elapsed

        if resp:
            status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            try:
                code = int(status_line.split(" ", 2)[1])
                result["status_code"] = code
            except (IndexError, ValueError):
                result["status_code"] = None
                result["detail"] = f"unparseable: {status_line[:80]}"

            if result["status_code"] == 502:
                result["crash_signal"] = True
                result["detail"] = "502 Bad Gateway — nonspecific upstream failure"
            elif result["status_code"] == 500:
                result["detail"] = "500 — graceful error (may be patched OOM or app error)"
            elif result["status_code"] in (200, 301, 302):
                result["detail"] = f"{result['status_code']} — body below memory_limit or not PHP"
            else:
                result["detail"] = f"{result['status_code']}"
        else:
            result["crash_signal"] = True
            result["detail"] = "empty response — cause unknown"

    except ConnectionResetError:
        elapsed = int((time.monotonic() - t0) * 1000)
        result["response_time_ms"] = elapsed
        result["crash_signal"] = True
        result["detail"] = "ConnectionReset — cause unknown"
    except BrokenPipeError:
        elapsed = int((time.monotonic() - t0) * 1000)
        result["response_time_ms"] = elapsed
        result["crash_signal"] = True
        result["detail"] = "BrokenPipe — cause unknown"
    except socket.timeout:
        elapsed = int((time.monotonic() - t0) * 1000)
        result["response_time_ms"] = elapsed
        result["detail"] = f"timeout after {elapsed}ms"
    except Exception as e:
        result["detail"] = f"error: {e}"

    return result


# ── Layer 4: Worker stability confirmation ────────────────────────────

def confirm_worker_stability(base_url, timeout=10, proxy=None):
    """
    After an OOM probe that caused a crash, send 3 normal GETs.
    Successful requests show availability, not worker respawn or SAPI identity.
    If any return 502, the pool is under stress from our probes -> stop.
    """
    opener = _build_opener(proxy)
    results = []
    for i in range(3):
        try:
            req = urllib.request.Request(
                base_url,
                headers={"User-Agent": UA}
            )
            resp = opener.open(req, timeout=timeout)
            results.append(resp.getcode())
        except urllib.error.HTTPError as e:
            results.append(e.code)
        except Exception as e:
            results.append(f"error: {e}")
        time.sleep(0.5)
    return results


# ── Helpers ───────────────────────────────────────────────────────────

UA = "SecPilot/behavioral-detect (non-intrusive)"


def _build_opener(proxy=None):
    if proxy:
        handler = urllib.request.ProxyHandler({
            "http": proxy, "https": proxy
        })
        return urllib.request.build_opener(handler)
    return urllib.request.build_opener()


def _print_signals(signals):
    for name, value, strength in signals:
        icon = {"definitive": "★", "strong": "●", "moderate": "◐", "weak": "○",
                "info": "·", "error": "✗"}.get(strength, "?")
        print(f"    {icon} {name}: {value}")


# ── Main ──────────────────────────────────────────────────────────────

def scan_one(url, deep=False, proxy=None):
    result = {
        "url": url,
        "php_detected": False,
        "version": None,
        "version_status": None,
        "upload_progress": None,
        "oom_vulnerable": None,
        "failure_signal_observed": None,
        "verdict": "unknown",
        "signals": [],
    }

    # Layer 1
    print(f"\n{'='*60}")
    print(f"  Target: {url}")
    print(f"{'='*60}")
    print("\n[Layer 1] PHP presence detection")
    is_php, signals, version = detect_php_presence(url, proxy=proxy)
    result["php_detected"] = is_php
    result["signals"] = [(s[0], s[1]) for s in signals]
    _print_signals(signals)

    if version:
        result["version"] = version
        ver_tuple, status = classify_version(version)
        result["version_status"] = status
        print(f"\n    >>> PHP {version} — {status.upper()}")
        if status in ("vulnerable", "eol_vulnerable"):
            result["verdict"] = "AFFECTED_VERSION_REQUIRES_VERIFICATION"
            print("    >>> Version is in the upstream affected range; verify vendor backports and runtime provenance")
            if status == "eol_vulnerable":
                print("    >>> EOL branch: check vendor support and backports; upstream support has ended")
            if not deep:
                return result

    if not is_php:
        print("\n    PHP not detected — skipping deeper probes")
        result["verdict"] = "PHP_NOT_DETECTED_INCONCLUSIVE"
        return result

    # Layer 2
    print("\n[Layer 2] session.upload_progress feature detection")
    up_result = detect_upload_progress(url, proxy=proxy)
    result["upload_progress"] = up_result["enabled"]
    for ev in up_result["evidence"]:
        icon = "●" if up_result["enabled"] else "○"
        print(f"    {icon} {ev}")
    if up_result["enabled"]:
        print("    >>> Session cookie observed; upload_progress configuration remains unverified")
    else:
        print("    >>> upload_progress not confirmed (may be disabled or detection blocked)")

    if not deep:
        result["verdict"] = ("UPSTREAM_FIXED_VERSION" if result["version_status"] == "patched"
                             else "PHP_DETECTED_INCONCLUSIVE")
        return result

    # Layer 3
    print("\n[Layer 3] OOM worker-crash behavioral probe")
    print("    Sending oversized multipart POSTs to detect worker crash behavior...")
    oom_result = probe_oom_behavior(url, proxy=proxy)
    result["failure_signal_observed"] = oom_result["oom_crash_detected"]
    for probe in oom_result["probes"]:
        icon = "🔴" if probe["crash_signal"] else "⚪"
        t = f" ({probe['response_time_ms']}ms)" if probe["response_time_ms"] else ""
        print(f"    {icon} {probe['limit_target']}: {probe['detail']}{t}")
    if oom_result["oom_crash_detected"]:
        print(f"    >>> Failure signal at {oom_result.get('crash_at', '?')} — INCONCLUSIVE")
        print("    >>> Cannot distinguish worker failure from proxy, network, or application behavior")
    else:
        print(f"    >>> No crash observed")
        print(f"    >>> Could mean: patched, memory_limit=-1, body rejected by proxy/WAF, or not PHP")

    # Layer 4
    if oom_result["oom_crash_detected"]:
        print("\n[Layer 4] Worker stability confirmation")
        stability = confirm_worker_stability(url, proxy=proxy)
        print(f"    Follow-up GETs: {stability}")
        if all(s == 200 for s in stability):
            print("    >>> Follow-up requests succeeded; worker identity and recovery cause are unknown")
        elif any(s == 502 for s in stability if isinstance(s, int)):
            print("    >>> Some 502s on follow-up — pool may be stressed, stopping")

    # Final verdict
    if result["failure_signal_observed"]:
        result["verdict"] = "INCONCLUSIVE_FAILURE_SIGNAL"
    elif result.get("version_status") in ("vulnerable", "eol_vulnerable"):
        result["verdict"] = "AFFECTED_VERSION_REQUIRES_VERIFICATION"
    elif result.get("version_status") == "patched":
        result["verdict"] = "UPSTREAM_FIXED_VERSION"
    elif result["upload_progress"]:
        result["verdict"] = "SESSION_COOKIE_OBSERVED_INCONCLUSIVE"
    elif is_php:
        result["verdict"] = "PHP_DETECTED_INCONCLUSIVE"
    else:
        result["verdict"] = "PHP_NOT_DETECTED_INCONCLUSIVE"

    print(f"\n{'='*60}")
    print(f"  VERDICT: {result['verdict']}")
    if result["version"]:
        print(f"  PHP Version: {result['version']} ({result['version_status']})")
    print("  upload_progress: unverified (cookie heuristic only)")
    print(f"  Failure signal observed: {result['failure_signal_observed']}")
    print(f"{'='*60}\n")

    return result


def main():
    ap = argparse.ArgumentParser(
        description="php2shell behavioral assessment (heuristics, not CVE confirmation)."
    )
    ap.add_argument("url", nargs="?", help="Target URL")
    ap.add_argument("-f", "--file", help="File with URLs (one per line)")
    ap.add_argument("-o", "--output", help="Write JSON results to file")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--deep", action="store_true",
                      help="Opt into disruptive oversized POST probes (not CVE confirmation)")
    mode.add_argument("--quick", action="store_true",
                      help="Layers 1-2 only (default; includes small multipart POSTs)")
    ap.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    args = ap.parse_args()

    if not args.url and not args.file:
        ap.error("provide a URL or -f file")

    deep = args.deep
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    results = []
    vulns = 0
    for url in targets:
        r = scan_one(url, deep=deep, proxy=args.proxy)
        results.append(r)
        if r["verdict"] in {"AFFECTED_VERSION_REQUIRES_VERIFICATION"}:
            vulns += 1

    if args.output:
        with open(args.output, "w") as fh:
            for r in results:
                fh.write(json.dumps(r) + "\n")
        print(f"Results written to {args.output}")

    return 2 if vulns > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
