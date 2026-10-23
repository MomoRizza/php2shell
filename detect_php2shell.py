#!/usr/bin/env python3
"""
php2shell (CVE-2026-109618 / CVE-2026-109619) — SAFE version-based detection.

WHAT THIS DOES (and deliberately does NOT do):
  * It fingerprints the remote PHP *version* from ordinary HTTP response headers /
    error-page banners, then classifies it against the 2026-10-21 patch line.
  * It sends ONE normal HTTP GET — the same shape a browser sends. It emits NO
    multipart payload, NO memory-corruption trigger, nothing that touches the bug.
    It cannot and will not exploit, crash, or "confirm-by-triggering" anything.

This is the detection half of TC-file-upload-15. A PHP version in a vulnerable range
on an unpatched build is ITSELF the finding — you do not fire a blind memory-corruption
exploit to "prove" it (see teaching/cards/php2shell-oom-corruption-stale-state-rce.md).

SCOPE: only point --url at hosts listed in state/scope.md. --version is fully offline.

Patch line (first FIXED patch release per branch), 2026-10-21 14:00 UTC:
  8.2.35  /  8.3.36  /  8.4.27  /  8.5.12
Vulnerable binaries: 8.2.0-8.2.34 / 8.3.0-8.3.35 / 8.4.0-8.4.26 / 8.5.0-8.5.11
(7.4 / 8.0 / 8.1 affected only via source backport -> MANUAL review.)

Usage:
  ./detect_php2shell.py --version 8.3.12              # offline: classify a known version
  ./detect_php2shell.py --url https://target.example/ # live (in-scope) header fingerprint
  ./detect_php2shell.py --url https://target.example/ --path /index.php
"""
import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request

# (major, minor) -> first patched (non-vulnerable) patch number
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

VER_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)

TAG = {
    "VULNERABLE": "[VULN] ",
    "PATCHED": "[ ok ] ",
    "MANUAL": "[man. ] ",
    "UNKNOWN-BRANCH": "[ ?  ] ",
    "NO-VERSION": "[ ?  ] ",
}


def classify(major, minor, patch):
    key = (major, minor)
    if key in FIXED:
        return "VULNERABLE" if patch < FIXED[key] else "PATCHED"
    if (major, minor) < (8, 2):
        # 7.4/8.0/8.1: only custom source-backport builds are affected -> human decides
        return "MANUAL"
    return "UNKNOWN-BRANCH"  # 8.6+ or anything past the advisory: check the advisory


def note(cls):
    return {
        "VULNERABLE": "version is below its branch's fixed release -> FINDING (patch + restart SAPI)",
        "PATCHED": "at/above the fixed release for its branch",
        "MANUAL": "pre-8.2 branch: only source-backport builds affected; verify build provenance",
        "UNKNOWN-BRANCH": "branch not in the advisory table; re-check php.net advisory",
        "NO-VERSION": "no version leaked (expose_php=Off / banner stripped) -> try phpinfo, "
                      "error pages, or a non-version signal; absence is not safety",
    }[cls]


def fmt(ver_str, cls):
    return f"{TAG.get(cls, '[ ?  ] ')}PHP {ver_str:<10} {cls:<14} {note(cls)}"


def fingerprint(url, path):
    full = url.rstrip("/") + (path if path else "/")
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        full,
        method="GET",
        # neutral UA on purpose: do NOT match the php2shell scanner IoC strings
        headers={"User-Agent": "SecPilot/php-version-check (non-intrusive)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.read(4096).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:  # error pages leak versions too
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            body = (e.read(4096) or b"").decode("latin-1", "replace")
        except Exception:
            body = ""
    except Exception as e:
        return None, f"request failed: {e}"

    for label, src in (
        ("X-Powered-By", headers.get("x-powered-by", "")),
        ("Server", headers.get("server", "")),
        ("body", body),
    ):
        m = VER_RE.search(src or "")
        if m:
            return (label, tuple(int(x) for x in m.groups())), None
    return None, None  # reached host, no version leaked


def main():
    ap = argparse.ArgumentParser(description="php2shell SAFE version detector (no exploit).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--version", help="classify a known version string offline, e.g. 8.3.12")
    g.add_argument("--url", help="in-scope base URL to fingerprint (headers/error page only)")
    ap.add_argument("--path", default="/", help="path to request (default /)")
    args = ap.parse_args()

    if args.version:
        m = VER_RE.search("PHP/" + args.version.strip().lstrip("Pp/Hh"))
        if not m:
            m = re.search(r"(\d+)\.(\d+)\.(\d+)", args.version)
        if not m:
            print(f"could not parse version: {args.version!r}", file=sys.stderr)
            return 2
        maj, mino, pat = (int(x) for x in m.groups())
        cls = classify(maj, mino, pat)
        print(fmt(f"{maj}.{mino}.{pat}", cls))
        return 1 if cls == "VULNERABLE" else 0

    found, err = fingerprint(args.url, args.path)
    if err:
        print(f"[err  ] {err}", file=sys.stderr)
        return 2
    if not found:
        print(fmt("(unknown)", "NO-VERSION"))
        return 0
    label, (maj, mino, pat) = found
    cls = classify(maj, mino, pat)
    print(f"{fmt(f'{maj}.{mino}.{pat}', cls)}   (source: {label})")
    return 1 if cls == "VULNERABLE" else 0


if __name__ == "__main__":
    sys.exit(main())
