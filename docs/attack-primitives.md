# php2shell Attack Primitives

A catalog of every known attack primitive in the php2shell vulnerability
space. Each primitive is a self-contained building block; the exploit chains
(SFI, heap UAF, deserialization) compose them.

---

## 1. OOM via Non-File POST Fields (zend memory amplification)

**Used by:** p2s.py (Strategies A, C), Labs 1 & 3

Non-file multipart form fields are stored in `$_POST` as PHP zval strings,
which consume approximately **4× their raw size** in the Zend Memory Manager
(zval header + string header + alignment + hash table bucket).

| Fields | Field size | Raw data | Zend allocation | Effect at memory_limit=8M |
|--------|-----------|----------|-----------------|--------------------------|
| 30 | 200 KB | 6 MB | ~24 MB | OOM guaranteed |
| 15 | 400 KB | 6 MB | ~24 MB | OOM guaranteed |
| 60 | 100 KB | 6 MB | ~24 MB | OOM guaranteed |

**Key detail:** File upload content goes to disk (`/tmp/php...`), NOT zend
memory. Only non-file field *values* consume zend memory. This asymmetry is
the foundation of the OOM primitive.

```python
# Minimal OOM trigger
fields = [{"name": f"x{i}", "data": b"A" * 200_000} for i in range(30)]
fields.append({"name": "f", "filename": "a.txt", "data": b"X"})
# POST this as multipart/form-data → OOM
```

---

## 2. OOM via No-Filename File Metadata Allocation

**Used by:** EDB-52704 (all stages)

PHP allocates file metadata arrays (`$_FILES` entries) even when the file part
has no `filename` attribute and carries no data. A multipart POST with no
`Content-Length` header and a nested file part without a filename triggers
metadata allocation that can exhaust `memory_limit`.

Combined with 1001 short POST fields, this shapes the heap differently from
Primitive #1, enabling the heap disclosure primitives (Stages 1–2).

```python
# OffSec OOM shape (stage 1)
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
]
```

---

## 3. Session File Persistence (cleanup bypass)

**Used by:** p2s.py (all strategies), Labs 1–3

When `session.upload_progress.enabled=On` (the default), PHP writes upload
progress to the session file, including the **filename** from
`Content-Disposition` — verbatim, with no sanitization.

`session.upload_progress.cleanup=On` (also the default) deletes the progress
data when the upload completes. But if the worker OOMs or crashes before
cleanup runs, the session file persists at `/tmp/sess_<PHPSESSID>` with the
attacker's controlled content still inside.

**The attacker controls:**
1. Session ID → via `PHPSESSID` cookie → controls the file path
2. Filename → via `Content-Disposition: filename="..."` → controls the content
3. Progress name → via `PHP_SESSION_UPLOAD_PROGRESS` field → controls the key

**Session file content after poisoning:**
```
upload_progress_<name>|a:5:{s:4:"key";...s:8:"filename";s:N:"<?php system('id'); ?>";...}
```

---

## 4. Session-Based Heap Disclosure (ASLR Defeat)

**Used by:** EDB-52704 (Stages 1–2)

The session handler stores the current session ID in the process-global
`PS(id)`. When an OOM interrupts session initialization, `PS(id)` is left
pointing to **freed memory** (a dangling pointer).

On the next request in the **same worker process**, PHP reads `PS(id)` to
construct the `Set-Cookie: PHPSESSID=<value>` header. Since `PS(id)` points
to freed/reused heap memory, the raw heap bytes are URL-encoded into the
cookie value and sent back to the attacker.

**Two-stage leak:**

*Stage 1 — Zend MM chunk base:*
- Heap metadata contains pointers to other heap regions
- Scan decoded cookie for 8-byte LE values in `[0x7F0000000000, 0x800000000000)`
- Align to 2MB (`& ~0x1FFFFF`), take mode (most frequent), require ≥8 matches
- Result: Zend MM chunk base address

*Stage 2 — libphp base:*
- Different heap shape places a HashTable struct where `PS(id)` points
- The HashTable's `pDestructor` field holds `ZVAL_PTR_DTOR` (a libphp address)
- Cookie bytes 8–16 (little-endian) = `pDestructor` value
- Verify: low 12 bits match `DTOR_OFFSET & 0xFFF` (4KB alignment)
- Result: `libphp_base = pDestructor - DTOR_OFFSET`

**Requirements:** Same worker must handle both the corrupting and the leaking
request. Apache prefork with a single worker guarantees this.

---

## 5. Global State Poisoning via `fatal_error_backtraces`

**Used by:** CVE-2026-109619 exploitation path (OffSec article)

PHP's `fatal_error_backtraces` setting (default: **On**) causes the most
recent fatal error's backtrace to persist in process-global memory. An
attacker:

1. Sends a request that triggers OOM with controlled data in the call stack
2. The backtrace is recorded in global state
3. A diagnostic or error-handling path on the **next request** (same worker)
   operates on the attacker-controlled backtrace data

This is a variant of CVE-2026-109619's stale-global-state primitive: the
backing allocation is freed at request end, but the global pointer is not
cleared, creating a use-after-free that the next request hits.

**Mitigation:** `fatal_error_backtraces = Off` (breaks debug diagnostics).

---

## 6. Handler Mismatch Deserialization

**Used by:** p2s.py (Strategy implicit in Lab 3), Lab 3

PHP has two session serialization handlers with different semantics:

| Handler | Format | `\|` character |
|---------|--------|---------------|
| `php_serialize` | `serialize($_SESSION)` → `a:N:{...}` | Literal character in strings |
| `php` | `key\|serialized_value key2\|serialized_value2` | Key/value separator |

**The attack:**
1. Session is **written** by a page using `php_serialize` handler
2. Attacker sets `PHP_SESSION_UPLOAD_PROGRESS` to `|<serialized_gadget>`
3. The `|` is stored literally by `php_serialize`: `"upload_progress_|O:10..."`
4. A different page reads the session with the `php` handler
5. The `php` handler splits on `|` → everything after it goes to `unserialize()`
6. Attacker's serialized gadget object is instantiated
7. `__destruct()` or `__wakeup()` fires the gadget chain → RCE

**Requirements:**
- At least two pages using different session handlers (common in legacy +
  modern mixed apps)
- A gadget class with dangerous `__destruct()` / `__wakeup()` in scope
- PHP ≤ 7.4 (PHP 8.1+ destroys the session on handler mismatch)

**Critical pitfall:** Class name length in serialized form must be exact.
`LogRotator` = 10 chars → `O:10:"LogRotator"`. An off-by-one (`O:11:...`)
causes `unserialize()` to silently return `false` with zero error output.

---

## 7. Race Condition Window (slow-drip upload)

**Used by:** p2s.py (Strategy B), Lab 2

When `session.upload_progress.cleanup=On`, the session file is deleted when
the upload completes. By drip-feeding the file body byte-by-byte with delays
between chunks, the attacker extends the window during which the session file
exists with the malicious content.

**Mechanics:**
1. Send multipart headers + file-part header normally
2. Start the file body but send it very slowly (e.g., 4KB chunks, 50ms sleep)
3. While the upload is "in progress," the session file exists at
   `/tmp/sess_<PHPSESSID>` with the attacker's PHP code in the filename field
4. From a separate connection, rapidly request the LFI:
   `GET /?page=/tmp/sess_<PHPSESSID>`
5. Win the race before the upload completes and cleanup runs

**Advantages:** Works even when `memory_limit` is high (no OOM needed) and
`post_max_size` / nginx `client_max_body_size` are restrictive.

**Disadvantage:** Inherently probabilistic — multiple attempts required.
Threading or async I/O improves success rate.

---

## Primitive Composition Matrix

| Chain | Primitives Used |
|-------|----------------|
| **SFI + OOM + LFI** (p2s.py Strategy A) | #1 + #3 + LFI |
| **SFI + Race + LFI** (p2s.py Strategy B) | #7 + #3 + LFI |
| **SFI + Deser** (Lab 3) | #1 + #3 + #6 |
| **Heap UAF** (EDB-52704) | #2 + #4 + fake struct write |
| **Global State Poisoning** (CVE-2026-109619) | #2 + #5 |
