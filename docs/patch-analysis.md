# php2shell Patch Analysis

Source-level analysis of the patches for CVE-2026-109618 and CVE-2026-109619,
based on the public PHP 8.3.35 → 8.3.36 diff. This documents what changed
and why, for defenders verifying their builds and researchers understanding
the fix.

---

## CVE-2026-109618: OOM Path Rewrite

### Root Cause

`_zend_hash_str_add_or_update_i()` (the internal function that inserts
string keys into PHP arrays) increments the array's internal counters
**before** the key string is fully initialized. If an OOM interrupts
initialization (via `longjmp`/`zend_bailout`), the key is left uninitialized
but still counted as valid. Later cleanup of `$_POST` follows a function
pointer table tagged by the uninitialized key → attacker-controlled code
execution.

### Patch Summary

**Core change: `Zend/zend_alloc.c`** (31 → 160 lines)

The OOM handling path was fundamentally rewritten:

1. **Removed `longjmp`-on-OOM.** The old `zend_mm_panic` / safe-error path
   used `longjmp()` to immediately abort execution on memory exhaustion. This
   is the root of the bug — `longjmp` skips C cleanup code (destructors,
   deferred frees, counter rollbacks).

2. **Added `EG(delayed_oom)` state machine.** OOM now sets a flag
   (`ZEND_OOM_STATE_HANDLING` and friends) instead of immediately bailing out.
   The flag is checked at the next VM safe point (between opcodes), where PHP
   can cleanly unwind.

3. **Added hard `_exit()` fallback.** If no VM safe point is reachable (e.g.,
   OOM in a C extension's internal loop), the process calls `_exit()` rather
   than `longjmp`. This kills the worker cleanly rather than leaving it in an
   inconsistent state.

4. **New `zend_set_memory_hard_limit_percent()` / `zend_mm_update_hard_limit()`.**
   A second, higher memory threshold (`hard_limit_percent`) gives the VM room
   to unwind after hitting `memory_limit` — the first OOM flag triggers at
   `memory_limit`, but actual allocation failure only happens at the hard
   limit.

**All allocator slow paths updated:** `zend_mm_alloc_pages`, `_small_slow`,
`_heap`, `_realloc_*`, `_huge` — every path that could previously `longjmp`
now sets the delayed flag instead.

### Trigger-Path Hardening

| File | Change |
|------|--------|
| `main/rfc1867.c` (`rfc1867_post_handler`) | ~20 hunks: the multipart POST parser now checks `EG(delayed_oom)` between field processing, does not proceed to write partially-parsed fields |
| `main/php_variables.c` | POST variable registration checks for pending OOM |
| `ext/session/session.c` (`php_session_rfc1867_callback`, `php_session_rfc1867_update`) | Upload progress callback checks OOM state before writing to session |

---

## CVE-2026-109619: Stale Global State Cleanup

### Root Cause

Request-owned internal state (e.g., the OOM error info, session handler
pointers) was stored in process-global variables (`EG()`, `PS()`) but
**not cleared at request shutdown**. After an OOM abort, the next request
on the same worker process found stale pointers to freed memory (UAF).

### Patch Summary

**Core change: `Zend/zend.c::zend_deactivate()`**

Added `zend_mm_oom_info_dtor(&EG(delayed_oom))` at request shutdown. This
explicitly destroys the OOM metadata, ensuring that its backing allocation
is no longer referenced by any global pointer when the next request begins.

**Additional changes:**

| File | Change |
|------|--------|
| `Zend/zend_errors.c` (`zend_error_zstr_at`) | Now gates error reporting on `EG(delayed_oom).state != ZEND_OOM_STATE_HANDLING` — prevents recursion into the error handler during OOM unwinding |
| `ext/session/session.c` (`php_rinit_session_globals`) | Session globals are now explicitly reinitialized at RINIT (request init), clearing any stale `PS(id)`, `PS(http_session_vars)`, etc. |

---

## Regression Tests

Three new `.phpt` tests prove the fixes:

| Test | CVE | What it verifies |
|------|-----|-----------------|
| `tests/basic/oom_rfc1867_upload_progress.phpt` | 109618 | OOM during upload progress does not leave exploitable state |
| `sapi/cli/tests/oom_request_parsing_next_request.phpt` | 109619 | Stale OOM state does not carry over to the next request |
| `sapi/cli/tests/oom_shutdown_function_next_request.phpt` | 109619 | Shutdown function OOM does not poison the next request |

---

## Verification

### Confirm Your Build is Patched

```bash
# Check version
php -v
# Must be >= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12

# Check for the delayed_oom symbol (confirms the new allocator)
nm $(php-config --extension-dir)/../libphp.so 2>/dev/null | grep delayed_oom
# Or for static builds:
strings $(which php) | grep -c "delayed_oom"

# Run the regression test (requires PHP source tree)
make test TESTS=tests/basic/oom_rfc1867_upload_progress.phpt
```

### Verify Mitigation is Active

```bash
# Check session.upload_progress.enabled
php -i | grep session.upload_progress.enabled
# "Off" = trigger surface disabled (interim mitigation)

# Check memory_limit
php -i | grep memory_limit
# Note: memory_limit=-1 prevents OOM but is NOT a real fix
```

---

## Timeline

| Date | Event |
|------|-------|
| 2026-08-24 | Reported to PHP security team |
| 2026-10-21 14:00 UTC | Patches released (8.2.35, 8.3.36, 8.4.27, 8.5.12) |
| 2026-10-21 | Public disclosure + vendor advisories |
| 2026-10-21 | GHSA-w8hw-w9fx-j79w (CVE-2026-109618) |
| 2026-10-21 | GHSA-6wmf-4rv5-p3rp (CVE-2026-109619) |

**Discovery credit:** Calif, OpenAI, and Wiz.
