# php2shell Detection and Defense Guide

Comprehensive detection, mitigation, and incident response guidance for
CVE-2026-109618 / CVE-2026-109619.

---

## 1. Version-Based Detection

The fastest and most reliable detection. If the PHP version is in a vulnerable
range and no vendor backport is applied, the system is vulnerable — no
behavioral test needed.

### Patch Line (2026-10-21)

| Branch | Vulnerable | First Fixed |
|--------|------------|-------------|
| 8.5 | 8.5.0 – 8.5.11 | 8.5.12 |
| 8.4 | 8.4.0 – 8.4.26 | 8.4.27 |
| 8.3 | 8.3.0 – 8.3.35 | 8.3.36 |
| 8.2 | 8.2.0 – 8.2.34 | 8.2.35 |
| 5.4 – 8.1 | All versions | EOL — no patch available |

### Where to Find the Version

| Source | Method |
|--------|--------|
| `X-Powered-By` header | `curl -sI target \| grep -i x-powered-by` |
| `Server` header | Sometimes includes `PHP/x.y.z` |
| `phpinfo()` page | `/info.php`, `/phpinfo.php`, `?debug=phpinfo` |
| Error pages | `display_errors=On` leaks version in stack traces |
| `PHPSESSID` cookie | Confirms PHP, doesn't reveal version |
| `.php` extensions | Confirms PHP routing |

### Automated Detection

```bash
# Offline (known version)
python3 detect_php2shell.py --version 8.3.12

# Live (fingerprint from headers)
python3 detect_php2shell.py --url https://target.example/

# When version is hidden (behavioral)
python3 detect_behavioral.py https://target.example/
```

---

## 2. Behavioral Detection Signals

### PHP Error Log Indicators

The strongest signal for active exploitation attempts:

```
# OOM BEFORE any application code ran
Fatal error: Allowed memory size of 8388608 bytes exhausted ... in Unknown on line 0
```

**Key:** "in Unknown on line 0" means OOM occurred in the PHP SAPI layer
(multipart parser / session handler), not in application code. Normal
application OOMs reference a specific file and line number.

### Web Server Log Indicators

```
# Apache error log — worker crashes
[core:notice] child pid XXXXX exit signal Segmentation fault (11)

# Repeated worker respawns in short succession
[mpm_prefork:notice] child XXXXX started
```

### Access Log Patterns

```
# Unusually large multipart POSTs to non-upload endpoints
POST /index.php HTTP/1.1  Content-Length: >6000000

# Rapid sequential POSTs from same IP (stage 0+1+2+3)
1.2.3.4 - - [timestamp] "POST /index.php" 500
1.2.3.4 - - [timestamp+1s] "POST /index.php" 200
1.2.3.4 - - [timestamp+2s] "POST /index.php" 500
1.2.3.4 - - [timestamp+3s] "POST /index.php" 200

# SFI chain: LFI inclusion of session file
GET /?page=/tmp/sess_hackertest01 HTTP/1.1
GET /index.php?page=/tmp/sess_XXXXXXXX HTTP/1.1
```

---

## 3. Network IoCs (Known Tooling Signatures)

### p2s.py (SFI chain)

| Indicator | Value |
|-----------|-------|
| User-Agent | `php2shell-scan/109618` |
| User-Agent | `php2shell-verify/1.0` |
| User-Agent | `Mozilla/5.0 (php2shell-poc)` |
| Multipart boundary | `------p2s9rdme2st6guc9g0drafic` |
| Upload filename | `p2s.txt` |
| Webshell body | `<?php echo 'PWNED::'; system($_GET['c']); ?>` |
| Session ID pattern | `hackertest01`, `p2s_` prefix |

### EDB-52704 (Heap UAF chain)

| Indicator | Value |
|-----------|-------|
| Session ID | `attacksessionid0001` |
| Multipart boundary | `SSSSSSSSSSSSSSSSSS` (17 S's) or `BBBBBBBBBB` (10 B's) |
| Field naming | `p0000`–`p1000`, `f0000`–`f1000`, `a00...` (long-name spray) |
| POST size | 12MB+ OOM payload |
| Request pattern | POST → 500 → POST → 200 (rotation + leak pairs) |

### General Signatures

| Pattern | Indicates |
|---------|-----------|
| `PHP_SESSION_UPLOAD_PROGRESS` in POST body | Trigger field (legitimate use exists but rare) |
| `PHPSESSID` cookie with binary/high-entropy value | Heap data in cookie (Stage 1/2 leak) |
| `PHPSESSID=\x00` (null byte) | Worker corruption attempt |
| Multiple large multipart POSTs with no file content | OOM shaping |

---

## 4. WAF / Reverse Proxy Rules

### ModSecurity / OWASP CRS

```apache
# Block oversized multipart POSTs to non-upload endpoints
# Adjust threshold and URI pattern for your application
SecRule REQUEST_METHOD "POST" \
  "id:109618001,\
   phase:1,\
   deny,\
   status:413,\
   chain,\
   msg:'php2shell: oversized multipart POST to non-upload endpoint'"
  SecRule REQUEST_HEADERS:Content-Type "multipart/form-data" \
    "chain"
  SecRule REQUEST_HEADERS:Content-Length "@gt 5000000" \
    "chain"
  SecRule REQUEST_URI "!@rx ^/(upload|api/upload|files)" ""

# Block known php2shell User-Agents
SecRule REQUEST_HEADERS:User-Agent "@rx php2shell" \
  "id:109618002,phase:1,deny,status:403,msg:'php2shell scanner detected'"

# Block known multipart boundaries
SecRule REQUEST_HEADERS:Content-Type "@rx boundary=(-{6}p2s|S{17}|B{10})" \
  "id:109618003,phase:1,deny,status:403,msg:'php2shell exploit boundary'"
```

### Nginx

```nginx
# Limit multipart body size (won't prevent the race variant)
client_max_body_size 2m;

# Block known User-Agents
if ($http_user_agent ~* "php2shell") {
    return 403;
}

# Rate-limit POSTs per IP
limit_req_zone $binary_remote_addr zone=post_limit:10m rate=10r/s;
location ~ \.php$ {
    limit_req zone=post_limit burst=20;
}
```

### Cloudflare / CDN

- WAF rule: block requests with `Content-Length > 5MB` and
  `Content-Type: multipart/form-data` to non-upload paths
- Rate limiting: cap POST requests per IP to non-upload endpoints
- Bot management: flag high-entropy `PHPSESSID` cookies

---

## 5. Mitigation

### Primary Fix: Patch PHP

Upgrade to the fixed version for your branch:

```bash
# Check current version
php -v

# Upgrade (Debian/Ubuntu)
apt update && apt install --only-upgrade php8.x-fpm php8.x-cli

# Restart the SAPI
systemctl restart php8.x-fpm   # or: apachectl restart
```

### Interim Stopgaps (NOT substitutes for patching)

| Mitigation | Effect | Limitation |
|------------|--------|-----------|
| `session.upload_progress.enabled = Off` | Disables the trigger surface | Breaks legitimate upload progress tracking; does NOT fix the underlying memory bug |
| `memory_limit = -1` (unlimited) | OOM never triggers | Dangerous: opens the server to memory exhaustion DoS |
| `session.use_strict_mode = On` | Rejects attacker-chosen session IDs | Only blocks session-ID control; does not prevent heap corruption |
| `expose_php = Off` | Hides version from headers | Security through obscurity; does not patch |
| Single-to-multi worker | Breaks heap UAF chain's same-worker requirement | Only mitigates EDB-52704; SFI chain unaffected |
| Restrict outbound connections | Limits reverse-shell/download payloads | Attacker can still write to webroot or use bind shells |

### For EOL PHP (5.4–8.1)

No official patch will be released. Options:
1. **Upgrade to a supported PHP branch** (recommended)
2. Disable `session.upload_progress.enabled` as permanent config
3. Deploy WAF rules from Section 4
4. Consider migration to a different runtime if upgrade is infeasible

---

## 6. Log Analysis Queries

### grep / awk (Apache/nginx access logs)

```bash
# Large multipart POSTs (>5MB)
awk '$6 ~ /POST/ && $10 > 5000000' access.log

# LFI attempts targeting session files
grep -E 'page=.*(/tmp/sess_|/var/lib/php/sessions/)' access.log

# Known tool signatures
grep -iE 'php2shell|attacksessionid' access.log

# Worker crashes (Apache error log)
grep -E 'Segmentation fault|exit signal' error.log | \
  awk '{print $1, $2, $3}' | sort | uniq -c | sort -rn
```

### ELK / Splunk

```
# Splunk — large multipart POSTs with worker crashes
index=web sourcetype=access_combined method=POST bytes>5000000
| stats count by src_ip, uri_path
| where count > 5

# Splunk — session file LFI
index=web uri_query="*sess_*" OR uri_query="*/tmp/*"

# ELK — PHP OOM in Unknown
message: "bytes exhausted" AND message: "in Unknown on line 0"
```

### SIEM Alert Rules

```yaml
# Alert: possible php2shell exploitation
name: php2shell_exploitation_attempt
condition:
  - event_type: http_request
  - method: POST
  - content_type: multipart/form-data
  - content_length: ">5000000"
  - followed_by:
    - event_type: process_crash
    - process_name: php-fpm|httpd|apache2
    - within: 5s
severity: critical
```

---

## 7. Incident Response

If you suspect active exploitation:

1. **Patch immediately** — even during an active incident, the patch stops
   further exploitation
2. **Check for webshells** — search the webroot and `/tmp/` for recently
   created PHP files:
   ```bash
   find /var/www -name "*.php" -newer /var/log/apache2/error.log
   find /tmp -name "sess_*" -exec grep -l "system\|exec\|passthru" {} \;
   ```
3. **Check for persistence** — crontabs, authorized_keys, new users
4. **Preserve logs** — Apache access/error logs, PHP-FPM logs, session files
5. **Check running processes** — look for shells spawned by www-data/apache
   ```bash
   ps auxf | grep -E 'www-data|apache' | grep -v php-fpm
   ```
6. **Network forensics** — check for outbound connections from the web user
