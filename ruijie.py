#!/usr/bin/env python3
"""
Ruijie WiFi Portal Tool
Wifidog-based session keep-alive for Ruijie captive portals.
"""

import argparse
import logging
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


def check_internet():
    try:
        return requests.get("http://www.google.com", timeout=3).status_code == 200
    except Exception:
        return False


def ping_wifidog(auth_link, session, sid, interval=0.1):
    while True:
        try:
            session.get(auth_link, timeout=5)
            log.debug(f"Pinging SID: {sid}")
        except Exception:
            break
        time.sleep(interval)


def run(ping_threads=5, ping_interval=0.1, access_code="123456"):
    log.info("Starting Ruijie portal session keeper...")
    sess = requests.Session()

    while True:
        try:
            # 1. Detect portal via redirect
            r = requests.get("http://connectivitycheck.gstatic.com/generate_204",
                           allow_redirects=True, timeout=5)
            if r.url == "http://connectivitycheck.gstatic.com/generate_204":
                if check_internet():
                    time.sleep(5)
                    continue
                else:
                    time.sleep(2)
                    continue

            portal_url = r.url
            parsed = urlparse(portal_url)
            portal_host = f"{parsed.scheme}://{parsed.netloc}"
            log.info(f"[*] Portal: {portal_url}")

            # 2. Follow JS redirect (location.href)
            r1 = sess.get(portal_url, verify=False, timeout=10)
            m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", r1.text)
            next_url = urljoin(portal_url, m.group(1)) if m else portal_url
            r2 = sess.get(next_url, verify=False, timeout=10)

            # 3. Extract SID
            sid = parse_qs(urlparse(r2.url).query).get("sessionId", [None])[0]
            if not sid:
                m = re.search(r"sessionId=([a-zA-Z0-9]+)", r2.text)
                sid = m.group(1) if m else None

            if not sid:
                log.warning("[-] No SID found, retrying...")
                time.sleep(3)
                continue

            log.info(f"[+] SID: {sid}")

            # 4. Activate voucher API
            voucher_api = f"{portal_host}/api/auth/voucher/"
            try:
                v = sess.post(voucher_api, json={
                    "accessCode": access_code,
                    "sessionId": sid,
                    "apiVersion": 1,
                }, timeout=5)
                log.info(f"[*] Voucher API: {v.status_code}")
            except Exception as e:
                log.warning(f"[!] Voucher API failed: {e}")

            # 5. Get gateway info from portal URL params
            params = parse_qs(parsed.query)
            gw_addr = params.get("gw_address", ["192.168.60.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]
            auth_link = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber=12345"

            log.info(f"[*] Gateway: {gw_addr}:{gw_port}")
            log.info(f"[*] Starting {ping_threads} ping threads...")

            for _ in range(ping_threads):
                t = threading.Thread(
                    target=ping_wifidog,
                    args=(auth_link, sess, sid, ping_interval),
                    daemon=True,
                )
                t.start()

            # 6. Monitor internet
            log.info("[+] Online! Watching connection (Ctrl+C to stop)")
            while check_internet():
                time.sleep(5)

            log.warning("[-] Connection lost, reconnecting...")

        except KeyboardInterrupt:
            log.info("Stopped")
            break
        except Exception as e:
            log.debug(f"Error: {e}")
            time.sleep(5)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Ruijie WiFi Portal Tool")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Ping threads")
    parser.add_argument("-i", "--interval", type=float, default=0.1, help="Ping interval (seconds)")
    parser.add_argument("-c", "--code", type=str, default="123456", help="Access code")
    args = parser.parse_args()

    def sigint(sig, frame):
        log.info("Stopped")
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint)
    run(ping_threads=args.threads, ping_interval=args.interval, access_code=args.code)


if __name__ == "__main__":
    main()
