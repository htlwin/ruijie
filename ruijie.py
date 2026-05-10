#!/usr/bin/env python3
"""
Ruijie WiFi Portal Tool
Connects to Ruijie captive portal, submits credentials,
extracts session, and keeps it alive via wifidog pings.
"""

import argparse
import logging
import re
import signal
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


def check_internet():
    try:
        return requests.get("http://www.google.com", timeout=3).status_code == 200
    except Exception:
        return False


def extract_form(html, form_id=None):
    form = {}
    if form_id:
        m = re.search(rf'<form[^>]*id=["\']{form_id}["\'][^>]*>', html, re.I)
    else:
        m = re.search(r'<form[^>]*>', html)
    if not m:
        m = re.search(r'<form[^>]*>', html)
    if not m:
        return form
    form_start = m.end()
    form_html = html[m.start():]
    end_m = re.search(r'</form>', form_html)
    if end_m:
        form_html = form_html[:end_m.end()]
    action_m = re.search(r'action=["\']([^"\']*)', form_html, re.I)
    if action_m:
        form["action"] = action_m.group(1).replace("&amp;", "&")
    method_m = re.search(r'method=["\']([^"\']*)', form_html, re.I)
    form["method"] = method_m.group(1).upper() if method_m else "GET"
    inputs = re.findall(
        r'<input[^>]*(?:name=["\']([^"\']*))[^>]*(?:value=["\']([^"\']*))[^>]*>',
        form_html, re.I
    )
    form["fields"] = {n: v for n, v in inputs}
    return form


def find_sid_in_html(html):
    m = re.search(r'sessionId["\s:=]+["\']?([a-zA-Z0-9_\-]+)["\']?', html)
    if m:
        return m.group(1)
    m = re.search(r'name=["\']sessionId["\'][^>]*value=["\']([^"\']*)', html)
    if m:
        return m.group(1)
    return None


def ping_wifidog(auth_link, sid, interval=0.1):
    while True:
        try:
            requests.get(auth_link, timeout=5)
        except Exception:
            break
        time.sleep(interval)


def run(ping_threads=5, ping_interval=0.1, access_code="123456"):
    log.info("Starting...")
    sess = requests.Session()

    while True:
        try:
            # 1. Detect captive portal
            r = requests.get("http://connectivitycheck.gstatic.com/generate_204",
                           allow_redirects=True, timeout=5)
            if r.url == "http://connectivitycheck.gstatic.com/generate_204":
                if check_internet():
                    time.sleep(5)
                    continue
                time.sleep(2)
                continue

            portal_url = r.url
            parsed = urlparse(portal_url)
            portal_host = f"{parsed.scheme}://{parsed.netloc}"
            log.info(f"[*] Portal: {portal_url}")

            # 2. Get portal page
            r1 = sess.get(portal_url, verify=False, timeout=10)
            html = r1.text

            # 3. Follow JS redirect if present
            m = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", html)
            if m:
                next_url = urljoin(portal_url, m.group(1))
                log.info(f"[*] Following redirect: {next_url}")
                r2 = sess.get(next_url, verify=False, timeout=10)
                html = r2.text
                parsed = urlparse(r2.url)

            # 4. Try to get SID from URL or HTML
            sid = parse_qs(parsed.query).get("sessionId", [None])[0]
            if not sid:
                sid = find_sid_in_html(html)

            # 5. Try voucher API regardless (some portals don't need SID)
            voucher_api = f"{portal_host}/api/auth/voucher/"
            try:
                payload = {"accessCode": access_code, "apiVersion": 1}
                if sid:
                    payload["sessionId"] = sid
                v = sess.post(voucher_api, json=payload, timeout=5)
                log.info(f"[*] Voucher API: {v.status_code}")
            except Exception as e:
                log.warning(f"[!] Voucher API: {e}")

            # 6. Extract gateway info
            params = parse_qs(parsed.query)
            gw_addr = params.get("gw_address", ["192.168.110.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]

            if not sid:
                sid = "test123"
                log.warning("[!] No SID found, using fallback")

            auth_link = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber=12345"
            log.info(f"[*] Gateway: {gw_addr}:{gw_port}")
            log.info(f"[*] SID: {sid}")
            log.info(f"[*] Starting {ping_threads} ping threads...")

            for _ in range(ping_threads):
                t = threading.Thread(
                    target=ping_wifidog,
                    args=(auth_link, sid, ping_interval),
                    daemon=True,
                )
                t.start()

            log.info("[+] Online! Watching (Ctrl+C to stop)")
            while check_internet():
                time.sleep(5)

            log.warning("[-] Disconnected, reconnecting...")

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
    parser.add_argument("-i", "--interval", type=float, default=0.1, help="Ping interval (s)")
    parser.add_argument("-c", "--code", type=str, default="123456", help="Access code")
    args = parser.parse_args()

    def sigint(sig, frame):
        log.info("Stopped")
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint)
    run(ping_threads=args.threads, ping_interval=args.interval, access_code=args.code)


if __name__ == "__main__":
    main()
