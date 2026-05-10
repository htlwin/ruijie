#!/usr/bin/env python3
"""
Ruijie WiFi Portal Bypass
Working flow: auth via voucher API with phone number, gateway keepalive.
"""

import json
import logging
import signal
import sys
import time
import urllib.parse

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


def check_online():
    try:
        r = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=3, allow_redirects=False)
        return r.status_code == 204
    except Exception:
        return False


def main():
    print(BANNER)
    code = input("Access code: ").strip()

    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    sess.verify = False

    while True:
        try:
            # 1. Portal redirect chain -> maccauth page
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
            parsed = urllib.parse.urlparse(r.url)
            params = urllib.parse.parse_qs(parsed.query)
            host = f"{parsed.scheme}://{parsed.netloc}"

            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
            log.info(f"SID: {sid}")

            # 2. Voucher API
            r = sess.post(f"{host}/api/auth/voucher/?lang=en_US", json={
                "accessCode": code,
                "sessionId": sid,
                "apiVersion": 1,
            }, timeout=10)
            data = r.json()
            log.info(f"Auth: {data.get('message', '')}")

            if data.get("success") == True and data.get("result", {}).get("authResult") == "1":
                logon_url = data["result"]["logonUrl"]
                log.info(f"logonUrl: {logon_url}")

                # 3. Activate token on gateway
                r = sess.get(logon_url, timeout=10, allow_redirects=False)
                log.info(f"Gateway: {r.status_code}")

            else:
                log.warning(f"Auth failed: {data}")
                time.sleep(5)
                continue

            # 4. Keepalive
            token = urllib.parse.parse_qs(urllib.parse.urlparse(logon_url).query).get("token", [""])[0]
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]
            ping_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token}"

            log.info(f"Keepalive - gateway {gw_addr}:{gw_port}")
            while True:
                try:
                    r = sess.get(ping_url, timeout=5, allow_redirects=False)
                    if "denied" in r.headers.get("Location", ""):
                        log.warning("Session denied, reconnecting...")
                        break
                except Exception:
                    break
                time.sleep(3)

            sess.close()
            time.sleep(3)

        except KeyboardInterrupt:
            log.info("Stopped")
            sys.exit(0)
        except Exception as e:
            log.warning(f"Error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
