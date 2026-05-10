#!/usr/bin/env python3
"""
Auth test v2 - fixed: don't follow redirects on logonUrl.
"""
import json, os, re, sys, time, urllib.parse, hashlib
import requests, urllib3
urllib3.disable_warnings()

sess = requests.Session()
sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
sess.verify = False

ACCESS_CODE = input("Enter access code: ").strip()
print(f"Code: {ACCESS_CODE[:4]}...{ACCESS_CODE[-4:]}")

# 1. Get sessionId
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
parsed = urllib.parse.urlparse(r.url)
params = urllib.parse.parse_qs(parsed.query)
host = f"{parsed.scheme}://{parsed.netloc}"

r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
print(f"sessionId: {sid}")

# 2. Voucher API
print("\nAuth...")
r = sess.post(f"{host}/api/auth/voucher/?lang=en_US", json={
    "accessCode": ACCESS_CODE, "sessionId": sid, "apiVersion": 1
}, timeout=10)
data = r.json()
print(f"  {data.get('message','')}")

if data.get("success") != True or data.get("result", {}).get("authResult") != "1":
    print(f"Auth failed: {data}")
    sys.exit(1)

logon_url = data["result"]["logonUrl"]
print(f"logonUrl: {logon_url}")

# 3. Hit gateway - DON'T follow redirects
print("Activating token...")
r = sess.get(logon_url, timeout=10, allow_redirects=False)
print(f"  Gateway: {r.status_code} -> {r.headers.get('Location','')[:100]}")

# Follow one more redirect manually if needed
if r.status_code in (301, 302, 303, 307, 308):
    loc = r.headers.get("Location", "")
    if "ruijienetworks.com" not in loc and "portal-as" not in loc:
        r = sess.get(loc, timeout=10, allow_redirects=False)
        print(f"  Follow: {r.status_code} -> {r.headers.get('Location','')[:100]}")

# 4. Keepalive ping
token = urllib.parse.parse_qs(urllib.parse.urlparse(logon_url).query).get("token", [""])[0]
gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
gw_port = params.get("gw_port", ["2060"])[0]
print(f"\nKeepalive pings (token={token[:16]}...)...")
for i in range(10):
    try:
        r = sess.get(f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token}",
                     timeout=5, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if "denied" in loc:
            print(f"  [{i+1}] DENIED - session lost")
            break
        print(f"  [{i+1}] OK")
    except Exception as e:
        print(f"  [{i+1}] error: {e}")
    time.sleep(3)

# 5. Internet check
print("\nInternet check...")
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=False)
if r.status_code == 204:
    print("*** ONLINE! ***")
elif r.status_code in (301, 302):
    print(f"Redirected -> {r.headers.get('Location','')[:80]}")
else:
    print(f"Status: {r.status_code}, URL: {r.url}")
