#!/usr/bin/env python3
"""
Auth test with your valid access code. Run this on Termux.
"""
import json, os, re, sys, time, urllib.parse, hashlib
import requests, urllib3
urllib3.disable_warnings()

sess = requests.Session()
sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
sess.verify = False

# Your real access code
ACCESS_CODE = "YOUR_CODE_HERE"
if ACCESS_CODE == "YOUR_CODE_HERE":
    ACCESS_CODE = input("Enter access code: ").strip()

print("=" * 60)
print("RUIJIE AUTH TEST")
print(f"Code: {ACCESS_CODE[:4]}...{ACCESS_CODE[-4:]}")
print("=" * 60)

# 1. Get portal -> maccauth sessionId
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
parsed = urllib.parse.urlparse(r.url)
params = urllib.parse.parse_qs(parsed.query)
host = f"{parsed.scheme}://{parsed.netloc}"

r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
maccath_parsed = urllib.parse.urlparse(r.url)
maccath_params = urllib.parse.parse_qs(maccath_parsed.query)
sid = maccath_params.get("sessionId", [""])[0]
print(f"\n[1] sessionId: {sid}")

# 2. Call voucher API
print("\n[2] Calling voucher API...")
api_url = f"{host}/api/auth/voucher/?lang=en_US"
r = sess.post(api_url, json={
    "accessCode": ACCESS_CODE,
    "sessionId": sid,
    "apiVersion": 1
}, timeout=10)
print(f"  Status: {r.status_code}")
print(f"  Response: {r.text[:500]}")

data = r.json()
if data.get("success") == True and data.get("result", {}).get("authResult") == "1":
    logon_url = data["result"]["logonUrl"]
    print(f"\n  *** AUTH SUCCESS! ***")
    print(f"  logonUrl: {logon_url}")
    
    # 3. Follow logonUrl to gateway
    print(f"\n[3] Following logonUrl...")
    r = sess.get(logon_url, timeout=10, allow_redirects=True)
    print(f"  Final URL: {r.url}")
    print(f"  Status: {r.status_code}")
    print(f"  Body: {r.text[:300]}")
    
    gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
    gw_port = params.get("gw_port", ["2060"])[0]
    print(f"\n[4] Keepalive ping...")
    for i in range(5):
        try:
            # Extract token from logonUrl
            token = urllib.parse.parse_qs(urllib.parse.urlparse(logon_url).query).get("token", [""])[0]
            r = sess.get(f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token}",
                         timeout=5, allow_redirects=False)
            status = "OK" if r.status_code == 302 and "denied" not in r.headers.get("Location","") else "DENIED"
            print(f"  Ping {i+1}: {r.status_code} -> {status}")
        except Exception as e:
            print(f"  Ping {i+1}: error {e}")
        time.sleep(2)
    
    # 5. Test internet
    print(f"\n[5] Internet check...")
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
    print(f"  Status: {r.status_code}, URL: {r.url}")
    if r.status_code == 204:
        print("  *** ONLINE! ***")
    else:
        print("  Still on portal page")
else:
    print(f"\n  Auth failed: {data.get('message', 'unknown')}")
    print(f"  Full response: {r.text[:500]}")
