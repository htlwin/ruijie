#!/usr/bin/env python3
"""
Ruijie Scanner v3 - Follows full auth flow, checks portal pages.
"""
import hashlib, json, os, re, urllib.parse
from datetime import datetime
import requests, urllib3
urllib3.disable_warnings()

LOG = []
def log(m): print(m); LOG.append(m)

sess = requests.Session()
sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
sess.verify = False
sess.allow_redirects = True

log("=" * 60)
log(f"RUIJIE SCANNER v3  {datetime.now()}")
log("=" * 60)

# Step 1: Get portal URL
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", allow_redirects=False, timeout=10)
if r.status_code == 204:
    log("Already online.")
else:
    portal_url = r.headers.get("Location", "")
    log(f"Redirect to: {portal_url}")

# Actually follow all redirects
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
portal_url = r.url
log(f"Portal URL: {portal_url}")

parsed = urllib.parse.urlparse(portal_url)
params = urllib.parse.parse_qs(parsed.query)
host = f"{parsed.scheme}://{parsed.netloc}"

# Step 2: Parse CHAP
def parse_octal(s):
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == '\\' and i+3 < len(s) and s[i+1:i+4].isdigit():
            out.append(int(s[i+1:i+4], 8)); i += 4
        else:
            out.append(ord(s[i])); i += 1
    return bytes(out)

chap_id = parse_octal(params.get("chap_id", [""])[0])
chap_chal = parse_octal(params.get("chap_challenge", [""])[0])
log(f"chap_id: {chap_id.hex()}")
log(f"chap_chal: {chap_chal.hex()}")
chap_resp = hashlib.md5(chap_id + b"123456" + chap_chal).hexdigest()
log(f"chap_md5(123456): {chap_resp}")

gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
gw_port = params.get("gw_port", ["2060"])[0]
log(f"Gateway: {gw_addr}:{gw_port}")

# Step 3: Follow /api/auth/wifidog?stage=portal
log("\n[1] FETCHING /api/auth/wifidog?stage=portal...")
wifidog_url = f"{host}/api/auth/wifidog?stage=portal&" + parsed.query
log(f"URL: {wifidog_url[:150]}")
try:
    r = sess.get(wifidog_url, timeout=10)
    log(f"Status: {r.status_code}")
    log(f"Final URL: {r.url}")
    log(f"Body ({len(r.text)} bytes):")
    log(r.text[:2000])
except Exception as e:
    log(f"Error: {e}")

# Step 4: Check local gateway
log("\n[2] LOCAL GATEWAY 10.44.77.240:2060...")
for path in ["/user_status.html", "/", "/wifidog/auth"]:
    try:
        r = sess.get(f"http://10.44.77.240:2060{path}", timeout=5)
        log(f"  {path}: {r.status_code} ({len(r.text)} bytes)")
        log(f"  Body: {r.text[:500]}")
    except Exception as e:
        log(f"  {path}: {e}")

# Step 5: Gateway auth with chap_md5 token - follow redirects
log("\n[3] GATEWAY AUTH WITH CHAP TOKEN (follow redirects)...")
try:
    r = sess.get(f"http://{gw_addr}:{gw_port}/wifidog/auth?token={chap_resp}",
                 timeout=10, allow_redirects=True)
    log(f"Final URL: {r.url}")
    log(f"Status: {r.status_code}")
    log(f"Body ({len(r.text)} bytes): {r.text[:1000]}")
    # Check if "denied" in any redirect URL
    for rh in r.history:
        log(f"  Redirect: {rh.status_code} -> {rh.headers.get('Location','')[:200]}")
except Exception as e:
    log(f"Error: {e}")

# Step 6: Gateway auth with empty/invalid token - compare
log("\n[4] GATEWAY AUTH WITH INVALID TOKEN (for comparison)...")
try:
    r = sess.get(f"http://{gw_addr}:{gw_port}/wifidog/auth?token=INVALID",
                 timeout=10, allow_redirects=True)
    log(f"Final URL: {r.url}")
    log(f"Body ({len(r.text)} bytes): {r.text[:500]}")
    for rh in r.history:
        log(f"  Redirect: {rh.status_code} -> {rh.headers.get('Location','')[:200]}")
except Exception as e:
    log(f"Error: {e}")

# Step 7: Post CHAP-MD5 to login endpoint - follow redirects
log("\n[5] POST CHAP TO LOGIN (follow redirects)...")
data = {
    "gw_id": params.get("gw_id", [""])[0],
    "gw_address": gw_addr,
    "gw_port": gw_port,
    "mac": params.get("mac", [""])[0],
    "chap_id": params.get("chap_id", [""])[0],
    "chap_challenge": params.get("chap_challenge", [""])[0],
    "chap_password": chap_resp,
    "ip": params.get("ip", [""])[0],
}
try:
    r = sess.post(f"{host}/auth/wifidogAuth/login/", data=data, timeout=10, allow_redirects=True)
    log(f"Final URL: {r.url}")
    log(f"Body ({len(r.text)} bytes): {r.text[:1000]}")
    for rh in r.history:
        log(f"  Redirect: {rh.status_code} -> {rh.headers.get('Location','')[:200]}")
except Exception as e:
    log(f"Error: {e}")

# Save
fname = f"portal_scan3_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(fname, "w") as f:
    f.write("\n".join(LOG))
log(f"\n[+] Saved to {fname}")
