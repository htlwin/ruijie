#!/usr/bin/env python3
"""
Ruijie Portal Scanner - Run this on Termux to dump ALL portal info.
"""

import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except:
    HAS_CRYPTO = False

LOG = []
def log(m):
    print(m)
    LOG.append(m)

RENDER_KEY = hashlib.md5(b"RenderSecretKey2026!@#").digest()
sess = requests.Session()
sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
sess.verify = False

log("=" * 60)
log("RUIJIE PORTAL SCANNER")
log(f"Time: {datetime.now()}")
log("=" * 60)

# Step 1: Detect portal
log("\n[1] DETECTING PORTAL...")
try:
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", allow_redirects=True, timeout=10)
    log(f"  Status: {r.status_code}")
    log(f"  Final URL: {r.url}")
    if r.status_code == 204:
        log("  => Already online, no portal")
        # Still try to find portal
except Exception as e:
    log(f"  Error: {e}")

# Step 2: Portal redirect chain
log("\n[2] FOLLOWING REDIRECT CHAIN...")
current = r.url
visited = set()
for hop in range(10):
    if current in visited:
        break
    visited.add(current)
    try:
        rr = sess.get(current, timeout=10, verify=False)
        log(f"  Hop {hop}: {rr.status_code} -> {rr.url}")
        log(f"    Headers: {dict(rr.headers)}")
        html = rr.text
        current = str(rr.url)

        # Check for SID in URL
        sid = re.search(r'sessionId=([a-f0-9]{32})', current)
        if sid:
            log(f"  [SID FOUND in URL]: {sid.group(1)}")
        
        # Check for SID in HTML
        sid = re.search(r'sessionId["\\\']?\\s*[=:]\\s*["\\\']?([a-f0-9]{32})', html)
        if sid:
            log(f"  [SID FOUND in HTML]: {sid.group(1)}")

        # Meta refresh
        m = re.search(r'<meta[^>]+http-equiv=["\\\']?refresh["\\\']?[^>]+content=["\\\']?\\d+;?\\s*url=([^"\\\' >]+)', html, re.I)
        if m:
            next_url = m.group(1)
            log(f"  Meta refresh -> {next_url}")
            current = urllib.parse.urljoin(current, next_url)
            continue
        # JS redirect
        m = re.search(r"location\\.href\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]", html)
        if m:
            log(f"  JS redirect -> {m.group(1)}")
            current = urllib.parse.urljoin(current, m.group(1))
            continue
        break
    except Exception as e:
        log(f"  Hop {hop} error: {e}")
        break

final_url = str(rr.url)
final_html = rr.text

# Step 3: Dump all URL params
log("\n[3] URL PARAMETERS...")
parsed = urllib.parse.urlparse(final_url)
params = urllib.parse.parse_qs(parsed.query)
for k, v in params.items():
    log(f"  {k} = {v[0][:80]}")

# Step 4: Fetch RES resource
log("\n[4] FETCHING RES RESOURCE...")
res = params.get("RES", [None])[0]
if res:
    res_path = res.replace("./..", "/download/static/maccauth")
    res_url = urllib.parse.urljoin(final_url, res_path)
    log(f"  RES URL: {res_url}")
    try:
        rr = sess.get(res_url, timeout=10)
        log(f"  Status: {rr.status_code}")
        log(f"  Content-Type: {rr.headers.get('content-type','')}")
        log(f"  Content (first 1KB):\\n{rr.text[:1024]}")
        if len(rr.text) > 1024:
            log(f"  ... ({len(rr.text)} total bytes)")
    except Exception as e:
        log(f"  Error: {e}")

# Step 5: Dump page JS
log("\n[5] PAGE JAVASCRIPT...")
scripts = re.findall(r'<script[^>]*>([^<]+)</script>', final_html, re.I | re.S)
for i, js in enumerate(scripts):
    js = js.strip()
    if len(js) > 50:
        log(f"  Script {i}: {len(js)} chars")
        # Look for API URLs
        apis = re.findall(r'https?://[^"\\\' ]+', js)
        for a in apis:
            log(f"    API URL: {a}")
        # Look for function names
        funcs = re.findall(r'function\\s+(\\w+)', js)
        if funcs:
            log(f"    Functions: {funcs}")
        # Look for key strings
        keys = re.findall(r'[\"\\\']([A-Za-z0-9+/=]{20,})[\"\\\']', js)
        for k in keys:
            try:
                decoded = base64.b64decode(k).decode(errors='replace')
                if any(c.isprintable() for c in decoded):
                    log(f"    Base64: {decoded[:80]}")
            except:
                pass

# Step 6: Dump all forms
log("\n[6] FORMS IN PAGE...")
forms = re.findall(r'<form[^>]*>.*?</form>', final_html, re.I | re.S)
for i, form in enumerate(forms):
    log(f"  Form {i}: {form[:500]}")

# Step 7: Test voucher API
log("\n[7] VOUCHER API TESTS...")
host = f"{parsed.scheme}://{parsed.netloc}"
sid_val = params.get("sessionId", [""])[0]
log(f"  Host: {host}")
log(f"  SID: {sid_val}")

api_url = f"{host}/api/auth/voucher/?lang=en_US"

# Test 1: Plain JSON
log("\\n  Test 1: Plain JSON")
try:
    r = sess.post(api_url, json={"accessCode": "123456", "sessionId": sid_val, "apiVersion": 1}, timeout=5)
    log(f"    Status: {r.status_code}")
    log(f"    Response: {r.text[:300]}")
except Exception as e:
    log(f"    Error: {e}")

# Test 2: Encrypted JSON
if HAS_CRYPTO and sid_val:
    log("\\n  Test 2: Encrypted (AES-CBC, RenderSecretKey)")
    try:
        payload = json.dumps({"accessCode": "123456", "sessionId": sid_val, "apiVersion": 1})
        iv = os.urandom(16)
        cipher = AES.new(RENDER_KEY, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pad(payload.encode(), AES.block_size))
        enc = base64.urlsafe_b64encode(iv + ct).decode()
        r = sess.post(api_url, json={"data": enc}, timeout=5)
        log(f"    Status: {r.status_code}")
        log(f"    Response: {r.text[:300]}")
    except Exception as e:
        log(f"    Error: {e}")

# Test 3: Form data
log("\\n  Test 3: Form data")
try:
    r = sess.post(api_url, data={"accessCode": "123456", "sessionId": sid_val}, timeout=5)
    log(f"    Status: {r.status_code}")
    log(f"    Response: {r.text[:300]}")
except Exception as e:
    log(f"    Error: {e}")

# Step 8: Scan wifidog gateway
log("\n[8] WIFIDOG GATEWAY SCAN...")
gw_addr = params.get("gw_address", ["192.168.110.1"])[0]
gw_port = params.get("gw_port", ["2060"])[0]
log(f"  Gateway: {gw_addr}:{gw_port}")

endpoints = ["/wifidog/auth", "/wifidog/portal", "/wifidog/denied", "/wifidog/success",
             "/wifidog/prelogin", "/wifidog/login", "/wifidog/", "/"]
for ep in endpoints:
    try:
        url = f"http://{gw_addr}:{gw_port}{ep}?token={sid_val}"
        r = sess.get(url, timeout=5, allow_redirects=False)
        loc = r.headers.get("Location", "")[:100]
        log(f"  {ep}: {r.status_code} -> {loc}")
    except Exception as e:
        log(f"  {ep}: error {e}")

# Step 9: CHAP data
log("\n[9] CHAP DATA...")
chap_id = urllib.parse.unquote(params.get("chap_id", [""])[0])
chap_chal = urllib.parse.unquote(params.get("chap_challenge", [""])[0])
log(f"  chap_id: {chap_id}")
log(f"  chap_challenge: {chap_chal}")

if chap_chal:
    # Parse octal
    out = bytearray()
    i = 0
    while i < len(chap_chal):
        if chap_chal[i] == '\\\\' and i + 3 < len(chap_chal) and chap_chal[i+1:i+4].isdigit():
            out.append(int(chap_chal[i+1:i+4], 8))
            i += 4
        else:
            out.append(ord(chap_chal[i]))
            i += 1
    log(f"  challenge_hex: {bytes(out).hex()}")
    # Compute CHAP-MD5 for common passwords
    for pwd in ["123456", "000000", "guest", ""]:
        h = hashlib.md5(chap_id.encode() + pwd.encode() + bytes(out)).hexdigest()
        log(f"  chap_md5({pwd}): {h}")

# Step 10: Other API endpoints
log("\n[10] OTHER ENDPOINTS...")
endpoints = [
    f"{host}/user/online_info",
    f"{host}/username_get",
    f"{host}/api/auth/login/",
]
for ep in endpoints:
    try:
        r = sess.get(ep, timeout=5)
        log(f"  GET {ep}: {r.status_code} {r.text[:200]}")
    except Exception as e:
        log(f"  GET {ep}: {e}")

# Save to file
fname = f"portal_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(fname, "w") as f:
    f.write("\\n".join(LOG))
log(f"\\n[+] Saved to {fname}")
print(f"\\nSend this file: {fname}")
