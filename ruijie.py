#!/usr/bin/env python3
"""
Ruijie WiFi Portal Auto-Login Tool
Reimplemented from reverse-engineered core.so.
Works on Kali Linux when connected to a Ruijie campus WiFi network.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import re
import sys
from pathlib import Path
from urllib.parse import unquote

import aiohttp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ruijie")

CONFIG_DIR = Path.home() / ".config" / "ruijie"
CONFIG_FILE = CONFIG_DIR / "config.json"
PORTAL_BASE = "https://portal-as.ruijienetworks.com"

BANNER = r"""
  _____  _    _ _____       _ _____ ______
 |  _  /| |  | | | |   _   | | | | |  __|
 |  __ \| |  | |_   _|     | |_   _|  ____|
 | | \ \| |__| |_| |_ | |__| |_| |_| |____
 | |__) | |  | | | |       | | | | | |__
 |_|  \_\____/|_____| \____/|_____|______|
"""


class Config:
    def __init__(self):
        self.data = {}
        self.load()

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, val):
        self.data[key] = val
        self.save()

    @property
    def portal_domain(self):
        return self.get("portal_domain", PORTAL_BASE)

    @portal_domain.setter
    def portal_domain(self, val):
        self.set("portal_domain", val)

    @property
    def voucher(self):
        return self.get("voucher", "")

    @voucher.setter
    def voucher(self, val):
        self.set("voucher", val)

    def load(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try:
                self.data = json.loads(CONFIG_FILE.read_text())
            except Exception:
                self.data = {}
        else:
            self.data = {}

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(self.data, indent=2))


def chap_md5(chap_id: str, password: str, challenge: str) -> str:
    mid = bytes.fromhex(chap_id) if re.match(r'^[0-9a-f]{2}$', chap_id, re.I) else chap_id.encode()
    ch = bytes.fromhex(challenge) if re.match(r'^[0-9a-f]{32}$', challenge, re.I) else challenge.encode()
    m = hashlib.md5()
    m.update(mid)
    m.update(password.encode())
    m.update(ch)
    return m.hexdigest().lower()


class PortalSession:
    def __init__(self):
        self.session_id = ""
        self.chap_id = ""
        self.chap_challenge = ""
        self.auth_url = ""
        self.logout_url = ""
        self.username = ""
        self.access_code = ""


async def fetch_portal(session: aiohttp.ClientSession, domain: str) -> PortalSession:
    ps = PortalSession()
    try:
        r = await session.get(domain, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15))
        html = await r.text()

        m = re.search(r'sessionId[=:][\s"\']*([a-zA-Z0-9]+)', html)
        ps.session_id = m.group(1) if m else ""

        m = re.search(r"chap_id=([^&]+)&chap_challenge=([^'>\s]+)", html)
        if m:
            ps.chap_id = unquote(m.group(1))
            ps.chap_challenge = unquote(m.group(2))

        m = re.search(r'action=["\']([^"\']+(?:login|auth)[^"\']*)', html, re.I)
        if m:
            ps.auth_url = m.group(1).replace("&amp;", "&")
        if not ps.auth_url:
            m = re.search(r'(https?://[^"\']*(?:login|auth)[^"\'\s]*)', html, re.I)
            ps.auth_url = m.group(1) if m else ""

        m = re.search(r'action=["\']([^"\']+logout[^"\']*)', html, re.I)
        if m:
            ps.logout_url = m.group(1).replace("&amp;", "&")
        if not ps.logout_url:
            m = re.search(r'(https?://[^"\']*logout[^"\'\s]*)', html, re.I)
            ps.logout_url = m.group(1) if m else ""

        m = re.search(r'accessCode[=:][\s"\']*([a-zA-Z0-9]+)', html)
        ps.access_code = m.group(1) if m else ""
    except Exception as e:
        log.error(f"Failed to fetch portal: {e}")
    return ps


async def authenticate(session: aiohttp.ClientSession, ps: PortalSession, password: str = "") -> bool:
    if not ps.auth_url:
        log.error("No auth URL found")
        return False
    chap_id = ps.chap_id or "01"
    challenge = ps.chap_challenge or ("00" * 16)
    pwd_hash = chap_md5(chap_id, password or "123456", challenge)
    log.info(f"CHAP id={chap_id} hash={pwd_hash[:16]}...")
    data = {
        "auth_type": "PAP",
        "username": ps.username or "guest",
        "password": pwd_hash,
        "sessionId": ps.session_id,
    }
    if ps.access_code:
        data["accessCode"] = ps.access_code
    try:
        r = await session.post(ps.auth_url, data=data, timeout=aiohttp.ClientTimeout(total=15))
        text = await r.text()
        log.info(f"Auth: {r.status} {text[:150]}")
        return r.status == 200 and ("success" in text.lower() or "ok" in text.lower())
    except Exception as e:
        log.error(f"Auth failed: {e}")
        return False


async def redeem_voucher(session: aiohttp.ClientSession, voucher: str) -> bool:
    url = f"{PORTAL_BASE}/api/auth/voucher/?lang=en_US"
    try:
        r = await session.post(url, json={"auth_type": "VOUCHER", "voucher_code": voucher},
                               timeout=aiohttp.ClientTimeout(total=15))
        if r.status == 200:
            result = await r.json()
            log.info(f"Voucher: {result}")
            return bool(result.get("success", False) or result.get("status") == "ok")
        log.warning(f"Voucher {r.status}: {(await r.text())[:200]}")
        return False
    except Exception as e:
        log.error(f"Voucher failed: {e}")
        return False


async def check_internet(session: aiohttp.ClientSession) -> bool:
    try:
        import ping3
        rtt = ping3.ping("google.com", timeout=3)
        if rtt is not None:
            return True
    except ImportError:
        pass
    try:
        r = await session.get("https://httpbin.org/get", timeout=aiohttp.ClientTimeout(total=5))
        return r.status == 200
    except Exception:
        return False


async def cmd_login(voucher: str, config: Config):
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    async with aiohttp.ClientSession(headers=headers) as session:
        log.info(f"Fetching portal: {config.portal_domain}")
        ps = await fetch_portal(session, config.portal_domain)
        log.info(f"Session: {ps.session_id or 'N/A'}")
        log.info(f"CHAP id={ps.chap_id or 'N/A'} challenge={(ps.chap_challenge or '')[:16]}...")
        if voucher:
            await redeem_voucher(session, voucher)
        else:
            await authenticate(session, ps, config.voucher)


async def cmd_monitor(interval: int, config: Config):
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    async with aiohttp.ClientSession(headers=headers) as session:
        log.info(f"Monitoring every {interval}s (Ctrl+C to stop)")
        try:
            while True:
                online = await check_internet(session)
                sym = "\033[1;32mONLINE\033[0m" if online else "\033[1;31mOFFLINE\033[0m"
                log.info(f"{sym}")
                if not online:
                    ps = await fetch_portal(session, config.portal_domain)
                    await authenticate(session, ps, config.voucher)
                await asyncio.sleep(interval)
        except (asyncio.CancelledError, KeyboardInterrupt):
            log.info("Monitor stopped")


async def cmd_status(config: Config):
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    async with aiohttp.ClientSession(headers=headers) as session:
        online = await check_internet(session)
        log.info(f"Internet: {'ONLINE' if online else 'OFFLINE'}")
        ps = await fetch_portal(session, config.portal_domain)
        log.info(f"Session: {ps.session_id or 'N/A'}")

        try:
            r = await session.get(f"{config.portal_domain}/username_get", timeout=aiohttp.ClientTimeout(total=10))
            uname = (await r.text()).strip() if r.status == 200 else "N/A"
        except Exception:
            uname = "N/A"
        log.info(f"Username: {uname}")

        try:
            r = await session.get(f"{config.portal_domain}/user/online_info", timeout=aiohttp.ClientTimeout(total=10))
            oinfo = await r.json() if r.status == 200 else "N/A"
        except Exception:
            oinfo = "N/A"
        log.info(f"Online info: {oinfo}")

        if config.voucher:
            log.info(f"Saved voucher: {config.voucher[:4]}****")


async def cmd_logout(config: Config):
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    async with aiohttp.ClientSession(headers=headers) as session:
        ps = await fetch_portal(session, config.portal_domain)
        url = ps.logout_url or f"{config.portal_domain}/logout"
        try:
            r = await session.get(url, timeout=aiohttp.ClientTimeout(total=10))
            log.info(f"Logged out" if r.status == 200 else "Logout failed")
        except Exception as e:
            log.error(f"Logout failed: {e}")


async def main_async():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Ruijie WiFi Portal Tool")
    parser.add_argument("action", nargs="?", default="status",
                        choices=["login", "monitor", "status", "logout", "set-domain"])
    parser.add_argument("value", nargs="?", default="", help="Voucher code or domain URL")
    parser.add_argument("-i", "--interval", type=int, default=30, help="Monitor interval (seconds)")
    args = parser.parse_args()

    config = Config()

    try:
        import uvloop
        uvloop.install()
    except ImportError:
        pass

    if args.action == "set-domain":
        config.portal_domain = args.value.rstrip("/")
        log.info(f"Portal domain set to: {config.portal_domain}")
    elif args.action == "login":
        await cmd_login(args.value, config)
    elif args.action == "monitor":
        await cmd_monitor(args.interval, config)
    elif args.action == "status":
        await cmd_status(config)
    elif args.action == "logout":
        await cmd_logout(config)
    else:
        parser.print_help()


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        log.info("Interrupted")


if __name__ == "__main__":
    main()
