#!/usr/bin/env python3
"""
Ruijie WiFi Portal Auto-Login Tool (Kali Linux)
Reimplemented from reverse-engineered core.so (Nuitka Android binary).
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, unquote

import aiohttp
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ruijie")


CONFIG_DIR = Path.home() / ".config" / "ruijie"
CONFIG_FILE = CONFIG_DIR / "config.json"

RENDER_SECRET_KEY = b"RenderSecretKey2026!@#"
PORTAL_BASE = "https://portal-as.ruijienetworks.com"
VOUCHER_API = f"{PORTAL_BASE}/api/auth/voucher/?lang=en_US"
HTTPBIN_URL = "https://httpbin.org/get"

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
    def secret_code(self):
        return self.get("secret_code", "")

    @secret_code.setter
    def secret_code(self, val):
        self.set("secret_code", val)

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

    @property
    def success_codes(self):
        return self.get("success_codes", [])

    @success_codes.setter
    def success_codes(self, val):
        self.set("success_codes", val)

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


class Crypto:
    @staticmethod
    def aes_decrypt_b64(encrypted_b64: str, key: bytes = RENDER_SECRET_KEY) -> str:
        raw = base64.b64decode(encrypted_b64)
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        dec = unpad(cipher.decrypt(ct), AES.block_size)
        return dec.decode("utf-8", errors="replace")

    @staticmethod
    def chap_md5(chap_id: str, password: str, challenge: str) -> str:
        mid = bytes.fromhex(chap_id) if re.match(r'^[0-9a-f]{2}$', chap_id, re.I) else chap_id.encode()
        m = hashlib.md5()
        m.update(mid)
        m.update(password.encode())
        ch = bytes.fromhex(challenge) if re.match(r'^[0-9a-f]{32}$', challenge, re.I) else challenge.encode()
        m.update(ch)
        return m.hexdigest().lower()

    @staticmethod
    def b64e(data: bytes) -> str:
        return base64.b64encode(data).decode()

    @staticmethod
    def b64d(data: str) -> bytes:
        return base64.b64decode(data)


class PortalSession:
    def __init__(self):
        self.session_id = ""
        self.chap_id = ""
        self.chap_challenge = ""
        self.auth_url = ""
        self.logout_url = ""
        self.username = ""
        self.access_code = ""
        self.portal_url = ""


class RuijieClient:
    def __init__(self, config: Config):
        self.config = config
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = {
                "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def get(self, url, **kwargs):
        kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=15))
        s = await self._get_session()
        async with s.get(url, **kwargs) as r:
            return r

    async def post(self, url, **kwargs):
        kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=15))
        s = await self._get_session()
        async with s.post(url, **kwargs) as r:
            return r


class InternetChecker:
    def __init__(self, client: RuijieClient):
        self.client = client

    async def ping(self, host: str = "google.com") -> bool:
        try:
            import ping3
            rtt = ping3.ping(host, timeout=3)
            return rtt is not None
        except ImportError:
            pass
        try:
            r = await self.client.get(f"https://{host}")
            return r.status < 500
        except Exception:
            return False

    async def check_http(self) -> bool:
        try:
            r = await self.client.get(HTTPBIN_URL)
            return r.status == 200
        except Exception:
            return False

    async def is_online(self) -> bool:
        return await self.ping() or await self.check_http()


class PortalParser:
    @staticmethod
    def extract_session(html: str) -> str:
        m = re.search(r'sessionId[=:][\s"\']*([a-zA-Z0-9]+)', html)
        return m.group(1) if m else ""

    @staticmethod
    def extract_chap(html: str) -> tuple:
        m = re.search(r"chap_id=([^&]+)&chap_challenge=([^'>\s]+)", html)
        if m:
            return unquote(m.group(1)), unquote(m.group(2))
        return "", ""

    @staticmethod
    def extract_auth_url(html: str) -> str:
        m = re.search(r'action=["\']([^"\']+(?:login|auth)[^"\']*)', html, re.I)
        if m:
            return m.group(1).replace("&amp;", "&")
        m = re.search(r'(https?://[^"\']*(?:login|auth)[^"\'\s]*)', html, re.I)
        return m.group(1) if m else ""

    @staticmethod
    def extract_logout_url(html: str) -> str:
        m = re.search(r'action=["\']([^"\']+logout[^"\']*)', html, re.I)
        if m:
            return m.group(1).replace("&amp;", "&")
        m = re.search(r'(https?://[^"\']*logout[^"\'\s]*)', html, re.I)
        return m.group(1) if m else ""

    @staticmethod
    def extract_access_code(html: str) -> str:
        m = re.search(r'accessCode[=:][\s"\']*([a-zA-Z0-9]+)', html)
        return m.group(1) if m else ""

    @staticmethod
    def extract_portal_url(html: str) -> str:
        m = re.search(r'(https?://[^"\']*portal[^"\']*)', html, re.I)
        return m.group(1) if m else ""


class SetupService:
    def __init__(self, config: Config, client: RuijieClient):
        self.config = config
        self.client = client

    async def fetch_portal(self) -> PortalSession:
        ps = PortalSession()
        try:
            domain = self.config.portal_domain
            r = await self.client.get(domain, allow_redirects=True)
            html = await r.text()
            ps.session_id = PortalParser.extract_session(html)
            ps.chap_id, ps.chap_challenge = PortalParser.extract_chap(html)
            ps.auth_url = PortalParser.extract_auth_url(html)
            ps.logout_url = PortalParser.extract_logout_url(html)
            ps.access_code = PortalParser.extract_access_code(html)
            ps.portal_url = PortalParser.extract_portal_url(html)
            if not ps.portal_url:
                ps.portal_url = str(r.url)
        except Exception as e:
            log.error(f"Failed to fetch portal: {e}")
        return ps

    async def authenticate(self, ps: PortalSession, password: str = "") -> bool:
        if not ps.auth_url:
            log.error("No auth URL found")
            return False
        chap_id = ps.chap_id or "01"
        challenge = ps.chap_challenge or ("00" * 16)
        pwd_hash = Crypto.chap_md5(chap_id, password or "123456", challenge)
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
            r = await self.client.post(ps.auth_url, data=data)
            text = await r.text()
            log.info(f"Auth: {r.status} {text[:150]}")
            return r.status == 200 and ("success" in text.lower() or "ok" in text.lower())
        except Exception as e:
            log.error(f"Auth failed: {e}")
            return False

    async def get_online_info(self) -> dict:
        url = f"{self.config.portal_domain}/user/online_info"
        try:
            r = await self.client.get(url)
            return await r.json() if r.status == 200 else {}
        except Exception:
            return {}

    async def get_username(self) -> str:
        url = f"{self.config.portal_domain}/username_get"
        try:
            r = await self.client.get(url)
            return (await r.text()).strip() if r.status == 200 else ""
        except Exception:
            return ""

    async def logout(self, ps: PortalSession) -> bool:
        url = ps.logout_url or f"{self.config.portal_domain}/logout"
        try:
            r = await self.client.get(url)
            return r.status == 200
        except Exception:
            return False


class VoucherService:
    def __init__(self, config: Config, client: RuijieClient):
        self.config = config
        self.client = client

    async def redeem(self, code: str) -> bool:
        if not code:
            log.error("No voucher code")
            return False
        log.info(f"Redeeming voucher: {code[:4]}****")
        data = {"auth_type": "VOUCHER", "voucher_code": code}
        try:
            r = await self.client.post(VOUCHER_API, json=data)
            if r.status == 200:
                result = await r.json()
                log.info(f"Voucher: {result}")
                ok = result.get("success", False) or result.get("status") == "ok"
                if ok:
                    self.config.voucher = code
                    codes = self.config.success_codes
                    if code not in codes:
                        codes = codes + [code]
                        self.config.success_codes = codes
                    log.info("[+] Voucher accepted!")
                return bool(ok)
            log.warning(f"Voucher {r.status}: {(await r.text())[:200]}")
            return False
        except Exception as e:
            log.error(f"Voucher failed: {e}")
            return False


class BackgroundWatcher:
    def __init__(self, config: Config, client: RuijieClient, setup_svc: SetupService):
        self.config = config
        self.client = client
        self.setup = setup_svc
        self._running = False
        self._task = None

    async def watch(self, interval: int = 30):
        log.info(f"Watcher started (interval={interval}s)")
        ps = await self.setup.fetch_portal()
        while self._running:
            online_checker = InternetChecker(self.client)
            if not await online_checker.is_online():
                log.warning("Offline, re-authenticating...")
                ps = await self.setup.fetch_portal()
                await self.setup.authenticate(ps, self.config.voucher)
            else:
                log.debug("Online check OK")
            await asyncio.sleep(interval)

    def start(self, interval: int = 30):
        self._running = True
        self._task = asyncio.ensure_future(self.watch(interval))

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()


def decode_secret(code: str) -> str:
    try:
        dec = Crypto.aes_decrypt_b64(code)
        log.info(f"[+] Decoded: {dec[:100]}...")
        return dec
    except Exception as e:
        log.error(f"Decode failed: {e}")
        return ""


async def cmd_secret(code: str, config: Config):
    dec = decode_secret(code)
    if dec:
        config.secret_code = code
        m = re.search(r'https?://[^\s"\'<>]+', dec)
        if m:
            config.portal_domain = m.group(0).rstrip("/")
            log.info(f"Portal domain: {config.portal_domain}")


async def cmd_login(voucher: str, config: Config):
    client = RuijieClient(config)
    setup = SetupService(config, client)
    ps = await setup.fetch_portal()
    log.info(f"Session: {ps.session_id or 'N/A'}")
    log.info(f"CHAP id={ps.chap_id or 'N/A'} challenge={(ps.chap_challenge or '')[:16]}...")
    if voucher:
        vs = VoucherService(config, client)
        await vs.redeem(voucher)
    else:
        await setup.authenticate(ps, config.voucher)
    await client.close()


async def cmd_monitor(interval: int, config: Config):
    client = RuijieClient(config)
    setup = SetupService(config, client)
    checker = InternetChecker(client)
    log.info(f"Monitoring (Ctrl+C to stop)")
    try:
        while True:
            online = await checker.is_online()
            sym = "\033[1;32mONLINE\033[0m" if online else "\033[1;31mOFFLINE\033[0m"
            log.info(f"{sym}")
            if not online:
                ps = await setup.fetch_portal()
                await setup.authenticate(ps, config.voucher)
            await asyncio.sleep(interval)
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("Monitor stopped")
    finally:
        await client.close()


async def cmd_status(config: Config):
    client = RuijieClient(config)
    setup = SetupService(config, client)
    checker = InternetChecker(client)
    online = await checker.is_online()
    log.info(f"Internet: {'ONLINE' if online else 'OFFLINE'}")
    ps = await setup.fetch_portal()
    log.info(f"Session: {ps.session_id or 'N/A'}")
    uname = await setup.get_username()
    log.info(f"Username: {uname or 'N/A'}")
    info = await setup.get_online_info()
    log.info(f"Online info: {info if info else 'N/A'}")
    if config.voucher:
        log.info(f"Saved voucher: {config.voucher[:4]}****")
    await client.close()


async def cmd_logout(config: Config):
    client = RuijieClient(config)
    setup = SetupService(config, client)
    ps = await setup.fetch_portal()
    if await setup.logout(ps):
        log.info("Logged out")
    else:
        log.warning("Logout failed")
    await client.close()


async def main_async():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Ruijie WiFi Portal Tool")
    parser.add_argument("action", nargs="?", default="status",
                        choices=["secret", "login", "monitor", "status", "logout"])
    parser.add_argument("value", nargs="?", default="", help="Value (secret code or voucher)")
    parser.add_argument("-i", "--interval", type=int, default=30, help="Check interval (seconds)")
    args = parser.parse_args()

    config = Config()
    try:
        import uvloop
        uvloop.install()
    except ImportError:
        pass

    if args.action == "secret":
        await cmd_secret(args.value, config)
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
