# ═══════════════════════════════════════════════════════════════════
#  KY-SHIRO API — iVAS SMS Platform (Per-User Auth + Proven iVAS Endpoints)
#  Developer : KY-SHIRO OFFICIAL
#  Telegram  : https://t.me/shiroky1
# ═══════════════════════════════════════════════════════════════════

from flask import (Flask, request, jsonify, Response, g,
                   render_template, redirect, url_for, session, abort, stream_with_context)
from datetime import datetime, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from bs4 import BeautifulSoup
import threading, time, re, os, json, hashlib, secrets, sqlite3
import logging, gzip, random, html as html_lib, requests as req_lib

# Socket.IO — untuk WebSocket iVAS real-time
try:
    import socketio as _sio_module
    _SOCKETIO_AVAILABLE = True
except ImportError:
    import types as _types_mod
    _sio_module = _types_mod.ModuleType("socketio")
    _sio_module.Client = object
    class _DummySioExc(Exception): pass
    _sio_module.exceptions = _types_mod.SimpleNamespace(ConnectionError=_DummySioExc)
    _SOCKETIO_AVAILABLE = False

try:
    import cloudscraper
    def _make_scraper():
        s = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False})
        s.headers.update({"Accept-Encoding": "gzip, deflate, br"})
        return s
except ImportError:
    def _make_scraper():
        s = req_lib.Session()
        _UA = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        ])
        s.headers.update({
            "User-Agent": _UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        })
        return s

try:
    import brotli as _brotli; _HAS_BROTLI = True
except ImportError:
    _HAS_BROTLI = False

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("kyshiro")

# ─── Flask ───────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("SECRET_KEY", "kyshiro-change-this-secret")

# ─── iVAS Constants ──────────────────────────────────────────────────
IVAS_BASE     = "https://www.ivasms.com"
IVAS_LOGIN    = f"{IVAS_BASE}/login"
IVAS_LIVE_MY  = f"{IVAS_BASE}/portal/live/my_sms"
IVAS_LIVE_TST = f"{IVAS_BASE}/portal/live/test_sms"
IVAS_RECV     = f"{IVAS_BASE}/portal/sms/received"
IVAS_WS       = "https://ivasms.com:2087"

# ═══════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════
DB_PATH = os.getenv("DB_PATH", "/tmp/kyshiro.db")

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS ky_users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT UNIQUE NOT NULL,
        nama        TEXT NOT NULL,
        email       TEXT UNIQUE NOT NULL,
        nomor_wa    TEXT NOT NULL,
        password    TEXT NOT NULL,
        role        TEXT DEFAULT 'user',
        api_key     TEXT UNIQUE,
        verified    INTEGER DEFAULT 0,
        otp_code    TEXT,
        otp_expires TEXT,
        otp_type    TEXT DEFAULT 'register',
        ivas_email  TEXT DEFAULT '',
        ivas_pass   TEXT DEFAULT '',
        ivas_status TEXT DEFAULT 'disconnected',
        ivas_login_at TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        last_login  TEXT,
        is_active   INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS ky_api_logs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        endpoint   TEXT,
        method     TEXT,
        ip         TEXT,
        status     INTEGER,
        created_at TEXT DEFAULT (datetime('now'))
    );
    """)
    if not c.execute("SELECT id FROM ky_users WHERE role='admin'").fetchone():
        akey = "ky-" + secrets.token_hex(24)
        ph   = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("""INSERT INTO ky_users
            (username,nama,email,nomor_wa,password,role,api_key,verified)
            VALUES (?,?,?,?,?,?,?,?)""",
            ("admin","KY-SHIRO Admin","admin@kyshiro.dev",
             "628000000000", ph, "admin", akey, 1))
        logger.info(f"[DB] Admin dibuat — API Key: {akey}")
    c.commit(); c.close()

init_db()

# ═══════════════════════════════════════════════════════════════════
# iVAS SESSION STORE  (per user, in-memory + DB status)
# ═══════════════════════════════════════════════════════════════════
_ivas_sessions: dict = {}   # user_id → session dict
_ivas_lock = threading.Lock()

# CSRF cache — hindari GET ke iVAS tiap request
_csrf_cache: dict = {}
_csrf_cache_lock  = threading.Lock()
_CSRF_CACHE_TTL   = 25  # detik

# WebSocket cache per user_id
_ws_live:   dict = {}   # user_id → deque(sms) dari /livesms namespace
_ws_test:   dict = {}   # user_id → deque(sms) dari test namespace
_ws_status: dict = {}   # user_id → {connected, live_connected, email, ...}
_ws_clients:dict = {}   # user_id → sio client (test)
_ws_live_clients: dict = {}  # user_id → sio client (livesms)
_ws_lock  = threading.Lock()
_ws_event: dict = {}  # user_id -> threading.Event, notify SSE saat ada SMS baru
_ws_enabled = True

# ─── CSRF Referer Map ─────────────────────────────────────────────
_CSRF_REFERER_MAP = {
    "/portal/numbers/test/export":              f"{IVAS_BASE}/portal/numbers/test",
    "/portal/numbers/termination/number/add":   f"{IVAS_BASE}/portal/numbers/test",
    "/portal/numbers/termination/details":      f"{IVAS_BASE}/portal/numbers/test",
    "/portal/numbers/return/number":            f"{IVAS_BASE}/portal/numbers",
    "/portal/numbers/return/number/bluck":      f"{IVAS_BASE}/portal/numbers",
    "/portal/numbers/return/allnumber/bluck":   f"{IVAS_BASE}/portal/numbers",
    "/portal/sms/received/getsms":              f"{IVAS_BASE}/portal/sms/received",
    "/portal/sms/received/getsms/number":       f"{IVAS_BASE}/portal/sms/received",
    "/portal/sms/received/getsms/getmessage":   f"{IVAS_BASE}/portal/sms/received",
}

# ─── Helpers ──────────────────────────────────────────────────────
def decode_resp(r):
    enc = r.headers.get("Content-Encoding","").lower()
    raw = r.content
    if enc == "br" and _HAS_BROTLI:
        try: return _brotli.decompress(raw).decode("utf-8","replace")
        except: pass
    if enc == "gzip":
        try: return gzip.decompress(raw).decode("utf-8","replace")
        except: pass
    try: return r.text
    except: return raw.decode("utf-8","replace")

def to_ivas_date(s):
    """DD/MM/YYYY → YYYY-MM-DD"""
    try:
        return datetime.strptime(s, "%d/%m/%Y").strftime("%Y-%m-%d")
    except: return s

def _is_expired(r):
    if r is None: return True
    url = getattr(r, "url", "") or ""
    if "/login" in url: return True
    try:
        t = r.text[:3000].lower()
        if any(k in t for k in ("forgot your password","login to your account")): return True
    except: pass
    return False

def _scrape_csrf_direct(scraper, page_url):
    """Scrape CSRF token langsung dari halaman iVAS."""
    try:
        r = scraper.get(page_url, headers={
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
            "Referer": IVAS_BASE,
        }, timeout=15, allow_redirects=True)
        if "/login" in r.url or r.status_code in (401, 403):
            return None
        html = decode_resp(r)
        soup = BeautifulSoup(html, "html.parser")
        meta = soup.find("meta", {"name": "csrf-token"})
        if meta and meta.get("content") and len(meta["content"]) > 10:
            return meta["content"]
        inp = soup.find("input", {"name": "_token"})
        if inp and inp.get("value") and len(inp["value"]) > 10:
            return inp["value"]
        for pat in [
            r"""['"]X-CSRF-TOKEN['"]\s*:\s*['"]([A-Za-z0-9_\-+/=]{20,})['"]""",
            r"""['"]_token['"][,:]?\s*['"]([A-Za-z0-9_\-+/=]{20,})['"]""",
        ]:
            m = re.search(pat, html, re.IGNORECASE)
            if m: return m.group(1)
    except Exception as e:
        logger.debug(f"[CSRF] Exception {page_url}: {e}")
    return None

def get_csrf_cached(scraper, page_url):
    """CSRF dari cache (TTL 25s), kalau miss → scrape fresh."""
    key = (id(scraper), page_url)
    now = time.time()
    with _csrf_cache_lock:
        cached = _csrf_cache.get(key)
        if cached:
            token, ts = cached
            if now - ts < _CSRF_CACHE_TTL:
                return token
            del _csrf_cache[key]
    token = _scrape_csrf_direct(scraper, page_url)
    if token:
        with _csrf_cache_lock:
            _csrf_cache[key] = (token, now)
    return token

# ─── Login iVAS per user ──────────────────────────────────────────
def ivas_login(user_id: int, ivas_email: str, ivas_pass: str) -> dict:
    """Login ke iVAS dengan kredensial user. Simpan session ke memory."""
    scraper = _make_scraper()
    try:
        pg   = scraper.get(IVAS_LOGIN, timeout=20)
        soup = BeautifulSoup(pg.text, "html.parser")
        tok_el = soup.find("input", {"name": "_token"})
        if not tok_el:
            return {"ok": False, "error": "Halaman login iVAS tidak bisa diakses"}
        tok = tok_el["value"]

        resp = scraper.post(IVAS_LOGIN,
            data={"email": ivas_email, "password": ivas_pass, "_token": tok},
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Referer": IVAS_LOGIN, "Origin": IVAS_BASE},
            allow_redirects=True, timeout=20)

        if "/login" in resp.url:
            return {"ok": False, "error": "Email atau password iVAS salah"}

        # ── Ambil CSRF dari halaman live ──
        portal = scraper.get(IVAS_LIVE_MY, timeout=15)
        html   = decode_resp(portal)
        psoup  = BeautifulSoup(html, "html.parser")
        meta   = psoup.find("meta", {"name": "csrf-token"})
        inp    = psoup.find("input", {"name": "_token"})
        csrf   = meta["content"] if meta else (inp["value"] if inp else tok)

        # ── Ambil recv_csrf khusus dari /portal/sms/received ──
        recv_csrf = csrf
        try:
            recv_pg   = scraper.get(IVAS_RECV, timeout=15)
            recv_html = decode_resp(recv_pg)
            recv_soup = BeautifulSoup(recv_html, "html.parser")
            recv_meta = recv_soup.find("meta", {"name": "csrf-token"})
            if recv_meta:
                recv_csrf = recv_meta["content"]
            else:
                recv_inp = recv_soup.find("input", {"name": "_token"})
                if recv_inp:
                    recv_csrf = recv_inp["value"]
                else:
                    mm = re.search(r"""['"]_token['"]\s*[,:]?\s*['"]([A-Za-z0-9_\-+/=]{20,})['"]""", recv_html)
                    if mm: recv_csrf = mm.group(1)
        except Exception as e:
            logger.warning(f"[iVAS] Gagal ambil recv_csrf: {e}")

        # ── Ambil JWT + user_hash + livesms_event dari halaman live ──
        jwt_tok       = ""
        user_hash     = ""
        livesms_event = ""
        try:
            xsrf = scraper.cookies.get("XSRF-TOKEN","")
            from urllib.parse import unquote
            jwt_tok = unquote(xsrf) if xsrf and xsrf.startswith("eyJ") else scraper.cookies.get("laravel_session","")
            uh_m = re.search(r'''[,{\s]\s*user\s*:\s*["']([a-f0-9]{32})["']''', html)
            if uh_m: user_hash = uh_m.group(1)
            ev_m = re.search(r'liveSMSSocket\.on\s*\(\s*["\']([A-Za-z0-9+/=_\-]{30,})["\']\s*,', html)
            if ev_m:
                livesms_event = ev_m.group(1)
                # Try from livesms block if not found
            if not livesms_event:
                block = re.search(r'liveSMSSocket\s*=\s*io\([^)]+\)([\s\S]{0,2000})', html)
                if block:
                    ev_m2 = re.search(r'\.on\s*\(\s*["\']([A-Za-z0-9+/=_\-]{30,})["\']\s*,', block.group(1))
                    if ev_m2: livesms_event = ev_m2.group(1)
        except Exception as e:
            logger.warning(f"[iVAS] JWT/hash extract error: {e}")

        result = {
            "ok":            True,
            "user_id":       user_id,
            "ivas_email":    ivas_email,
            "scraper":       scraper,
            "csrf":          csrf,
            "recv_csrf":     recv_csrf,
            "jwt_tok":       jwt_tok,
            "user_hash":     user_hash,
            "livesms_event": livesms_event,
            "live_html":     html,
            "login_at":      datetime.now().isoformat(),
            "status":        "connected",
        }
        with _ivas_lock:
            _ivas_sessions[user_id] = result

        # Update DB status
        c = db()
        c.execute("UPDATE ky_users SET ivas_status='connected',ivas_login_at=? WHERE id=?",
                  (result["login_at"], user_id))
        c.commit(); c.close()

        logger.info(f"[iVAS] ✅ User {user_id} login sebagai {ivas_email} — "
                    f"recv_csrf={'✅' if recv_csrf!=csrf else '⚠️same'}, "
                    f"jwt={'✅' if jwt_tok else '❌'}, user_hash={'✅' if user_hash else '❌'}")
        return result

    except Exception as e:
        logger.error(f"[iVAS] User {user_id} login error: {e}")
        return {"ok": False, "error": str(e)}

def get_ivas_session(user_id: int, force=False) -> dict | None:
    with _ivas_lock:
        sess = _ivas_sessions.get(user_id)
    if sess and sess.get("ok") and not force:
        return sess
    return None

def do_ivas(user_id, method, url, data=None, headers=None):
    """Request ke iVAS dengan CSRF rotating fix. Auto re-login kalau expired."""
    data  = dict(data) if data else {}
    for attempt in range(2):
        sess = get_ivas_session(user_id, force=(attempt > 0))
        if not sess:
            # Auto re-login
            c2 = db()
            u  = c2.execute("SELECT ivas_email,ivas_pass FROM ky_users WHERE id=?",(user_id,)).fetchone()
            c2.close()
            if u and u["ivas_email"]:
                new_s = ivas_login(user_id, u["ivas_email"], u["ivas_pass"])
                if new_s.get("ok"):
                    sess = new_s
                else:
                    return None, "Login iVAS gagal"
            else:
                return None, "Belum ada kredensial iVAS"

        scraper = sess["scraper"]

        # ── Rotating CSRF fix: ambil CSRF dari halaman sumber ──
        if method.upper() != "GET":
            url_path = url.replace(IVAS_BASE, "")
            csrf_page = None
            for ep_path, src_page in _CSRF_REFERER_MAP.items():
                if ep_path in url_path:
                    csrf_page = src_page
                    break
            if not csrf_page and headers:
                ref = headers.get("Referer","")
                if ref.startswith(IVAS_BASE): csrf_page = ref

            if csrf_page:
                fresh = get_csrf_cached(scraper, csrf_page)
                csrf  = fresh if fresh else (
                    sess.get("recv_csrf") if "/portal/sms/received" in url else sess["csrf"])
            else:
                csrf = sess.get("recv_csrf") if "/portal/sms/received" in url else sess["csrf"]
            data["_token"] = csrf
        else:
            data["_token"] = sess["csrf"]

        try:
            kw = dict(headers=headers, timeout=25, allow_redirects=True)
            if method.upper() == "POST":
                r = scraper.post(url, data=data, **kw)
            else:
                r = scraper.get(url, params=data, **kw)

            if _is_expired(r):
                logger.warning(f"[iVAS-REQ] Session expired user={user_id} attempt {attempt+1}, re-login...")
                with _ivas_lock:
                    _ivas_sessions.pop(user_id, None)
                continue
            return r, None
        except Exception as e:
            logger.error(f"[iVAS-REQ] user={user_id} attempt={attempt}: {e}")
    return None, "Request gagal"

# ─── Helper: clean iVAS HTML ─────────────────────────────────────
def _clean_html(raw):
    s = html_lib.unescape(html_lib.unescape(str(raw)))
    s = re.sub(r'<script[\s\S]*?</script>', '', s, flags=re.IGNORECASE)
    s = re.sub(r'<style[\s\S]*?</style>',  '', s, flags=re.IGNORECASE)
    s = re.sub(r'<[^>]+>', '', s)
    s = re.sub(r'[ \t]+', ' ', s)
    return s.strip()

def _clean_sid(raw):
    s = _clean_html(raw)
    for line in s.split('\n'):
        line = line.strip()
        if line: return line
    return s.strip()

def ajax_hdrs(referer=None):
    return {
        "Accept":           "text/html, */*; q=0.01",
        "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin":           IVAS_BASE,
        "Referer":          referer or IVAS_RECV,
    }

# ─── iVAS: Ranges ────────────────────────────────────────────────
def ivas_get_ranges(user_id, from_date, to_date):
    """Level 1 — POST /portal/sms/received/getsms → list range."""
    result = []
    def _add(name, rid):
        name = name.strip(); rid = (rid or name.replace(" ","_")).strip()
        if name and not any(r["name"]==name for r in result):
            result.append({"name": name, "id": rid})
    def _parse(html):
        for m in re.finditer(r"toggleRange\s*\(\s*'([^']+)'\s*,\s*'([^']+)'\s*\)", html):
            _add(m.group(1), m.group(2))
        if not result:
            for m in re.finditer(r'toggleRange\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', html):
                _add(m.group(1), m.group(2))
        if not result:
            soup = BeautifulSoup(html, "html.parser")
            for div in soup.select("div.rng"):
                oc = div.get("onclick","")
                m  = re.search(r"toggleRange[^(]*\(\s*'([^']+)'\s*,\s*'([^']+)'", oc)
                if m: _add(m.group(1), m.group(2))
    fd = to_ivas_date(from_date); td = to_ivas_date(to_date)
    for payload in [{"from": fd, "to": td}, {"from": from_date, "to": to_date}]:
        r, _ = do_ivas(user_id, "POST",
            f"{IVAS_BASE}/portal/sms/received/getsms",
            data=payload, headers=ajax_hdrs(IVAS_RECV))
        if r and r.status_code == 200:
            _parse(decode_resp(r))
            if result: break
    return result

# ─── iVAS: Numbers per range ─────────────────────────────────────
def ivas_get_numbers(user_id, range_name, from_date, to_date, range_id=None):
    """Level 2 — POST /portal/sms/received/getsms/number → list nomor."""
    rid = range_id or range_name.replace(" ","_")
    def _parse(html):
        nums = []
        def _add(num, nid=""):
            d = re.sub(r'\D','',str(num))
            if 7 <= len(d) <= 15 and not any(n["number"]==d for n in nums):
                nums.append({"number": d, "num_id": nid or d})
        # FIX: regex \w* bukan \w+ — handle toggleNum(), toggleNumABC(), dll
        for m in re.finditer(r"toggleNum\w*\s*\(\s*'(\d{7,15})'\s*,\s*'([^']+)'\s*\)", html):
            _add(m.group(1), m.group(2))
        if not nums:
            for m in re.finditer(r'toggleNum\w*\s*\(\s*"(\d{7,15})"\s*,\s*"([^"]+)"\s*\)', html):
                _add(m.group(1), m.group(2))
        if not nums:
            soup = BeautifulSoup(html, "html.parser")
            for el in soup.select("span.nnum"):
                raw = re.sub(r'\D','', el.get_text(strip=True))
                if raw: _add(raw)
        return nums
    fd = to_ivas_date(from_date); td = to_ivas_date(to_date)
    # 3 attempt: range=NAMA, range=ID, range_name=NAMA
    for payload in [
        {"start": fd, "end": td, "range": range_name},
        {"start": fd, "end": td, "range": rid},
        {"start": fd, "end": td, "range_name": range_name},
    ]:
        r, _ = do_ivas(user_id, "POST",
            f"{IVAS_BASE}/portal/sms/received/getsms/number",
            data=payload, headers=ajax_hdrs(IVAS_RECV))
        if r and r.status_code == 200:
            nums = _parse(decode_resp(r))
            if nums:
                logger.info(f"[NUMS] user={user_id} range='{range_name}' → {len(nums)} nomor")
                return nums
    return []

# ─── iVAS: SMS per nomor ─────────────────────────────────────────
def ivas_get_sms(user_id, phone, range_name, from_date, to_date):
    """Level 3 — POST /portal/sms/received/getsms/number/sms → list SMS."""
    rid = range_name.replace(" ","_")
    fd  = to_ivas_date(from_date); td = to_ivas_date(to_date)
    # Confirmed payload format: Number+Range kapital
    payloads = [
        {"start": fd, "end": td, "Number": phone, "Range": range_name},
        {"start": fd, "end": td, "Number": phone, "Range": rid},
        {"start": fd, "end": td, "number": phone, "range": range_name},
    ]
    messages = []
    def _add(t):
        t = html_lib.unescape(str(t)).strip()
        if len(t) > 3 and t not in messages:
            messages.append(t)
    for payload in payloads:
        r, _ = do_ivas(user_id, "POST",
            f"{IVAS_BASE}/portal/sms/received/getsms/number/sms",
            data=payload, headers=ajax_hdrs(IVAS_RECV))
        if not r or r.status_code != 200: continue
        raw = decode_resp(r)
        # FIX: Skip spinner/error response
        if "spinner-border" in raw and len(raw) < 500: continue
        if "Something went wrong" in raw and len(raw) < 500: continue
        soup = BeautifulSoup(raw, "html.parser")
        for el in soup.select("div.msg-text,td.msg-text,p.msg-text,span.msg-text"):
            _add(el.get_text(separator="\n", strip=True))
        if not messages:
            for tbl in soup.find_all("table"):
                ths = [th.get_text(strip=True).lower() for th in tbl.find_all("th")]
                col = next((i for i,h in enumerate(ths)
                            if any(k in h for k in ("message","content","sms","text"))), None)
                if col is None: continue
                for tr in tbl.select("tbody tr"):
                    tds = tr.find_all("td")
                    if len(tds) > col:
                        inn = tds[col].select_one("div.msg-text,.msg-text")
                        t   = inn.get_text(separator="\n",strip=True) if inn \
                              else tds[col].get_text(separator="\n",strip=True)
                        if t and not t.isdigit(): _add(t)
        if messages:
            logger.info(f"[SMS] user={user_id} {phone}@{range_name} → {len(messages)} SMS")
            break
    return messages

# ─── iVAS: DataTables (Test Numbers + My Numbers) ────────────────
def _fetch_datatables(user_id, base_url, search="", length=100,
                      col_data=None, col_name=None, fallback_fields=None):
    """Fetch DataTables JSON dari iVAS. Return (rows, recordsTotal)."""
    sess = get_ivas_session(user_id)
    if not sess: return [], 0
    if col_data is None:
        col_data = ["range", "test_number"]
        col_name = ["terminations.range", "terminations.test_number"]
    if fallback_fields is None:
        fallback_fields = ["range","test_number","term","A2P","Limit_Range",
                           "limit_did_a2p","limit_cli_did_a2p","created_at","action"]
    col_qs = "".join(
        f"&columns[{i}][data]={d}&columns[{i}][name]={n}"
        for i,(d,n) in enumerate(zip(col_data, col_name))
    )
    qs = (f"draw=1{col_qs}"
          "&order[0][column]=0&order[0][dir]=asc"
          f"&start=0&length={length}"
          f"&search[value]={search}&search[regex]=false")
    hdrs = {
        "Accept":           "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer":          base_url,
    }
    scraper = sess["scraper"]
    try:
        resp = scraper.get(f"{base_url}?{qs}", headers=hdrs, timeout=20)
        if _is_expired(resp):
            with _ivas_lock: _ivas_sessions.pop(user_id, None)
            return [], 0
        data  = resp.json()
        rows  = data.get("data", [])
        total = data.get("recordsTotal", len(rows))
        if rows and isinstance(rows[0], list):
            rows = [dict(zip(fallback_fields, r)) for r in rows]
        return rows, total
    except Exception as e:
        logger.error(f"[DT] user={user_id} {base_url}: {e}")
        return [], 0

def _fetch_my_numbers(user_id, search="", length=100):
    """Fetch My Numbers dari /portal/numbers."""
    col_data = ["Number","range","A2P","LimitA2P","limit_did_a2p","limit_cli_a2p","number_id","action"]
    col_name = col_data[:]
    fallback = col_data[:]
    return _fetch_datatables(user_id, f"{IVAS_BASE}/portal/numbers",
        search=search, length=length,
        col_data=col_data, col_name=col_name, fallback_fields=fallback)

def _get_number_id(row):
    """Ambil termination ID dari row DataTables."""
    nid = str(row.get("number_id","") or "")
    m = re.search(r'value=["\']?(\d+)["\']?', nid)
    if m: return m.group(1)
    if nid.strip().isdigit(): return nid.strip()
    action = str(row.get("action","") or "")
    for pat in [
        r'data-id=["\']?(\d+)["\']?',
        r'TerminationDetials\s*\(\s*["\']?(\d+)["\']?\s*\)',
        r'ReturnNumberToSystem\s*\(\s*["\']?(\d+)["\']?\s*\)',
    ]:
        m = re.search(pat, action)
        if m: return m.group(1)
    for key in ("id","DT_RowId"):
        v = str(row.get(key,"")).strip()
        if v and v.isdigit(): return v
    return ""

def _parse_ivas_resp(resp):
    if resp is None: return False, "No response", ""
    raw = decode_resp(resp)
    try:
        jr      = resp.json()
        message = str(jr.get("message", jr.get("msg", jr.get("error", str(jr)))))
        st      = jr.get("status", jr.get("success",""))
        success = str(st).lower() in ("success","ok","true","1") or st is True or st == 1
        if not success:
            ml = message.lower()
            success = any(k in ml for k in ("berhasil","success","returned","added","deleted","good job","done"))
        return success, message, raw
    except:
        raw_low = raw.lower()
        if any(k in raw_low for k in ("berhasil","success","added","returned","deleted","good job")):
            return True, "OK", raw
        return resp.status_code in (200,201), f"HTTP {resp.status_code}", raw

# ─── iVAS: Add Number ────────────────────────────────────────────
def ivas_add_number(user_id, termination_id):
    r, err = do_ivas(user_id, "POST",
        f"{IVAS_BASE}/portal/numbers/termination/number/add",
        data={"id": termination_id},
        headers={
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{IVAS_BASE}/portal/numbers/test",
            "Origin": IVAS_BASE,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        })
    if not r: return False, err
    ok, msg, _ = _parse_ivas_resp(r)
    return ok, msg

# ─── iVAS: Delete Number ─────────────────────────────────────────
def ivas_delete_number(user_id, termination_id):
    for path in [
        "/portal/numbers/termination/number/delete",
        "/portal/numbers/termination/details",
        "/portal/numbers/return/number",
    ]:
        r, _ = do_ivas(user_id, "POST", f"{IVAS_BASE}{path}",
            data={"id": termination_id},
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{IVAS_BASE}/portal/numbers",
                "Origin": IVAS_BASE,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            })
        if not r: continue
        ok, msg, _ = _parse_ivas_resp(r)
        if ok: return True, msg
    return False, "Delete gagal"

# ─── iVAS: Scrape public/test SMS dari XHR ───────────────────────
def _ivas_scrape_public(user_id, limit=100, sid_filter="", rng_filter=""):
    """Scrape /portal/sms/test/sms via DataTables XHR — fallback kalau WS tidak tersedia."""
    PUBLIC_URL = f"{IVAS_BASE}/portal/sms/test/sms"
    sess = get_ivas_session(user_id)
    if not sess: return []
    qs = (
        "draw=1&columns[0][data]=0&columns[0][name]=0"
        "&columns[1][data]=1&columns[1][name]=1"
        "&columns[2][data]=2&columns[2][name]=2"
        "&columns[3][data]=3&columns[3][name]=3"
        "&columns[4][data]=4&columns[4][name]=4"
        "&order[0][column]=0&order[0][dir]=desc"
        f"&start=0&length={limit}&search[value]=&search[regex]=false"
    )
    hdrs = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": PUBLIC_URL,
    }
    items = []
    try:
        scraper = sess["scraper"]
        resp    = scraper.get(f"{PUBLIC_URL}?{qs}", headers=hdrs, timeout=20)
        if not resp or resp.status_code != 200: return []
        rows = resp.json().get("data",[])
        for row in rows:
            if isinstance(row, dict):
                raw_sid = str(row.get("originator",""))
                term    = row.get("termination",{})
                raw_num = str(term.get("test_number","")) if isinstance(term,dict) else ""
                if not raw_num: raw_num = str(row.get("termination_id",""))
                msg = _clean_html(str(row.get("messagedata","")))
                rcv = str(row.get("senttime",""))
                rng = _clean_sid(str(row.get("range","")))
            elif isinstance(row, list) and len(row) >= 4:
                raw_sid = str(row[2]); raw_num = str(row[1])
                msg = _clean_html(str(row[3]))
                rcv = str(row[4]) if len(row) > 4 else ""
                rng = _clean_sid(str(row[0]))
            else: continue
            sid = _clean_sid(raw_sid); num = _clean_sid(raw_num)
            if not any([rng, num, sid, msg]): continue
            if sid_filter and sid_filter not in sid.lower() and sid_filter not in msg.lower(): continue
            if rng_filter and rng_filter not in rng.lower(): continue
            items.append({
                "range": rng, "number": num, "originator": sid, "sid": sid,
                "message": msg, "received_at": rcv, "source": "scrape_xhr_test",
            })
    except Exception as e:
        logger.warning(f"[PUBLIC] user={user_id}: {e}")
    return items

# ─── iVAS: Scrape live/getNumbers ────────────────────────────────
def ivas_live_get_numbers(user_id, termination_id):
    """POST /portal/live/getNumbers → list nomor dalam range (dari halaman Live My SMS)."""
    sess = get_ivas_session(user_id)
    if not sess: return None, "Belum login iVAS"
    scraper = sess["scraper"]
    csrf    = get_csrf_cached(scraper, IVAS_LIVE_MY) or sess["csrf"]
    try:
        r = scraper.post(
            f"{IVAS_BASE}/portal/live/getNumbers",
            data={"_token": csrf, "termination_id": termination_id},
            headers={
                "Accept":           "application/json, text/javascript, */*; q=0.01",
                "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Origin":           IVAS_BASE,
                "Referer":          IVAS_LIVE_MY,
            },
            timeout=20)
        body = decode_resp(r)
        try:
            data = r.json()
        except:
            data = json.loads(body)
        if isinstance(data, list): numbers = data
        elif isinstance(data, dict): numbers = data.get("data", data.get("numbers", [data]))
        else: numbers = []
        return numbers, None
    except Exception as e:
        return None, str(e)

# ═══════════════════════════════════════════════════════════════════
# WEBSOCKET — iVAS Socket.IO Live SMS  (per user_id)
# ═══════════════════════════════════════════════════════════════════
#
# iVAS pakai Socket.IO v4 (EIO=4) di port 2087
# URL test  : wss://ivasms.com:2087  (namespace default)
# URL live  : wss://ivasms.com:2087/livesms (My SMS)
# Auth      : JWT token + user hash dari halaman portal
# Events:
#   - send_message_test       → Test SMS (publik)
#   - send_message_live       → Live My SMS
#   - <dynamic_eyJpdi...>     → My SMS (encrypted event name)
#   - send_message_max_Limit  → SMS over limit
#
_WS_SMS_MAX  = 500
_WS_LIVE_MAX = 500

def _ws_set_status(user_id, **kwargs):
    with _ws_lock:
        if user_id not in _ws_status:
            _ws_status[user_id] = {}
        _ws_status[user_id].update(kwargs)

def _ws_add_test(user_id, data):
    """Tambah SMS ke cache test namespace."""
    entry = {
        "originator":  str(data.get("cli", data.get("originator",""))).replace("+",""),
        "number":      str(data.get("test_number", data.get("number",""))),
        "sid":         _clean_sid(str(data.get("originator", data.get("sid","")))),
        "range":       str(data.get("termination_id", data.get("range",""))),
        "message":     _clean_html(str(data.get("message",""))),
        "paid":        "Paid" if float(data.get("client_revenue",0) or 0) > 0 else "Unpaid",
        "source":      "websocket_test",
        "received_at": datetime.now().isoformat(),
    }
    with _ws_lock:
        if user_id not in _ws_test:
            _ws_test[user_id] = deque(maxlen=_WS_SMS_MAX)
        _ws_test[user_id].appendleft(entry)
    # Signal SSE test stream
    ev = _ws_event.get(user_id)
    if ev: ev.set()
    with _ws_lock:
        st = _ws_status.get(user_id, {})
        _ws_status[user_id] = st
        _ws_status[user_id]["test_sms_count"] = _ws_status[user_id].get("test_sms_count", 0) + 1

def _ws_add_live(user_id, data, source="websocket_live"):
    """Tambah SMS ke cache livesms namespace (My SMS)."""
    orig = str(data.get("originator", data.get("cli",""))).replace("+","")
    recp = str(data.get("recipient", data.get("number","")))
    entry = {
        "originator":  orig or recp,
        "recipient":   recp,
        "number":      recp or orig,
        "sid":         _clean_sid(str(data.get("originator",""))),
        "message":     _clean_html(str(data.get("message",""))),
        "range":       str(data.get("range", data.get("termination_id",""))),
        "sid_raw":     str(data.get("sid","")),
        "paid":        "Paid" if float(data.get("client_revenue",0) or 0) > 0 else "Unpaid",
        "in_limit":    str(data.get("limit",1)) == "1",
        "source":      source,
        "received_at": datetime.now().isoformat(),
    }
    with _ws_lock:
        if user_id not in _ws_live:
            _ws_live[user_id] = deque(maxlen=_WS_LIVE_MAX)
        _ws_live[user_id].appendleft(entry)
    # Signal SSE stream — wakeup instant, no sleep
    ev = _ws_event.get(user_id)
    if ev: ev.set()
    with _ws_lock:
        if user_id not in _ws_status: _ws_status[user_id] = {}
        _ws_status[user_id]["live_sms_count"] = _ws_status[user_id].get("live_sms_count", 0) + 1

def _build_test_ws_client(user_id, jwt_token):
    """Buat Socket.IO client untuk test namespace."""
    if not _SOCKETIO_AVAILABLE: return None
    try:
        sio = _sio_module.Client(reconnection=False, logger=False, engineio_logger=False)

        @sio.event
        def connect():
            _ws_set_status(user_id, connected=True, ts=datetime.now().isoformat())
            logger.info(f"[WS-TEST] ✅ user={user_id} connected")

        @sio.event
        def disconnect():
            _ws_set_status(user_id, connected=False)
            logger.info(f"[WS-TEST] user={user_id} disconnected")

        @sio.event
        def connect_error(data):
            _ws_set_status(user_id, connected=False, error=str(data))

        @sio.on("send_message_test")
        def on_test(data): _ws_add_test(user_id, data)

        @sio.on("send_message_live")
        def on_live(data): _ws_add_live(user_id, data, "ws_test_ns_live")

        @sio.on("send_message_max_Limit_231177")
        def on_limit(data): _ws_add_test(user_id, data)

        @sio.on("*")
        def on_any(ev, data):
            known = {"connect","disconnect","connect_error",
                     "send_message_test","send_message_live","send_message_max_Limit_231177"}
            if ev not in known and isinstance(data, dict):
                if "message" in data or "originator" in data:
                    _ws_add_test(user_id, data)
        return sio
    except Exception as e:
        logger.error(f"[WS-TEST] Build client error: {e}")
        return None

def _build_live_ws_client(user_id, jwt_token, user_hash="", livesms_event=""):
    """Buat Socket.IO client untuk /livesms namespace (My SMS)."""
    if not _SOCKETIO_AVAILABLE: return None
    try:
        sio = _sio_module.Client(reconnection=False, logger=False, engineio_logger=False)

        def _parse_payload(data, source):
            orig  = str(data.get("originator", data.get("cli",""))).replace("+","")
            recp  = str(data.get("recipient",  data.get("number","")))
            entry = {
                "originator":  orig or recp,
                "recipient":   recp,
                "number":      recp or orig,
                "sid":         _clean_sid(str(data.get("originator",""))),
                "message":     _clean_html(str(data.get("message",""))),
                "range":       str(data.get("range", data.get("termination_id",""))),
                "sid_raw":     str(data.get("sid","")),
                "paid":        "Paid" if float(data.get("client_revenue",0) or 0) > 0 else "Unpaid",
                "in_limit":    str(data.get("limit",1)) == "1",
                "source":      source,
                "received_at": datetime.now().isoformat(),
            }
            with _ws_lock:
                if user_id not in _ws_live:
                    _ws_live[user_id] = deque(maxlen=_WS_LIVE_MAX)
                _ws_live[user_id].appendleft(entry)
            with _ws_lock:
                if user_id not in _ws_status: _ws_status[user_id] = {}
                _ws_status[user_id]["live_sms_count"] = \
                    _ws_status[user_id].get("live_sms_count", 0) + 1

        @sio.event(namespace="/livesms")
        def connect():
            _ws_set_status(user_id, live_connected=True, live_ts=datetime.now().isoformat())
            logger.info(f"[WS-LIVE] ✅ user={user_id} connected /livesms")

        @sio.event(namespace="/livesms")
        def disconnect():
            _ws_set_status(user_id, live_connected=False)
            logger.info(f"[WS-LIVE] user={user_id} disconnected /livesms")

        if livesms_event:
            @sio.on(livesms_event, namespace="/livesms")
            def on_dynamic(data): _parse_payload(data, "ws_live_dynamic")

        @sio.on("send_message_live", namespace="/livesms")
        def on_live(data): _parse_payload(data, "ws_live")

        @sio.on("send_message_max_Limit_231177", namespace="/livesms")
        def on_limit(data): _parse_payload(data, "ws_live_limit")

        @sio.on("*", namespace="/livesms")
        def on_any_live(ev, data):
            known = {"connect","disconnect","connect_error","send_message_live",
                     "send_message_max_Limit_231177"}
            if livesms_event: known.add(livesms_event)
            if ev not in known and isinstance(data, dict):
                if "message" in data or "originator" in data:
                    _parse_payload(data, f"ws_live_catchall_{ev[:20]}")
        return sio
    except Exception as e:
        logger.error(f"[WS-LIVE] Build client error: {e}")
        return None

def _ws_auto_relogin(user_id: int):
    """Auto re-login iVAS kalau session expired. Return session baru atau None."""
    try:
        c = db()
        u = c.execute("SELECT ivas_email,ivas_pass FROM ky_users WHERE id=? AND is_active=1",(user_id,)).fetchone()
        c.close()
        if not u or not u["ivas_email"]:
            logger.warning(f"[AUTO-LOGIN] user={user_id} tidak ada kredensial iVAS")
            return None
        logger.info(f"[AUTO-LOGIN] user={user_id} re-login sebagai {u['ivas_email']}...")
        result = ivas_login(user_id, u["ivas_email"], u["ivas_pass"])
        if result.get("ok"):
            logger.info(f"[AUTO-LOGIN] user={user_id} re-login BERHASIL")
            return result
        logger.error(f"[AUTO-LOGIN] user={user_id} gagal: {result.get('error')}")
    except Exception as e:
        logger.error(f"[AUTO-LOGIN] user={user_id} exception: {e}")
    return None

def _ws_get_or_relogin(user_id: int):
    """Ambil session aktif. Kalau tidak ada/expired langsung auto re-login."""
    sess = get_ivas_session(user_id)
    if sess and sess.get("ok"):
        return sess
    return _ws_auto_relogin(user_id)

def _ws_start_test(user_id: int):
    """
    Thread: connect ke test namespace Socket.IO iVAS.
    FAST RECONNECT — no sleep/backoff. Instant reconnect on disconnect.
    Auto re-login on session expired.
    """
    def _run():
        consecutive_fail = 0
        while _ws_enabled:
            try:
                sess = _ws_get_or_relogin(user_id)
                if not sess:
                    logger.error(f"[WS-TEST] user={user_id} no session/creds -> thread stop")
                    break

                scraper = sess["scraper"]
                jwt_tok = sess.get("jwt_tok","")
                if not jwt_tok:
                    xsrf = scraper.cookies.get("XSRF-TOKEN","")
                    if xsrf and xsrf.startswith("eyJ"):
                        from urllib.parse import unquote
                        jwt_tok = unquote(xsrf)
                if not jwt_tok:
                    jwt_tok = scraper.cookies.get("laravel_session","")

                sio = _build_test_ws_client(user_id, jwt_tok)
                if not sio:
                    time.sleep(1); continue

                with _ws_lock:
                    old_sio = _ws_clients.get(user_id)
                    if old_sio:
                        try: old_sio.disconnect()
                        except: pass
                    _ws_clients[user_id] = sio

                cookie_str = "; ".join(f"{k}={v}" for k,v in dict(scraper.cookies).items())
                auth_data  = {"token": jwt_tok} if jwt_tok else {}

                logger.info(f"[WS-TEST] user={user_id} connecting... jwt={'YES' if jwt_tok else 'cookie-only'}")
                sio.connect(IVAS_WS,
                    headers={
                        "Cookie":     cookie_str,
                        "Origin":     IVAS_BASE,
                        "Referer":    IVAS_LIVE_TST,
                        "User-Agent": scraper.headers.get("User-Agent",""),
                    },
                    auth=auth_data if auth_data else None,
                    transports=["websocket"],
                    socketio_path="/socket.io/",
                    wait_timeout=15)

                try:
                    email = sess["ivas_email"]
                    sio.emit("join", {"UserName": email.split("@")[0].upper(), "Email": email})
                except: pass

                consecutive_fail = 0
                logger.info(f"[WS-TEST] user={user_id} CONNECTED - listening...")
                sio.wait()

                _ws_set_status(user_id, connected=False)
                with _ws_lock:
                    if user_id in _ws_status:
                        _ws_status[user_id]["reconnects"] = _ws_status[user_id].get("reconnects",0)+1
                logger.warning(f"[WS-TEST] user={user_id} disconnected -> instant reconnect")

                # Force re-login check after disconnect
                if not get_ivas_session(user_id):
                    logger.info(f"[WS-TEST] user={user_id} session lost -> will re-login next iter")

            except _sio_module.exceptions.ConnectionError as e:
                consecutive_fail += 1
                err_str = str(e)
                logger.error(f"[WS-TEST] user={user_id} ConnError ({consecutive_fail}): {err_str}")
                _ws_set_status(user_id, connected=False, error=err_str)
                # Auth error = session expired -> force re-login
                if any(k in err_str.lower() for k in ("403","401","unauthorized","expired","token")):
                    with _ivas_lock: _ivas_sessions.pop(user_id, None)
                time.sleep(min(consecutive_fail, 3))

            except Exception as e:
                consecutive_fail += 1
                logger.error(f"[WS-TEST] user={user_id} error ({consecutive_fail}): {e}")
                _ws_set_status(user_id, connected=False, error=str(e))
                time.sleep(min(consecutive_fail, 3))

        logger.info(f"[WS-TEST] user={user_id} thread stopped")
    t = threading.Thread(target=_run, name=f"ws-test-{user_id}", daemon=True)
    t.start()

def _ws_start_live(user_id: int):
    """
    Thread: connect ke /livesms namespace Socket.IO iVAS (My SMS).
    FAST RECONNECT — no sleep/backoff. Instant reconnect on disconnect.
    Auto re-login kalau session expired/403.
    """
    def _run():
        consecutive_fail = 0
        while _ws_enabled:
            try:
                # Ambil session aktif — kalau expired langsung re-login
                sess = _ws_get_or_relogin(user_id)
                if not sess:
                    logger.error(f"[WS-LIVE] user={user_id} no session/creds -> thread stop")
                    break

                scraper       = sess["scraper"]
                jwt_tok       = sess.get("jwt_tok","")
                user_hash     = sess.get("user_hash","")
                livesms_event = sess.get("livesms_event","")

                if not jwt_tok:
                    xsrf = scraper.cookies.get("XSRF-TOKEN","")
                    if xsrf and xsrf.startswith("eyJ"):
                        from urllib.parse import unquote
                        jwt_tok = unquote(xsrf)
                if not jwt_tok:
                    jwt_tok = scraper.cookies.get("laravel_session","")

                # Re-scrape halaman live — cari jwt/user_hash/livesms_event fresh
                # (harus dilakukan setiap reconnect karena event name per-user encrypted)
                try:
                    live_pg   = scraper.get(IVAS_LIVE_MY, timeout=10)
                    live_html = decode_resp(live_pg)

                    # Detect session expired dari redirect ke /login
                    if "/login" in live_pg.url or "login" in live_html[:500].lower():
                        logger.warning(f"[WS-LIVE] user={user_id} session expired (redirect login) -> force re-login")
                        with _ivas_lock: _ivas_sessions.pop(user_id, None)
                        relogin = _ws_auto_relogin(user_id)
                        if not relogin:
                            time.sleep(0)  # no-op; continue
                        sess = relogin
                        scraper = sess["scraper"]
                        live_pg   = scraper.get(IVAS_LIVE_MY, timeout=10)
                        live_html = decode_resp(live_pg)

                    xsrf = scraper.cookies.get("XSRF-TOKEN","")
                    if xsrf and xsrf.startswith("eyJ"):
                        from urllib.parse import unquote
                        jwt_tok = unquote(xsrf)

                    uh_m = re.search(r"""[,{\s]\s*user\s*:\s*["']([a-f0-9]{32})["']""", live_html)
                    if uh_m: user_hash = uh_m.group(1)

                    # Scrape livesms_event (encrypted per-user event name)
                    ev_m = re.search(r'liveSMSSocket\.on\s*\(\s*["\'"]([A-Za-z0-9+/=_\-]{30,})["\'"]\s*,', live_html)
                    if ev_m:
                        livesms_event = ev_m.group(1)
                    else:
                        block = re.search(r'liveSMSSocket\s*=\s*io\([^)]+\)([\s\S]{0,2000})', live_html)
                        if block:
                            ev_m2 = re.search(r'\.on\s*\(\s*["\'"]([A-Za-z0-9+/=_\-]{30,})["\'"]\s*,', block.group(1))
                            if ev_m2: livesms_event = ev_m2.group(1)

                    with _ivas_lock:
                        if user_id in _ivas_sessions:
                            _ivas_sessions[user_id].update({
                                "jwt_tok": jwt_tok,
                                "user_hash": user_hash,
                                "livesms_event": livesms_event,
                            })
                    logger.info(
                        f"[WS-LIVE] user={user_id} tokens — "
                        f"jwt={'YES' if jwt_tok else 'NO'} "
                        f"user_hash={'YES' if user_hash else 'NO'} "
                        f"event={'YES:'+livesms_event[:20] if livesms_event else 'NO(catch-all)'}"
                    )
                except Exception as e:
                    logger.warning(f"[WS-LIVE] re-scrape error: {e}")

                sio = _build_live_ws_client(user_id, jwt_tok, user_hash, livesms_event)
                if not sio:
                    logger.error(f"[WS-LIVE] user={user_id} gagal build client, retry 1s...")
                    time.sleep(1); continue

                with _ws_lock:
                    old_sio = _ws_live_clients.get(user_id)
                    if old_sio:
                        try: old_sio.disconnect()
                        except: pass
                    _ws_live_clients[user_id] = sio

                cookie_str = "; ".join(f"{k}={v}" for k,v in dict(scraper.cookies).items())
                auth_data  = {}
                if jwt_tok:   auth_data["token"] = jwt_tok
                if user_hash: auth_data["user"]  = user_hash

                logger.info(f"[WS-LIVE] user={user_id} connecting /livesms namespace...")
                sio.connect(IVAS_WS,
                    headers={
                        "Cookie":     cookie_str,
                        "Origin":     IVAS_BASE,
                        "Referer":    IVAS_LIVE_MY,
                        "User-Agent": scraper.headers.get("User-Agent",""),
                    },
                    auth=auth_data if auth_data else None,
                    transports=["websocket"],
                    socketio_path="/socket.io/",
                    namespaces=["/livesms"],
                    wait_timeout=15)

                try:
                    email = sess["ivas_email"]
                    sio.emit("join", {"Email": email, "UserName": email.split("@")[0].upper()},
                             namespace="/livesms")
                except: pass

                consecutive_fail = 0
                logger.info(f"[WS-LIVE] user={user_id} CONNECTED /livesms — listening for My SMS...")
                sio.wait()  # block sampai disconnect

                # Disconnected — langsung reconnect, TANPA sleep
                _ws_set_status(user_id, live_connected=False)
                with _ws_lock:
                    if user_id in _ws_status:
                        _ws_status[user_id]["live_reconnects"] = _ws_status[user_id].get("live_reconnects",0)+1
                logger.warning(f"[WS-LIVE] user={user_id} disconnected -> instant reconnect")

                # Session masih ada? Kalau tidak, re-login di iter berikutnya
                if not get_ivas_session(user_id):
                    logger.info(f"[WS-LIVE] user={user_id} session lost -> will re-login next iter")

            except _sio_module.exceptions.ConnectionError as e:
                consecutive_fail += 1
                err_str = str(e)
                logger.error(f"[WS-LIVE] user={user_id} ConnError ({consecutive_fail}): {err_str}")
                _ws_set_status(user_id, live_connected=False, live_error=err_str)

                # Auth/403 = session expired -> force re-login sekarang
                if any(k in err_str.lower() for k in ("403","401","unauthorized","expired","token")):
                    logger.info(f"[WS-LIVE] user={user_id} auth error -> force re-login")
                    with _ivas_lock: _ivas_sessions.pop(user_id, None)

                # Fast retry: max 3s
                time.sleep(min(consecutive_fail, 3))

            except Exception as e:
                consecutive_fail += 1
                logger.error(f"[WS-LIVE] user={user_id} error ({consecutive_fail}): {e}")
                _ws_set_status(user_id, live_connected=False, live_error=str(e))
                time.sleep(min(consecutive_fail, 3))

        logger.info(f"[WS-LIVE] user={user_id} thread stopped")
    t = threading.Thread(target=_run, name=f"ws-live-{user_id}", daemon=True)
    t.start()


def ws_start_all(user_id: int):
    """Start KEDUA WebSocket thread (test + livesms) untuk 1 user."""
    _ws_start_test(user_id)
    _ws_start_live(user_id)
    logger.info(f"[WS] Kedua thread (test+live) started untuk user={user_id}")

# ═══════════════════════════════════════════════════════════════════
# DATABASE HELPERS
# ═══════════════════════════════════════════════════════════════════
def _log_api(user_id, endpoint, method, ip, status):
    try:
        c = db()
        c.execute("INSERT INTO ky_api_logs (user_id,endpoint,method,ip,status) VALUES(?,?,?,?,?)",
                  (user_id,endpoint,method,ip,status))
        c.commit(); c.close()
    except: pass

# ═══════════════════════════════════════════════════════════════════
# WhatsApp OTP  (via Baileys server lokal)
# ═══════════════════════════════════════════════════════════════════
WA_URL   = os.getenv("WA_BOT_URL","http://localhost:3001")
WA_TOKEN = os.getenv("WA_BOT_TOKEN","kyshiro-wa-secret")

def send_otp_wa(nomor: str, otp: str, nama: str="") -> tuple:
    pesan = (f"Halo {nama}!\n\n"
             f"Kode OTP kamu: *{otp}*\n\n"
             f"Berlaku 5 menit. Jangan bagikan ke siapapun.\n\n"
             f"— KY-SHIRO OFFICIAL")
    try:
        r = req_lib.post(f"{WA_URL}/send",
            json={"token": WA_TOKEN, "number": nomor, "message": pesan},
            timeout=10)
        if r.status_code == 200:
            return True, "OTP terkirim"
        return False, f"WA bot error: {r.status_code}"
    except Exception as e:
        logger.error(f"[WA] {e}")
        logger.info(f"[WA-DEMO] OTP untuk {nomor}: {otp}")
        return True, f"DEMO: OTP={otp} (WA bot belum aktif, cek log server)"

def _gen_otp(): return str(secrets.randbelow(900000)+100000)

# ═══════════════════════════════════════════════════════════════════
# AUTH DECORATORS
# ═══════════════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def _d(*a, **kw):
        if "uid" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"status":"error","message":"Login diperlukan"}), 401
            return redirect(url_for("pg_login"))
        return f(*a, **kw)
    return _d

def admin_required(f):
    @wraps(f)
    def _d(*a, **kw):
        if "uid" not in session: return redirect(url_for("pg_login"))
        if session.get("role") != "admin": abort(403)
        return f(*a, **kw)
    return _d

def ivas_required(f):
    """Endpoint butuh user sudah login ke iVAS. Support API Key."""
    @wraps(f)
    def _d(*a, **kw):
        key = request.headers.get("X-API-Key") or request.args.get("api_key","")
        if key:
            c = db()
            u = c.execute("SELECT * FROM ky_users WHERE api_key=? AND is_active=1 AND verified=1",(key,)).fetchone()
            c.close()
            if not u: return jsonify({"status":"error","message":"API Key tidak valid"}), 401
            uid  = u["id"]
            sess = get_ivas_session(uid)
            if not sess:
                if u["ivas_email"] and u["ivas_pass"]:
                    r = ivas_login(uid, u["ivas_email"], u["ivas_pass"])
                    if not r.get("ok"):
                        return jsonify({"status":"error","message":f"Login iVAS gagal: {r.get('error')}"}), 403
                    # Start WS otomatis
                    threading.Thread(target=ws_start_all, args=(uid,), daemon=True).start()
                else:
                    return jsonify({"status":"error","message":"Belum set kredensial iVAS"}), 403
            g.uid = uid
            _log_api(uid, request.path, request.method, request.remote_addr, 200)
            return f(*a, **kw)
        if "uid" not in session:
            return jsonify({"status":"error","message":"Login diperlukan"}), 401
        uid  = session["uid"]
        sess = get_ivas_session(uid)
        if not sess:
            return jsonify({"status":"error","message":"Belum login ke iVAS. Pergi ke /dashboard/ivas-login"}), 403
        g.uid = uid
        return f(*a, **kw)
    return _d

# ═══════════════════════════════════════════════════════════════════
# AUTH PAGES
# ═══════════════════════════════════════════════════════════════════
@app.route("/")
def pg_landing(): return render_template("landing.html")

@app.route("/login", methods=["GET","POST"])
def pg_login():
    if "uid" in session: return redirect(url_for("pg_dashboard"))
    err = None
    if request.method == "POST":
        uname = request.form.get("username","").strip()
        pw    = request.form.get("password","").strip()
        if not uname or not pw:
            err = "Username dan password wajib diisi."
        else:
            c = db()
            u = c.execute("SELECT * FROM ky_users WHERE username=? AND is_active=1",(uname,)).fetchone()
            c.close()
            if not u: err = "Username tidak ditemukan."
            elif u["password"] != hashlib.sha256(pw.encode()).hexdigest(): err = "Password salah."
            elif not u["verified"]: err = "Akun belum diverifikasi. Cek WhatsApp."
            else:
                session["uid"] = u["id"]; session["username"] = u["username"]
                session["role"] = u["role"]; session["nama"] = u["nama"]
                c = db(); c.execute("UPDATE ky_users SET last_login=? WHERE id=?",(datetime.now().isoformat(),u["id"]))
                c.commit(); c.close()
                # Auto re-login iVAS kalau ada kredensial tersimpan
                if u["ivas_email"] and u["ivas_pass"]:
                    def _auto_login():
                        res = ivas_login(u["id"], u["ivas_email"], u["ivas_pass"])
                        if res.get("ok"):
                            ws_start_all(u["id"])
                    threading.Thread(target=_auto_login, daemon=True).start()
                return redirect(url_for("pg_dashboard"))
    return render_template("auth/login.html", error=err)

@app.route("/register", methods=["GET","POST"])
def pg_register():
    if "uid" in session: return redirect(url_for("pg_dashboard"))
    err = None
    if request.method == "POST":
        username  = request.form.get("username","").strip()
        nama      = request.form.get("nama","").strip()
        email     = request.form.get("email","").strip()
        nomor_wa  = request.form.get("nomor_wa","").strip()
        password  = request.form.get("password","").strip()
        password2 = request.form.get("password2","").strip()
        if not all([username,nama,email,nomor_wa,password,password2]):
            err = "Semua kolom wajib diisi."
        elif password != password2: err = "Password tidak cocok."
        elif len(password) < 8: err = "Password minimal 8 karakter."
        elif not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
            err = "Username 3-20 karakter, hanya huruf, angka, underscore."
        elif not re.match(r"^\d{10,15}$", nomor_wa.replace("+","")):
            err = "Format nomor WA tidak valid. Contoh: 6281234567890"
        else:
            c = db()
            if c.execute("SELECT id FROM ky_users WHERE username=?",(username,)).fetchone():
                err = "Username sudah dipakai."
            elif c.execute("SELECT id FROM ky_users WHERE email=?",(email,)).fetchone():
                err = "Email sudah terdaftar."
            c.close()
        if not err:
            ph   = hashlib.sha256(password.encode()).hexdigest()
            akey = "ky-" + secrets.token_hex(24)
            otp  = _gen_otp()
            exp  = (datetime.now()+timedelta(minutes=5)).isoformat()
            c = db()
            c.execute("""INSERT INTO ky_users
                (username,nama,email,nomor_wa,password,api_key,otp_code,otp_expires,otp_type)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (username,nama,email,nomor_wa,ph,akey,otp,exp,"register"))
            c.commit(); c.close()
            send_otp_wa(nomor_wa, otp, nama)
            session["pending_verify"] = username
            return redirect(url_for("pg_verify_otp"))
    return render_template("auth/register.html", error=err)

@app.route("/verify-otp", methods=["GET","POST"])
def pg_verify_otp():
    uname = session.get("pending_verify","")
    if not uname: return redirect(url_for("pg_register"))
    err = None; ok = False
    if request.method == "POST":
        otp_in = request.form.get("otp","").strip()
        c = db(); u = c.execute("SELECT * FROM ky_users WHERE username=?",(uname,)).fetchone(); c.close()
        if not u: err = "Akun tidak ditemukan."
        elif datetime.now().isoformat() > (u["otp_expires"] or ""): err = "OTP kadaluarsa. Klik kirim ulang."
        elif otp_in != u["otp_code"]: err = "Kode OTP salah."
        else:
            c = db(); c.execute("UPDATE ky_users SET verified=1,otp_code=NULL,otp_expires=NULL WHERE username=?",(uname,))
            c.commit(); c.close()
            session.pop("pending_verify",None); ok = True
    return render_template("auth/verify_otp.html", error=err, success=ok, username=uname)

@app.route("/resend-otp", methods=["POST"])
def pg_resend_otp():
    uname = session.get("pending_verify","") or request.form.get("username","")
    c = db(); u = c.execute("SELECT * FROM ky_users WHERE username=?",(uname,)).fetchone(); c.close()
    if not u: return jsonify({"status":"error","message":"Akun tidak ditemukan"}), 404
    otp = _gen_otp(); exp = (datetime.now()+timedelta(minutes=5)).isoformat()
    c = db(); c.execute("UPDATE ky_users SET otp_code=?,otp_expires=? WHERE username=?",(otp,exp,uname)); c.commit(); c.close()
    ok, msg = send_otp_wa(u["nomor_wa"], otp, u["nama"])
    return jsonify({"status":"ok","message":msg})

@app.route("/forgot-password", methods=["GET","POST"])
def pg_forgot():
    err = None; sent = False
    if request.method == "POST":
        idf = request.form.get("identifier","").strip()
        c = db(); u = c.execute("SELECT * FROM ky_users WHERE username=? OR email=?",(idf,idf)).fetchone(); c.close()
        if not u: err = "Username atau email tidak ditemukan."
        else:
            otp = _gen_otp(); exp = (datetime.now()+timedelta(minutes=5)).isoformat()
            c = db(); c.execute("UPDATE ky_users SET otp_code=?,otp_expires=?,otp_type='reset' WHERE id=?",(otp,exp,u["id"])); c.commit(); c.close()
            send_otp_wa(u["nomor_wa"], otp, u["nama"])
            session["reset_uid"] = u["id"]; sent = True
    return render_template("auth/forgot.html", error=err, sent=sent)

@app.route("/reset-password", methods=["GET","POST"])
def pg_reset():
    uid = session.get("reset_uid")
    if not uid: return redirect(url_for("pg_forgot"))
    err = None; ok = False
    if request.method == "POST":
        otp_in = request.form.get("otp","").strip()
        pw     = request.form.get("password","").strip()
        pw2    = request.form.get("password2","").strip()
        if pw != pw2: err = "Password tidak cocok."
        elif len(pw) < 8: err = "Minimal 8 karakter."
        else:
            c = db(); u = c.execute("SELECT * FROM ky_users WHERE id=?",(uid,)).fetchone(); c.close()
            if not u or datetime.now().isoformat() > (u["otp_expires"] or ""): err = "OTP kadaluarsa."
            elif otp_in != u["otp_code"]: err = "OTP salah."
            else:
                ph = hashlib.sha256(pw.encode()).hexdigest()
                c = db(); c.execute("UPDATE ky_users SET password=?,otp_code=NULL,otp_expires=NULL WHERE id=?",(ph,uid)); c.commit(); c.close()
                session.pop("reset_uid",None); ok = True
    return render_template("auth/reset.html", error=err, success=ok)

@app.route("/logout")
def pg_logout():
    uid = session.get("uid")
    if uid:
        with _ws_lock:
            sio_t = _ws_clients.pop(uid, None)
            sio_l = _ws_live_clients.pop(uid, None)
            _ws_status.pop(uid, None)
            _ws_live.pop(uid, None)
            _ws_test.pop(uid, None)
        for sio in [sio_t, sio_l]:
            if sio:
                try: sio.disconnect()
                except: pass
        with _ivas_lock: _ivas_sessions.pop(uid, None)
    session.clear()
    return redirect(url_for("pg_landing"))

# ═══════════════════════════════════════════════════════════════════
# DASHBOARD PAGES
# ═══════════════════════════════════════════════════════════════════
def _get_user():
    c = db()
    u = c.execute("SELECT * FROM ky_users WHERE id=?",(session["uid"],)).fetchone()
    c.close()
    return dict(u)

@app.route("/dashboard")
@login_required
def pg_dashboard():
    u   = _get_user(); uid = session["uid"]
    sess = get_ivas_session(uid)
    with _ws_lock:
        live_total = len(_ws_live.get(uid,[]))
        test_total = len(_ws_test.get(uid,[]))
    return render_template("dashboard/index.html", user=u,
        ivas_connected=bool(sess and sess.get("ok")),
        ws_live_total=live_total, ws_test_total=test_total)

@app.route("/dashboard/ivas-login", methods=["GET","POST"])
@login_required
def pg_ivas_login():
    u = _get_user(); err = None; ok = False
    if request.method == "POST":
        ie = request.form.get("ivas_email","").strip()
        ip = request.form.get("ivas_pass","").strip()
        if not ie or not ip: err = "Email dan password iVAS wajib diisi."
        else:
            result = ivas_login(session["uid"], ie, ip)
            if result.get("ok"):
                c = db()
                c.execute("UPDATE ky_users SET ivas_email=?,ivas_pass=?,ivas_status='connected' WHERE id=?",
                          (ie, ip, session["uid"]))
                c.commit(); c.close()
                # Start KEDUA WebSocket thread
                threading.Thread(target=ws_start_all, args=(session["uid"],), daemon=True).start()
                ok = True
            else: err = result.get("error","Login iVAS gagal")
    return render_template("dashboard/ivas_login.html", user=u, error=err, success=ok)

@app.route("/dashboard/sms-live")
@login_required
def pg_sms_live(): return render_template("dashboard/sms_live.html", user=_get_user())

@app.route("/dashboard/sms-received")
@login_required
def pg_sms_received(): return render_template("dashboard/sms_received.html", user=_get_user())

@app.route("/dashboard/numbers")
@login_required
def pg_numbers(): return render_template("dashboard/numbers.html", user=_get_user())

@app.route("/dashboard/check-number")
@login_required
def pg_check_number(): return render_template("dashboard/check_number.html", user=_get_user())

@app.route("/dashboard/ranges")
@login_required
def pg_ranges(): return render_template("dashboard/ranges.html", user=_get_user())

@app.route("/dashboard/apikey")
@login_required
def pg_apikey(): return render_template("dashboard/apikey.html", user=_get_user())

@app.route("/dashboard/docs")
@login_required
def pg_docs(): return render_template("dashboard/docs.html", user=_get_user())

@app.route("/dashboard/profile")
@login_required
def pg_profile(): return render_template("dashboard/profile.html", user=_get_user())

@app.route("/dashboard/otp-received")
@login_required
def pg_otp_received(): return render_template("dashboard/otp_received.html", user=_get_user())

@app.route("/dashboard/stats")
@login_required
def pg_stats():
    uid = session["uid"]
    c   = db()
    logs  = c.execute("""SELECT endpoint,method,status,created_at FROM ky_api_logs
        WHERE user_id=? ORDER BY created_at DESC LIMIT 100""",(uid,)).fetchall()
    total = c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE user_id=?",(uid,)).fetchone()[0]
    today = c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE user_id=? AND date(created_at)=date('now')",(uid,)).fetchone()[0]
    c.close()
    return render_template("dashboard/stats.html", user=_get_user(),
        logs=[dict(x) for x in logs], total=total, today=today)

@app.route("/dashboard/support")
@login_required
def pg_support(): return render_template("dashboard/support.html", user=_get_user())

@app.route("/admin")
@admin_required
def pg_admin():
    c = db()
    users = c.execute("SELECT * FROM ky_users ORDER BY created_at DESC").fetchall()
    logs  = c.execute("""SELECT l.*,u.username FROM ky_api_logs l
        LEFT JOIN ky_users u ON l.user_id=u.id
        ORDER BY l.created_at DESC LIMIT 200""").fetchall()
    stats = {
        "total_users":  c.execute("SELECT COUNT(*) FROM ky_users").fetchone()[0],
        "verified":     c.execute("SELECT COUNT(*) FROM ky_users WHERE verified=1").fetchone()[0],
        "today_logs":   c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE date(created_at)=date('now')").fetchone()[0],
        "total_logs":   c.execute("SELECT COUNT(*) FROM ky_api_logs").fetchone()[0],
        "ivas_active":  len(_ivas_sessions),
        "ws_live":      sum(1 for v in _ws_status.values() if v.get("live_connected")),
        "ws_test":      sum(1 for v in _ws_status.values() if v.get("connected")),
    }
    c.close()
    u = {"username":session["username"],"nama":session.get("nama","Admin"),"role":"admin"}
    return render_template("dashboard/admin.html",
        users=[dict(x) for x in users],
        logs=[dict(x) for x in logs], stats=stats, user=u)

# ═══════════════════════════════════════════════════════════════════
# iVAS API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/ivas/login", methods=["POST"])
@login_required
def api_ivas_login():
    data = request.get_json(silent=True) or {}
    ie   = (data.get("ivas_email","") or request.form.get("ivas_email","")).strip()
    ip_  = (data.get("ivas_pass","")  or request.form.get("ivas_pass","")).strip()
    if not ie or not ip_:
        return jsonify({"status":"error","message":"ivas_email dan ivas_pass wajib"}), 400
    uid    = session["uid"]
    result = ivas_login(uid, ie, ip_)
    if result.get("ok"):
        c = db(); c.execute("UPDATE ky_users SET ivas_email=?,ivas_pass=?,ivas_status='connected' WHERE id=?",(ie,ip_,uid))
        c.commit(); c.close()
        threading.Thread(target=ws_start_all, args=(uid,), daemon=True).start()
        return jsonify({"status":"ok","message":"Login iVAS berhasil","email":ie})
    return jsonify({"status":"error","message":result.get("error","Login gagal")}), 401

@app.route("/api/ivas/status")
@login_required
def api_ivas_status():
    uid  = session["uid"]
    sess = get_ivas_session(uid)
    with _ws_lock:
        ws_stat      = _ws_status.get(uid,{})
        live_count   = len(_ws_live.get(uid,[]))
        test_count   = len(_ws_test.get(uid,[]))
    c = db(); u = c.execute("SELECT ivas_email,ivas_status,ivas_login_at FROM ky_users WHERE id=?",(uid,)).fetchone(); c.close()
    return jsonify({
        "status":           "ok",
        "ivas_connected":   bool(sess and sess.get("ok")),
        "ivas_email":       u["ivas_email"] if u else "",
        "ivas_status":      u["ivas_status"] if u else "disconnected",
        "ivas_login_at":    u["ivas_login_at"] if u else None,
        "ws_test_connected": ws_stat.get("connected",False),
        "ws_live_connected": ws_stat.get("live_connected",False),
        "ws_live_cached":   live_count,
        "ws_test_cached":   test_count,
    })

@app.route("/api/ivas/logout", methods=["POST"])
@login_required
def api_ivas_logout():
    uid = session["uid"]
    with _ws_lock:
        sio_t = _ws_clients.pop(uid,None)
        sio_l = _ws_live_clients.pop(uid,None)
        _ws_status.pop(uid,None)
    for sio in [sio_t, sio_l]:
        if sio:
            try: sio.disconnect()
            except: pass
    with _ivas_lock: _ivas_sessions.pop(uid,None)
    c = db(); c.execute("UPDATE ky_users SET ivas_status='disconnected' WHERE id=?",(uid,)); c.commit(); c.close()
    return jsonify({"status":"ok","message":"Logout dari iVAS berhasil"})

# ─── SMS Live (My Numbers) ────────────────────────────────────────
@app.route("/api/sms/live")
@ivas_required
def api_sms_live():
    """
    Ambil My SMS real-time dari WebSocket cache (/livesms namespace).
    Fallback: scrape /portal/sms/received/getsms jika WS kosong.
    """
    uid        = g.uid
    limit      = min(int(request.args.get("limit",50)), 500)
    sid_filter = request.args.get("sid","").lower()
    num_filter = request.args.get("number","").strip()
    since      = request.args.get("since","").strip()

    # ── Priority 1: WebSocket cache /livesms ──
    with _ws_lock:
        items = list(_ws_live.get(uid,[]))[:limit]
    if sid_filter: items = [i for i in items if sid_filter in i.get("sid","").lower() or sid_filter in i.get("message","").lower()]
    if num_filter: items = [i for i in items if num_filter in i.get("number","") or num_filter in i.get("originator","")]
    if since:      items = [i for i in items if i.get("received_at","") > since]

    if items:
        return jsonify({"status":"ok","source":"websocket_live_cache","total":len(items),"sms":items})

    # ── Priority 2: Scrape /portal/sms/received/getsms ──
    today_s = datetime.now().strftime("%Y-%m-%d")
    ranges  = ivas_get_ranges(uid, today_s, today_s)
    results = []
    seen    = set()
    for rng in ranges[:10]:
        nums = ivas_get_numbers(uid, rng["name"], today_s, today_s, range_id=rng["id"])
        for num_info in nums[:20]:
            num   = num_info["number"]
            smses = ivas_get_sms(uid, num, rng["name"], today_s, today_s)
            for sms_text in smses:
                msg = _clean_html(sms_text)
                if not msg: continue
                if num_filter and num_filter not in num: continue
                if sid_filter and sid_filter not in msg.lower(): continue
                key = (num, msg[:50])
                if key in seen: continue
                seen.add(key)
                results.append({
                    "range":       rng["name"],
                    "number":      num,
                    "originator":  num,
                    "message":     msg,
                    "received_at": today_s,
                    "source":      "scrape_received",
                })
    results = results[:limit]
    return jsonify({"status":"ok","source":"scrape_received","total":len(results),"sms":results})

@app.route("/api/sms/live/stream")
@ivas_required
def api_sms_live_stream():
    """SSE stream — push INSTANT tiap ada My SMS baru (no sleep, event-driven)."""
    uid   = g.uid
    sid_f = request.args.get("sid","").lower()
    # Buat/ambil Event khusus user ini
    ev = threading.Event()
    _ws_event[uid] = ev
    last_ts = [""]
    def _gen():
        try:
            yield 'data: {"type":"connected"}\n\n'
            while True:
                # Tunggu sampai ada SMS baru, max 30s lalu kirim keepalive
                triggered = ev.wait(timeout=30)
                ev.clear()
                if not triggered:
                    # Keepalive ping supaya koneksi tidak putus
                    yield ": keepalive\n\n"
                    continue
                # Ada SMS baru — kirim semua yang belum dikirim
                with _ws_lock:
                    items = list(_ws_live.get(uid,[]))
                new = [i for i in items if i.get("received_at","") > last_ts[0]]
                if sid_f:
                    new = [i for i in new if
                           sid_f in i.get("sid","").lower() or
                           sid_f in i.get("message","").lower()]
                for i in new:
                    yield f"data: {json.dumps(i)}\n\n"
                    if i.get("received_at","") > last_ts[0]:
                        last_ts[0] = i["received_at"]
        finally:
            # Cleanup event saat client disconnect
            _ws_event.pop(uid, None)
    return Response(stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/sms/live/clear", methods=["POST"])
@ivas_required
def api_sms_live_clear():
    uid = g.uid
    with _ws_lock: _ws_live.pop(uid,None)
    return jsonify({"status":"ok","message":"Cache SMS live dikosongkan"})

# ─── Test SMS (Live test SMS publik) ─────────────────────────────
@app.route("/api/sms/test")
@ivas_required
def api_sms_test():
    """
    Ambil test SMS real-time dari WebSocket cache (test namespace).
    Fallback: scrape /portal/sms/test/sms via XHR.
    Data ini public — SMS dari semua user iVAS (bukan hanya akun kamu).
    """
    uid        = g.uid
    limit      = min(int(request.args.get("limit",100)), 500)
    sid_filter = request.args.get("sid","").lower()
    num_filter = request.args.get("number","").strip()
    since      = request.args.get("since","").strip()

    # ── Priority 1: WebSocket cache test ──
    with _ws_lock:
        items = list(_ws_test.get(uid,[]))

    if sid_filter: items = [i for i in items if sid_filter in i.get("sid","").lower() or sid_filter in i.get("message","").lower()]
    if num_filter: items = [i for i in items if num_filter in i.get("number","")]
    if since:      items = [i for i in items if i.get("received_at","") > since]
    items = items[:limit]

    if items:
        return jsonify({"status":"ok","source":"websocket_test_cache","total":len(items),"sms":items})

    # ── Fallback: scrape XHR ──
    scraped = _ivas_scrape_public(uid, limit=limit, sid_filter=sid_filter)
    if num_filter: scraped = [i for i in scraped if num_filter in i.get("number","")]
    return jsonify({"status":"ok","source":"scrape_xhr_test","total":len(scraped),"sms":scraped})

@app.route("/api/sms/test/stream")
@ivas_required
def api_sms_test_stream():
    """SSE stream untuk test SMS real-time — push INSTANT, no sleep."""
    uid   = g.uid
    sid_f = request.args.get("sid","").lower()
    ev = threading.Event()
    _ws_event[uid] = ev
    last_ts = [""]
    def _gen():
        try:
            yield 'data: {"type":"connected"}\n\n'
            while True:
                triggered = ev.wait(timeout=30)
                ev.clear()
                if not triggered:
                    yield ": keepalive\n\n"
                    continue
                with _ws_lock:
                    items = list(_ws_test.get(uid,[]))
                new = [i for i in items if i.get("received_at","") > last_ts[0]]
                if sid_f:
                    new = [i for i in new if
                           sid_f in i.get("sid","").lower() or
                           sid_f in i.get("message","").lower()]
                for i in new:
                    yield f"data: {json.dumps(i)}\n\n"
                    if i.get("received_at","") > last_ts[0]:
                        last_ts[0] = i["received_at"]
        finally:
            _ws_event.pop(uid, None)
    return Response(stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ─── SMS Received ─────────────────────────────────────────────────
@app.route("/api/sms/received")
@ivas_required
def api_sms_received():
    uid = g.uid
    rng = request.args.get("range","").strip()
    num = request.args.get("number","").strip()
    fd  = request.args.get("from", datetime.now().strftime("%Y-%m-%d"))
    td  = request.args.get("to",   datetime.now().strftime("%Y-%m-%d"))
    if not rng: return jsonify({"status":"error","message":"Parameter 'range' wajib"}), 400
    if not num: return jsonify({"status":"error","message":"Parameter 'number' wajib"}), 400
    msgs = ivas_get_sms(uid, num, rng, fd, td)
    return jsonify({"status":"ok","number":num,"range":rng,"total":len(msgs),"messages":msgs})

# ─── SMS OTP (extract OTP candidates) ────────────────────────────
@app.route("/api/sms/otp")
@ivas_required
def api_sms_otp():
    uid = g.uid
    num = request.args.get("number","").strip()
    rng = request.args.get("range","").strip()
    fd  = request.args.get("from", datetime.now().strftime("%Y-%m-%d"))
    td  = request.args.get("to",   datetime.now().strftime("%Y-%m-%d"))
    if not num: return jsonify({"status":"error","message":"Parameter 'number' wajib"}), 400
    if not rng: return jsonify({"status":"error","message":"Parameter 'range' wajib"}), 400
    msgs     = ivas_get_sms(uid, num, rng, fd, td)
    otp_list = []
    for m in msgs:
        otps = re.findall(r'\b\d{4,8}\b', m)
        otp_list.append({"message": m, "otp_candidates": otps})
    return jsonify({"status":"ok","number":num,"range":rng,"total":len(msgs),"messages":otp_list})

# ─── Ranges ───────────────────────────────────────────────────────
@app.route("/api/ranges")
@ivas_required
def api_ranges():
    uid  = g.uid
    fd   = request.args.get("from", datetime.now().strftime("%Y-%m-%d"))
    td   = request.args.get("to",   datetime.now().strftime("%Y-%m-%d"))
    rngs = ivas_get_ranges(uid, fd, td)
    return jsonify({"status":"ok","total":len(rngs),"ranges":rngs})

# ─── Numbers per range ────────────────────────────────────────────
@app.route("/api/numbers")
@ivas_required
def api_numbers():
    uid = g.uid
    rng = request.args.get("range","").strip()
    fd  = request.args.get("from", datetime.now().strftime("%Y-%m-%d"))
    td  = request.args.get("to",   datetime.now().strftime("%Y-%m-%d"))
    if not rng: return jsonify({"status":"error","message":"Parameter 'range' wajib"}), 400
    nums = ivas_get_numbers(uid, rng, fd, td)
    return jsonify({"status":"ok","range":rng,"total":len(nums),"numbers":nums})

# ─── Test Numbers list ────────────────────────────────────────────
@app.route("/api/numbers/test-list")
@ivas_required
def api_numbers_test_list():
    """Daftar Test Numbers dari /portal/numbers/test (DataTables)."""
    uid    = g.uid
    search = request.args.get("search","").strip()
    limit  = min(int(request.args.get("limit",100)), 1000)
    rows, total = _fetch_datatables(uid, f"{IVAS_BASE}/portal/numbers/test",
        search=search, length=limit)
    clean = []
    for row in rows:
        test_num = re.sub(r"<[^>]+>","",str(row.get("test_number",""))).strip()
        if not test_num: continue
        clean.append({
            "number_id":  _get_number_id(row),
            "range_name": re.sub(r"<[^>]+>","",str(row.get("range",""))).strip(),
            "test_number":test_num,
            "term":       str(row.get("term","")),
            "rate_a2p":   str(row.get("A2P","")),
            "limit_range":str(row.get("Limit_Range","")),
        })
    return jsonify({"status":"ok","total_ivas":total,"total":len(clean),"numbers":clean})

# ─── My Numbers list ──────────────────────────────────────────────
@app.route("/api/numbers/my-list")
@ivas_required
def api_numbers_my_list():
    """Daftar My Numbers dari /portal/numbers (DataTables)."""
    uid    = g.uid
    search = request.args.get("search","").strip()
    limit  = min(int(request.args.get("limit",200)), 1000)
    rows, total = _fetch_my_numbers(uid, search=search, length=limit)
    clean = []
    for row in rows:
        raw_num    = re.sub(r"<[^>]+>","",str(row.get("Number",row.get("number","")))).strip()
        range_name = re.sub(r"<[^>]+>","",str(row.get("range",""))).strip()
        if not raw_num: continue
        clean.append({
            "number_id":   _get_number_id(row),
            "number":      raw_num,
            "range_name":  range_name,
            "rate_a2p":    str(row.get("A2P","")).strip(),
            "limit_range": str(row.get("LimitA2P",row.get("Limit_Range",""))).strip(),
        })
    return jsonify({"status":"ok","total_ivas":total,"total":len(clean),"numbers":clean})

# ─── Check Number ─────────────────────────────────────────────────
@app.route("/api/check-number")
@ivas_required
def api_check_number():
    uid = g.uid
    num = request.args.get("number","").strip()
    if not num: return jsonify({"status":"error","message":"Parameter 'number' wajib"}), 400
    # Cari di test dulu, lalu my numbers
    for page_url in [f"{IVAS_BASE}/portal/numbers/test", f"{IVAS_BASE}/portal/numbers"]:
        rows, _ = _fetch_datatables(uid, page_url, search=num, length=50)
        for row in rows:
            def _s(k): return re.sub(r"<[^>]+>","",str(row.get(k,""))).strip()
            raw_num = _s("test_number") or _s("Number") or _s("number")
            if re.sub(r"\D","",raw_num) == re.sub(r"\D","",num):
                return jsonify({"status":"ok","found":True,
                    "number":    raw_num,
                    "range":     _s("range"),
                    "term_id":   _get_number_id(row),
                    "from_page": "test" if "test" in page_url else "my"})
    return jsonify({"status":"ok","found":False,"number":num})

# ─── Live Get Numbers (untuk range tertentu) ──────────────────────
@app.route("/api/numbers/live")
@ivas_required
def api_numbers_live():
    """POST /portal/live/getNumbers → nomor dalam range."""
    uid     = g.uid
    term_id = request.args.get("termination_id","").strip()
    if not term_id: return jsonify({"status":"error","message":"Parameter 'termination_id' wajib"}), 400
    numbers, err = ivas_live_get_numbers(uid, term_id)
    if err: return jsonify({"status":"error","message":err}), 500
    return jsonify({"status":"ok","termination_id":term_id,"total":len(numbers),"numbers":numbers})

# ─── Add Number ───────────────────────────────────────────────────
@app.route("/api/numbers/add", methods=["GET","POST"])
@ivas_required
def api_add_number():
    uid  = g.uid
    data = request.get_json(silent=True) or {}
    term_id    = (data.get("termination_id","") or request.form.get("termination_id","") or request.args.get("termination_id","")).strip()
    range_name = (data.get("range_name","")     or request.form.get("range_name","")     or request.args.get("range_name","")).strip()
    number     = (data.get("number","")         or request.form.get("number","")         or request.args.get("number","")).strip()

    if not term_id and not range_name and not number:
        return jsonify({"status":"error",
            "message":"Wajib isi salah satu: termination_id / range_name / number"}), 400

    if term_id:
        ok, msg = ivas_add_number(uid, term_id)
        return jsonify({"status":"ok" if ok else "error","termination_id":term_id,"success":ok,"message":msg})

    # Resolve via DataTables
    results = []; errors = []
    search  = range_name or number
    rows, _ = _fetch_datatables(uid, f"{IVAS_BASE}/portal/numbers/test", search=search, length=500)
    rn_low  = range_name.lower()
    for row in rows:
        def _s(k): return re.sub(r"<[^>]+>","",str(row.get(k,""))).strip()
        rng    = _s("range"); raw_num = _s("test_number")
        if range_name and rn_low not in rng.lower(): continue
        if number and re.sub(r"\D","",raw_num) != re.sub(r"\D","",number): continue
        tid = _get_number_id(row)
        if not tid: continue
        ok, msg = ivas_add_number(uid, tid)
        (results if ok else errors).append({"number":raw_num,"range":rng,"termination_id":tid,"message":msg})
    return jsonify({"status":"ok","added":len(results),"failed":len(errors),
                    "results":results,"errors":errors})

# ─── Delete Number ────────────────────────────────────────────────
@app.route("/api/numbers/delete", methods=["GET","POST"])
@ivas_required
def api_delete_number():
    uid  = g.uid
    data = request.get_json(silent=True) or {}
    term_id = (data.get("termination_id","") or request.form.get("termination_id","") or request.args.get("termination_id","")).strip()
    number  = (data.get("number","")         or request.form.get("number","")         or request.args.get("number","")).strip()
    if not term_id and not number:
        return jsonify({"status":"error","message":"Wajib isi termination_id atau number"}), 400
    if not term_id and number:
        rows, _ = _fetch_my_numbers(uid, search=number, length=50)
        for row in rows:
            def _s(k): return re.sub(r"<[^>]+>","",str(row.get(k,""))).strip()
            raw = _s("Number") or _s("number")
            if re.sub(r"\D","",raw) == re.sub(r"\D","",number):
                term_id = _get_number_id(row)
                break
    if not term_id:
        return jsonify({"status":"error","message":f"Nomor {number} tidak ditemukan"}), 404
    ok, msg = ivas_delete_number(uid, term_id)
    return jsonify({"status":"ok" if ok else "error","termination_id":term_id,"success":ok,"message":msg})

# ─── WS Reconnect ─────────────────────────────────────────────────
@app.route("/api/ws/reconnect", methods=["POST"])
@ivas_required
def api_ws_reconnect():
    uid = g.uid
    with _ws_lock:
        sio_t = _ws_clients.pop(uid,None)
        sio_l = _ws_live_clients.pop(uid,None)
    for sio in [sio_t, sio_l]:
        if sio:
            try: sio.disconnect()
            except: pass
    threading.Thread(target=ws_start_all, args=(uid,), daemon=True).start()
    return jsonify({"status":"ok","message":"WebSocket reconnect dimulai (test + livesms)"})

@app.route("/api/ws/status")
@login_required
def api_ws_status():
    uid = session["uid"]
    with _ws_lock:
        st = _ws_status.get(uid, {})
        live_count = len(_ws_live.get(uid,[]))
        test_count = len(_ws_test.get(uid,[]))
    return jsonify({
        "status":            "ok",
        "ws_test_connected": st.get("connected",False),
        "ws_live_connected": st.get("live_connected",False),
        "ws_live_cached":    live_count,
        "ws_test_cached":    test_count,
        "reconnects_test":   st.get("reconnects",0),
        "reconnects_live":   st.get("live_reconnects",0),
        "last_error_test":   st.get("error",""),
        "last_error_live":   st.get("live_error",""),
    })

@app.route("/api/ws/clear", methods=["POST"])
@ivas_required
def api_ws_clear():
    uid  = g.uid
    what = request.args.get("what","all")  # all, live, test
    with _ws_lock:
        if what in ("all","live"): _ws_live.pop(uid,None)
        if what in ("all","test"): _ws_test.pop(uid,None)
    return jsonify({"status":"ok","message":f"Cache WS '{what}' dikosongkan"})

# ─── User API ─────────────────────────────────────────────────────
@app.route("/api/me")
@login_required
def api_me():
    c = db()
    u = c.execute("SELECT id,username,nama,email,nomor_wa,role,api_key,ivas_email,ivas_status,created_at,last_login FROM ky_users WHERE id=?",(session["uid"],)).fetchone()
    c.close()
    return jsonify({"status":"ok","user":dict(u)})

@app.route("/api/regen-key", methods=["POST"])
@login_required
def api_regen_key():
    key = "ky-" + secrets.token_hex(24)
    c = db(); c.execute("UPDATE ky_users SET api_key=? WHERE id=?",(key,session["uid"])); c.commit(); c.close()
    return jsonify({"status":"ok","api_key":key})

@app.route("/api/update-profile", methods=["POST"])
@login_required
def api_update_profile():
    nama  = request.form.get("nama","").strip()
    email = request.form.get("email","").strip()
    if not nama or not email: return jsonify({"status":"error","message":"Nama dan email wajib"}), 400
    c = db(); c.execute("UPDATE ky_users SET nama=?,email=? WHERE id=?",(nama,email,session["uid"])); c.commit(); c.close()
    session["nama"] = nama
    return jsonify({"status":"ok"})

@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_pw():
    op  = request.form.get("old_password","").strip()
    nw  = request.form.get("new_password","").strip()
    nw2 = request.form.get("new_password2","").strip()
    if not all([op,nw,nw2]): return jsonify({"status":"error","message":"Semua kolom wajib"}), 400
    if nw != nw2: return jsonify({"status":"error","message":"Password baru tidak cocok"}), 400
    if len(nw) < 8: return jsonify({"status":"error","message":"Minimal 8 karakter"}), 400
    c = db(); u = c.execute("SELECT password FROM ky_users WHERE id=?",(session["uid"],)).fetchone(); c.close()
    if u["password"] != hashlib.sha256(op.encode()).hexdigest():
        return jsonify({"status":"error","message":"Password lama salah"}), 400
    ph = hashlib.sha256(nw.encode()).hexdigest()
    c = db(); c.execute("UPDATE ky_users SET password=? WHERE id=?",(ph,session["uid"])); c.commit(); c.close()
    return jsonify({"status":"ok","message":"Password berhasil diubah"})

@app.route("/api/stats")
@login_required
def api_stats():
    uid = session["uid"]
    c   = db()
    total = c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE user_id=?",(uid,)).fetchone()[0]
    today = c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE user_id=? AND date(created_at)=date('now')",(uid,)).fetchone()[0]
    top   = c.execute("SELECT endpoint,COUNT(*) as cnt FROM ky_api_logs WHERE user_id=? GROUP BY endpoint ORDER BY cnt DESC LIMIT 10",(uid,)).fetchall()
    c.close()
    with _ws_lock:
        live_c = len(_ws_live.get(uid,[]))
        test_c = len(_ws_test.get(uid,[]))
    return jsonify({"status":"ok","total_requests":total,"today_requests":today,
        "ws_live_cached":live_c,"ws_test_cached":test_c,
        "top_endpoints":[dict(x) for x in top]})

# ─── Admin API ────────────────────────────────────────────────────
@app.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    c = db()
    s = {"total_users": c.execute("SELECT COUNT(*) FROM ky_users").fetchone()[0],
         "verified":    c.execute("SELECT COUNT(*) FROM ky_users WHERE verified=1").fetchone()[0],
         "today_logs":  c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE date(created_at)=date('now')").fetchone()[0],
         "total_logs":  c.execute("SELECT COUNT(*) FROM ky_api_logs").fetchone()[0],
         "ivas_active_sessions": len(_ivas_sessions),
         "ws_live_active": sum(1 for v in _ws_status.values() if v.get("live_connected")),
         "ws_test_active": sum(1 for v in _ws_status.values() if v.get("connected"))}
    c.close()
    return jsonify({"status":"ok","stats":s})

@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    c = db()
    users = c.execute("SELECT id,username,nama,email,nomor_wa,role,verified,is_active,ivas_email,ivas_status,api_key,created_at,last_login FROM ky_users ORDER BY created_at DESC").fetchall()
    c.close()
    return jsonify({"status":"ok","total":len(users),"users":[dict(u) for u in users]})

@app.route("/api/admin/user/<int:uid>/toggle", methods=["POST"])
@admin_required
def api_admin_toggle(uid):
    c = db(); u = c.execute("SELECT * FROM ky_users WHERE id=?",(uid,)).fetchone()
    if not u: c.close(); return jsonify({"status":"error","message":"User tidak ditemukan"}), 404
    ns = 0 if u["is_active"] else 1
    c.execute("UPDATE ky_users SET is_active=? WHERE id=?",(ns,uid)); c.commit(); c.close()
    return jsonify({"status":"ok","is_active":ns})

@app.route("/api/admin/user/<int:uid>/delete", methods=["POST"])
@admin_required
def api_admin_delete(uid):
    if uid == session["uid"]: return jsonify({"status":"error","message":"Tidak bisa hapus diri sendiri"}), 400
    c = db(); c.execute("DELETE FROM ky_users WHERE id=?",(uid,)); c.commit(); c.close()
    return jsonify({"status":"ok"})

# ─── Health ───────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({
        "status":     "ok",
        "ivas_sessions": len(_ivas_sessions),
        "ws_live_active": sum(1 for v in _ws_status.values() if v.get("live_connected")),
        "ws_test_active": sum(1 for v in _ws_status.values() if v.get("connected")),
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
