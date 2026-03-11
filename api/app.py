# ═══════════════════════════════════════════════════════════════════
#  KY-SHIRO API — iVAS SMS Platform
#  Developer : KY-SHIRO OFFICIAL
#  Telegram  : https://t.me/shiroky1
#  Email     : kikimodesad8@gmail.com
#  Instagram : @kiki_fzl1
# ═══════════════════════════════════════════════════════════════════

from flask import (Flask, request, jsonify, Response,
                   render_template, redirect, url_for, session, abort, stream_with_context)
from datetime import datetime, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from bs4 import BeautifulSoup
import threading, time, re, os, json, hashlib, secrets, sqlite3
import logging, gzip, random, html as html_lib, requests as req_lib

try:
    import cloudscraper
    def _make_scraper():
        s = cloudscraper.create_scraper(
            browser={"browser":"chrome","platform":"windows","mobile":False})
        s.headers.update({"Accept-Encoding":"gzip, deflate, br"})
        return s
except ImportError:
    def _make_scraper():
        s = req_lib.Session()
        s.headers.update({"Accept-Encoding":"gzip, deflate, br"})
        return s

try:
    import brotli as _brotli; _HAS_BROTLI = True
except ImportError:
    _HAS_BROTLI = False

try:
    import socketio as _sio; _HAS_SIO = True
except ImportError:
    _HAS_SIO = False

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("kyshiro")

# ─── Flask ───────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("SECRET_KEY", "kyshiro-change-this-secret")

# ─── iVAS Constants ──────────────────────────────────────────────────
IVAS_BASE  = "https://www.ivasms.com"
IVAS_LOGIN = f"{IVAS_BASE}/login"
IVAS_LIVE  = f"{IVAS_BASE}/portal/live/my_sms"
IVAS_RECV  = f"{IVAS_BASE}/portal/sms/received"
IVAS_WS    = "https://ivasms.com:2087"

_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

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
    # Admin default
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
# IVAS SESSION STORE  (per user, in-memory + DB status)
# ═══════════════════════════════════════════════════════════════════
# Key: user_id (int) → {scraper, csrf, recv_csrf, email, status, login_at, ...}
_ivas_sessions: dict = {}
_ivas_lock = threading.Lock()

# WS cache per user
_ws_live:   dict = {}  # user_id → deque(sms)
_ws_test:   dict = {}
_ws_status: dict = {}  # user_id → {connected, email, event}
_ws_clients:dict = {}  # user_id → sio client
_ws_lock  = threading.Lock()

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

def ajax_hdrs(referer=None):
    return {
        "Accept":           "text/html, */*; q=0.01",
        "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin":           IVAS_BASE,
        "Referer":          referer or IVAS_RECV,
    }

def to_ivas_date(s):
    try:
        return datetime.strptime(s, "%d/%m/%Y").strftime("%Y-%m-%d")
    except: return s

def _is_expired(r):
    if r is None: return True
    url = getattr(r,"url","") or ""
    if "/login" in url: return True
    try:
        t = r.text[:2000].lower()
        if any(k in t for k in ("forgot your password","login to your account")): return True
    except: pass
    return False

# ─── Login iVAS per user ──────────────────────────────────────────
def ivas_login(user_id: int, ivas_email: str, ivas_pass: str) -> dict:
    """Login ke iVAS dengan kredensial user. Simpan session ke memory."""
    scraper = _make_scraper()
    scraper.headers.update({"User-Agent": random.choice(_UA_LIST)})
    try:
        pg = scraper.get(IVAS_LOGIN, timeout=20)
        soup = BeautifulSoup(pg.text, "html.parser")
        tok_el = soup.find("input",{"name":"_token"})
        if not tok_el:
            return {"ok":False,"error":"Halaman login iVAS tidak bisa diakses"}
        tok = tok_el["value"]

        resp = scraper.post(IVAS_LOGIN,
            data={"email":ivas_email,"password":ivas_pass,"_token":tok},
            headers={"Content-Type":"application/x-www-form-urlencoded",
                     "Referer":IVAS_LOGIN,"Origin":IVAS_BASE},
            allow_redirects=True, timeout=20)

        if "/login" in resp.url:
            return {"ok":False,"error":"Email atau password iVAS salah"}

        # Ambil CSRF dari live page
        pg2  = scraper.get(IVAS_LIVE, timeout=15)
        html2 = decode_resp(pg2)
        soup2 = BeautifulSoup(html2,"html.parser")
        meta  = soup2.find("meta",{"name":"csrf-token"})
        inp   = soup2.find("input",{"name":"_token"})
        csrf  = (meta["content"] if meta else (inp["value"] if inp else tok))

        # CSRF khusus received
        recv_csrf = csrf
        try:
            pg3 = scraper.get(IVAS_RECV, timeout=15)
            h3  = decode_resp(pg3)
            s3  = BeautifulSoup(h3,"html.parser")
            m3  = s3.find("meta",{"name":"csrf-token"})
            i3  = s3.find("input",{"name":"_token"})
            if m3: recv_csrf = m3["content"]
            elif i3: recv_csrf = i3["value"]
            else:
                mm = re.search(r"['\"]_token['\"]\s*[,:]?\s*['\"]([A-Za-z0-9_\-+/=]{20,})['\"]",h3)
                if mm: recv_csrf = mm.group(1)
        except: pass

        # JWT & user hash for WS
        xsrf = scraper.cookies.get("XSRF-TOKEN","")
        from urllib.parse import unquote
        jwt_tok = unquote(xsrf) if xsrf and xsrf.startswith("eyJ") else scraper.cookies.get("laravel_session","")
        user_hash = ""
        livesms_event = ""
        uh_m = re.search(r"""[,{\s]\s*user\s*:\s*["']([a-f0-9]{32})["']""", html2)
        if uh_m: user_hash = uh_m.group(1)
        ev_m = re.search(r'liveSMSSocket\.on\s*\(\s*["\']([A-Za-z0-9+/=_\-]{30,})["\']', html2)
        if ev_m: livesms_event = ev_m.group(1)

        result = {
            "ok": True,
            "user_id":      user_id,
            "ivas_email":   ivas_email,
            "scraper":      scraper,
            "csrf":         csrf,
            "recv_csrf":    recv_csrf,
            "jwt_tok":      jwt_tok,
            "user_hash":    user_hash,
            "livesms_event":livesms_event,
            "live_html":    html2,
            "login_at":     datetime.now().isoformat(),
            "status":       "connected",
        }
        with _ivas_lock:
            _ivas_sessions[user_id] = result

        # Update DB status
        c = db()
        c.execute("UPDATE ky_users SET ivas_status='connected',ivas_login_at=? WHERE id=?",
                  (result["login_at"], user_id))
        c.commit(); c.close()

        logger.info(f"[iVAS] ✅ User {user_id} login sebagai {ivas_email}")
        return result

    except Exception as e:
        logger.error(f"[iVAS] User {user_id} login error: {e}")
        return {"ok":False,"error":str(e)}

def get_ivas_session(user_id: int, force=False) -> dict | None:
    with _ivas_lock:
        sess = _ivas_sessions.get(user_id)
    if sess and sess.get("ok") and not force:
        return sess
    return None  # Caller harus handle re-login

def do_ivas(user_id, method, url, data=None, headers=None):
    """Buat request ke iVAS pakai session user. Auto re-login kalau expired."""
    sess = get_ivas_session(user_id)
    if not sess:
        return None, "Belum login ke iVAS"
    scraper = sess["scraper"]
    for attempt in range(2):
        try:
            kw = dict(headers=headers, timeout=25, allow_redirects=True)
            if method.upper() == "POST":
                r = scraper.post(url, data=data, **kw)
            else:
                r = scraper.get(url, params=data, **kw)
            if _is_expired(r):
                # Re-login otomatis
                c2 = db()
                u  = c2.execute("SELECT ivas_email,ivas_pass FROM ky_users WHERE id=?",(user_id,)).fetchone()
                c2.close()
                if u and u["ivas_email"]:
                    new_sess = ivas_login(user_id, u["ivas_email"], u["ivas_pass"])
                    if new_sess.get("ok"):
                        scraper = new_sess["scraper"]
                        continue
                return None, "Session expired, re-login gagal"
            return r, None
        except Exception as e:
            logger.error(f"[iVAS-REQ] user={user_id} attempt={attempt}: {e}")
    return None, "Request gagal"

# ─── iVAS: Ranges ────────────────────────────────────────────────
def ivas_get_ranges(user_id, from_date, to_date):
    result = []
    def _add(name, rid):
        name = name.strip()
        rid  = (rid or name.replace(" ","_")).strip()
        if name and not any(r["name"]==name for r in result):
            result.append({"name":name,"id":rid})

    def _parse(html):
        for m in re.finditer(r"toggleRange\s*\(\s*'([^']+)'\s*,\s*'([^']+)'\s*\)", html):
            _add(m.group(1), m.group(2))
        if not result:
            for m in re.finditer(r'toggleRange\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', html):
                _add(m.group(1), m.group(2))
        if not result:
            soup = BeautifulSoup(html,"html.parser")
            for div in soup.select("div.rng"):
                oc = div.get("onclick","")
                m  = re.search(r"toggleRange[^(]*\(\s*'([^']+)'\s*,\s*'([^']+)'",oc)
                if m: _add(m.group(1), m.group(2))

    fd = to_ivas_date(from_date)
    td = to_ivas_date(to_date)
    for payload in [{"from":fd,"to":td},{"from":from_date,"to":to_date}]:
        r, err = do_ivas(user_id,"POST",
            f"{IVAS_BASE}/portal/sms/received/getsms",
            data=payload, headers=ajax_hdrs())
        if r and r.status_code==200:
            _parse(decode_resp(r))
            if result: break
    return result

# ─── iVAS: Numbers per range ─────────────────────────────────────
def ivas_get_numbers(user_id, range_name, from_date, to_date):
    rid = range_name.replace(" ","_")
    def _parse(html):
        nums = []
        def _add(num, nid=""):
            d = re.sub(r'\D','',str(num))
            if 7<=len(d)<=15 and not any(n["number"]==d for n in nums):
                nums.append({"number":d,"num_id":nid or d})
        for m in re.finditer(r"toggleNum\w*\s*\(\s*'(\d{7,15})'\s*,\s*'([^']+)'\s*\)",html):
            _add(m.group(1),m.group(2))
        if not nums:
            for m in re.finditer(r'toggleNum\w*\s*\(\s*"(\d{7,15})"\s*,\s*"([^"]+)"\s*\)',html):
                _add(m.group(1),m.group(2))
        if not nums:
            soup = BeautifulSoup(html,"html.parser")
            for el in soup.select("span.nnum"):
                raw = re.sub(r'\D','',el.get_text(strip=True))
                if raw: _add(raw)
        return nums
    fd = to_ivas_date(from_date); td = to_ivas_date(to_date)
    for payload in [
        {"start":fd,"end":td,"range":range_name},
        {"start":fd,"end":td,"range":rid},
        {"start":fd,"end":td,"range_name":range_name},
    ]:
        r, _ = do_ivas(user_id,"POST",
            f"{IVAS_BASE}/portal/sms/received/getsms/number",
            data=payload, headers=ajax_hdrs())
        if r and r.status_code==200:
            nums = _parse(decode_resp(r))
            if nums: return nums
    return []

# ─── iVAS: SMS per nomor ─────────────────────────────────────────
def ivas_get_sms(user_id, phone, range_name, from_date, to_date):
    rid = range_name.replace(" ","_")
    fd  = to_ivas_date(from_date); td = to_ivas_date(to_date)
    payloads = [
        {"start":fd,"end":td,"Number":phone,"Range":range_name},
        {"start":fd,"end":td,"Number":phone,"Range":rid},
        {"start":fd,"end":td,"number":phone,"range":range_name},
    ]
    messages = []
    def _add(t):
        t = html_lib.unescape(t).strip()
        if len(t)>3 and t not in messages: messages.append(t)

    for payload in payloads:
        r, _ = do_ivas(user_id,"POST",
            f"{IVAS_BASE}/portal/sms/received/getsms/number/sms",
            data=payload, headers=ajax_hdrs())
        if not r or r.status_code!=200: continue
        raw = decode_resp(r)
        if "spinner-border" in raw and len(raw)<500: continue
        if "Something went wrong" in raw and len(raw)<500: continue
        soup = BeautifulSoup(raw,"html.parser")
        for el in soup.select("div.msg-text,td.msg-text,p.msg-text,span.msg-text"):
            _add(el.get_text(separator="\n",strip=True))
        if not messages:
            for tbl in soup.find_all("table"):
                ths = [th.get_text(strip=True).lower() for th in tbl.find_all("th")]
                col = next((i for i,h in enumerate(ths)
                            if any(k in h for k in ("message","content","sms","text"))), None)
                if col is None: continue
                for tr in tbl.select("tbody tr"):
                    tds = tr.find_all("td")
                    if len(tds)>col:
                        inn = tds[col].select_one("div.msg-text,.msg-text")
                        t   = inn.get_text(separator="\n",strip=True) if inn \
                              else tds[col].get_text(separator="\n",strip=True)
                        if t and not t.isdigit(): _add(t)
        if messages: break
    return messages

# ─── iVAS: My Numbers (DataTables) ───────────────────────────────
def ivas_my_numbers(user_id, search="", length=200, page="test"):
    url  = f"{IVAS_BASE}/portal/numbers/{page}"
    sess = get_ivas_session(user_id)
    if not sess: return []
    params = {"draw":1,"start":0,"length":length,
              "search[value]":search,"search[regex]":"false",
              "columns[0][data]":"range","columns[1][data]":"test_number",
              "columns[2][data]":"A2P","columns[3][data]":"Limit_Range",
              "order[0][column]":"0","order[0][dir]":"asc"}
    try:
        r = sess["scraper"].get(url, params=params, timeout=15)
        return r.json().get("data",[])
    except Exception as e:
        logger.error(f"[MY-NUMS] {e}")
        return []

# ─── iVAS: Add Number ────────────────────────────────────────────
def ivas_add_number(user_id, termination_id):
    r, err = do_ivas(user_id,"POST",
        f"{IVAS_BASE}/portal/numbers/termination/number/add",
        data={"id":termination_id},
        headers={
            "Accept":"application/json, text/javascript, */*; q=0.01",
            "X-Requested-With":"XMLHttpRequest",
            "Referer":f"{IVAS_BASE}/portal/numbers/test",
            "Origin":IVAS_BASE,
            "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
        })
    if not r: return False, err
    try:
        j = r.json()
        if "success" in str(j).lower() or j.get("status") in ("success","ok",True,1):
            return True, j.get("message","Added")
        return False, str(j.get("message","Failed"))
    except:
        txt = r.text[:300]
        if "success" in txt.lower(): return True, "Added"
        return False, txt

# ─── iVAS: Delete Number ─────────────────────────────────────────
def ivas_delete_number(user_id, termination_id):
    for path in [
        "/portal/numbers/termination/number/delete",
        "/portal/numbers/termination/number/remove",
        "/portal/numbers/return",
    ]:
        r, err = do_ivas(user_id,"POST",f"{IVAS_BASE}{path}",
            data={"id":termination_id},
            headers={
                "Accept":"application/json, text/javascript, */*; q=0.01",
                "X-Requested-With":"XMLHttpRequest",
                "Referer":f"{IVAS_BASE}/portal/numbers/my",
                "Origin":IVAS_BASE,
                "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
            })
        if not r: continue
        try:
            j = r.json()
            if "success" in str(j).lower() or j.get("status") in ("success","ok",True,1):
                return True, j.get("message","Deleted")
        except:
            if "success" in r.text.lower(): return True, "Deleted"
    return False, "Delete gagal"

# ─── iVAS: WebSocket Live SMS ────────────────────────────────────
def _ws_start(user_id: int):
    """Start WebSocket koneksi untuk 1 user di background thread."""
    if not _HAS_SIO:
        logger.warning("[WS] python-socketio tidak tersedia")
        return
    sess = get_ivas_session(user_id)
    if not sess: return

    email         = sess["ivas_email"]
    jwt_tok       = sess["jwt_tok"]
    user_hash     = sess["user_hash"]
    livesms_event = sess["livesms_event"]
    scraper       = sess["scraper"]

    def _run():
        logger.info(f"[WS] Mulai WS untuk user={user_id} ({email})")
        while True:
            # Cek session masih valid
            cur_sess = get_ivas_session(user_id)
            if not cur_sess: break

            try:
                sio = _sio.Client(reconnection=False, logger=False, engineio_logger=False)

                def _save(data, source="live"):
                    orig = str(data.get("originator", data.get("cli",""))).replace("+","")
                    recp = str(data.get("recipient", data.get("number","")))
                    entry = {
                        "originator":  orig or recp,
                        "recipient":   recp,
                        "message":     str(data.get("message","")),
                        "sid":         str(data.get("sid","")),
                        "range":       str(data.get("range", data.get("termination_id",""))),
                        "paid":        "Paid" if float(data.get("client_revenue",0) or 0)>0 else "Unpaid",
                        "in_limit":    str(data.get("limit",1)) == "1",
                        "source":      source,
                        "account":     email,
                        "received_at": datetime.now().isoformat(),
                    }
                    with _ws_lock:
                        if user_id not in _ws_live:
                            _ws_live[user_id] = deque(maxlen=500)
                        _ws_live[user_id].appendleft(entry)

                @sio.event
                def connect():
                    with _ws_lock:
                        _ws_status[user_id] = {"connected":True,"email":email,"ts":datetime.now().isoformat()}
                    logger.info(f"[WS] ✅ Connected user={user_id}")

                @sio.event
                def disconnect():
                    with _ws_lock:
                        if user_id in _ws_status:
                            _ws_status[user_id]["connected"] = False
                    logger.info(f"[WS] Disconnected user={user_id}")

                if livesms_event:
                    @sio.on(livesms_event)
                    def on_dyn(data): _save(data,"live_dynamic")

                @sio.on("send_message_live")
                def on_live(data): _save(data,"live")

                @sio.on("send_message_max_Limit_231177")
                def on_limit(data): _save(data,"live_limit")

                @sio.on("send_message_test")
                def on_test(data):
                    entry = {
                        "originator": str(data.get("originator",data.get("cli",""))).replace("+",""),
                        "message":    str(data.get("message","")),
                        "sid":        str(data.get("sid","")),
                        "range":      str(data.get("range","")),
                        "source":     "test",
                        "received_at":datetime.now().isoformat(),
                    }
                    with _ws_lock:
                        if user_id not in _ws_test:
                            _ws_test[user_id] = deque(maxlen=200)
                        _ws_test[user_id].appendleft(entry)

                @sio.on("*")
                def on_any(ev, data):
                    known = {"connect","disconnect","connect_error",
                             "send_message_live","send_message_test","send_message_max_Limit_231177"}
                    if livesms_event: known.add(livesms_event)
                    if ev not in known and isinstance(data,dict):
                        if "message" in data or "originator" in data:
                            _save(data, f"catchall_{ev[:20]}")

                cookies = dict(scraper.cookies)
                cookie_str = "; ".join(f"{k}={v}" for k,v in cookies.items())
                auth = {"token":jwt_tok}
                if user_hash: auth["user"] = user_hash

                with _ws_lock:
                    _ws_clients[user_id] = sio

                sio.connect(IVAS_WS,
                    headers={"Cookie":cookie_str,"Origin":IVAS_BASE,
                             "Referer":IVAS_LIVE,
                             "User-Agent":random.choice(_UA_LIST)},
                    auth=auth,
                    transports=["websocket"],
                    socketio_path="/socket.io/",
                    namespaces=["/livesms"],
                    wait_timeout=15)
                sio.wait()

            except Exception as e:
                logger.error(f"[WS] user={user_id} error: {e}")
                with _ws_lock:
                    if user_id in _ws_status:
                        _ws_status[user_id]["connected"] = False

            # Tunggu sebelum reconnect
            cur_sess2 = get_ivas_session(user_id)
            if not cur_sess2: break
            time.sleep(10)

    t = threading.Thread(target=_run, name=f"ws-{user_id}", daemon=True)
    t.start()
    logger.info(f"[WS] Thread WS started untuk user={user_id}")

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
    """Kirim OTP via WA. Return (ok: bool, msg: str)"""
    pesan = (f"Halo {nama}!\n\n"
             f"Kode OTP kamu: *{otp}*\n\n"
             f"Berlaku 5 menit. Jangan bagikan ke siapapun.\n\n"
             f"— KY-SHIRO OFFICIAL")
    try:
        r = req_lib.post(f"{WA_URL}/send",
            json={"token":WA_TOKEN,"number":nomor,"message":pesan},
            timeout=10)
        if r.status_code == 200:
            return True, "OTP terkirim"
        return False, f"WA bot error: {r.status_code}"
    except Exception as e:
        logger.error(f"[WA] {e}")
        # Demo mode kalau WA bot belum aktif
        logger.info(f"[WA-DEMO] OTP untuk {nomor}: {otp}")
        return True, f"DEMO: OTP={otp} (WA bot belum aktif, cek log server)"

def _gen_otp(): return str(secrets.randbelow(900000)+100000)

# ═══════════════════════════════════════════════════════════════════
# AUTH DECORATORS
# ═══════════════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def _d(*a,**kw):
        if "uid" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"status":"error","message":"Login diperlukan"}),401
            return redirect(url_for("pg_login"))
        return f(*a,**kw)
    return _d

def admin_required(f):
    @wraps(f)
    def _d(*a,**kw):
        if "uid" not in session: return redirect(url_for("pg_login"))
        if session.get("role")!="admin": abort(403)
        return f(*a,**kw)
    return _d

def ivas_required(f):
    """Endpoint butuh user sudah login ke iVAS."""
    @wraps(f)
    def _d(*a,**kw):
        key = request.headers.get("X-API-Key") or request.args.get("api_key","")
        if key:
            c = db()
            u = c.execute("SELECT * FROM ky_users WHERE api_key=? AND is_active=1 AND verified=1",(key,)).fetchone()
            c.close()
            if not u: return jsonify({"status":"error","message":"API Key tidak valid"}),401
            uid = u["id"]
            sess = get_ivas_session(uid)
            if not sess:
                # Auto re-login kalau ada kredensial
                if u["ivas_email"] and u["ivas_pass"]:
                    r = ivas_login(uid, u["ivas_email"], u["ivas_pass"])
                    if not r.get("ok"):
                        return jsonify({"status":"error","message":f"Login iVAS gagal: {r.get('error')}"}),403
                else:
                    return jsonify({"status":"error","message":"Belum set kredensial iVAS"}),403
            request.uid = uid
            _log_api(uid, request.path, request.method, request.remote_addr, 200)
            return f(*a,**kw)

        if "uid" not in session:
            return jsonify({"status":"error","message":"Login diperlukan"}),401
        uid = session["uid"]
        sess = get_ivas_session(uid)
        if not sess:
            return jsonify({"status":"error","message":"Belum login ke iVAS. Pergi ke /dashboard/ivas-login"}),403
        request.uid = uid
        return f(*a,**kw)
    return _d

# ═══════════════════════════════════════════════════════════════════
# AUTH PAGES
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def pg_landing(): return render_template("landing.html")

@app.route("/login", methods=["GET","POST"])
def pg_login():
    if "uid" in session: return redirect(url_for("pg_dashboard"))
    err=None
    if request.method=="POST":
        uname = request.form.get("username","").strip()
        pw    = request.form.get("password","").strip()
        if not uname or not pw:
            err="Username dan password wajib diisi."
        else:
            c = db()
            u = c.execute("SELECT * FROM ky_users WHERE username=? AND is_active=1",(uname,)).fetchone()
            c.close()
            if not u: err="Username tidak ditemukan."
            elif u["password"]!=hashlib.sha256(pw.encode()).hexdigest(): err="Password salah."
            elif not u["verified"]: err="Akun belum diverifikasi. Cek WhatsApp."
            else:
                session["uid"]=u["id"]; session["username"]=u["username"]
                session["role"]=u["role"]; session["nama"]=u["nama"]
                c=db(); c.execute("UPDATE ky_users SET last_login=? WHERE id=?",(datetime.now().isoformat(),u["id"]))
                c.commit(); c.close()
                # Auto re-login iVAS kalau ada kredensial tersimpan
                if u["ivas_email"] and u["ivas_pass"]:
                    threading.Thread(target=ivas_login,
                        args=(u["id"],u["ivas_email"],u["ivas_pass"]),daemon=True).start()
                return redirect(url_for("pg_dashboard"))
    return render_template("auth/login.html",error=err)

@app.route("/register", methods=["GET","POST"])
def pg_register():
    if "uid" in session: return redirect(url_for("pg_dashboard"))
    err=None
    if request.method=="POST":
        username =request.form.get("username","").strip()
        nama     =request.form.get("nama","").strip()
        email    =request.form.get("email","").strip()
        nomor_wa =request.form.get("nomor_wa","").strip()
        password =request.form.get("password","").strip()
        password2=request.form.get("password2","").strip()
        if not all([username,nama,email,nomor_wa,password,password2]):
            err="Semua kolom wajib diisi."
        elif password!=password2: err="Password tidak cocok."
        elif len(password)<8: err="Password minimal 8 karakter."
        elif not re.match(r"^[a-zA-Z0-9_]{3,20}$",username):
            err="Username 3-20 karakter, hanya huruf, angka, underscore."
        elif not re.match(r"^\d{10,15}$",nomor_wa.replace("+","")):
            err="Format nomor WA tidak valid. Contoh: 6281234567890"
        else:
            c=db()
            if c.execute("SELECT id FROM ky_users WHERE username=?",(username,)).fetchone():
                err="Username sudah dipakai."
            elif c.execute("SELECT id FROM ky_users WHERE email=?",(email,)).fetchone():
                err="Email sudah terdaftar."
            c.close()
        if not err:
            ph  =hashlib.sha256(password.encode()).hexdigest()
            akey="ky-"+secrets.token_hex(24)
            otp =_gen_otp()
            exp =(datetime.now()+timedelta(minutes=5)).isoformat()
            c=db()
            c.execute("""INSERT INTO ky_users
                (username,nama,email,nomor_wa,password,api_key,otp_code,otp_expires,otp_type)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (username,nama,email,nomor_wa,ph,akey,otp,exp,"register"))
            c.commit(); c.close()
            ok,msg = send_otp_wa(nomor_wa,otp,nama)
            session["pending_verify"]=username
            return redirect(url_for("pg_verify_otp"))
    return render_template("auth/register.html",error=err)

@app.route("/verify-otp",methods=["GET","POST"])
def pg_verify_otp():
    uname=session.get("pending_verify","")
    if not uname: return redirect(url_for("pg_register"))
    err=None; ok=False
    if request.method=="POST":
        otp_in=request.form.get("otp","").strip()
        c=db(); u=c.execute("SELECT * FROM ky_users WHERE username=?",(uname,)).fetchone(); c.close()
        if not u: err="Akun tidak ditemukan."
        elif datetime.now().isoformat()>(u["otp_expires"] or ""): err="OTP kadaluarsa. Klik kirim ulang."
        elif otp_in!=u["otp_code"]: err="Kode OTP salah."
        else:
            c=db(); c.execute("UPDATE ky_users SET verified=1,otp_code=NULL,otp_expires=NULL WHERE username=?",(uname,))
            c.commit(); c.close()
            session.pop("pending_verify",None); ok=True
    return render_template("auth/verify_otp.html",error=err,success=ok,username=uname)

@app.route("/resend-otp",methods=["POST"])
def pg_resend_otp():
    uname=session.get("pending_verify","") or request.form.get("username","")
    c=db(); u=c.execute("SELECT * FROM ky_users WHERE username=?",(uname,)).fetchone(); c.close()
    if not u: return jsonify({"status":"error","message":"Akun tidak ditemukan"}),404
    otp=_gen_otp(); exp=(datetime.now()+timedelta(minutes=5)).isoformat()
    c=db(); c.execute("UPDATE ky_users SET otp_code=?,otp_expires=? WHERE username=?",(otp,exp,uname)); c.commit(); c.close()
    ok,msg=send_otp_wa(u["nomor_wa"],otp,u["nama"])
    return jsonify({"status":"ok","message":msg})

@app.route("/forgot-password",methods=["GET","POST"])
def pg_forgot():
    err=None; sent=False
    if request.method=="POST":
        idf=request.form.get("identifier","").strip()
        c=db(); u=c.execute("SELECT * FROM ky_users WHERE username=? OR email=?",(idf,idf)).fetchone(); c.close()
        if not u: err="Username atau email tidak ditemukan."
        else:
            otp=_gen_otp(); exp=(datetime.now()+timedelta(minutes=5)).isoformat()
            c=db(); c.execute("UPDATE ky_users SET otp_code=?,otp_expires=?,otp_type='reset' WHERE id=?",(otp,exp,u["id"])); c.commit(); c.close()
            send_otp_wa(u["nomor_wa"],otp,u["nama"])
            session["reset_uid"]=u["id"]; sent=True
    return render_template("auth/forgot.html",error=err,sent=sent)

@app.route("/reset-password",methods=["GET","POST"])
def pg_reset():
    uid=session.get("reset_uid")
    if not uid: return redirect(url_for("pg_forgot"))
    err=None; ok=False
    if request.method=="POST":
        otp_in=request.form.get("otp","").strip()
        pw=request.form.get("password","").strip()
        pw2=request.form.get("password2","").strip()
        if pw!=pw2: err="Password tidak cocok."
        elif len(pw)<8: err="Minimal 8 karakter."
        else:
            c=db(); u=c.execute("SELECT * FROM ky_users WHERE id=?",(uid,)).fetchone(); c.close()
            if not u or datetime.now().isoformat()>(u["otp_expires"] or ""): err="OTP kadaluarsa."
            elif otp_in!=u["otp_code"]: err="OTP salah."
            else:
                ph=hashlib.sha256(pw.encode()).hexdigest()
                c=db(); c.execute("UPDATE ky_users SET password=?,otp_code=NULL,otp_expires=NULL WHERE id=?",(ph,uid)); c.commit(); c.close()
                session.pop("reset_uid",None); ok=True
    return render_template("auth/reset.html",error=err,success=ok)

@app.route("/logout")
def pg_logout():
    uid=session.get("uid")
    if uid:
        # Hentikan WS
        with _ws_lock:
            sio=_ws_clients.pop(uid,None)
            _ws_status.pop(uid,None)
            _ws_live.pop(uid,None)
        if sio:
            try: sio.disconnect()
            except: pass
        with _ivas_lock: _ivas_sessions.pop(uid,None)
    session.clear()
    return redirect(url_for("pg_landing"))

# ═══════════════════════════════════════════════════════════════════
# DASHBOARD PAGES
# ═══════════════════════════════════════════════════════════════════
def _get_user():
    c=db()
    u=c.execute("SELECT * FROM ky_users WHERE id=?",(session["uid"],)).fetchone()
    c.close()
    return dict(u)

@app.route("/dashboard")
@login_required
def pg_dashboard():
    u=_get_user()
    uid=session["uid"]
    sess=get_ivas_session(uid)
    with _ws_lock: ws_total=len(_ws_live.get(uid,[]))
    return render_template("dashboard/index.html",user=u,
        ivas_connected=bool(sess and sess.get("ok")),ws_total=ws_total)

@app.route("/dashboard/ivas-login",methods=["GET","POST"])
@login_required
def pg_ivas_login():
    u=_get_user(); err=None; ok=False
    if request.method=="POST":
        ie=request.form.get("ivas_email","").strip()
        ip=request.form.get("ivas_pass","").strip()
        if not ie or not ip: err="Email dan password iVAS wajib diisi."
        else:
            result=ivas_login(session["uid"],ie,ip)
            if result.get("ok"):
                # Simpan kredensial ke DB
                c=db()
                c.execute("UPDATE ky_users SET ivas_email=?,ivas_pass=?,ivas_status='connected' WHERE id=?",
                          (ie,ip,session["uid"]))
                c.commit(); c.close()
                # Start WS
                threading.Thread(target=_ws_start,args=(session["uid"],),daemon=True).start()
                ok=True
            else: err=result.get("error","Login iVAS gagal")
    return render_template("dashboard/ivas_login.html",user=u,error=err,success=ok)

@app.route("/dashboard/sms-live")
@login_required
def pg_sms_live():
    return render_template("dashboard/sms_live.html",user=_get_user())

@app.route("/dashboard/sms-received")
@login_required
def pg_sms_received():
    return render_template("dashboard/sms_received.html",user=_get_user())

@app.route("/dashboard/numbers")
@login_required
def pg_numbers():
    return render_template("dashboard/numbers.html",user=_get_user())

@app.route("/dashboard/check-number")
@login_required
def pg_check_number():
    return render_template("dashboard/check_number.html",user=_get_user())

@app.route("/dashboard/ranges")
@login_required
def pg_ranges():
    return render_template("dashboard/ranges.html",user=_get_user())

@app.route("/dashboard/apikey")
@login_required
def pg_apikey():
    return render_template("dashboard/apikey.html",user=_get_user())

@app.route("/dashboard/docs")
@login_required
def pg_docs():
    return render_template("dashboard/docs.html",user=_get_user())

@app.route("/dashboard/profile")
@login_required
def pg_profile():
    return render_template("dashboard/profile.html",user=_get_user())

@app.route("/admin")
@admin_required
def pg_admin():
    c=db()
    users=c.execute("SELECT * FROM ky_users ORDER BY created_at DESC").fetchall()
    logs=c.execute("""SELECT l.*,u.username FROM ky_api_logs l
        LEFT JOIN ky_users u ON l.user_id=u.id
        ORDER BY l.created_at DESC LIMIT 200""").fetchall()
    stats={
        "total_users":c.execute("SELECT COUNT(*) FROM ky_users").fetchone()[0],
        "verified":c.execute("SELECT COUNT(*) FROM ky_users WHERE verified=1").fetchone()[0],
        "today_logs":c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE date(created_at)=date('now')").fetchone()[0],
        "total_logs":c.execute("SELECT COUNT(*) FROM ky_api_logs").fetchone()[0],
        "ivas_active":len(_ivas_sessions),
    }
    c.close()
    u={"username":session["username"],"nama":session.get("nama","Admin"),"role":"admin"}
    return render_template("dashboard/admin.html",users=[dict(x) for x in users],
        logs=[dict(x) for x in logs],stats=stats,user=u)

# ═══════════════════════════════════════════════════════════════════
# iVAS API ENDPOINTS  (proxy langsung ke iVAS)
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/ivas/login",methods=["POST"])
@login_required
def api_ivas_login():
    """Login ke iVAS dengan kredensial user sendiri."""
    ie=request.form.get("ivas_email","") or request.json.get("ivas_email","") if request.is_json else ""
    ip_=request.form.get("ivas_pass","") or (request.json.get("ivas_pass","") if request.is_json else "")
    if not ie or not ip_:
        return jsonify({"status":"error","message":"ivas_email dan ivas_pass wajib"}),400
    uid=session["uid"]
    result=ivas_login(uid,ie,ip_)
    if result.get("ok"):
        c=db(); c.execute("UPDATE ky_users SET ivas_email=?,ivas_pass=?,ivas_status='connected' WHERE id=?",(ie,ip_,uid))
        c.commit(); c.close()
        threading.Thread(target=_ws_start,args=(uid,),daemon=True).start()
        return jsonify({"status":"ok","message":"Login iVAS berhasil","email":ie})
    return jsonify({"status":"error","message":result.get("error","Login gagal")}),401

@app.route("/api/ivas/status")
@login_required
def api_ivas_status():
    uid=session["uid"]
    sess=get_ivas_session(uid)
    with _ws_lock:
        ws_stat=_ws_status.get(uid,{})
        ws_count=len(_ws_live.get(uid,[]))
    c=db(); u=c.execute("SELECT ivas_email,ivas_status,ivas_login_at FROM ky_users WHERE id=?",(uid,)).fetchone(); c.close()
    return jsonify({
        "status":"ok",
        "ivas_connected": bool(sess and sess.get("ok")),
        "ivas_email":     u["ivas_email"] if u else "",
        "ivas_status":    u["ivas_status"] if u else "disconnected",
        "ivas_login_at":  u["ivas_login_at"] if u else None,
        "ws_connected":   ws_stat.get("connected",False),
        "ws_cached_sms":  ws_count,
    })

@app.route("/api/ivas/logout",methods=["POST"])
@login_required
def api_ivas_logout():
    uid=session["uid"]
    with _ws_lock:
        sio=_ws_clients.pop(uid,None)
        _ws_status.pop(uid,None)
    if sio:
        try: sio.disconnect()
        except: pass
    with _ivas_lock: _ivas_sessions.pop(uid,None)
    c=db(); c.execute("UPDATE ky_users SET ivas_status='disconnected' WHERE id=?",(uid,)); c.commit(); c.close()
    return jsonify({"status":"ok","message":"Logout dari iVAS berhasil"})

# ─── SMS Live ────────────────────────────────────────────────────
@app.route("/api/sms/live")
@ivas_required
def api_sms_live():
    uid    = request.uid
    limit  = min(int(request.args.get("limit",50)),500)
    sid_f  = request.args.get("sid","").lower()
    since  = request.args.get("since","")
    with _ws_lock:
        items = list(_ws_live.get(uid,[]))[:limit]
    if sid_f: items=[i for i in items if sid_f in i.get("sid","").lower()]
    if since:  items=[i for i in items if i.get("received_at","")>since]
    return jsonify({"status":"ok","source":"websocket","total":len(items),"sms":items})

@app.route("/api/sms/live/stream")
@ivas_required
def api_sms_live_stream():
    """SSE stream — push otomatis tiap ada SMS baru."""
    uid   = request.uid
    sid_f = request.args.get("sid","").lower()
    last_ts = [""]
    def _gen():
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            with _ws_lock:
                items = list(_ws_live.get(uid,[]))
            new = [i for i in items if i.get("received_at","")>last_ts[0]]
            if sid_f: new=[i for i in new if sid_f in i.get("sid","").lower()]
            for i in new:
                yield f"data: {json.dumps(i)}\n\n"
                if i.get("received_at","") > last_ts[0]:
                    last_ts[0] = i["received_at"]
            time.sleep(2)
    return Response(stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/sms/live/clear",methods=["POST"])
@ivas_required
def api_sms_live_clear():
    uid=request.uid
    with _ws_lock: _ws_live.pop(uid,None)
    return jsonify({"status":"ok","message":"Cache SMS live dikosongkan"})

# ─── SMS Received ─────────────────────────────────────────────────
@app.route("/api/sms/received")
@ivas_required
def api_sms_received():
    uid  = request.uid
    rng  = request.args.get("range","").strip()
    num  = request.args.get("number","").strip()
    fd   = request.args.get("from", datetime.now().strftime("%Y-%m-%d"))
    td   = request.args.get("to",   datetime.now().strftime("%Y-%m-%d"))
    if not rng: return jsonify({"status":"error","message":"Parameter 'range' wajib"}),400
    if not num: return jsonify({"status":"error","message":"Parameter 'number' wajib"}),400
    msgs = ivas_get_sms(uid,num,rng,fd,td)
    return jsonify({"status":"ok","number":num,"range":rng,
                    "total":len(msgs),"messages":msgs})

# ─── Ranges ───────────────────────────────────────────────────────
@app.route("/api/ranges")
@ivas_required
def api_ranges():
    uid = request.uid
    fd  = request.args.get("from", datetime.now().strftime("%Y-%m-%d"))
    td  = request.args.get("to",   datetime.now().strftime("%Y-%m-%d"))
    rngs = ivas_get_ranges(uid,fd,td)
    return jsonify({"status":"ok","total":len(rngs),"ranges":rngs})

# ─── Numbers per range ────────────────────────────────────────────
@app.route("/api/numbers")
@ivas_required
def api_numbers():
    uid = request.uid
    rng = request.args.get("range","").strip()
    fd  = request.args.get("from", datetime.now().strftime("%Y-%m-%d"))
    td  = request.args.get("to",   datetime.now().strftime("%Y-%m-%d"))
    if not rng: return jsonify({"status":"error","message":"Parameter 'range' wajib"}),400
    nums = ivas_get_numbers(uid,rng,fd,td)
    return jsonify({"status":"ok","range":rng,"total":len(nums),"numbers":nums})

# ─── My Numbers ───────────────────────────────────────────────────
@app.route("/api/numbers/my")
@ivas_required
def api_numbers_my():
    uid    = request.uid
    search = request.args.get("search","").strip()
    page   = request.args.get("page","test")  # test atau my
    length = min(int(request.args.get("limit",200)),1000)
    rows   = ivas_my_numbers(uid,search,length,page)
    clean  = []
    for row in rows:
        def _s(k): return re.sub(r"<[^>]+>","",str(row.get(k,""))).strip()
        clean.append({
            "number":  _s("test_number") or _s("number"),
            "range":   _s("range"),
            "a2p":     _s("A2P"),
            "limit":   _s("Limit_Range"),
            "term_id": str(row.get("id",row.get("DT_RowId",""))),
        })
    return jsonify({"status":"ok","page":page,"total":len(clean),"numbers":clean})

# ─── Check Number ─────────────────────────────────────────────────
@app.route("/api/check-number")
@ivas_required
def api_check_number():
    uid = request.uid
    num = request.args.get("number","").strip()
    if not num: return jsonify({"status":"error","message":"Parameter 'number' wajib"}),400
    rows = ivas_my_numbers(uid,search=num,length=50,page="test")
    if not rows: rows = ivas_my_numbers(uid,search=num,length=50,page="my")
    for row in rows:
        def _s(k): return re.sub(r"<[^>]+>","",str(row.get(k,""))).strip()
        raw_num = _s("test_number") or _s("number")
        if re.sub(r"\D","",raw_num) == re.sub(r"\D","",num):
            return jsonify({"status":"ok","found":True,
                "number": raw_num,
                "range":  _s("range"),
                "a2p":    _s("A2P"),
                "term_id":str(row.get("id",row.get("DT_RowId","")))})
    return jsonify({"status":"ok","found":False,"number":num})

# ─── Add Number ───────────────────────────────────────────────────
@app.route("/api/numbers/add",methods=["GET","POST"])
@ivas_required
def api_add_number():
    uid  = request.uid
    data = request.get_json(silent=True) or {}
    term_id    = (data.get("termination_id","") or request.form.get("termination_id","") or request.args.get("termination_id","")).strip()
    range_name = (data.get("range_name","") or request.form.get("range_name","") or request.args.get("range_name","")).strip()
    number     = (data.get("number","") or request.form.get("number","") or request.args.get("number","")).strip()

    if not term_id and not range_name and not number:
        return jsonify({"status":"error",
            "message":"Wajib isi salah satu: termination_id / range_name / number",
            "contoh":{
                "by_termination_id":"/api/numbers/add?termination_id=82774",
                "by_range":"/api/numbers/add?range_name=PAKISTAN+34",
                "by_number":"/api/numbers/add?number=923008264692",
            }}),400

    results=[]; errors=[]

    if term_id:
        ok,msg = ivas_add_number(uid,term_id)
        return jsonify({"status":"ok" if ok else "error",
                        "termination_id":term_id,"success":ok,"message":msg})

    if range_name or number:
        rows = ivas_my_numbers(uid,search=range_name or number,length=500,page="test")
        rn_low = (range_name or "").lower()
        for row in rows:
            def _s(k): return re.sub(r"<[^>]+>","",str(row.get(k,""))).strip()
            rng   = _s("range")
            raw_num=_s("test_number") or _s("number")
            # Match range atau nomor
            if range_name and rn_low not in rng.lower(): continue
            if number and re.sub(r"\D","",raw_num)!=re.sub(r"\D","",number): continue
            tid = str(row.get("id",row.get("DT_RowId",""))).strip()
            m   = re.search(r"(\d+)",tid); tid=m.group(1) if m else tid
            if not tid: continue
            ok,msg=ivas_add_number(uid,tid)
            (results if ok else errors).append({"number":raw_num,"range":rng,"termination_id":tid,"message":msg})
            time.sleep(0.2)
        return jsonify({"status":"ok","added":len(results),"failed":len(errors),
                        "results":results,"errors":errors})

# ─── Delete Number ────────────────────────────────────────────────
@app.route("/api/numbers/delete",methods=["GET","POST"])
@ivas_required
def api_delete_number():
    uid  = request.uid
    data = request.get_json(silent=True) or {}
    term_id = (data.get("termination_id","") or request.form.get("termination_id","") or request.args.get("termination_id","")).strip()
    number  = (data.get("number","") or request.form.get("number","") or request.args.get("number","")).strip()
    if not term_id and not number:
        return jsonify({"status":"error","message":"Wajib isi termination_id atau number"}),400
    if not term_id and number:
        rows=ivas_my_numbers(uid,search=number,length=50,page="my")
        for row in rows:
            def _s(k): return re.sub(r"<[^>]+>","",str(row.get(k,""))).strip()
            raw=_s("number") or _s("test_number")
            if re.sub(r"\D","",raw)==re.sub(r"\D","",number):
                term_id=str(row.get("id",row.get("DT_RowId",""))).strip()
                m=re.search(r"(\d+)",term_id); term_id=m.group(1) if m else term_id
                break
    if not term_id:
        return jsonify({"status":"error","message":f"Nomor {number} tidak ditemukan"}),404
    ok,msg=ivas_delete_number(uid,term_id)
    return jsonify({"status":"ok" if ok else "error",
                    "termination_id":term_id,"success":ok,"message":msg})

# ─── WS Reconnect ─────────────────────────────────────────────────
@app.route("/api/ws/reconnect",methods=["POST"])
@ivas_required
def api_ws_reconnect():
    uid=request.uid
    with _ws_lock:
        sio=_ws_clients.pop(uid,None)
    if sio:
        try: sio.disconnect()
        except: pass
    threading.Thread(target=_ws_start,args=(uid,),daemon=True).start()
    return jsonify({"status":"ok","message":"WebSocket reconnect dimulai"})

# ─── User API ─────────────────────────────────────────────────────
@app.route("/api/me")
@login_required
def api_me():
    c=db()
    u=c.execute("SELECT id,username,nama,email,nomor_wa,role,api_key,ivas_email,ivas_status,created_at,last_login FROM ky_users WHERE id=?",(session["uid"],)).fetchone()
    c.close()
    return jsonify({"status":"ok","user":dict(u)})

@app.route("/api/regen-key",methods=["POST"])
@login_required
def api_regen_key():
    key="ky-"+secrets.token_hex(24)
    c=db(); c.execute("UPDATE ky_users SET api_key=? WHERE id=?",(key,session["uid"])); c.commit(); c.close()
    return jsonify({"status":"ok","api_key":key})

@app.route("/api/update-profile",methods=["POST"])
@login_required
def api_update_profile():
    nama=request.form.get("nama","").strip(); email=request.form.get("email","").strip()
    if not nama or not email: return jsonify({"status":"error","message":"Nama dan email wajib"}),400
    c=db(); c.execute("UPDATE ky_users SET nama=?,email=? WHERE id=?",(nama,email,session["uid"])); c.commit(); c.close()
    session["nama"]=nama
    return jsonify({"status":"ok"})

@app.route("/api/change-password",methods=["POST"])
@login_required
def api_change_pw():
    op=request.form.get("old_password","").strip()
    nw=request.form.get("new_password","").strip()
    nw2=request.form.get("new_password2","").strip()
    if not all([op,nw,nw2]): return jsonify({"status":"error","message":"Semua kolom wajib"}),400
    if nw!=nw2: return jsonify({"status":"error","message":"Password baru tidak cocok"}),400
    if len(nw)<8: return jsonify({"status":"error","message":"Minimal 8 karakter"}),400
    c=db(); u=c.execute("SELECT password FROM ky_users WHERE id=?",(session["uid"],)).fetchone(); c.close()
    if u["password"]!=hashlib.sha256(op.encode()).hexdigest():
        return jsonify({"status":"error","message":"Password lama salah"}),400
    ph=hashlib.sha256(nw.encode()).hexdigest()
    c=db(); c.execute("UPDATE ky_users SET password=? WHERE id=?",(ph,session["uid"])); c.commit(); c.close()
    return jsonify({"status":"ok","message":"Password berhasil diubah"})

# ─── Admin API ────────────────────────────────────────────────────
@app.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    c=db()
    s={"total_users":c.execute("SELECT COUNT(*) FROM ky_users").fetchone()[0],
       "verified":c.execute("SELECT COUNT(*) FROM ky_users WHERE verified=1").fetchone()[0],
       "today_logs":c.execute("SELECT COUNT(*) FROM ky_api_logs WHERE date(created_at)=date('now')").fetchone()[0],
       "total_logs":c.execute("SELECT COUNT(*) FROM ky_api_logs").fetchone()[0],
       "ivas_active_sessions":len(_ivas_sessions),
       "ws_active":sum(1 for v in _ws_status.values() if v.get("connected"))}
    c.close()
    return jsonify({"status":"ok","stats":s})

@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    c=db()
    users=c.execute("SELECT id,username,nama,email,nomor_wa,role,verified,is_active,ivas_email,ivas_status,api_key,created_at,last_login FROM ky_users ORDER BY created_at DESC").fetchall()
    c.close()
    return jsonify({"status":"ok","total":len(users),"users":[dict(u) for u in users]})

@app.route("/api/admin/user/<int:uid>/toggle",methods=["POST"])
@admin_required
def api_admin_toggle(uid):
    c=db(); u=c.execute("SELECT * FROM ky_users WHERE id=?",(uid,)).fetchone()
    if not u: c.close(); return jsonify({"status":"error","message":"User tidak ditemukan"}),404
    ns=0 if u["is_active"] else 1
    c.execute("UPDATE ky_users SET is_active=? WHERE id=?",(ns,uid)); c.commit(); c.close()
    return jsonify({"status":"ok","is_active":ns})

@app.route("/api/admin/user/<int:uid>/delete",methods=["POST"])
@admin_required
def api_admin_delete(uid):
    if uid==session["uid"]: return jsonify({"status":"error","message":"Tidak bisa hapus diri sendiri"}),400
    c=db(); c.execute("DELETE FROM ky_users WHERE id=?",(uid,)); c.commit(); c.close()
    return jsonify({"status":"ok"})

@app.route("/health")
def health():
    return jsonify({"status":"ok","ivas_sessions":len(_ivas_sessions),"ws_active":sum(1 for v in _ws_status.values() if v.get("connected"))})

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=False,threaded=True)
