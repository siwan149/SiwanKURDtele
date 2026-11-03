"""siwan__kurd panel — a small panel for Telegram (MTProto) proxy only.

- Admin panel: add users, set data quota + expiry, enable/disable, reset usage
- Subscription page per user: remaining volume, expiry, one-tap connect
- Runs alexbers/mtprotoproxy as a child process and meters traffic per user
"""
import asyncio
import hashlib
import hmac
import math
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import DictLoader, Environment

# --------------------------------------------------------------------------
# Settings (environment variables)
# --------------------------------------------------------------------------
BRAND = os.getenv("BRAND_NAME", "siwan__kurd")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS")
if not ADMIN_PASS:
    ADMIN_PASS = secrets.token_urlsafe(9)
    print(f"[siwan] ADMIN_PASS is not set. Temporary password: {ADMIN_PASS}", flush=True)
SECRET_KEY = os.getenv("SECRET_KEY") or hashlib.sha256(("k:" + ADMIN_PASS).encode()).hexdigest()

DATA_DIR = os.getenv("DATA_DIR") or ("/data" if os.path.isdir("/data") else "./data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "panel.db")

# Public address of the proxy (Railway TCP Proxy domain + port)
PROXY_HOST = os.getenv("PROXY_HOST", "")
PROXY_PORT = os.getenv("PROXY_PORT", "")
INTERNAL_PORT = int(os.getenv("INTERNAL_PORT", "8443"))
TLS_DOMAIN = os.getenv("TLS_DOMAIN", "www.google.com")
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")

PROXY_DIR = os.getenv("MTPROTO_DIR", "/opt/mtprotoproxy")
METRICS_PORT = 9100
POLL_SECONDS = 5

GB = 1024 ** 3


def now() -> int:
    return int(time.time())


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
_lock = threading.Lock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.execute(
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        secret TEXT NOT NULL,
        sub_token TEXT UNIQUE NOT NULL,
        quota INTEGER NOT NULL DEFAULT 0,
        used INTEGER NOT NULL DEFAULT 0,
        expire_at INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        created INTEGER NOT NULL
    )"""
)
_conn.commit()


def q(sql, args=(), one=False, write=False):
    with _lock:
        cur = _conn.execute(sql, args)
        if write:
            _conn.commit()
            return cur.lastrowid
        rows = cur.fetchall()
    if one:
        return dict(rows[0]) if rows else None
    return [dict(r) for r in rows]


def state(u) -> str:
    if not u["enabled"]:
        return "disabled"
    if u["expire_at"] and u["expire_at"] <= now():
        return "expired"
    if u["quota"] and u["used"] >= u["quota"]:
        return "exhausted"
    return "active"


def view(u):
    u = dict(u)
    u["state"] = state(u)
    u["remaining"] = max(u["quota"] - u["used"], 0) if u["quota"] else 0
    u["percent"] = min(round(u["used"] * 100 / u["quota"]), 100) if u["quota"] else 0
    if u["expire_at"]:
        u["days_left"] = max(math.ceil((u["expire_at"] - now()) / 86400), 0)
        u["expire_date"] = time.strftime("%Y-%m-%d", time.gmtime(u["expire_at"]))
    else:
        u["days_left"] = None
        u["expire_date"] = ""
    return u


def all_users():
    return [view(u) for u in q("SELECT * FROM users ORDER BY id DESC")]


# --------------------------------------------------------------------------
# MTProto proxy manager
# --------------------------------------------------------------------------
class Proxy:
    def __init__(self):
        self.proc = None
        self.last = {}
        self.active_ids = None

    def _active(self):
        return [u for u in all_users() if u["state"] == "active"]

    def _write_config(self, users):
        entries = {f"u{u['id']}": u["secret"] for u in users}
        if not entries:  # the proxy refuses to start without users
            entries = {"u0": secrets.token_hex(16)}
        cfg = (
            f"PORT = {INTERNAL_PORT}\n"
            f"USERS = {entries!r}\n"
            'MODES = {"classic": False, "secure": False, "tls": True}\n'
            f"TLS_DOMAIN = {TLS_DOMAIN!r}\n"
            f"METRICS_PORT = {METRICS_PORT}\n"
            'METRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"\n'
            'METRICS_WHITELIST = ["127.0.0.1"]\n'
            'METRICS_PREFIX = "mtproxy_"\n'
            "METRICS_EXPORT_LINKS = False\n"
        )
        with open(os.path.join(PROXY_DIR, "config.py"), "w") as f:
            f.write(cfg)

    def start(self):
        users = self._active()
        self._write_config(users)
        self.active_ids = {u["id"] for u in users}
        self.last = {}
        self.proc = subprocess.Popen(
            [sys.executable, "mtprotoproxy.py"], cwd=PROXY_DIR
        )
        print(f"[siwan] proxy started with {len(users)} active user(s)", flush=True)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def restart(self):
        self.stop()
        self.start()

    def _scrape(self):
        url = f"http://127.0.0.1:{METRICS_PORT}/"
        text = urllib.request.urlopen(url, timeout=3).read().decode()
        data = {}
        pat = re.compile(
            r'^mtproxy_user_octets_(from|to)_client\{user="u(\d+)"\}\s+([0-9.eE+-]+)', re.M
        )
        for direction, uid, val in pat.findall(text):
            row = data.setdefault(int(uid), [0, 0])
            row[0 if direction == "from" else 1] = int(float(val))
        return data

    def tick(self):
        if self.proc is None or self.proc.poll() is not None:
            self.start()
            return
        try:
            data = self._scrape()
        except Exception:
            return
        for uid, (a, b) in data.items():
            la, lb = self.last.get(uid, (0, 0))
            delta = (a - la if a >= la else a) + (b - lb if b >= lb else b)
            if delta > 0:
                q("UPDATE users SET used = used + ? WHERE id = ?", (delta, uid), write=True)
            self.last[uid] = (a, b)
        if {u["id"] for u in self._active()} != self.active_ids:
            self.restart()


PROXY = Proxy()


@asynccontextmanager
async def lifespan(app):
    PROXY.start()

    async def loop():
        while True:
            await asyncio.sleep(POLL_SECONDS)
            try:
                await asyncio.to_thread(PROXY.tick)
            except Exception as e:  # keep the loop alive
                print("[siwan] tick error:", e, flush=True)

    task = asyncio.create_task(loop())
    yield
    task.cancel()
    PROXY.stop()


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def _sign(msg: str) -> str:
    return hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()


def make_session() -> str:
    exp = str(now() + 7 * 86400)
    return f"{exp}.{_sign(exp)}"


def authed(request: Request) -> bool:
    tok = request.cookies.get("siwan_session", "")
    try:
        exp, sig = tok.split(".", 1)
        return int(exp) > now() and hmac.compare_digest(sig, _sign(exp))
    except Exception:
        return False


_fails = {}


def _blocked(ip: str) -> bool:
    recent = [t for t in _fails.get(ip, []) if t > now() - 600]
    _fails[ip] = recent
    return len(recent) >= 5


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def fmt(n) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def proxy_link(u, request: Request) -> str:
    host = PROXY_HOST or request.url.hostname or ""
    port = PROXY_PORT or str(INTERNAL_PORT)
    secret = "ee" + u["secret"] + TLS_DOMAIN.encode().hex()
    return f"https://t.me/proxy?server={host}&port={port}&secret={secret}"


def base_url(request: Request) -> str:
    return (PUBLIC_URL or str(request.base_url).rstrip("/")) + "/"


STATE_LABELS = {
    "active": "فعال",
    "disabled": "غیرفعال",
    "expired": "منقضی شده",
    "exhausted": "حجم تمام شده",
}

# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------
BASE = """<!doctype html>
<html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}{{ brand }}{% endblock %}</title>
<link rel="icon" href="/static/logo.png">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root{--red:#d8222c;--green:#1f8a3f;--sun:#f2b01e;--ink:#15221a;--mute:#64736a;--line:#dfe5e0;--bg:#f6f8f5;--card:#fff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:Vazirmatn,Tahoma,sans-serif;line-height:1.7}
.flag{display:flex;height:6px}.flag i{flex:1}.flag i:nth-child(1){background:var(--red)}.flag i:nth-child(2){background:#fff}.flag i:nth-child(3){background:var(--green)}
main{max-width:760px;margin:0 auto;padding:20px 16px 60px}
.num{direction:ltr;unicode-bidi:isolate;display:inline-block}
.head{display:flex;align-items:center;gap:12px;margin-bottom:22px}
.head img{width:48px;height:48px;border-radius:50%}
.head h1{margin:0;font-size:20px;font-weight:800;flex:1}
button,.btn{font:inherit;font-weight:600;border:0;border-radius:10px;padding:9px 16px;background:var(--green);color:#fff;cursor:pointer;text-decoration:none;display:inline-block}
button.ghost,.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
button.red{background:var(--red)}
button:focus-visible,.btn:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid var(--sun);outline-offset:2px}
input{font:inherit;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:#fff;min-width:0;width:100%}
label{font-size:13px;color:var(--mute);display:block}
.bar{height:8px;background:#e8ede9;border-radius:99px;overflow:hidden}
.bar b{display:block;height:100%;background:var(--green)}
.bar.warn b{background:var(--sun)}.bar.crit b{background:var(--red)}
.pill{font-size:12px;font-weight:600;padding:2px 10px;border-radius:99px;background:#e3f2e7;color:var(--green)}
.pill.disabled{background:#eceeed;color:var(--mute)}
.pill.expired,.pill.exhausted{background:#fbe6e7;color:var(--red)}
.note{background:#fff7e0;border:1px solid #f2dc9a;border-radius:10px;padding:10px 14px;font-size:14px;margin-bottom:18px}
@media (prefers-reduced-motion:no-preference){.bar b{transition:width .6s}}
{% block css %}{% endblock %}
</style></head><body>
<div class="flag"><i></i><i></i><i></i></div>
<main>{% block body %}{% endblock %}</main>
<script>
document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(!b)return;
navigator.clipboard.writeText(b.dataset.copy).then(function(){var t=b.textContent;b.textContent='کپی شد';setTimeout(function(){b.textContent=t},1500)})});
</script>
</body></html>"""

LOGIN = """{% extends "base" %}
{% block css %}.box{max-width:340px;margin:12vh auto 0;text-align:center}.box img{width:96px;height:96px;border-radius:50%}
.box form{display:grid;gap:12px;margin-top:20px;text-align:right}{% endblock %}
{% block body %}
<div class="box">
<img src="/static/logo.png" alt="">
<h1>{{ brand }}</h1>
<form method="post" action="/login">
<div><label for="u">نام کاربری</label><input id="u" name="username" autocomplete="username" required></div>
<div><label for="p">رمز عبور</label><input id="p" name="password" type="password" autocomplete="current-password" required></div>
{% if error %}<div class="note" style="margin:0">{{ error }}</div>{% endif %}
<button>ورود</button>
</form></div>
{% endblock %}"""

ADMIN = """{% extends "base" %}
{% block title %}{{ brand }} | پنل{% endblock %}
{% block css %}
.add{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:10px;align-items:end;padding-bottom:20px;border-bottom:1px solid var(--line);margin-bottom:8px}
.u{padding:16px 0;border-bottom:1px solid var(--line)}
.u .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.u .top strong{font-size:17px}
.u .meta{display:flex;justify-content:space-between;font-size:13px;color:var(--mute);margin:6px 0 8px}
.u .acts{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.u .acts button{padding:6px 12px;font-size:13px}
.u form{display:inline}
details{margin-top:10px}summary{cursor:pointer;font-size:13px;color:var(--mute)}
.edit{display:grid;grid-template-columns:1fr 1fr auto;gap:10px;align-items:end;margin-top:10px}
.empty{padding:40px 0;text-align:center;color:var(--mute)}
@media (max-width:560px){.add,.edit{grid-template-columns:1fr 1fr}.add>:first-child{grid-column:1/-1}}
{% endblock %}
{% block body %}
<div class="head"><img src="/static/logo.png" alt=""><h1>{{ brand }}</h1>
<form method="post" action="/logout"><button class="ghost">خروج</button></form></div>

{% if not proxy_host %}<div class="note">برای ساخت لینک درست، متغیرهای <span class="num">PROXY_HOST</span> و <span class="num">PROXY_PORT</span> را در Railway تنظیم کنید (آدرس TCP Proxy).</div>{% endif %}

<form class="add" method="post" action="/admin/users">
<div><label for="n">نام کاربر</label><input id="n" name="name" maxlength="40" required></div>
<div><label for="g">حجم (گیگابایت)</label><input id="g" name="gb" type="number" min="0" step="any" value="10"></div>
<div><label for="d">مدت (روز)</label><input id="d" name="days" type="number" min="0" value="30"></div>
<button>افزودن کاربر</button>
</form>
<div style="font-size:12px;color:var(--mute)">صفر یعنی نامحدود</div>

{% for u in users %}
<div class="u">
 <div class="top"><strong>{{ u.name }}</strong><span class="pill {{ u.state }}">{{ labels[u.state] }}</span></div>
 <div class="meta">
  <span><span class="num">{{ u.used|fmt }}</span> / {% if u.quota %}<span class="num">{{ u.quota|fmt }}</span>{% else %}نامحدود{% endif %}</span>
  <span>{% if u.days_left is none %}بدون انقضا{% elif u.state == 'expired' %}منقضی شده{% else %}<span class="num">{{ u.days_left }}</span> روز مانده{% endif %}</span>
 </div>
 {% if u.quota %}<div class="bar {% if u.percent >= 90 %}crit{% elif u.percent >= 70 %}warn{% endif %}"><b style="width:{{ u.percent }}%"></b></div>{% endif %}
 <div class="acts">
  <button type="button" data-copy="{{ base }}sub/{{ u.sub_token }}">کپی لینک اشتراک</button>
  <button type="button" class="ghost" data-copy="{{ links[u.id] }}">کپی لینک پروکسی</button>
  <form method="post" action="/admin/users/{{ u.id }}/toggle"><button class="ghost">{% if u.enabled %}غیرفعال کردن{% else %}فعال کردن{% endif %}</button></form>
  <form method="post" action="/admin/users/{{ u.id }}/reset"><button class="ghost">صفر کردن مصرف</button></form>
  <form method="post" action="/admin/users/{{ u.id }}/delete" onsubmit="return confirm('حذف شود؟')"><button class="red">حذف</button></form>
 </div>
 <details><summary>ویرایش حجم و مدت</summary>
  <form class="edit" method="post" action="/admin/users/{{ u.id }}/edit">
   <div><label>حجم کل (GB)</label><input name="gb" type="number" min="0" step="any" placeholder="بدون تغییر"></div>
   <div><label>مدت از امروز (روز)</label><input name="days" type="number" min="0" placeholder="بدون تغییر"></div>
   <button>ذخیره</button>
  </form>
 </details>
</div>
{% else %}
<div class="empty">هنوز کاربری اضافه نشده است. از فرم بالا اولین کاربر را بسازید.</div>
{% endfor %}
{% endblock %}"""

SUB = """{% extends "base" %}
{% block title %}{{ brand }} | {{ u.name }}{% endblock %}
{% block css %}
.s{text-align:center;padding-top:6vh}.s img{width:104px;height:104px;border-radius:50%}
.s h1{margin:10px 0 0;font-size:22px;font-weight:800}.who{color:var(--mute);margin:0 0 14px}
.big{font-size:52px;font-weight:800;line-height:1.2;margin-top:22px}
.lbl{color:var(--mute);margin-bottom:14px}
.s .bar{height:12px;max-width:420px;margin:0 auto}
dl{display:grid;grid-template-columns:1fr 1fr;gap:14px;max-width:420px;margin:26px auto;text-align:right}
dt{font-size:13px;color:var(--mute)}dd{margin:0;font-weight:600}
.cta{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.cta .btn{padding:13px 22px}
{% endblock %}
{% block body %}
<div class="s">
<img src="/static/logo.png" alt="">
<h1>{{ brand }}</h1>
<p class="who">{{ u.name }} <span class="pill {{ u.state }}">{{ labels[u.state] }}</span></p>
<div class="big">{% if u.quota %}<span class="num">{{ u.remaining|fmt }}</span>{% else %}نامحدود{% endif %}</div>
<div class="lbl">حجم باقی‌مانده</div>
{% if u.quota %}<div class="bar {% if u.percent >= 90 %}crit{% elif u.percent >= 70 %}warn{% endif %}"><b style="width:{{ u.percent }}%"></b></div>{% endif %}
<dl>
<div><dt>مصرف شده</dt><dd><span class="num">{{ u.used|fmt }}</span></dd></div>
<div><dt>حجم کل</dt><dd>{% if u.quota %}<span class="num">{{ u.quota|fmt }}</span>{% else %}نامحدود{% endif %}</dd></div>
<div><dt>زمان باقی‌مانده</dt><dd>{% if u.days_left is none %}بدون انقضا{% elif u.state == 'expired' %}منقضی شده{% else %}<span class="num">{{ u.days_left }}</span> روز{% endif %}</dd></div>
<div><dt>تاریخ پایان</dt><dd>{% if u.expire_date %}<span class="num">{{ u.expire_date }}</span>{% else %}—{% endif %}</dd></div>
</dl>
{% if u.state == 'active' %}
<div class="cta"><a class="btn" href="{{ link }}">اتصال به پروکسی تلگرام</a>
<button class="ghost" data-copy="{{ link }}">کپی لینک</button></div>
{% else %}<p>این اشتراک فعال نیست. برای تمدید با پشتیبانی تماس بگیرید.</p>{% endif %}
</div>
{% endblock %}"""

env = Environment(loader=DictLoader({"base": BASE, "login": LOGIN, "admin": ADMIN, "sub": SUB}), autoescape=True)
env.filters["fmt"] = fmt


def render(name, **ctx):
    return HTMLResponse(env.get_template(name).render(brand=BRAND, labels=STATE_LABELS, **ctx))


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(STATIC_DIR, exist_ok=True)
for _src in (os.path.join(BASE_DIR, "logo.png"), os.path.join(BASE_DIR, "static", "logo.png")):
    if os.path.isfile(_src):  # logo may sit in the repo root or in static/
        shutil.copyfile(_src, os.path.join(STATIC_DIR, "logo.png"))
        break
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def index():
    return RedirectResponse("/admin")


@app.get("/login")
def login_page():
    return render("login", error="")


@app.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form("")):
    ip = request.client.host if request.client else "?"
    if _blocked(ip):
        return render("login", error="تلاش‌های ناموفق زیاد بود. چند دقیقه بعد دوباره امتحان کنید.")
    ok = hmac.compare_digest(username.encode(), ADMIN_USER.encode()) and hmac.compare_digest(
        password.encode(), ADMIN_PASS.encode()
    )
    if not ok:
        _fails.setdefault(ip, []).append(now())
        return render("login", error="نام کاربری یا رمز عبور درست نیست.")
    resp = RedirectResponse("/admin", status_code=303)
    secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    resp.set_cookie("siwan_session", make_session(), max_age=7 * 86400, httponly=True, samesite="strict", secure=secure)
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("siwan_session")
    return resp


@app.get("/admin")
def admin(request: Request):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    users = all_users()
    links = {u["id"]: proxy_link(u, request) for u in users}
    return render("admin", users=users, links=links, base=base_url(request), proxy_host=bool(PROXY_HOST))


def _gb(value: str):
    value = (value or "").strip()
    if value == "":
        return None
    return max(int(float(value) * GB), 0)


def _days(value: str):
    value = (value or "").strip()
    if value == "":
        return None
    d = int(float(value))
    return 0 if d <= 0 else now() + d * 86400


@app.post("/admin/users")
def create_user(request: Request, name: str = Form(...), gb: str = Form("0"), days: str = Form("0")):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    name = name.strip()[:40]
    if name:
        try:
            q(
                "INSERT INTO users (name, secret, sub_token, quota, expire_at, created) VALUES (?,?,?,?,?,?)",
                (name, secrets.token_hex(16), secrets.token_urlsafe(16), _gb(gb) or 0, _days(days) or 0, now()),
                write=True,
            )
        except sqlite3.IntegrityError:
            pass  # duplicate name
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{uid}/edit")
def edit_user(request: Request, uid: int, gb: str = Form(""), days: str = Form("")):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    quota, expire = _gb(gb), _days(days)
    if quota is not None:
        q("UPDATE users SET quota=? WHERE id=?", (quota, uid), write=True)
    if expire is not None:
        q("UPDATE users SET expire_at=? WHERE id=?", (expire, uid), write=True)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{uid}/toggle")
def toggle_user(request: Request, uid: int):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    q("UPDATE users SET enabled = 1 - enabled WHERE id=?", (uid,), write=True)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{uid}/reset")
def reset_user(request: Request, uid: int):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    q("UPDATE users SET used=0 WHERE id=?", (uid,), write=True)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{uid}/delete")
def delete_user(request: Request, uid: int):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    q("DELETE FROM users WHERE id=?", (uid,), write=True)
    return RedirectResponse("/admin", status_code=303)


def _by_token(token: str):
    row = q("SELECT * FROM users WHERE sub_token=?", (token,), one=True)
    return view(row) if row else None


def _userinfo(u) -> str:
    return f"upload=0; download={u['used']}; total={u['quota']}; expire={u['expire_at']}"


@app.get("/sub/{token}")
def sub_page(request: Request, token: str):
    u = _by_token(token)
    if not u:
        return HTMLResponse("Not found", status_code=404)
    resp = render("sub", u=u, link=proxy_link(u, request))
    resp.headers["subscription-userinfo"] = _userinfo(u)
    resp.headers["cache-control"] = "no-store"
    return resp


@app.get("/sub/{token}/json")
def sub_json(request: Request, token: str):
    u = _by_token(token)
    if not u:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(
        {
            "name": u["name"],
            "state": u["state"],
            "used": u["used"],
            "total": u["quota"],
            "remaining": u["remaining"] if u["quota"] else None,
            "expire_at": u["expire_at"] or None,
            "link": proxy_link(u, request) if u["state"] == "active" else None,
        },
        headers={"subscription-userinfo": _userinfo(u), "cache-control": "no-store"},
    )
