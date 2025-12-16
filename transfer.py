#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import threading
import unicodedata
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, request, abort, url_for, send_file, Response
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import RequestEntityTooLarge

# ==============================================================================
# 配置区（默认值 + 环境变量覆盖）
# ==============================================================================

# 监听
BIND_HOST = os.environ.get("UD_BIND_HOST", "::")
BIND_PORT = int(os.environ.get("UD_BIND_PORT", "8000"))

# 存储目录
UPLOAD_DIR = Path(os.environ.get("UD_UPLOAD_DIR", "./uploads")).resolve()

# 上传大小限制
MAX_UPLOAD_MB = int(os.environ.get("UD_MAX_UPLOAD_MB", "50"))
MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024

# 上传鉴权：仅 POST /ud 生效；不设置则无需 key
API_KEY = os.environ.get("UD_API_KEY", "").strip()
REQUIRE_UPLOAD_AUTH = bool(API_KEY)

# 单 IP 上传限速：每 N 秒最多 1 次（0=关闭）
RATE_LIMIT_SECONDS = int(os.environ.get("UD_RATE_LIMIT_SECONDS", "10"))

# 待下载的 token/file 最多保留 N 份（0=不限制）
MAX_PENDING_FILES = int(os.environ.get("UD_MAX_PENDING_FILES", "10"))

# token/file 过期秒数（0=永不过期，不建议）
TOKEN_TTL_SECONDS = int(os.environ.get("UD_TOKEN_TTL_SECONDS", str(24 * 3600)))

# 清理线程周期（秒）
CLEANUP_INTERVAL_SECONDS = int(os.environ.get("UD_CLEANUP_INTERVAL_SECONDS", "120"))

# claimed/tmp 残留清理阈值（秒）——用于进程异常退出后的兜底清理
CLAIMED_GRACE_SECONDS = int(os.environ.get("UD_CLAIMED_GRACE_SECONDS", "1800"))  # 30min
TMP_GRACE_SECONDS = int(os.environ.get("UD_TMP_GRACE_SECONDS", "1800"))          # 30min

# 反代支持：让 url_for(_external=True) 带正确 host/proto/prefix
# 注意：ProxyFix 只应该在“前面确实有可信反代”的情况下开启
ENABLE_PROXY_FIX = os.environ.get("UD_ENABLE_PROXY_FIX", "1") != "0"
PROXY_FIX_X_FOR = int(os.environ.get("UD_PROXY_FIX_X_FOR", "1"))
PROXY_FIX_X_PROTO = int(os.environ.get("UD_PROXY_FIX_X_PROTO", "1"))
PROXY_FIX_X_HOST = int(os.environ.get("UD_PROXY_FIX_X_HOST", "1"))
PROXY_FIX_X_PREFIX = int(os.environ.get("UD_PROXY_FIX_X_PREFIX", "1"))  # X-Forwarded-Prefix

# 文件名支持中文：限制 UTF-8 字节长度（避免极端长名）
MAX_FILENAME_UTF8_BYTES = int(os.environ.get("UD_MAX_FILENAME_UTF8_BYTES", "200"))

# token 形式（secrets.token_urlsafe() 产生的字符集：A-Za-z0-9_-）
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,200}$")

TITLE = os.environ.get("UD_TITLE", "UD Relay")

# ==============================================================================
# Flask 初始化
# ==============================================================================
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

if ENABLE_PROXY_FIX:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=PROXY_FIX_X_FOR,
        x_proto=PROXY_FIX_X_PROTO,
        x_host=PROXY_FIX_X_HOST,
        x_prefix=PROXY_FIX_X_PREFIX,
    )

# 进程内限速（多 worker 需要 Redis 才能做到全局严格）
_last_upload_ts = {}
_rate_lock = threading.Lock()

# ==============================================================================
# 工具函数
# ==============================================================================
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def client_ip() -> str:
    # ProxyFix 启用后，remote_addr 可能来自 X-Forwarded-For（按 x_for 配置）
    return request.remote_addr or "unknown"

def wants_html() -> bool:
    fmt = (request.args.get("format") or "").lower()
    if fmt in ("text", "plain"):
        return False
    if fmt == "html":
        return True
    accept = (request.headers.get("Accept") or "").lower()
    ua = (request.headers.get("User-Agent") or "").lower()
    return ("text/html" in accept) and ("curl" not in ua) and ("httpie" not in ua)

def no_cache_headers(resp: Response) -> Response:
    # 确保下载不被浏览器/代理缓存
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

def truncate_utf8(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8", errors="ignore")
    if len(b) <= max_bytes:
        return s
    b = b[:max_bytes]
    while True:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            b = b[:-1]
            if not b:
                return ""

def sanitize_filename(raw: str) -> str:
    """
    支持中文文件名，同时防路径穿越：
    - 去掉目录部分
    - 禁止 / \\ 与控制字符
    - 替换 Windows 禁用字符 <>:"|?*
    - 去掉首尾空白与尾部点/空格
    - 限制 UTF-8 字节长度
    """
    if not raw:
        return ""
    raw = raw.split("/")[-1].split("\\")[-1]
    raw = unicodedata.normalize("NFC", raw).strip()
    raw = "".join(ch for ch in raw if ch >= " " and ch != "\x7f")
    raw = re.sub(r'[<>:"|?*]', "_", raw)
    raw = raw.replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    raw = raw.rstrip(" .")

    raw = truncate_utf8(raw, MAX_FILENAME_UTF8_BYTES).strip()
    if raw in ("", ".", ".."):
        return ""
    if "/" in raw or "\\" in raw:
        return ""
    return raw

def get_key_from_request() -> str:
    return (request.form.get("key") or request.args.get("key") or request.headers.get("X-API-Key") or "").strip()

def check_upload_auth() -> bool:
    if not REQUIRE_UPLOAD_AUTH:
        return True
    return get_key_from_request() == API_KEY

def rate_limit_upload() -> bool:
    if not RATE_LIMIT_SECONDS or RATE_LIMIT_SECONDS <= 0:
        return True
    ip = client_ip()
    now = time.time()
    with _rate_lock:
        last = _last_upload_ts.get(ip, 0.0)
        remain = RATE_LIMIT_SECONDS - (now - last)
        if remain > 0:
            return False
        _last_upload_ts[ip] = now
        return True

def token_meta_path(token: str) -> Path:
    return UPLOAD_DIR / f"{token}.json"

def claimed_meta_path(token: str) -> Path:
    return UPLOAD_DIR / f"{token}.claimed.json"

def write_json_atomic(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)

def cleanup_pair(meta: dict, meta_file: Path):
    # 删除对应文件 + meta
    try:
        stored = meta.get("stored_name")
        if stored:
            (UPLOAD_DIR / stored).unlink(missing_ok=True)
    except Exception:
        pass
    try:
        meta_file.unlink(missing_ok=True)
    except Exception:
        pass

def cleanup_orphans(now: float):
    # 兜底：清理异常退出残留的 .claimed.json / .claimed / .tmp
    for p in UPLOAD_DIR.iterdir():
        if not p.is_file():
            continue
        name = p.name
        try:
            age = now - p.stat().st_mtime
        except Exception:
            continue

        if name.endswith(".tmp") and age > TMP_GRACE_SECONDS:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        elif name.endswith(".claimed.json") and age > CLAIMED_GRACE_SECONDS:
            # 同时尝试删除对应的 .claimed 文件
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        elif name.endswith(".claimed") and age > CLAIMED_GRACE_SECONDS:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

def cleanup_tokens():
    now = time.time()

    # 0) 清理残留
    cleanup_orphans(now)

    # 1) 删除过期 token
    for mf in UPLOAD_DIR.glob("*.json"):
        if mf.name.endswith(".claimed.json"):
            continue
        try:
            meta = json.loads(mf.read_text(encoding="utf-8"))
            exp = int(meta.get("expires_at", 0) or 0)
            if exp and exp < now:
                cleanup_pair(meta, mf)
        except Exception:
            # 坏 meta 直接删
            try:
                mf.unlink(missing_ok=True)
            except Exception:
                pass

    # 2) 限制待下载数量（按 meta mtime 最旧优先清）
    if MAX_PENDING_FILES and MAX_PENDING_FILES > 0:
        metas = [p for p in UPLOAD_DIR.glob("*.json") if not p.name.endswith(".claimed.json")]
        if len(metas) > MAX_PENDING_FILES:
            metas.sort(key=lambda p: p.stat().st_mtime)
            for mf in metas[: max(0, len(metas) - MAX_PENDING_FILES)]:
                try:
                    meta = json.loads(mf.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
                cleanup_pair(meta, mf)

def cleanup_daemon():
    while True:
        try:
            cleanup_tokens()
        except Exception:
            pass
        time.sleep(CLEANUP_INTERVAL_SECONDS)

def make_external(endpoint: str, **kwargs) -> str:
    return url_for(endpoint, _external=True, **kwargs)

# ==============================================================================
# “像没网站”：404/405 默认空响应
# ==============================================================================
@app.errorhandler(404)
def not_found(_e):
    return ("", 404)

@app.errorhandler(405)
def not_allowed(_e):
    return ("", 405)

@app.errorhandler(RequestEntityTooLarge)
def too_large(_e):
    return (f"File too large (max {MAX_UPLOAD_MB}MB)\n", 413)

# ==============================================================================
# 页面渲染：/ud 同页显示错误或成功链接
# ==============================================================================
def render_ud_page(message: str = "", level: str = "info", download_url: str = ""):
    base = request.url_root.rstrip("/")
    key_note = "需要 key 才能上传" if REQUIRE_UPLOAD_AUTH else "无需 key"
    curl_key = "YOUR_KEY" if REQUIRE_UPLOAD_AUTH else ""
    curl_example = f'curl -sS -F "file=@/path/to/file" "{base}/ud?key={curl_key}"'.rstrip("?key=")

    if not wants_html():
        txt = f"""UD

GET  {base}/hc
GET  {base}/hp
GET  {base}/ud
POST {base}/ud
GET  {base}/ud/d/<token>   (one-time download, then 404)

curl upload:
  {curl_example}
"""
        return (txt, 200, {"Content-Type": "text/plain; charset=utf-8"})

    color = {"ok": "#46f2a6", "err": "#ff6b6b", "info": "#a7c5ff"}.get(level, "#a7c5ff")
    msg_block = ""
    if message:
        msg_block = f"""
        <div style="margin-top:12px;padding:10px 12px;border-radius:12px;
                    background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.12);">
          <div style="color:{color};font-weight:700;margin-bottom:6px;">{message}</div>
          {"<div class='muted'>下载链接（一次性）：</div><div style='margin-top:6px;word-break:break-all;'><a href='"+download_url+"'>"+download_url+"</a></div>" if download_url else ""}
        </div>
        """

    html = f"""<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{TITLE} - UD</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:0;background:#0b1220;color:#e8eefc}}
.wrap{{max-width:860px;margin:40px auto;padding:0 16px}}
.card{{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
border-radius:14px;padding:18px;box-shadow:0 12px 30px rgba(0,0,0,.25)}}
input[type=file],input[type=text]{{width:100%;padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,.18);
background:rgba(0,0,0,.25);color:#e8eefc}}
button{{padding:10px 14px;border-radius:10px;border:0;cursor:pointer;font-weight:700;background:#4b8cff;color:#071022}}
.muted{{color:#b7c3dd;font-size:13px}}
a{{color:#a7c5ff;text-decoration:none}}
pre{{background:rgba(0,0,0,.35);padding:12px;border-radius:10px;overflow:auto}}
</style></head><body>
<div class="wrap"><div class="card">
<h1 style="margin:0 0 10px;font-size:20px;">UD Upload（{key_note}）</h1>
<div class="muted">仅开放 /hc /hp /ud。上传成功返回一次性下载链接：下载成功后立即失效（再次访问为 404）。</div>

<form action="{base}/ud" method="post" enctype="multipart/form-data" style="margin-top:14px;">
  {"<div class='muted' style='margin:10px 0 6px;'>Key：</div><input type='text' name='key' placeholder='填入 key（错了会在本页提示）'/>" if REQUIRE_UPLOAD_AUTH else ""}
  <div class="muted" style="margin:10px 0 6px;">选择文件：</div>
  <input type="file" name="file" required/>
  <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
    <button type="submit">上传</button>
    <div class="muted">最大 {MAX_UPLOAD_MB}MB；单 IP {RATE_LIMIT_SECONDS}s 1 次；待下载最多 {MAX_PENDING_FILES} 份；TTL {TOKEN_TTL_SECONDS}s。</div>
  </div>
</form>

{msg_block}

<h2 style="margin-top:18px;font-size:16px;">curl 示例</h2>
<pre>{curl_example}</pre>

<div class="muted" style="margin-top:14px;">
  帮助：<a href="{base}/hp">{base}/hp</a> · 健康检查：<a href="{base}/hc">{base}/hc</a>
</div>
</div></div></body></html>"""
    return (html, 200, {"Content-Type": "text/html; charset=utf-8"})

# ==============================================================================
# 路由：/hc /hp /ud + /ud/d/<token>
# ==============================================================================

@app.route("/hc", methods=["GET"])
def hc():
    return ("ok\n", 200)

@app.route("/hp", methods=["GET"])
def hp():
    base = request.url_root.rstrip("/")
    curl_key = "YOUR_KEY" if REQUIRE_UPLOAD_AUTH else ""
    curl_upload = f'curl -sS -F "file=@/path/to/file" "{base}/ud?key={curl_key}"'.rstrip("?key=")

    text = f"""UD Help

GET  {base}/hc
GET  {base}/hp
GET  {base}/ud
POST {base}/ud
GET  {base}/ud/d/<token>   one-time download (then 404)

curl upload:
  {curl_upload}
"""
    if not wants_html():
        return (text, 200, {"Content-Type": "text/plain; charset=utf-8"})

    # 简洁 HTML（不赘述）
    html = f"""<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{TITLE} - Help</title></head><body style="font-family:system-ui;background:#0b1220;color:#e8eefc;padding:24px">
<h2>UD Help</h2>
<pre style="background:#111a2e;padding:12px;border-radius:10px;overflow:auto">{text}</pre>
<h3>Env vars</h3>
<pre style="background:#111a2e;padding:12px;border-radius:10px;overflow:auto">UD_API_KEY=...                   # optional; if set, POST /ud requires key
UD_UPLOAD_DIR=./uploads
UD_BIND_HOST=::
UD_BIND_PORT=8000
UD_MAX_UPLOAD_MB=50
UD_RATE_LIMIT_SECONDS=10          # 0 disables
UD_MAX_PENDING_FILES=10           # 0 disables
UD_TOKEN_TTL_SECONDS=86400        # 0 disables
UD_CLEANUP_INTERVAL_SECONDS=120
UD_ENABLE_PROXY_FIX=1
UD_PROXY_FIX_X_PREFIX=1
UD_CLAIMED_GRACE_SECONDS=1800
UD_TMP_GRACE_SECONDS=1800</pre>
</body></html>"""
    return (html, 200, {"Content-Type": "text/html; charset=utf-8"})

@app.route("/ud", methods=["GET"])
def ud_get():
    return render_ud_page()

@app.route("/ud", methods=["POST"])
def ud_post():
    # 网页端：key 错/限速/文件错误 都在本页提示，不跳转
    if REQUIRE_UPLOAD_AUTH and not check_upload_auth():
        return render_ud_page("Key 错误或缺失，上传未执行。", level="err")

    if not rate_limit_upload():
        return render_ud_page(f"上传过于频繁：每 {RATE_LIMIT_SECONDS}s 仅允许 1 次。", level="err")

    if "file" not in request.files:
        return render_ud_page("未选择文件（No file part）。", level="err") if wants_html() else ("No file part\n", 400)

    f = request.files["file"]
    if not f or f.filename == "":
        return render_ud_page("未选择文件（No selected file）。", level="err") if wants_html() else ("No selected file\n", 400)

    original_name = sanitize_filename(f.filename)
    if not original_name:
        return render_ud_page("文件名不合法（支持中文，但禁止路径/控制字符）。", level="err") if wants_html() else ("Invalid filename\n", 400)

    # 生成一次性 token；存储文件用 token（只保留扩展名）
    import secrets
    token = secrets.token_urlsafe(24)
    suffix = Path(original_name).suffix
    stored_name = token + (suffix if suffix else "")

    file_path = (UPLOAD_DIR / stored_name).resolve()
    tmp = (UPLOAD_DIR / (stored_name + ".tmp")).resolve()
    if UPLOAD_DIR not in file_path.parents or UPLOAD_DIR not in tmp.parents:
        return render_ud_page("内部路径错误。", level="err") if wants_html() else ("Invalid path\n", 400)

    f.save(tmp)
    os.replace(tmp, file_path)

    exp = int(time.time()) + TOKEN_TTL_SECONDS if TOKEN_TTL_SECONDS else 0
    meta = {
        "token": token,
        "stored_name": stored_name,
        "download_name": original_name,
        "created_at": now_utc_iso(),
        "expires_at": exp,
        "uploader_ip": client_ip(),
    }
    write_json_atomic(token_meta_path(token), meta)

    # 清理（过期 + 超量 + 残留）
    cleanup_tokens()

    dl = make_external("ud_download", token=token)
    if wants_html():
        return render_ud_page("上传成功！", level="ok", download_url=dl)

    return (f"OK\n{dl}\n", 201, {"Content-Type": "text/plain; charset=utf-8"})

@app.route("/ud/d/<token>", methods=["GET"])
def ud_download(token: str):
    # 一次性下载：成功一次后删除 meta + 文件；之后统一 404 空 body
    if not token or not TOKEN_RE.fullmatch(token):
        abort(404)

    meta_file = token_meta_path(token)
    claimed_meta = claimed_meta_path(token)

    # 已被抢占/已下载：统一 404
    if claimed_meta.exists():
        abort(404)

    if not meta_file.exists():
        abort(404)

    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
    except Exception:
        try:
            meta_file.unlink(missing_ok=True)
        except Exception:
            pass
        abort(404)

    exp = int(meta.get("expires_at") or 0)
    if exp and exp < time.time():
        cleanup_pair(meta, meta_file)
        abort(404)

    stored_name = meta.get("stored_name")
    download_name = meta.get("download_name") or "download.bin"
    if not stored_name:
        cleanup_pair(meta, meta_file)
        abort(404)

    path = (UPLOAD_DIR / stored_name).resolve()
    if UPLOAD_DIR not in path.parents or not path.exists() or not path.is_file():
        cleanup_pair(meta, meta_file)
        abort(404)

    # 抢占：meta.json -> meta.claimed.json（并发保护）
    try:
        os.replace(meta_file, claimed_meta)
    except Exception:
        abort(404)

    # 文件也改名，避免并发读取同一路径
    claimed_data_path = path.with_name(path.name + ".claimed")
    try:
        os.replace(path, claimed_data_path)
    except Exception:
        # 尽量回滚
        try:
            os.replace(claimed_meta, meta_file)
        except Exception:
            pass
        abort(404)

    resp = send_file(
        claimed_data_path,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/octet-stream",
        conditional=False,
        etag=False,
        max_age=0,
    )
    resp = no_cache_headers(resp)

    # 响应结束后清理：删除文件与 claimed meta（“曾经有效”的痕迹也会消失）
    def _cleanup():
        try:
            claimed_data_path.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            claimed_meta.unlink(missing_ok=True)
        except Exception:
            pass

    resp.call_on_close(_cleanup)
    return resp

# ==============================================================================
# 启动 banner：补充环境变量说明
# ==============================================================================
def print_startup_banner():
    print("\n=== UD Relay (stealth routes) ===")
    print(f"Bind: [{BIND_HOST}]:{BIND_PORT}")
    print(f"Upload dir: {UPLOAD_DIR}")
    print(f"Max upload: {MAX_UPLOAD_MB}MB")
    print(f"Upload auth (POST /ud): {'ON' if REQUIRE_UPLOAD_AUTH else 'OFF'}")
    print(f"Rate limit: {RATE_LIMIT_SECONDS}s per IP" if RATE_LIMIT_SECONDS else "Rate limit: OFF")
    print(f"Pending cap: {MAX_PENDING_FILES if MAX_PENDING_FILES else 'OFF'}")
    print(f"TTL: {TOKEN_TTL_SECONDS if TOKEN_TTL_SECONDS else 'OFF'} seconds")
    print(f"ProxyFix: {'ON' if ENABLE_PROXY_FIX else 'OFF'} (supports X-Forwarded-Host/Proto/Prefix)\n")

    print("Endpoints (others -> 404 empty body):")
    print("  GET  /hc")
    print("  GET  /hp  (no auth)")
    print("  GET  /ud  (no auth)")
    print("  POST /ud  (upload; key optional depending config)")
    print("  GET  /ud/d/<token> (one-time download; after success -> 404)\n")

    print("Environment variables:")
    print("  UD_API_KEY=...                   # optional; if set, POST /ud requires key")
    print("  UD_UPLOAD_DIR=./uploads")
    print("  UD_BIND_HOST=::")
    print("  UD_BIND_PORT=8000")
    print("  UD_MAX_UPLOAD_MB=50")
    print("  UD_RATE_LIMIT_SECONDS=10          # 0 disables")
    print("  UD_MAX_PENDING_FILES=10           # 0 disables")
    print("  UD_TOKEN_TTL_SECONDS=86400        # 0 disables")
    print("  UD_CLEANUP_INTERVAL_SECONDS=120")
    print("  UD_ENABLE_PROXY_FIX=1")
    print("  UD_PROXY_FIX_X_PREFIX=1")
    print("  UD_CLAIMED_GRACE_SECONDS=1800     # cleanup crash leftovers")
    print("  UD_TMP_GRACE_SECONDS=1800         # cleanup crash leftovers\n")

    if REQUIRE_UPLOAD_AUTH:
        print('curl upload example:')
        print(f'  curl -sS -F "file=@/path/to/file" "http://<host>:{BIND_PORT}/ud?key=YOUR_KEY"\n')
    else:
        print('curl upload example:')
        print(f'  curl -sS -F "file=@/path/to/file" "http://<host>:{BIND_PORT}/ud"\n')

if __name__ == "__main__":
    cleanup_tokens()
    threading.Thread(target=cleanup_daemon, daemon=True).start()
    print_startup_banner()
    app.run(host=BIND_HOST, port=BIND_PORT, threaded=True)
