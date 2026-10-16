#!/usr/bin/env python3
"""Local CPI quiz server with SQLite-backed test codes and admin tools."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CPI_DB", ROOT / "cpi.sqlite3"))
HOST = os.environ.get("CPI_HOST", "127.0.0.1")
PORT = int(os.environ.get("CPI_PORT", "8000"))
COOKIE_NAME = "cpi_admin_session"
SESSION_TTL = 8 * 60 * 60


def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def initialize():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS test_codes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          code_hash TEXT UNIQUE NOT NULL,
          code_display TEXT NOT NULL,
          label TEXT NOT NULL DEFAULT '',
          max_uses INTEGER NOT NULL DEFAULT 3,
          used_count INTEGER NOT NULL DEFAULT 0,
          active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS results (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          code_hash TEXT NOT NULL,
          score INTEGER NOT NULL,
          cpi INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL
        );
        """)
        admin = db.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()
        if not admin:
            password = secrets.token_urlsafe(9)
            db.execute("INSERT INTO settings(key,value) VALUES('admin_hash',?)", (hash_password(password),))
            db.commit()
            print(f"Admin password (save this now): {password}")
        default = "CPI-START-2026"
        digest = hash_code(default)
        if not db.execute("SELECT 1 FROM test_codes WHERE code_hash=?", (digest,)).fetchone():
            db.execute("INSERT INTO test_codes(code_hash,code_display,label,max_uses,created_at) VALUES(?,?,?,?,?)",
                       (digest, default, "示例测试密码", 3, int(time.time())))
        db.commit()


def hash_password(value: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${digest}"


def verify_password(value: str, stored: str) -> bool:
    try:
        salt, expected = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 200_000).hex()
        return hmac.compare_digest(actual, expected)
    except ValueError:
        return False


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


class Handler(BaseHTTPRequestHandler):
    server_version = "CPIQuiz/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, status, data, extra_headers=None):
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for key, value in extra_headers:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("请求内容过大")
        return json.loads(self.rfile.read(length) or b"{}")

    def session_valid(self):
        cookie = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(COOKIE_NAME)
        if not morsel:
            return False
        token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
        with connect() as db:
            row = db.execute("SELECT expires_at FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
            return bool(row and row["expires_at"] > int(time.time()))

    def require_admin(self):
        if not self.session_valid():
            self.send_json(401, {"error": "请先登录管理后台"})
            return False
        return True

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/admin/session":
            self.send_json(200, {"authenticated": self.session_valid()})
            return
        if path == "/api/admin/codes":
            if not self.require_admin(): return
            with connect() as db:
                rows = db.execute("""SELECT id,code_display,label,max_uses,used_count,active,created_at
                  FROM test_codes ORDER BY created_at DESC,id DESC""").fetchall()
                data = [dict(row) for row in rows]
                stats = db.execute("SELECT COUNT(*) codes, SUM(used_count) uses FROM test_codes").fetchone()
                results = db.execute("SELECT COUNT(*) count FROM results").fetchone()["count"]
            self.send_json(200, {"codes": data, "stats": {"codes": stats["codes"] or 0, "uses": stats["uses"] or 0, "results": results}})
            return
        if path == "/" or path == "/index.html":
            self.serve_file(ROOT / "index.html", "text/html; charset=utf-8")
            return
        if path == "/admin" or path == "/admin.html":
            self.serve_file(ROOT / "admin.html", "text/html; charset=utf-8")
            return
        self.send_json(404, {"error": "未找到"})

    def serve_file(self, path: Path, content_type: str):
        try:
            raw = path.read_bytes()
        except OSError:
            self.send_json(404, {"error": "文件不存在"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self.read_json()
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "请求内容无效"})
            return
        if path == "/api/validate":
            code = str(data.get("code", "")).strip()
            if not code or len(code) > 128:
                self.send_json(400, {"error": "请输入有效密码"})
                return
            digest = hash_code(code)
            with connect() as db:
                row = db.execute("SELECT max_uses,used_count,active FROM test_codes WHERE code_hash=?", (digest,)).fetchone()
                if not row or not row["active"]:
                    self.send_json(403, {"error": "密码无效或已停用"})
                    return
                if row["used_count"] >= row["max_uses"]:
                    self.send_json(403, {"error": "此密码的测评次数已用完"})
                    return
                db.execute("UPDATE test_codes SET used_count=used_count+1 WHERE code_hash=?", (digest,))
                db.commit()
            self.send_json(200, {"ok": True, "remaining": row["max_uses"] - row["used_count"] - 1})
            return
        if path == "/api/result":
            code = str(data.get("code", "")).strip()
            score, cpi = data.get("score"), data.get("cpi")
            if not code or not isinstance(score, int) or not isinstance(cpi, int) or not 12 <= score <= 48 or not 0 <= cpi <= 100:
                self.send_json(400, {"error": "结果数据无效"})
                return
            with connect() as db:
                db.execute("INSERT INTO results(code_hash,score,cpi,created_at) VALUES(?,?,?,?)",
                           (hash_code(code), score, cpi, int(time.time())))
                db.commit()
            self.send_json(200, {"ok": True})
            return
        if path == "/api/admin/login":
            password = str(data.get("password", ""))
            with connect() as db:
                row = db.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()
                if not row or not verify_password(password, row["value"]):
                    self.send_json(403, {"error": "管理员口令错误"})
                    return
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                expires = int(time.time()) + SESSION_TTL
                db.execute("INSERT INTO sessions(token_hash,expires_at) VALUES(?,?)", (token_hash, expires))
                db.commit()
            self.send_json(200, {"ok": True}, [("Set-Cookie", f"{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")])
            return
        if path == "/api/admin/logout":
            cookie = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get(COOKIE_NAME)
            if morsel:
                token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
                with connect() as db: db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            self.send_json(200, {"ok": True}, [("Set-Cookie", f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")])
            return
        if path.startswith("/api/admin/"):
            if not self.require_admin(): return
            if path == "/api/admin/codes":
                label = str(data.get("label", "")).strip()[:80]
                max_uses = data.get("max_uses", 3)
                quantity = data.get("quantity", 1)
                if not isinstance(max_uses, int) or not 1 <= max_uses <= 1000 or not isinstance(quantity, int) or not 1 <= quantity <= 100:
                    self.send_json(400, {"error": "次数需为 1–1000，每次最多生成 100 个密码"})
                    return
                codes = []
                with connect() as db:
                    for _ in range(quantity):
                        while True:
                            code = "CPI-" + secrets.token_hex(3).upper() + "-" + secrets.token_hex(2).upper()
                            digest = hash_code(code)
                            try:
                                db.execute("INSERT INTO test_codes(code_hash,code_display,label,max_uses,created_at) VALUES(?,?,?,?,?)",
                                           (digest, code, label, max_uses, int(time.time())))
                                codes.append(code)
                                break
                            except sqlite3.IntegrityError:
                                continue
                    db.commit()
                self.send_json(201, {"codes": codes})
                return
            if path == "/api/admin/change-password":
                current, new = str(data.get("current", "")), str(data.get("new", ""))
                if len(new) < 12:
                    self.send_json(400, {"error": "新管理员口令至少需要 12 个字符"})
                    return
                with connect() as db:
                    row = db.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()
                    if not row or not verify_password(current, row["value"]):
                        self.send_json(403, {"error": "当前管理员口令错误"})
                        return
                    db.execute("UPDATE settings SET value=? WHERE key='admin_hash'", (hash_password(new),))
                    db.execute("DELETE FROM sessions")
                    db.commit()
                self.send_json(200, {"ok": True}, [("Set-Cookie", f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")])
                return
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:3] == ["api", "admin", "codes"]:
                try: code_id = int(parts[3])
                except ValueError:
                    self.send_json(400, {"error": "密码编号无效"}); return
                action = data.get("action")
                with connect() as db:
                    row = db.execute("SELECT id FROM test_codes WHERE id=?", (code_id,)).fetchone()
                    if not row:
                        self.send_json(404, {"error": "密码不存在"}); return
                    if action == "reset":
                        db.execute("UPDATE test_codes SET used_count=0 WHERE id=?", (code_id,))
                    elif action == "toggle":
                        db.execute("UPDATE test_codes SET active=1-active WHERE id=?", (code_id,))
                    elif action == "delete":
                        db.execute("DELETE FROM test_codes WHERE id=?", (code_id,))
                    else:
                        self.send_json(400, {"error": "未知操作"}); return
                    db.commit()
                self.send_json(200, {"ok": True})
                return
        self.send_json(404, {"error": "未找到"})


if __name__ == "__main__":
    initialize()
    if len(sys.argv) > 1 and sys.argv[1] == "init-only":
        print(f"Database initialized: {DB_PATH}")
        raise SystemExit(0)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"CPI quiz running at http://{HOST}:{PORT}/")
    print(f"Admin dashboard: http://{HOST}:{PORT}/admin")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
