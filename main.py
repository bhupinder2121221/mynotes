"""
AstraNotes - single-file FastAPI + SQLite notes and memorization web app.

Run:
  pip install fastapi uvicorn python-multipart
  python app.py

Open:
  http://127.0.0.1:8000
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
import uvicorn


APP_NAME = "AstraNotes"
APP_DIR = Path(__file__).resolve().parent


def default_data_dir() -> Path:
    """
    Keep SQLite outside OneDrive / cloud-synced project folders by default.

    On Windows this uses:
      %LOCALAPPDATA%\AstraNotes

    This avoids SQLite write/journal failures like:
      sqlite3.OperationalError: unable to open database file
    """
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
        return Path(root) / "AstraNotes"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "astranotes"


DATA_DIR = Path(os.environ.get("ASTRANOTES_DATA_DIR", str(default_data_dir()))).expanduser().resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.environ.get("ASTRANOTES_DB_PATH", str(DATA_DIR / "astranotes.sqlite3"))).expanduser().resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# One-time convenience migration: if an older DB exists beside app.py, copy it
# into the safe local data folder. Existing local DB is never overwritten.
LEGACY_DB_PATH = APP_DIR / "astranotes.sqlite3"
if not DB_PATH.exists() and LEGACY_DB_PATH.exists() and LEGACY_DB_PATH.resolve() != DB_PATH:
    try:
        import shutil
        shutil.copy2(LEGACY_DB_PATH, DB_PATH)
    except Exception:
        pass

SECRET_KEY = os.environ.get("ASTRANOTES_SECRET_KEY", "change-this-dev-secret-key")
SESSION_COOKIE = "astranotes_session"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database
    init_db()
    yield
    # Shutdown: Add cleanup here if needed


app = FastAPI(title=APP_NAME, lifespan=lifespan)


# -----------------------------
# Database
# -----------------------------
def db() -> sqlite3.Connection:
    """
    Open SQLite in a cloud-folder-safe way.

    WAL is intentionally not enabled. On Windows OneDrive/Dropbox folders,
    WAL often fails because SQLite has to create -wal and -shm sidecar files.
    Using a local app-data DB plus DELETE journaling is the most reliable
    setup for this single-user local app.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    try:
        conn.execute("PRAGMA journal_mode = DELETE")
    except sqlite3.OperationalError:
        # Last-resort fallback for hostile/synced filesystems.
        conn.execute("PRAGMA journal_mode = MEMORY")
    return conn


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS spaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                space_id INTEGER,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                tags TEXT DEFAULT '',
                is_favorite INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                importance INTEGER DEFAULT 3,
                memory_level INTEGER DEFAULT 0,
                visit_count INTEGER DEFAULT 0,
                last_position INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_visited_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(space_id) REFERENCES spaces(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                note_id INTEGER,
                text TEXT NOT NULL,
                label TEXT DEFAULT '',
                memory_bucket TEXT DEFAULT 'Review',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_notes_user_updated ON notes(user_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_notes_user_title_body ON notes(user_id, title, body);
            CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks(user_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS note_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                note_id INTEGER,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_note_activity_user_action_date ON note_activity(user_id, action, created_at DESC);

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                note_id INTEGER NOT NULL,
                selected_text TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(note_id) REFERENCES notes(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_comments_note ON comments(note_id, created_at DESC);
            """
        )


# Database initialization now handled by lifespan event handler


# -----------------------------
# Auth helpers: no external auth libs
# -----------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest_hex = stored.split("$", 1)
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180_000).hex()
        return hmac.compare_digest(test, digest_hex)
    except Exception:
        return False


def sign_payload(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    sig = hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def unsign_payload(token: str) -> Optional[dict]:
    try:
        raw, sig = token.split(".", 1)
        expected = hmac.new(SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return json.loads(base64.urlsafe_b64decode(raw.encode()).decode())
    except Exception:
        return None


def current_user(request: Request) -> Optional[sqlite3.Row]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    payload = unsign_payload(token)
    if not payload or not payload.get("user_id"):
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (payload["user_id"],)).fetchone()


def login_response(user_id: int) -> RedirectResponse:
    res = RedirectResponse("/", status_code=303)
    res.set_cookie(
        SESSION_COOKIE,
        sign_payload({"user_id": user_id, "ts": now_iso()}),
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 14,
    )
    return res


def require_user(request: Request):
    user = current_user(request)
    if not user:
        return None
    return user


# -----------------------------
# Inline template
# -----------------------------
HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ app_name }}</title>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg: #080b14;
      --panel: rgba(15, 23, 42, .70);
      --panel2: rgba(30, 41, 59, .74);
      --stroke: rgba(226, 232, 240, .18);
      --text: #f7fbff;
      --muted: #aebbd0;
      --accent: #38bdf8;
      --accent2: #a78bfa;
      --accent3: #22d3ee;
      --rose: #fb7185;
      --gold: #f8d477;
      --emerald: #34d399;
      --good: #86efac;
      --warn: #fde68a;
      --danger: #fca5a5;
      --shadow: 0 28px 110px rgba(0,0,0,.58);
      --radius: 26px;
    }

    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at 10% 12%, rgba(56,189,248,.34), transparent 24%),
        radial-gradient(circle at 78% 10%, rgba(167,139,250,.34), transparent 25%),
        radial-gradient(circle at 68% 84%, rgba(34,211,238,.18), transparent 27%),
        radial-gradient(circle at 20% 86%, rgba(251,113,133,.14), transparent 24%),
        linear-gradient(135deg, #050814 0%, #101729 43%, #151329 72%, #070a12 100%);
      overflow-x: hidden;
    }

    body:before {
      content: "";
      position: fixed;
      inset: -35%;
      pointer-events: none;
      background:
        linear-gradient(110deg, transparent 35%, rgba(255,255,255,.12) 45%, rgba(255,255,255,.03) 50%, transparent 60%),
        repeating-linear-gradient(90deg, rgba(255,255,255,.025) 0 1px, transparent 1px 52px);
      transform: rotate(9deg);
      animation: shine 12s linear infinite;
      mix-blend-mode: screen;
    }

    body:after {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px);
      background-size: 72px 72px;
      mask-image: radial-gradient(circle at 50% 20%, black, transparent 72%);
      opacity: .36;
    }

    @keyframes shine {
      0% { translate: -42% -24%; opacity: .18; }
      45% { opacity: .62; }
      100% { translate: 42% 24%; opacity: .18; }
    }

    @keyframes floatGlow {
      0%, 100% { transform: translateY(0) scale(1); filter: saturate(1); }
      50% { transform: translateY(-3px) scale(1.01); filter: saturate(1.16); }
    }

    @keyframes borderPulse {
      0%, 100% { box-shadow: inset 0 1px 0 rgba(255,255,255,.12), 0 22px 80px rgba(0,0,0,.34); }
      50% { box-shadow: inset 0 1px 0 rgba(255,255,255,.20), 0 28px 95px rgba(56,189,248,.12); }
    }

    a { color: inherit; text-decoration: none; }
    button, input, textarea, select {
      font: inherit;
      color: inherit;
    }

    .shell {
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: 18px;
      width: min(1500px, calc(100vw - 28px));
      margin: 14px auto;
    }

    .card {
      position: relative;
      background:
        linear-gradient(145deg, rgba(255,255,255,.145), rgba(255,255,255,.052)),
        linear-gradient(135deg, rgba(56,189,248,.075), rgba(167,139,250,.060));
      border: 1px solid var(--stroke);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(24px);
      overflow: hidden;
      animation: borderPulse 8s ease-in-out infinite;
    }

    .card:before {
      content: "";
      position: absolute;
      inset: 0;
      border-radius: inherit;
      pointer-events: none;
      background:
        linear-gradient(135deg, rgba(255,255,255,.20), transparent 28%, transparent 70%, rgba(56,189,248,.12)),
        radial-gradient(circle at top left, rgba(255,255,255,.16), transparent 28%);
      opacity: .52;
      mask: linear-gradient(#000, transparent 38%);
    }

    .sidebar {
      position: sticky;
      top: 14px;
      height: calc(100vh - 28px);
      padding: 16px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }

    .brand {
      display: flex;
      gap: 12px;
      align-items: center;
      margin-bottom: 16px;
    }

    .logo {
      width: 50px;
      height: 50px;
      border-radius: 18px;
      display: grid;
      place-items: center;
      background:
        linear-gradient(135deg, #ffffff 0%, #dbeafe 32%, #7dd3fc 58%, #a78bfa 100%);
      color: #0b1220;
      font-weight: 950;
      box-shadow:
        inset 0 2px 4px rgba(255,255,255,.95),
        inset 0 -8px 16px rgba(15,23,42,.22),
        0 18px 48px rgba(56,189,248,.34);
      animation: floatGlow 5s ease-in-out infinite;
    }

    .brand h1 { font-size: 18px; line-height: 1.1; margin: 0; }
    .brand p { color: var(--muted); font-size: 12px; margin: 3px 0 0; }

    .searchbox {
      position: relative;
      margin-bottom: 12px;
    }

    .searchbox input {
      width: 100%;
      border: 1px solid var(--stroke);
      border-radius: 18px;
      padding: 12px 14px;
      background: rgba(255,255,255,.08);
      outline: none;
    }

    .small {
      color: var(--muted);
      font-size: 12px;
    }

    .pillrow { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 14px; }

    .pill, .btn {
      border: 1px solid rgba(226,232,240,.20);
      border-radius: 999px;
      padding: 10px 14px;
      background:
        linear-gradient(145deg, rgba(255,255,255,.13), rgba(255,255,255,.045));
      cursor: pointer;
      transition: transform .18s ease, background .18s ease, border .18s ease, box-shadow .18s ease;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      white-space: nowrap;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.08);
    }

    .pill:hover, .btn:hover {
      transform: translateY(-2px);
      background:
        linear-gradient(145deg, rgba(255,255,255,.20), rgba(255,255,255,.07));
      border-color: rgba(226,232,240,.38);
      box-shadow: 0 12px 30px rgba(56,189,248,.12), inset 0 1px 0 rgba(255,255,255,.16);
    }

    .btn.primary, .pill.active, .tabbar .active {
      background:
        linear-gradient(135deg, color-mix(in srgb, var(--accent) 42%, transparent), color-mix(in srgb, var(--accent2) 34%, transparent)),
        linear-gradient(180deg, rgba(255,255,255,.18), transparent);
      border-color: rgba(191,219,254,.42);
      font-weight: 800;
      box-shadow: 0 16px 40px rgba(56,189,248,.17), inset 0 1px 0 rgba(255,255,255,.24);
    }

    .navarea {
      overflow: auto;
      padding-right: 4px;
      flex: 1;
    }

    .section-title {
      color: var(--muted);
      font-size: 11px;
      letter-spacing: .12em;
      text-transform: uppercase;
      margin: 18px 4px 9px;
    }

    .note-link, .space-link, .bookmark-link {
      display: block;
      padding: 13px 14px;
      border-radius: 18px;
      border: 1px solid rgba(226,232,240,.08);
      margin-bottom: 8px;
      background:
        linear-gradient(135deg, rgba(255,255,255,.078), rgba(255,255,255,.038)),
        radial-gradient(circle at 100% 0%, rgba(56,189,248,.09), transparent 35%);
      transition: transform .18s ease, border-color .18s ease, background .18s ease, box-shadow .18s ease;
    }

    .note-link:hover, .space-link:hover, .bookmark-link:hover {
      transform: translateX(3px);
      border-color: rgba(125,211,252,.30);
      background:
        linear-gradient(135deg, rgba(255,255,255,.13), rgba(255,255,255,.055)),
        radial-gradient(circle at 100% 0%, rgba(167,139,250,.14), transparent 38%);
      box-shadow: 0 16px 36px rgba(0,0,0,.22);
    }

    .note-link strong, .space-link strong, .bookmark-link strong {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .main {
      min-height: calc(100vh - 28px);
      display: grid;
      grid-template-rows: auto 1fr;
      gap: 18px;
    }

    .topbar {
      padding: 14px 16px;
      display: flex;
      justify-content: space-between;
      gap: 14px;
      align-items: center;
    }

    .topbar h2 { margin: 0; font-size: 24px; }
    .topbar-actions { display: flex; gap: 9px; flex-wrap: wrap; align-items: center; }

    .grid {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(320px, .75fr);
      gap: 18px;
    }

    .panel { padding: 18px; }

    .stats {
      display: grid;
      grid-template-columns: repeat(4, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }

    .stat {
      padding: 16px;
      border-radius: 20px;
      background:
        linear-gradient(145deg, rgba(255,255,255,.13), rgba(255,255,255,.055)),
        radial-gradient(circle at top right, rgba(125,211,252,.16), transparent 35%);
      border: 1px solid var(--stroke);
    }

    .stat b { font-size: 25px; display: block; }
    .stat span { color: var(--muted); font-size: 12px; }


    .insights-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(220px, 1fr));
      gap: 12px;
      margin: 18px 0;
    }

    .insight-card {
      position: relative;
      overflow: hidden;
      min-height: 128px;
      padding: 16px;
      border-radius: 20px;
      border: 1px solid var(--stroke);
      background:
        linear-gradient(145deg, rgba(255,255,255,.115), rgba(255,255,255,.052)),
        radial-gradient(circle at 92% 0%, rgba(192,132,252,.18), transparent 35%);
    }

    .insight-card:after {
      content: "";
      position: absolute;
      inset: -60% -30%;
      background: linear-gradient(110deg, transparent 40%, rgba(255,255,255,.10), transparent 60%);
      transform: rotate(12deg);
      animation: shine 10s linear infinite;
      pointer-events: none;
    }

    .insight-card .label {
      color: var(--muted);
      font-size: 11px;
      letter-spacing: .11em;
      text-transform: uppercase;
      margin-bottom: 10px;
    }

    .insight-card h3 {
      margin: 0 0 8px;
      font-size: 19px;
      line-height: 1.25;
    }

    .insight-card .value {
      color: #dbeafe;
      font-size: 13px;
      line-height: 1.45;
    }

    .insight-card.empty-insight h3 {
      color: var(--muted);
      font-weight: 600;
    }

    .home-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .home-card {
      border-radius: 20px;
      border: 1px solid var(--stroke);
      background: rgba(255,255,255,.06);
      padding: 15px;
    }

    .editor {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 12px;
    }

    .field, textarea {
      width: 100%;
      border: 1px solid var(--stroke);
      border-radius: 16px;
      padding: 12px 13px;
      background: rgba(255,255,255,.075);
      outline: none;
      margin-bottom: 10px;
    }

    textarea {
      min-height: 420px;
      resize: vertical;
      line-height: 1.55;
    }

    .preview {
      min-height: 420px;
      max-height: 70vh;
      overflow: auto;
      border-radius: 18px;
      border: 1px solid var(--stroke);
      padding: 18px;
      background: rgba(3,7,18,.42);
      line-height: 1.65;
    }

    .preview h1, .preview h2, .preview h3 { line-height: 1.2; }
    .preview code { background: rgba(255,255,255,.11); padding: 2px 5px; border-radius: 6px; }
    .preview pre { background: rgba(0,0,0,.35); padding: 14px; border-radius: 14px; overflow: auto; }
    .preview blockquote { border-left: 3px solid var(--accent); margin-left: 0; padding-left: 14px; color: #dbeafe; }
    mark { background: linear-gradient(135deg, rgba(253,230,138,.9), rgba(125,211,252,.55)); color: #0f172a; border-radius: 6px; padding: 0 3px; }

    .auth-wrap {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
    }

    .auth {
      width: min(980px, 100%);
      display: grid;
      grid-template-columns: 1.1fr .9fr;
      overflow: hidden;
    }

    .hero {
      padding: 42px;
      background:
        radial-gradient(circle at 20% 20%, rgba(125,211,252,.22), transparent 34%),
        linear-gradient(145deg, rgba(255,255,255,.12), rgba(255,255,255,.045));
      border-right: 1px solid var(--stroke);
    }

    .hero h1 { font-size: clamp(36px, 6vw, 66px); line-height: .92; margin: 20px 0; }
    .hero p { color: var(--muted); font-size: 17px; line-height: 1.7; }

    .auth-form { padding: 42px; }
    .auth-form h2 { margin-top: 0; }
    .error { color: var(--danger); font-size: 13px; margin-bottom: 12px; }

    .empty {
      color: var(--muted);
      padding: 18px;
      border: 1px dashed var(--stroke);
      border-radius: 18px;
      text-align: center;
    }

    .toolbar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 8px 0 14px;
    }

    .scroll-memory {
      position: fixed;
      right: 7px;
      top: 10vh;
      height: 80vh;
      width: 9px;
      border-radius: 999px;
      background: rgba(255,255,255,.10);
      border: 1px solid rgba(255,255,255,.10);
      z-index: 30;
    }

    .scroll-memory span {
      position: absolute;
      left: -2px;
      top: 0;
      will-change: transform;
      width: 13px;
      height: 13px;
      border-radius: 50%;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      box-shadow: 0 0 18px rgba(125,211,252,.8);
    }


    body.reading-focus .sidebar {
      transform: translateX(-106%);
      opacity: 0;
      pointer-events: none;
    }

    body.reading-focus .shell {
      grid-template-columns: 1fr;
      width: min(1720px, calc(100vw - 24px));
    }

    body.reading-focus .main {
      margin-left: 0;
    }

    body.reading-focus .topbar,
    body.reading-focus .note-meta,
    body.reading-focus .note-title-main,
    body.reading-focus .note-actions {
      transform: translateY(-118%);
      opacity: 0;
      pointer-events: none;
      max-height: 0;
      padding-top: 0;
      padding-bottom: 0;
      margin: 0;
      overflow: hidden;
    }

    body.reading-focus.near-top .topbar,
    body.reading-focus.near-top .note-meta,
    body.reading-focus.near-top .note-title-main,
    body.reading-focus.near-top .note-actions,
    body.reading-focus:hover-top .topbar,
    body.reading-focus:hover-top .note-meta,
    body.reading-focus:hover-top .note-title-main,
    body.reading-focus:hover-top .note-actions {
      transform: translateY(0);
      opacity: 1;
      pointer-events: auto;
      max-height: 220px;
      overflow: visible;
    }

    .top-hover-zone {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 34px;
      z-index: 80;
      pointer-events: auto;
    }

    .reader-tools {
      position: sticky;
      top: 12px;
      z-index: 50;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 12px;
      padding: 10px;
      border-radius: 999px;
      background: rgba(5, 8, 15, .58);
      border: 1px solid var(--stroke);
      backdrop-filter: blur(18px);
      width: fit-content;
    }

    body.reading-focus .reader-tools {
      position: fixed;
      top: 14px;
      right: 24px;
    }

    body.fullscreen-reader .shell {
      width: 100vw;
      margin: 0;
    }

    body.fullscreen-reader .main {
      min-height: 100vh;
    }

    body.fullscreen-reader .panel.card {
      border-radius: 0;
      min-height: 100vh;
    }

    body.fullscreen-reader .preview {
      max-height: none;
      min-height: calc(100vh - 120px);
      font-size: 20px;
      line-height: 1.82;
    }

    body.reader-hide-sidebar .sidebar {
      display: none;
    }

    body.reader-hide-sidebar .shell {
      grid-template-columns: 1fr;
    }

    body.reader-hide-sidebar .grid {
      grid-template-columns: 1fr;
    }

    .speech-status {
      color: var(--muted);
      font-size: 12px;
      align-self: center;
      padding: 0 8px;
    }

    .note-actions,
    .note-meta,
    .note-title-main,
    .topbar {
      transition: transform .24s ease, opacity .24s ease, max-height .24s ease, padding .24s ease, margin .24s ease;
    }

    .sidebar,
    .shell {
      transition: transform .26s ease, opacity .26s ease, grid-template-columns .26s ease, width .26s ease;
    }


    .dashboard-section {
      margin: 22px 0;
    }

    .section-head {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 14px;
      margin: 4px 0 12px;
    }

    .section-head h3 {
      margin: 0;
      font-size: 22px;
    }

    .section-head p {
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 13px;
    }

    .insights-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(230px, 1fr));
      gap: 12px;
      margin: 12px 0 0;
    }

    .insight-card {
      position: relative;
      overflow: hidden;
      min-height: 142px;
      padding: 17px;
      border-radius: 22px;
      border: 1px solid rgba(226,232,240,.16);
      background:
        linear-gradient(145deg, rgba(226,232,240,.115), rgba(15,23,42,.18)),
        radial-gradient(circle at 95% 5%, var(--card-glow, rgba(148,163,184,.16)), transparent 38%);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 18px 60px rgba(0,0,0,.22);
      transition: transform .18s ease, border-color .18s ease, background .18s ease;
    }

    a.insight-card:hover {
      transform: translateY(-2px);
      border-color: rgba(226,232,240,.34);
      background:
        linear-gradient(145deg, rgba(226,232,240,.15), rgba(15,23,42,.16)),
        radial-gradient(circle at 95% 5%, var(--card-glow, rgba(148,163,184,.2)), transparent 40%);
    }

    .insight-card:after {
      content: "";
      position: absolute;
      inset: -80% -40%;
      background: linear-gradient(110deg, transparent 42%, rgba(255,255,255,.08), transparent 58%);
      transform: rotate(12deg);
      animation: shine 13s linear infinite;
      pointer-events: none;
    }

    .insight-card .label {
      color: var(--muted);
      font-size: 11px;
      letter-spacing: .12em;
      text-transform: uppercase;
      margin-bottom: 10px;
    }

    .insight-card h3 {
      margin: 0 0 8px;
      font-size: 20px;
      line-height: 1.25;
    }

    .insight-card .value {
      color: #dbeafe;
      font-size: 13px;
      line-height: 1.45;
    }

    .insight-card.empty-insight {
      opacity: .78;
      border-style: dashed;
    }

    .insight-card.empty-insight h3 {
      color: var(--muted);
      font-weight: 650;
    }

    .tone-steel { --card-glow: rgba(148,163,184,.20); }
    .tone-blue { --card-glow: rgba(125,211,252,.20); }
    .tone-violet { --card-glow: rgba(167,139,250,.20); }
    .tone-slate { --card-glow: rgba(203,213,225,.16); }
    .tone-graphite { --card-glow: rgba(100,116,139,.23); }
    .tone-platinum { --card-glow: rgba(226,232,240,.18); }

    .analytics-grid {
      display: grid;
      grid-template-columns: minmax(360px, 1.15fr) minmax(300px, .85fr);
      gap: 14px;
      align-items: start;
    }

    .chart-card {
      min-height: 315px;
      padding: 17px;
      border-radius: 22px;
      border: 1px solid var(--stroke);
      background: linear-gradient(145deg, rgba(255,255,255,.095), rgba(255,255,255,.045));
    }

    .chart-card h4 {
      margin: 0 0 6px;
      font-size: 18px;
    }

    .chart-card p {
      margin: 0 0 14px;
      color: var(--muted);
      font-size: 13px;
    }

    .mini-metrics {
      display: grid;
      grid-template-columns: repeat(3, minmax(120px, 1fr));
      gap: 10px;
      margin: 10px 0 0;
    }

    .mini-metric {
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.055);
      border-radius: 18px;
      padding: 13px;
    }

    .mini-metric b {
      display: block;
      font-size: 22px;
    }

    .mini-metric span {
      color: var(--muted);
      font-size: 12px;
    }

    .note-list-section {
      margin-top: 22px;
    }


    .tabbar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 0 0 16px;
    }

    .tabbar .active {
      background: linear-gradient(135deg, rgba(226,232,240,.20), rgba(125,211,252,.16));
      border-color: rgba(226,232,240,.34);
      font-weight: 800;
    }

    .note-reader-panel {
      padding-top: 14px;
    }

    .note-reader-panel .preview {
      max-height: none;
      min-height: calc(100vh - 220px);
      overflow: visible;
      font-size: 19px;
      line-height: 1.78;
      padding: 26px;
    }

    .note-reader-panel .reader-tools {
      position: sticky;
      top: 10px;
      z-index: 55;
      max-width: calc(100vw - 40px);
    }

    .note-actions {
      display: none;
    }

    body.show-note-actions .note-actions {
      display: flex;
    }

    body.reading-focus .note-reader-panel {
      padding-top: 72px;
    }

    body.reading-focus .note-reader-panel .preview {
      min-height: calc(100vh - 92px);
      padding: 34px clamp(24px, 5vw, 72px);
      font-size: 21px;
      line-height: 1.86;
    }

    body.reading-focus .reader-tools {
      opacity: .18;
      transform: translateY(-4px);
      transition: opacity .18s ease, transform .18s ease;
    }

    body.reading-focus .reader-tools:hover,
    body.reading-focus.near-top .reader-tools,
    body.reading-focus.hover-top .reader-tools {
      opacity: 1;
      transform: translateY(0);
    }

    body.fullscreen-reader .note-reader-panel .preview {
      min-height: calc(100vh - 92px);
      max-width: min(1180px, 100%);
      margin: 0 auto;
    }

    .selection-menu {
      position: fixed;
      z-index: 120;
      display: none;
      gap: 8px;
      padding: 8px;
      border-radius: 999px;
      border: 1px solid rgba(226,232,240,.24);
      background: rgba(10,14,24,.86);
      backdrop-filter: blur(18px);
      box-shadow: 0 18px 55px rgba(0,0,0,.42);
    }

    .selection-menu.visible {
      display: flex;
    }

    .quick-memory-panel {
      position: fixed;
      z-index: 121;
      display: none;
      width: min(420px, calc(100vw - 30px));
      padding: 14px;
      border-radius: 22px;
      border: 1px solid rgba(226,232,240,.22);
      background: linear-gradient(145deg, rgba(30,41,59,.96), rgba(15,23,42,.96));
      box-shadow: 0 24px 75px rgba(0,0,0,.55);
      backdrop-filter: blur(18px);
    }

    .quick-memory-panel.visible {
      display: block;
    }

    .quick-memory-panel textarea {
      min-height: 120px;
      max-height: 180px;
      margin-bottom: 8px;
    }

    .quick-memory-panel .panel-title {
      margin: 0 0 8px;
      font-weight: 850;
    }

    .reading-help {
      color: var(--muted);
      font-size: 12px;
      margin: 8px 0 0;
    }

    body.reader-hide-sidebar .note-reader-panel .preview,
    body.reading-focus .note-reader-panel .preview {
      width: min(1240px, 100%);
      margin-left: auto;
      margin-right: auto;
    }


    /* Premium theme overrides */
    .sidebar {
      background:
        linear-gradient(160deg, rgba(15,23,42,.76), rgba(30,41,59,.60)),
        radial-gradient(circle at 18% 0%, rgba(56,189,248,.18), transparent 34%);
    }

    .topbar {
      background:
        linear-gradient(135deg, rgba(15,23,42,.78), rgba(49,46,129,.48)),
        radial-gradient(circle at 96% 0%, rgba(167,139,250,.20), transparent 34%);
    }

    .field, textarea, .searchbox input {
      background:
        linear-gradient(145deg, rgba(15,23,42,.60), rgba(255,255,255,.055));
      border-color: rgba(226,232,240,.17);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.07);
    }

    .field:focus, textarea:focus, .searchbox input:focus {
      border-color: rgba(56,189,248,.50);
      box-shadow: 0 0 0 4px rgba(56,189,248,.10), inset 0 1px 0 rgba(255,255,255,.12);
    }

    .stat {
      background:
        linear-gradient(145deg, rgba(255,255,255,.16), rgba(255,255,255,.06)),
        radial-gradient(circle at top right, rgba(56,189,248,.20), transparent 38%),
        radial-gradient(circle at bottom left, rgba(167,139,250,.14), transparent 42%);
      border-color: rgba(226,232,240,.18);
      transition: transform .18s ease, box-shadow .18s ease;
    }

    .stat:hover {
      transform: translateY(-3px);
      box-shadow: 0 20px 55px rgba(56,189,248,.12);
    }

    .home-card, .chart-card, .mini-metric, .insight-card {
      background:
        linear-gradient(145deg, rgba(255,255,255,.12), rgba(255,255,255,.045)),
        radial-gradient(circle at 92% 0%, var(--card-glow, rgba(56,189,248,.16)), transparent 38%);
      border-color: rgba(226,232,240,.16);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 18px 60px rgba(0,0,0,.22);
    }

    .home-card:hover, a.insight-card:hover {
      transform: translateY(-3px);
      border-color: rgba(226,232,240,.34);
      box-shadow: 0 22px 70px rgba(56,189,248,.12);
    }

    .tone-steel { --card-glow: rgba(148,163,184,.22); }
    .tone-blue { --card-glow: rgba(56,189,248,.25); }
    .tone-violet { --card-glow: rgba(167,139,250,.24); }
    .tone-slate { --card-glow: rgba(100,116,139,.25); }
    .tone-graphite { --card-glow: rgba(71,85,105,.27); }
    .tone-platinum { --card-glow: rgba(226,232,240,.20); }

    .preview {
      background:
        linear-gradient(145deg, rgba(3,7,18,.72), rgba(15,23,42,.62)),
        radial-gradient(circle at 100% 0%, rgba(56,189,248,.08), transparent 34%);
      border-color: rgba(226,232,240,.14);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.06);
    }

    .preview pre {
      background: rgba(2,6,23,.74);
      border: 1px solid rgba(226,232,240,.10);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.05);
    }

    .reader-tools, .selection-menu, .quick-memory-panel {
      background:
        linear-gradient(145deg, rgba(15,23,42,.86), rgba(30,41,59,.76)),
        radial-gradient(circle at 0% 0%, rgba(56,189,248,.16), transparent 42%);
      border-color: rgba(226,232,240,.20);
    }

    .scroll-memory {
      background: rgba(15,23,42,.56);
      border-color: rgba(226,232,240,.14);
    }

    .scroll-memory span {
      background: linear-gradient(135deg, var(--accent), var(--accent2), var(--rose));
      box-shadow: 0 0 22px rgba(56,189,248,.92), 0 0 38px rgba(167,139,250,.35);
    }

    ::selection {
      background: rgba(56,189,248,.38);
      color: white;
    }


    body.theme-aurora {
      --accent: #38bdf8;
      --accent2: #a78bfa;
      --accent3: #22d3ee;
      --rose: #fb7185;
    }

    body.theme-emerald {
      --accent: #34d399;
      --accent2: #38bdf8;
      --accent3: #a7f3d0;
      --rose: #f8d477;
    }

    body.theme-rose {
      --accent: #fb7185;
      --accent2: #a78bfa;
      --accent3: #f0abfc;
      --rose: #38bdf8;
    }

    .theme-dot {
      width: 28px;
      height: 28px;
      padding: 0;
      border-radius: 50%;
      border: 1px solid rgba(255,255,255,.24);
      cursor: pointer;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.3), 0 8px 24px rgba(0,0,0,.20);
    }

    .theme-aurora-dot { background: linear-gradient(135deg, #38bdf8, #a78bfa); }
    .theme-emerald-dot { background: linear-gradient(135deg, #34d399, #38bdf8); }
    .theme-rose-dot { background: linear-gradient(135deg, #fb7185, #a78bfa); }


    /* Fix native dropdown white background */
    select,
    select.field,
    .quick-memory-panel select,
    .field option,
    select option {
      color: #f7fbff;
      background-color: #111827;
    }

    select:focus,
    select.field:focus {
      color: #f7fbff;
      background:
        linear-gradient(145deg, rgba(15,23,42,.92), rgba(30,41,59,.86));
    }

    select option {
      padding: 10px;
      background: #111827;
      color: #f7fbff;
    }

    select option:checked,
    select option:hover {
      background: #1e3a5f;
      color: #ffffff;
    }


    /* Sidebar collapse handle */
    .sidebar-toggle-handle {
      position: fixed;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      z-index: 95;
      width: 46px;
      height: 46px;
      border-radius: 999px;
      border: 1px solid rgba(226,232,240,.26);
      background:
        linear-gradient(145deg, rgba(15,23,42,.92), rgba(30,41,59,.82)),
        radial-gradient(circle at 25% 10%, rgba(56,189,248,.30), transparent 45%);
      color: #f8fbff;
      font-size: 22px;
      font-weight: 900;
      cursor: pointer;
      box-shadow: 0 16px 48px rgba(0,0,0,.42), inset 0 1px 0 rgba(255,255,255,.18);
      backdrop-filter: blur(18px);
      display: grid;
      place-items: center;
      transition: left .24s ease, transform .18s ease, opacity .18s ease;
    }

    .sidebar-toggle-handle:hover {
      transform: translateY(-50%) scale(1.06);
      border-color: rgba(125,211,252,.45);
      box-shadow: 0 18px 54px rgba(56,189,248,.18), inset 0 1px 0 rgba(255,255,255,.24);
    }

    body:not(.reader-hide-sidebar):not(.reading-focus) .sidebar-toggle-handle {
      left: 342px;
    }

    body.reader-hide-sidebar .sidebar-toggle-handle,
    body.reading-focus .sidebar-toggle-handle {
      left: 14px;
    }

    body.reader-hide-sidebar .shell,
    body.reading-focus .shell {
      grid-template-columns: 1fr;
      width: min(1720px, calc(100vw - 24px));
    }

    body.reader-hide-sidebar .sidebar,
    body.reading-focus .sidebar {
      display: none !important;
      transform: translateX(-106%);
      opacity: 0;
      pointer-events: none;
    }

    body.reader-hide-sidebar .main,
    body.reading-focus .main {
      grid-column: 1 / -1;
    }

    body.reader-hide-sidebar .note-reader-panel,
    body.reading-focus .note-reader-panel {
      margin-left: 0;
    }

    body.reader-hide-sidebar .topbar {
      margin-left: 52px;
      width: calc(100% - 52px);
    }

    body.reading-focus .topbar {
      display: none;
    }

    body.reading-focus .reader-tools {
      right: 18px;
      left: auto;
    }

    @media (max-width: 1000px) {
      .note-reader-panel .preview {
        font-size: 17px;
        padding: 18px;
      }
      .reader-tools {
        border-radius: 22px;
      }
    }


    /* Premium theme overrides */
    .sidebar {
      background:
        linear-gradient(160deg, rgba(15,23,42,.76), rgba(30,41,59,.60)),
        radial-gradient(circle at 18% 0%, rgba(56,189,248,.18), transparent 34%);
    }

    .topbar {
      background:
        linear-gradient(135deg, rgba(15,23,42,.78), rgba(49,46,129,.48)),
        radial-gradient(circle at 96% 0%, rgba(167,139,250,.20), transparent 34%);
    }

    .field, textarea, .searchbox input {
      background:
        linear-gradient(145deg, rgba(15,23,42,.60), rgba(255,255,255,.055));
      border-color: rgba(226,232,240,.17);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.07);
    }

    .field:focus, textarea:focus, .searchbox input:focus {
      border-color: rgba(56,189,248,.50);
      box-shadow: 0 0 0 4px rgba(56,189,248,.10), inset 0 1px 0 rgba(255,255,255,.12);
    }

    .stat {
      background:
        linear-gradient(145deg, rgba(255,255,255,.16), rgba(255,255,255,.06)),
        radial-gradient(circle at top right, rgba(56,189,248,.20), transparent 38%),
        radial-gradient(circle at bottom left, rgba(167,139,250,.14), transparent 42%);
      border-color: rgba(226,232,240,.18);
      transition: transform .18s ease, box-shadow .18s ease;
    }

    .stat:hover {
      transform: translateY(-3px);
      box-shadow: 0 20px 55px rgba(56,189,248,.12);
    }

    .home-card, .chart-card, .mini-metric, .insight-card {
      background:
        linear-gradient(145deg, rgba(255,255,255,.12), rgba(255,255,255,.045)),
        radial-gradient(circle at 92% 0%, var(--card-glow, rgba(56,189,248,.16)), transparent 38%);
      border-color: rgba(226,232,240,.16);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 18px 60px rgba(0,0,0,.22);
    }

    .home-card:hover, a.insight-card:hover {
      transform: translateY(-3px);
      border-color: rgba(226,232,240,.34);
      box-shadow: 0 22px 70px rgba(56,189,248,.12);
    }

    .tone-steel { --card-glow: rgba(148,163,184,.22); }
    .tone-blue { --card-glow: rgba(56,189,248,.25); }
    .tone-violet { --card-glow: rgba(167,139,250,.24); }
    .tone-slate { --card-glow: rgba(100,116,139,.25); }
    .tone-graphite { --card-glow: rgba(71,85,105,.27); }
    .tone-platinum { --card-glow: rgba(226,232,240,.20); }

    .preview {
      background:
        linear-gradient(145deg, rgba(3,7,18,.72), rgba(15,23,42,.62)),
        radial-gradient(circle at 100% 0%, rgba(56,189,248,.08), transparent 34%);
      border-color: rgba(226,232,240,.14);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.06);
    }

    .preview pre {
      background: rgba(2,6,23,.74);
      border: 1px solid rgba(226,232,240,.10);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.05);
    }

    .reader-tools, .selection-menu, .quick-memory-panel {
      background:
        linear-gradient(145deg, rgba(15,23,42,.86), rgba(30,41,59,.76)),
        radial-gradient(circle at 0% 0%, rgba(56,189,248,.16), transparent 42%);
      border-color: rgba(226,232,240,.20);
    }

    .scroll-memory {
      background: rgba(15,23,42,.56);
      border-color: rgba(226,232,240,.14);
    }

    .scroll-memory span {
      background: linear-gradient(135deg, var(--accent), var(--accent2), var(--rose));
      box-shadow: 0 0 22px rgba(56,189,248,.92), 0 0 38px rgba(167,139,250,.35);
    }

    ::selection {
      background: rgba(56,189,248,.38);
      color: white;
    }


    body.theme-aurora {
      --accent: #38bdf8;
      --accent2: #a78bfa;
      --accent3: #22d3ee;
      --rose: #fb7185;
    }

    body.theme-emerald {
      --accent: #34d399;
      --accent2: #38bdf8;
      --accent3: #a7f3d0;
      --rose: #f8d477;
    }

    body.theme-rose {
      --accent: #fb7185;
      --accent2: #a78bfa;
      --accent3: #f0abfc;
      --rose: #38bdf8;
    }

    .theme-dot {
      width: 28px;
      height: 28px;
      padding: 0;
      border-radius: 50%;
      border: 1px solid rgba(255,255,255,.24);
      cursor: pointer;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.3), 0 8px 24px rgba(0,0,0,.20);
    }

    .theme-aurora-dot { background: linear-gradient(135deg, #38bdf8, #a78bfa); }
    .theme-emerald-dot { background: linear-gradient(135deg, #34d399, #38bdf8); }
    .theme-rose-dot { background: linear-gradient(135deg, #fb7185, #a78bfa); }


    /* Fix native dropdown white background */
    select,
    select.field,
    .quick-memory-panel select,
    .field option,
    select option {
      color: #f7fbff;
      background-color: #111827;
    }

    select:focus,
    select.field:focus {
      color: #f7fbff;
      background:
        linear-gradient(145deg, rgba(15,23,42,.92), rgba(30,41,59,.86));
    }

    select option {
      padding: 10px;
      background: #111827;
      color: #f7fbff;
    }

    select option:checked,
    select option:hover {
      background: #1e3a5f;
      color: #ffffff;
    }


    /* Sidebar collapse handle */
    .sidebar-toggle-handle {
      position: fixed;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      z-index: 95;
      width: 46px;
      height: 46px;
      border-radius: 999px;
      border: 1px solid rgba(226,232,240,.26);
      background:
        linear-gradient(145deg, rgba(15,23,42,.92), rgba(30,41,59,.82)),
        radial-gradient(circle at 25% 10%, rgba(56,189,248,.30), transparent 45%);
      color: #f8fbff;
      font-size: 22px;
      font-weight: 900;
      cursor: pointer;
      box-shadow: 0 16px 48px rgba(0,0,0,.42), inset 0 1px 0 rgba(255,255,255,.18);
      backdrop-filter: blur(18px);
      display: grid;
      place-items: center;
      transition: left .24s ease, transform .18s ease, opacity .18s ease;
    }

    .sidebar-toggle-handle:hover {
      transform: translateY(-50%) scale(1.06);
      border-color: rgba(125,211,252,.45);
      box-shadow: 0 18px 54px rgba(56,189,248,.18), inset 0 1px 0 rgba(255,255,255,.24);
    }

    body:not(.reader-hide-sidebar):not(.reading-focus) .sidebar-toggle-handle {
      left: 342px;
    }

    body.reader-hide-sidebar .sidebar-toggle-handle,
    body.reading-focus .sidebar-toggle-handle {
      left: 14px;
    }

    body.reader-hide-sidebar .shell,
    body.reading-focus .shell {
      grid-template-columns: 1fr;
      width: min(1720px, calc(100vw - 24px));
    }

    body.reader-hide-sidebar .sidebar,
    body.reading-focus .sidebar {
      display: none !important;
      transform: translateX(-106%);
      opacity: 0;
      pointer-events: none;
    }

    body.reader-hide-sidebar .main,
    body.reading-focus .main {
      grid-column: 1 / -1;
    }

    body.reader-hide-sidebar .note-reader-panel,
    body.reading-focus .note-reader-panel {
      margin-left: 0;
    }

    body.reader-hide-sidebar .topbar {
      margin-left: 52px;
      width: calc(100% - 52px);
    }

    body.reading-focus .topbar {
      display: none;
    }

    body.reading-focus .reader-tools {
      right: 18px;
      left: auto;
    }

    @media (max-width: 1000px) {
      .shell { grid-template-columns: 1fr; }
      .sidebar { position: relative; height: auto; }
      .grid, .editor, .auth { grid-template-columns: 1fr; }
      .stats { grid-template-columns: repeat(2, 1fr); }
      .insights-grid { grid-template-columns: 1fr; }
      .analytics-grid { grid-template-columns: 1fr; }
      .mini-metrics { grid-template-columns: 1fr; }
      .scroll-memory { display: none; }
    }
  
    /* Robust sidebar toggle fix: always visible, never hidden by reading/dashboard layout */
    #sidebarToggleHandle {
      position: fixed !important;
      left: 14px !important;
      top: 50% !important;
      transform: translateY(-50%) !important;
      z-index: 99999 !important;
      display: grid !important;
      place-items: center !important;
      opacity: 1 !important;
      visibility: visible !important;
      pointer-events: auto !important;
    }

    body:not(.reader-hide-sidebar):not(.reading-focus) #sidebarToggleHandle {
      left: 340px !important;
    }

    body.reader-hide-sidebar #sidebarToggleHandle,
    body.reading-focus #sidebarToggleHandle {
      left: 14px !important;
    }

    body.reader-hide-sidebar .sidebar,
    body.reading-focus .sidebar {
      display: none !important;
      width: 0 !important;
      min-width: 0 !important;
      opacity: 0 !important;
      pointer-events: none !important;
    }

    body.reader-hide-sidebar .shell,
    body.reading-focus .shell {
      grid-template-columns: minmax(0, 1fr) !important;
      width: min(1500px, calc(100vw - 28px)) !important;
      margin-left: auto !important;
      margin-right: auto !important;
    }

    body.reader-hide-sidebar .main,
    body.reading-focus .main {
      grid-column: 1 / -1 !important;
      width: 100% !important;
    }

    /* Hide top chrome only in actual note reading focus, not when sidebar is merely hidden */
    body.reader-hide-sidebar .topbar {
      display: flex !important;
      transform: none !important;
      opacity: 1 !important;
      pointer-events: auto !important;
      max-height: none !important;
      margin-left: 0 !important;
      width: 100% !important;
    }

    body.reading-focus .topbar {
      display: none !important;
    }

    body.reader-hide-sidebar .panel.card {
      margin-left: 0 !important;
    }

  
    /* Clean sidebar toggle inside the left pane */
    #sidebarToggleHandle {
      display: none !important;
    }

    .sidebar-header-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
    }

    .sidebar-header-row .brand {
      margin-bottom: 0;
      min-width: 0;
    }

    .sidebar-pane-toggle {
      width: 38px;
      height: 38px;
      border-radius: 14px;
      border: 1px solid rgba(226,232,240,.22);
      background:
        linear-gradient(145deg, rgba(255,255,255,.16), rgba(255,255,255,.055)),
        radial-gradient(circle at 30% 10%, rgba(56,189,248,.20), transparent 45%);
      color: #f8fbff;
      cursor: pointer;
      display: grid;
      place-items: center;
      flex: 0 0 auto;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.16), 0 10px 28px rgba(0,0,0,.22);
      transition: transform .18s ease, border-color .18s ease, background .18s ease;
    }

    .sidebar-pane-toggle:hover {
      transform: translateY(-1px);
      border-color: rgba(125,211,252,.44);
      background:
        linear-gradient(145deg, rgba(255,255,255,.22), rgba(255,255,255,.075)),
        radial-gradient(circle at 30% 10%, rgba(56,189,248,.28), transparent 45%);
    }

    .sidebar-pane-toggle svg {
      width: 20px;
      height: 20px;
      stroke-width: 2.25;
    }

    .sidebar-restore-toggle {
      position: fixed;
      left: 18px;
      top: 24px;
      z-index: 99999;
      width: 44px;
      height: 44px;
      border-radius: 16px;
      border: 1px solid rgba(226,232,240,.26);
      background:
        linear-gradient(145deg, rgba(15,23,42,.94), rgba(30,41,59,.84)),
        radial-gradient(circle at 25% 10%, rgba(56,189,248,.26), transparent 45%);
      color: #f8fbff;
      cursor: pointer;
      display: none;
      place-items: center;
      box-shadow: 0 16px 48px rgba(0,0,0,.40), inset 0 1px 0 rgba(255,255,255,.18);
      backdrop-filter: blur(18px);
      transition: transform .18s ease, border-color .18s ease;
    }

    .sidebar-restore-toggle:hover {
      transform: translateY(-1px);
      border-color: rgba(125,211,252,.45);
    }

    .sidebar-restore-toggle svg {
      width: 21px;
      height: 21px;
      stroke-width: 2.25;
    }

    body.reader-hide-sidebar .sidebar-restore-toggle,
    body.reading-focus .sidebar-restore-toggle {
      display: grid;
    }

    body.reader-hide-sidebar .topbar {
      padding-left: 70px;
    }

  
    /* Professional neutral theme override: graphite, warm slate, restrained teal/bronze */
    :root {
      --bg: #0b0f14;
      --panel: rgba(20, 26, 34, .82);
      --panel2: rgba(31, 39, 50, .78);
      --stroke: rgba(226, 232, 240, .15);
      --text: #f4f7fb;
      --muted: #a7b0bd;
      --accent: #5fb3a9;
      --accent2: #b89b5e;
      --accent3: #8aa0b8;
      --rose: #b77979;
      --gold: #c5a867;
      --emerald: #5fb3a9;
      --shadow: 0 28px 92px rgba(0,0,0,.52);
    }

    body,
    body.theme-aurora,
    body.theme-emerald,
    body.theme-rose {
      background:
        radial-gradient(circle at 12% 10%, rgba(95,179,169,.16), transparent 24%),
        radial-gradient(circle at 86% 16%, rgba(184,155,94,.12), transparent 26%),
        radial-gradient(circle at 52% 92%, rgba(138,160,184,.11), transparent 28%),
        linear-gradient(135deg, #080b10 0%, #111722 42%, #17151d 72%, #080b10 100%) !important;
    }

    body:before {
      opacity: .32 !important;
      background:
        linear-gradient(110deg, transparent 38%, rgba(255,255,255,.07) 47%, rgba(255,255,255,.018) 52%, transparent 62%),
        repeating-linear-gradient(90deg, rgba(255,255,255,.018) 0 1px, transparent 1px 58px) !important;
      animation-duration: 16s !important;
    }

    body:after {
      opacity: .18 !important;
    }

    .card,
    .sidebar,
    .topbar,
    .panel.card {
      background:
        linear-gradient(145deg, rgba(34, 42, 54, .78), rgba(13, 18, 25, .78)),
        radial-gradient(circle at 0% 0%, rgba(95,179,169,.07), transparent 34%),
        radial-gradient(circle at 100% 0%, rgba(184,155,94,.06), transparent 34%) !important;
      border-color: rgba(226,232,240,.13) !important;
      box-shadow: 0 24px 82px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.055) !important;
      animation: none !important;
    }

    .topbar {
      background:
        linear-gradient(135deg, rgba(27, 34, 45, .92), rgba(30, 28, 36, .88)),
        radial-gradient(circle at 92% 0%, rgba(184,155,94,.11), transparent 36%) !important;
    }

    .sidebar {
      background:
        linear-gradient(160deg, rgba(22, 30, 39, .94), rgba(13, 18, 26, .94)),
        radial-gradient(circle at 0% 10%, rgba(95,179,169,.11), transparent 34%) !important;
    }

    .logo {
      background:
        linear-gradient(135deg, #f5f1e6 0%, #d6c6a1 42%, #5fb3a9 100%) !important;
      color: #111827 !important;
      box-shadow:
        inset 0 2px 4px rgba(255,255,255,.78),
        inset 0 -8px 16px rgba(17,24,39,.18),
        0 16px 38px rgba(0,0,0,.34) !important;
      animation: none !important;
    }

    .btn.primary,
    .pill.active,
    .tabbar .active {
      background:
        linear-gradient(135deg, rgba(95,179,169,.38), rgba(184,155,94,.22)),
        linear-gradient(180deg, rgba(255,255,255,.10), transparent) !important;
      border-color: rgba(211, 194, 150, .32) !important;
      box-shadow: 0 14px 34px rgba(0,0,0,.24), inset 0 1px 0 rgba(255,255,255,.18) !important;
    }

    .pill,
    .btn,
    .theme-dot {
      background:
        linear-gradient(145deg, rgba(255,255,255,.105), rgba(255,255,255,.035)) !important;
      border-color: rgba(226,232,240,.14) !important;
      color: #f3f6fb !important;
    }

    .pill:hover,
    .btn:hover,
    .sidebar-pane-toggle:hover,
    .sidebar-restore-toggle:hover {
      background:
        linear-gradient(145deg, rgba(255,255,255,.16), rgba(255,255,255,.052)) !important;
      border-color: rgba(211,194,150,.34) !important;
      box-shadow: 0 16px 36px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.14) !important;
    }

    .theme-aurora-dot,
    .theme-emerald-dot,
    .theme-rose-dot {
      background: linear-gradient(135deg, #5fb3a9, #b89b5e) !important;
    }

    .note-link,
    .space-link,
    .bookmark-link {
      background:
        linear-gradient(135deg, rgba(255,255,255,.065), rgba(255,255,255,.026)),
        radial-gradient(circle at 100% 0%, rgba(184,155,94,.07), transparent 38%) !important;
      border-color: rgba(226,232,240,.08) !important;
    }

    .note-link:hover,
    .space-link:hover,
    .bookmark-link:hover {
      border-color: rgba(95,179,169,.30) !important;
      background:
        linear-gradient(135deg, rgba(255,255,255,.105), rgba(255,255,255,.04)),
        radial-gradient(circle at 100% 0%, rgba(95,179,169,.10), transparent 38%) !important;
    }

    .home-card,
    .chart-card,
    .mini-metric,
    .insight-card,
    .stat {
      background:
        linear-gradient(145deg, rgba(48, 58, 72, .70), rgba(20, 26, 36, .72)),
        radial-gradient(circle at 92% 0%, var(--card-glow, rgba(184,155,94,.10)), transparent 38%) !important;
      border-color: rgba(226,232,240,.12) !important;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.055), 0 18px 50px rgba(0,0,0,.28) !important;
    }

    .home-card:hover,
    a.insight-card:hover,
    .stat:hover {
      border-color: rgba(211,194,150,.25) !important;
      box-shadow: 0 22px 58px rgba(0,0,0,.36), inset 0 1px 0 rgba(255,255,255,.08) !important;
      transform: translateY(-2px);
    }

    .tone-steel { --card-glow: rgba(138,160,184,.14) !important; }
    .tone-blue { --card-glow: rgba(95,179,169,.15) !important; }
    .tone-violet { --card-glow: rgba(184,155,94,.14) !important; }
    .tone-slate { --card-glow: rgba(117,128,143,.15) !important; }
    .tone-graphite { --card-glow: rgba(80,91,105,.16) !important; }
    .tone-platinum { --card-glow: rgba(210,205,190,.13) !important; }

    .preview {
      background:
        linear-gradient(145deg, rgba(17,24,34,.94), rgba(10,14,20,.93)),
        radial-gradient(circle at 100% 0%, rgba(184,155,94,.055), transparent 34%) !important;
      border-color: rgba(226,232,240,.105) !important;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.045), 0 18px 52px rgba(0,0,0,.30) !important;
    }

    .preview pre {
      background: #080c13 !important;
      border: 1px solid rgba(226,232,240,.08) !important;
    }

    .preview code {
      background: rgba(226,232,240,.11) !important;
      color: #f8fafc !important;
    }

    .selection-menu,
    .quick-memory-panel,
    .reader-tools,
    .sidebar-pane-toggle,
    .sidebar-restore-toggle {
      background:
        linear-gradient(145deg, rgba(26,34,44,.94), rgba(13,18,25,.92)),
        radial-gradient(circle at 0% 0%, rgba(95,179,169,.10), transparent 42%) !important;
      border-color: rgba(226,232,240,.14) !important;
      box-shadow: 0 18px 52px rgba(0,0,0,.38), inset 0 1px 0 rgba(255,255,255,.06) !important;
    }

    .field,
    textarea,
    .searchbox input,
    select,
    select.field {
      background:
        linear-gradient(145deg, rgba(9,13,19,.78), rgba(31,39,50,.54)) !important;
      border-color: rgba(226,232,240,.13) !important;
      color: #f4f7fb !important;
    }

    .field:focus,
    textarea:focus,
    .searchbox input:focus,
    select:focus {
      border-color: rgba(95,179,169,.46) !important;
      box-shadow: 0 0 0 4px rgba(95,179,169,.10), inset 0 1px 0 rgba(255,255,255,.10) !important;
    }

    .scroll-memory span {
      background: linear-gradient(135deg, #5fb3a9, #b89b5e) !important;
      box-shadow: 0 0 18px rgba(95,179,169,.55), 0 0 28px rgba(184,155,94,.24) !important;
    }

    ::selection {
      background: rgba(184,155,94,.36) !important;
      color: #fff !important;
    }

  
    /* Compact student-focused UI refinement */
    * {
      scrollbar-width: thin;
      scrollbar-color: rgba(197,168,103,.55) rgba(12,17,24,.45);
    }

    ::-webkit-scrollbar {
      width: 10px;
      height: 10px;
    }

    ::-webkit-scrollbar-track {
      background: rgba(12,17,24,.44);
      border-radius: 999px;
    }

    ::-webkit-scrollbar-thumb {
      background: linear-gradient(180deg, rgba(95,179,169,.70), rgba(184,155,94,.62));
      border: 2px solid rgba(12,17,24,.70);
      border-radius: 999px;
    }

    .dashboard-shell-compact {
      display: grid;
      gap: 18px;
    }

    .compact-kpis {
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 10px;
    }

    .compact-kpi {
      border: 1px solid rgba(226,232,240,.11);
      background: linear-gradient(145deg, rgba(255,255,255,.075), rgba(255,255,255,.028));
      border-radius: 18px;
      padding: 13px 14px;
    }

    .compact-kpi b {
      display: block;
      font-size: 24px;
      line-height: 1;
      margin-bottom: 5px;
    }

    .compact-kpi span {
      color: var(--muted);
      font-size: 12px;
    }

    .filter-panel {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: 10px;
      align-items: center;
      margin: 12px 0 14px;
      padding: 10px;
      border: 1px solid rgba(226,232,240,.10);
      border-radius: 20px;
      background: rgba(8,12,18,.22);
    }

    .filter-panel input,
    .filter-panel select {
      margin: 0;
    }

    .note-list {
      display: grid;
      grid-template-columns: 1fr;
      gap: 10px;
    }

    .note-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 14px;
      align-items: center;
      padding: 15px 16px;
      border-radius: 20px;
      border: 1px solid rgba(226,232,240,.11);
      background:
        linear-gradient(145deg, rgba(255,255,255,.075), rgba(255,255,255,.03)),
        radial-gradient(circle at 100% 0%, rgba(95,179,169,.07), transparent 34%);
      transition: transform .16s ease, border-color .16s ease, background .16s ease;
    }

    .note-row:hover {
      transform: translateY(-1px);
      border-color: rgba(197,168,103,.28);
      background:
        linear-gradient(145deg, rgba(255,255,255,.105), rgba(255,255,255,.04)),
        radial-gradient(circle at 100% 0%, rgba(184,155,94,.09), transparent 34%);
    }

    .note-row-title {
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0 0 5px;
      font-size: 18px;
      line-height: 1.25;
    }

    .note-row-title .star {
      color: #d6bd7a;
      font-size: 16px;
    }

    .note-row-meta {
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 6px;
    }

    .note-row-excerpt {
      color: #c8d0dc;
      font-size: 13px;
      line-height: 1.45;
      max-width: 880px;
      margin: 0;
    }

    .note-row-badges {
      display: flex;
      gap: 7px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      border: 1px solid rgba(226,232,240,.12);
      border-radius: 999px;
      padding: 7px 10px;
      font-size: 12px;
      color: #e6edf7;
      background: rgba(255,255,255,.055);
      white-space: nowrap;
    }

    .badge.important {
      border-color: rgba(197,168,103,.28);
      background: rgba(197,168,103,.10);
    }

    .section-tabs {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      padding: 6px;
      border-radius: 18px;
      background: rgba(8,12,18,.24);
      width: fit-content;
      border: 1px solid rgba(226,232,240,.08);
    }

    .stats-layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 340px;
      gap: 14px;
      align-items: start;
    }

    .study-summary {
      display: grid;
      grid-template-columns: repeat(2, minmax(150px, 1fr));
      gap: 10px;
    }

    .study-card {
      border: 1px solid rgba(226,232,240,.11);
      border-radius: 18px;
      padding: 14px;
      background: rgba(255,255,255,.045);
    }

    .study-card .label {
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .10em;
      margin-bottom: 8px;
    }

    .study-card h4 {
      margin: 0;
      font-size: 17px;
      line-height: 1.25;
    }

    .study-card p {
      margin: 6px 0 0;
      color: #c8d0dc;
      font-size: 12px;
      line-height: 1.4;
    }

    .chart-card.compact-chart {
      min-height: 260px;
      padding: 14px;
    }

    .chart-card.compact-chart canvas {
      max-height: 210px;
    }

    .importance-live {
      display: inline-flex;
      min-width: 32px;
      justify-content: center;
      padding: 3px 9px;
      margin-left: 7px;
      border-radius: 999px;
      background: rgba(197,168,103,.12);
      border: 1px solid rgba(197,168,103,.22);
      color: #f5e8c4;
    }

    .bookmark-target-highlight {
      background: rgba(197,168,103,.32) !important;
      color: #fff !important;
      border-radius: 6px;
      padding: 1px 3px;
      box-shadow: 0 0 0 3px rgba(197,168,103,.10);
    }

    @media (max-width: 1100px) {
      .stats-layout {
        grid-template-columns: 1fr;
      }
      .compact-kpis {
        grid-template-columns: repeat(2, 1fr);
      }
      .filter-panel {
        grid-template-columns: 1fr;
      }
      .note-row {
        grid-template-columns: 1fr;
      }
      .note-row-badges {
        justify-content: flex-start;
      }
    }

  
    /* Final UX cleanup: compact filters, paginated sidebar spaces, bookmark minimap */
    .filter-panel {
      grid-template-columns: minmax(240px, 1fr) 160px 160px 160px auto !important;
      padding: 10px 12px !important;
      gap: 9px !important;
      align-items: center !important;
    }

    .filter-panel .btn {
      width: auto !important;
      min-width: 86px;
      justify-content: center;
      padding-left: 16px;
      padding-right: 16px;
    }

    .filter-panel .field {
      height: 46px;
      margin: 0 !important;
    }

    .sidebar-space-tools {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 7px;
      margin: 6px 0 10px;
    }

    .sidebar-space-tools input {
      width: 100%;
      min-width: 0;
      border: 1px solid rgba(226,232,240,.13);
      border-radius: 14px;
      padding: 9px 10px;
      background: rgba(8,12,18,.34);
      color: var(--text);
      outline: none;
    }

    .sidebar-space-tools button {
      border-radius: 14px;
      padding: 8px 10px;
    }

    .sidebar-pager {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin: 8px 2px 12px;
      color: var(--muted);
      font-size: 12px;
    }

    .sidebar-pager a {
      border: 1px solid rgba(226,232,240,.12);
      border-radius: 999px;
      padding: 6px 9px;
      background: rgba(255,255,255,.045);
    }

    .space-link.active {
      border-color: rgba(197,168,103,.34) !important;
      background:
        linear-gradient(135deg, rgba(197,168,103,.13), rgba(95,179,169,.08)) !important;
    }

    .main .panel.card {
      padding: 20px 22px !important;
    }

    .section-head {
      margin-bottom: 10px !important;
    }

    .note-list {
      gap: 8px !important;
    }

    .note-row {
      padding: 13px 15px !important;
    }

    .note-row-title {
      font-size: 17px !important;
    }

    .note-row-excerpt {
      max-width: 940px;
    }

    .reader-layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 14px;
      gap: 12px;
      align-items: stretch;
    }

    .bookmark-minimap {
      position: sticky;
      top: 96px;
      height: calc(100vh - 126px);
      width: 14px;
      border-radius: 999px;
      border: 1px solid rgba(226,232,240,.10);
      background: rgba(8,12,18,.38);
      overflow: hidden;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.025);
    }

    .bookmark-minimap-marker {
      position: absolute;
      left: 2px;
      width: 8px;
      height: 18px;
      border-radius: 999px;
      background: linear-gradient(180deg, #c5a867, #5fb3a9);
      box-shadow: 0 0 12px rgba(197,168,103,.55);
      cursor: pointer;
    }

    .bookmark-minimap-marker:hover {
      width: 10px;
      left: 1px;
      box-shadow: 0 0 16px rgba(197,168,103,.8);
    }

    .bookmark-target-highlight {
      background: rgba(197,168,103,.36) !important;
      color: #fff !important;
      border-radius: 6px;
      padding: 1px 3px;
      box-shadow: 0 0 0 3px rgba(197,168,103,.10);
    }

    @media (max-width: 1100px) {
      .filter-panel {
        grid-template-columns: 1fr 1fr !important;
      }
      .filter-panel .btn {
        grid-column: 1 / -1;
      }
      .reader-layout {
        grid-template-columns: 1fr;
      }
      .bookmark-minimap {
        display: none;
      }
    }

    @media (max-width: 700px) {
      .filter-panel {
        grid-template-columns: 1fr !important;
      }
    }

  
    /* Fixed reader tools + annotation/comments UX */
    .reader-tools {
      position: fixed !important;
      right: 28px !important;
      top: 18px !important;
      z-index: 1000 !important;
      opacity: .92 !important;
      max-width: calc(100vw - 80px);
      border-radius: 999px !important;
      box-shadow: 0 18px 50px rgba(0,0,0,.42), inset 0 1px 0 rgba(255,255,255,.10) !important;
    }

    .reader-tools:hover {
      opacity: 1 !important;
    }

    .note-reader-panel {
      padding-top: 84px !important;
    }

    .reader-layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 24px !important;
      gap: 14px !important;
      align-items: stretch;
    }

    .note-reader-panel .preview {
      max-height: none !important;
      overflow: visible !important;
    }

    .bookmark-minimap {
      position: sticky !important;
      top: 92px !important;
      height: calc(100vh - 112px) !important;
      width: 24px !important;
      border-radius: 999px;
      border: 1px solid rgba(226,232,240,.12);
      background: rgba(8,12,18,.52);
      overflow: visible !important;
      pointer-events: auto !important;
    }

    .annotation-marker {
      position: absolute;
      left: 3px;
      width: 18px;
      height: 18px;
      border: 0;
      border-radius: 999px;
      display: grid;
      place-items: center;
      cursor: pointer;
      color: #081018;
      font-size: 11px;
      font-weight: 950;
      box-shadow: 0 0 12px rgba(0,0,0,.35);
      transition: transform .15s ease, box-shadow .15s ease;
    }

    .annotation-marker:hover {
      transform: scale(1.18);
      box-shadow: 0 0 18px rgba(197,168,103,.75);
      z-index: 5;
    }

    .annotation-marker.bookmark {
      background: linear-gradient(135deg, #c5a867, #f1d68a);
    }

    .annotation-marker.memory {
      background: linear-gradient(135deg, #5fb3a9, #bfe7de);
    }

    .annotation-marker.comment {
      background: linear-gradient(135deg, #8aa0b8, #d8e2ed);
    }

    .annotation-target-highlight {
      background: rgba(197,168,103,.32) !important;
      color: #fff !important;
      border-radius: 6px;
      padding: 1px 3px;
      box-shadow: 0 0 0 3px rgba(197,168,103,.10);
    }

    .comment-target-highlight {
      background: rgba(138,160,184,.34) !important;
      color: #fff !important;
      border-radius: 6px;
      padding: 1px 3px;
      box-shadow: 0 0 0 3px rgba(138,160,184,.11);
    }

    .annotation-list {
      display: grid;
      gap: 10px;
    }

    .annotation-card {
      padding: 14px 16px;
      border-radius: 18px;
      border: 1px solid rgba(226,232,240,.12);
      background: linear-gradient(145deg, rgba(255,255,255,.065), rgba(255,255,255,.028));
    }

    .annotation-card .small {
      margin-bottom: 8px;
    }

    .annotation-card blockquote {
      margin: 8px 0;
      padding-left: 12px;
      border-left: 3px solid rgba(197,168,103,.55);
      color: #d9e0ea;
    }

    .selection-menu {
      gap: 7px !important;
      border-radius: 18px !important;
    }

    .comment-panel {
      position: fixed;
      z-index: 122;
      display: none;
      width: min(460px, calc(100vw - 30px));
      padding: 14px;
      border-radius: 22px;
      border: 1px solid rgba(226,232,240,.18);
      background: linear-gradient(145deg, rgba(26,34,44,.96), rgba(13,18,25,.96));
      box-shadow: 0 24px 75px rgba(0,0,0,.55);
      backdrop-filter: blur(18px);
    }

    .comment-panel.visible {
      display: block;
    }

    .comment-panel textarea {
      min-height: 110px;
    }

    @media (max-width: 900px) {
      .reader-tools {
        left: 14px !important;
        right: 14px !important;
        top: 12px !important;
        border-radius: 20px !important;
      }
      .reader-layout {
        grid-template-columns: 1fr !important;
      }
      .bookmark-minimap {
        display: none !important;
      }
    }

  
    .scroll-memory {
      pointer-events: none !important;
      right: 3px !important;
      width: 5px !important;
      opacity: .55 !important;
    }

    .scroll-memory span {
      pointer-events: none !important;
    }

  
    /* Final reader ergonomics: no title overlap, sticky in-note toolbar, inline annotation icons */
    .topbar {
      align-items: flex-start !important;
    }

    .topbar h2 {
      max-width: min(780px, 58vw);
      line-height: 1.15 !important;
      font-size: clamp(22px, 2.1vw, 30px) !important;
      overflow-wrap: anywhere;
    }

    .topbar-actions {
      max-width: 48%;
      justify-content: flex-end;
    }

    .note-reader-panel {
      padding-top: 18px !important;
      overflow: visible !important;
    }

    .note-title-main {
      max-width: calc(100% - 340px);
      line-height: 1.15 !important;
      overflow-wrap: anywhere;
      margin-bottom: 18px !important;
    }

    .reader-tools {
      position: sticky !important;
      top: 12px !important;
      right: auto !important;
      left: auto !important;
      z-index: 500 !important;
      opacity: .96 !important;
      width: fit-content;
      max-width: min(100%, 860px);
      margin-left: auto;
      margin-bottom: 14px;
      border-radius: 24px !important;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 9px !important;
      background:
        linear-gradient(145deg, rgba(11,16,24,.92), rgba(27,35,45,.88)),
        radial-gradient(circle at 0% 0%, rgba(95,179,169,.10), transparent 42%) !important;
    }

    .reader-tools .btn {
      padding: 8px 12px !important;
      font-size: 14px;
    }

    body.reading-focus .reader-tools {
      position: sticky !important;
      top: 12px !important;
      right: auto !important;
      opacity: .96 !important;
      transform: none !important;
    }

    .reader-layout {
      grid-template-columns: minmax(0, 1fr) 28px !important;
      align-items: start !important;
    }

    .annotation-inline {
      display: inline-grid;
      place-items: center;
      width: 21px;
      height: 21px;
      margin: 0 4px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,.22);
      color: #081018;
      font-size: 12px;
      font-weight: 950;
      line-height: 1;
      vertical-align: text-bottom;
      cursor: pointer;
      box-shadow: 0 0 0 3px rgba(255,255,255,.045), 0 8px 18px rgba(0,0,0,.30);
      transform: translateY(-1px);
    }

    .annotation-inline.bookmark {
      background: linear-gradient(135deg, #d8b65f, #f4df9d);
    }

    .annotation-inline.memory {
      background: linear-gradient(135deg, #5fb3a9, #c3eee5);
    }

    .annotation-inline.comment {
      background: linear-gradient(135deg, #9bb2ca, #e0ebf5);
    }

    .annotation-inline:hover {
      transform: translateY(-2px) scale(1.08);
      box-shadow: 0 0 0 4px rgba(197,168,103,.12), 0 12px 24px rgba(0,0,0,.38);
    }

    .annotation-popover {
      position: fixed;
      z-index: 1400;
      display: none;
      width: min(420px, calc(100vw - 30px));
      padding: 14px;
      border-radius: 18px;
      border: 1px solid rgba(226,232,240,.18);
      background: linear-gradient(145deg, rgba(24,32,42,.98), rgba(10,14,21,.98));
      box-shadow: 0 24px 70px rgba(0,0,0,.55);
      color: var(--text);
      backdrop-filter: blur(18px);
    }

    .annotation-popover.visible {
      display: block;
    }

    .annotation-popover .kind {
      color: #d8c487;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .10em;
      margin-bottom: 8px;
    }

    .annotation-popover blockquote {
      margin: 8px 0;
      padding-left: 12px;
      border-left: 3px solid rgba(197,168,103,.55);
      color: #d9e0ea;
      max-height: 150px;
      overflow: auto;
    }

    .annotation-popover .comment-text {
      margin-top: 8px;
      color: #f3f6fb;
      line-height: 1.5;
    }

    .annotation-popover .close-pop {
      position: absolute;
      right: 10px;
      top: 8px;
      border: 0;
      background: transparent;
      color: var(--muted);
      font-size: 20px;
      cursor: pointer;
    }

    .bookmark-minimap {
      z-index: 20;
    }

    .annotation-marker {
      font-family: ui-sans-serif, system-ui, sans-serif;
    }

    @media (max-width: 900px) {
      .topbar h2 {
        max-width: 100%;
      }
      .topbar-actions {
        max-width: 100%;
        justify-content: flex-start;
      }
      .note-title-main {
        max-width: 100%;
      }
      .reader-tools {
        width: 100%;
        justify-content: flex-start;
      }
    }

  </style>
</head>
<body>
{{ body }}
<script>
  const bodyInput = document.querySelector("#bodyInput");
  const markdownSource = document.querySelector("#markdownSource");
  const preview = document.querySelector("#preview");
  const searchInput = document.querySelector("#globalSearch");
  const scrollDot = document.querySelector("#scrollDot");
  const topHoverZone = document.querySelector("#topHoverZone");
  const speechStatus = document.querySelector("#speechStatus");

  let renderTimer = null;
  function getMarkdownText() {
    if (bodyInput) return bodyInput.value || "";
    if (markdownSource) return markdownSource.textContent || "";
    return "";
  }

  let bookmarkHighlightDone = false;
  function renderMarkdownNow() {
    if (!preview) return;
    preview.innerHTML = marked.parse(getMarkdownText());
    if (!bookmarkHighlightDone && typeof highlightBookmarkTarget === "function") {
      bookmarkHighlightDone = true;
      setTimeout(() => {
        highlightBookmarkTarget();
        if (typeof buildBookmarkMinimap === "function") buildBookmarkMinimap();
      }, 120);
      setTimeout(() => {
        if (typeof buildBookmarkMinimap === "function") buildBookmarkMinimap();
      }, 420);
    }
  }

  function scheduleMarkdownRender() {
    clearTimeout(renderTimer);
    renderTimer = setTimeout(renderMarkdownNow, 120);
  }

  function applySearchHighlight() {
    const term = searchInput ? searchInput.value.trim().toLowerCase() : "";
    const cards = document.querySelectorAll("[data-search]");
    cards.forEach(card => {
      const text = card.getAttribute("data-search").toLowerCase();
      card.style.display = !term || text.includes(term) ? "" : "none";
    });
  }

  if (bodyInput) bodyInput.addEventListener("input", scheduleMarkdownRender);
  renderMarkdownNow();

  if (searchInput) {
    searchInput.addEventListener("input", applySearchHighlight);
  }

  function updateNearTop() {
    if (window.scrollY < 90) document.body.classList.add("near-top");
    else document.body.classList.remove("near-top");
  }

  let ticking = false;
  window.addEventListener("scroll", () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      if (scrollDot) {
        const doc = document.documentElement;
        const max = Math.max(1, doc.scrollHeight - innerHeight);
        const pct = scrollY / max;
        scrollDot.style.transform = `translateY(${Math.round(pct * 80)}vh)`;
      }
      updateNearTop();
      ticking = false;
    });
  }, { passive: true });
  updateNearTop();

  if (topHoverZone) {
    topHoverZone.addEventListener("mouseenter", () => document.body.classList.add("hover-top"));
    topHoverZone.addEventListener("mouseleave", () => document.body.classList.remove("hover-top"));
  }

  function toggleClass(name) {
    document.body.classList.toggle(name);
    try { localStorage.setItem(name, document.body.classList.contains(name) ? "1" : "0"); } catch(e) {}
  }

  ["fullscreen-reader"].forEach(name => {
    try { if (localStorage.getItem(name) === "1") document.body.classList.add(name); } catch(e) {}
  });
  document.body.classList.remove("reader-hide-sidebar", "reading-focus");
  setTimeout(updateSidebarHandle, 0);

  window.toggleReadingFocus = () => {
    document.body.classList.toggle("reading-focus");
    updateSidebarHandle();
  };
  function updateSidebarHandle() {
    const restore = document.querySelector("#sidebarRestoreToggle");
    const hidden = document.body.classList.contains("reader-hide-sidebar") || document.body.classList.contains("reading-focus");
    if (restore) restore.title = hidden ? "Show sidebar" : "Hide sidebar";
  }

  window.toggleSidebar = () => {
    document.body.classList.toggle("reader-hide-sidebar");
    updateSidebarHandle();
  };

  window.toggleFullscreenReader = async () => {
    toggleClass("fullscreen-reader");
    try {
      if (!document.fullscreenElement) await document.documentElement.requestFullscreen();
      else await document.exitFullscreen();
    } catch(e) {}
  };

  function readableNoteText() {
    const tmp = document.createElement("div");
    tmp.innerHTML = marked.parse(getMarkdownText());
    return (tmp.innerText || tmp.textContent || "").replace(/\s+/g, " ").trim();
  }

  window.speakNote = () => {
    if (!("speechSynthesis" in window)) {
      if (speechStatus) speechStatus.textContent = "Speech not supported in this browser.";
      return;
    }
    window.speechSynthesis.cancel();
    const text = readableNoteText();
    if (!text) return;
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 0.95;
    utterance.pitch = 1;
    utterance.onstart = () => { if (speechStatus) speechStatus.textContent = "Reading aloud…"; updateSpeechButton("reading"); };
    utterance.onend = () => { if (speechStatus) speechStatus.textContent = "Finished."; updateSpeechButton("stopped"); };
    utterance.onerror = () => { if (speechStatus) speechStatus.textContent = "Speech stopped."; updateSpeechButton("stopped"); };
    window.speechSynthesis.speak(utterance);
  };

  window.pauseSpeech = () => {
    if ("speechSynthesis" in window) {
      if (window.speechSynthesis.paused) {
        window.speechSynthesis.resume();
        if (speechStatus) speechStatus.textContent = "Reading aloud…";
        updateSpeechButton("reading");
      } else {
        window.speechSynthesis.pause();
        if (speechStatus) speechStatus.textContent = "Paused.";
        updateSpeechButton("paused");
      }
    }
  };

  window.stopSpeech = () => {
    if ("speechSynthesis" in window) window.speechSynthesis.cancel();
    if (speechStatus) speechStatus.textContent = "Stopped.";
    updateSpeechButton("stopped");
  };

  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: { legend: { labels: { color: "#e5e7eb" } } },
    scales: {
      x: { ticks: { color: "#a8b3c7" }, grid: { color: "rgba(255,255,255,.075)" } },
      y: { beginAtZero: true, ticks: { color: "#a8b3c7", precision: 0 }, grid: { color: "rgba(255,255,255,.075)" } }
    }
  };

  function parseData(el, key, fallback) {
    try { return JSON.parse(el.dataset[key] || JSON.stringify(fallback)); }
    catch(e) { return fallback; }
  }

  const activityChart = document.querySelector("#activityChart");
  if (activityChart) {
    new Chart(activityChart, {
      type: "line",
      data: {
        labels: parseData(activityChart, "labels", []),
        datasets: [
          { label: "Created", data: parseData(activityChart, "created", []), tension: .38, fill: false, borderColor: "#5fb3a9", backgroundColor: "rgba(95,179,169,.18)" },
          { label: "Read / opened", data: parseData(activityChart, "read", []), tension: .38, fill: false, borderColor: "#c5a867", backgroundColor: "rgba(197,168,103,.18)" }
        ]
      },
      options: chartDefaults
    });
  }

  const spaceChart = document.querySelector("#spaceChart");
  if (spaceChart) {
    new Chart(spaceChart, {
      type: "bar",
      data: {
        labels: parseData(spaceChart, "labels", []),
        datasets: [
          { label: "Notes", data: parseData(spaceChart, "notes", []), backgroundColor: "rgba(95,179,169,.45)", borderColor: "#5fb3a9" },
          { label: "Visits", data: parseData(spaceChart, "visits", []), backgroundColor: "rgba(197,168,103,.42)", borderColor: "#c5a867" }
        ]
      },
      options: chartDefaults
    });
  }

  const statusChart = document.querySelector("#statusChart");
  if (statusChart) {
    new Chart(statusChart, {
      type: "doughnut",
      data: {
        labels: ["Favorites", "Read", "Unread", "Bookmarked"],
        datasets: [{ data: parseData(statusChart, "values", []), backgroundColor: ["rgba(197,168,103,.55)", "rgba(95,179,169,.55)", "rgba(138,160,184,.46)", "rgba(183,121,121,.48)"], borderColor: "rgba(255,255,255,.10)" }]
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: "#e5e7eb" } } }
      }
    });
  }

  const memoryChart = document.querySelector("#memoryChart");
  if (memoryChart) {
    new Chart(memoryChart, {
      type: "bar",
      data: {
        labels: parseData(memoryChart, "labels", []),
        datasets: [{ label: "Bookmarks", data: parseData(memoryChart, "counts", []), backgroundColor: "rgba(197,168,103,.45)", borderColor: "#c5a867" }]
      },
      options: chartDefaults
    });
  }

  function copySelectedToBookmark() {
    openQuickMemory("Review");
  }

  function currentSelectionText() {
    let selected = window.getSelection().toString().trim();
    const active = document.activeElement;
    if (!selected && active && active.tagName === "TEXTAREA") {
      selected = active.value.substring(active.selectionStart || 0, active.selectionEnd || 0).trim();
    }
    return selected;
  }

  function setMemoryPanelPosition(x, y) {
    const panel = document.querySelector("#quickMemoryPanel");
    if (!panel) return;
    const maxLeft = Math.max(12, window.innerWidth - panel.offsetWidth - 14);
    const maxTop = Math.max(12, window.innerHeight - panel.offsetHeight - 14);
    panel.style.left = Math.min(Math.max(12, x), maxLeft) + "px";
    panel.style.top = Math.min(Math.max(12, y), maxTop) + "px";
  }

  window.openQuickMemory = (bucketName) => {
    const selected = currentSelectionText();
    if (!selected) return;
    const panel = document.querySelector("#quickMemoryPanel");
    const text = document.querySelector("#quickBookmarkText");
    const label = document.querySelector("#quickBookmarkLabel");
    const bucket = document.querySelector("#quickBookmarkBucket");
    const menu = document.querySelector("#selectionMenu");
    if (text) text.value = selected;
    if (label && !label.value) label.value = bucketName === "Important Formula" ? "Important formula" : "Bookmark";
    if (bucket) bucket.value = bucketName || "Review";
    if (menu) menu.classList.remove("visible");
    if (panel) {
      panel.classList.add("visible");
      const rect = window.getSelection().rangeCount ? window.getSelection().getRangeAt(0).getBoundingClientRect() : {left: 80, bottom: 80};
      setMemoryPanelPosition(rect.left, rect.bottom + 12);
      const first = panel.querySelector("input, textarea, select");
      if (first) first.focus();
    }
  };

  window.closeQuickMemory = () => {
    const panel = document.querySelector("#quickMemoryPanel");
    const menu = document.querySelector("#selectionMenu");
    if (panel) panel.classList.remove("visible");
    if (menu) menu.classList.remove("visible");
  };

  function showSelectionMenuFromRange() {
    const menu = document.querySelector("#selectionMenu");
    const panel = document.querySelector("#quickMemoryPanel");
    const preview = document.querySelector("#preview");
    if (!menu || !preview) return;
    const selected = currentSelectionText();
    const sel = window.getSelection();
    if (!selected || !sel.rangeCount || !preview.contains(sel.anchorNode)) {
      menu.classList.remove("visible");
      return;
    }
    const rect = sel.getRangeAt(0).getBoundingClientRect();
    menu.style.left = Math.min(Math.max(12, rect.left), window.innerWidth - 260) + "px";
    menu.style.top = Math.max(12, rect.top - 54) + "px";
    menu.classList.add("visible");
    if (panel) panel.classList.remove("visible");
  }

  document.addEventListener("mouseup", () => setTimeout(showSelectionMenuFromRange, 30));
  document.addEventListener("keyup", (e) => {
    if (e.key === "Escape") closeQuickMemory();
    else setTimeout(showSelectionMenuFromRange, 30);
  });

  window.toggleNoteActions = () => {
    document.body.classList.toggle("show-note-actions");
  };

  function updateSpeechButton(state) {
    const btn = document.querySelector("#speechToggleBtn");
    if (!btn) return;
    if (state === "reading") btn.textContent = "Pause";
    else if (state === "paused") btn.textContent = "Resume";
    else btn.textContent = "Pause";
  }


  window.setTheme = (themeName) => {
    document.body.classList.remove("theme-aurora", "theme-emerald", "theme-rose");
    document.body.classList.add(themeName);
    try { localStorage.setItem("astra-theme", themeName); } catch(e) {}
  };

  try {
    const savedTheme = localStorage.getItem("astra-theme") || "theme-aurora";
    document.body.classList.add(savedTheme);
  } catch(e) {
    document.body.classList.add("theme-aurora");
  }


  window.resetLayout = () => {
    document.body.classList.remove("reader-hide-sidebar", "reading-focus", "fullscreen-reader");
    try {
      localStorage.removeItem("reader-hide-sidebar");
      localStorage.removeItem("reading-focus");
      localStorage.removeItem("fullscreen-reader");
    } catch(e) {}
    updateSidebarHandle();
  };


  function initImportanceLiveLabel() {
    const slider = document.querySelector("#importanceInput");
    const output = document.querySelector("#importanceValue");
    if (!slider || !output) return;
    const update = () => { output.textContent = slider.value; };
    slider.addEventListener("input", update);
    update();
  }

  function normalizeTextForFind(value) {
    return (value || "").replace(/\s+/g, " ").trim();
  }

  function findTextNodeContaining(root, needle) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const shortNeedle = normalizeTextForFind(needle).slice(0, 80);
    let node;
    while ((node = walker.nextNode())) {
      const normalized = normalizeTextForFind(node.nodeValue);
      if (normalized.includes(shortNeedle) || shortNeedle.includes(normalized.slice(0, 40))) return node;
    }
    return null;
  }

  function highlightBookmarkTarget() {
    const target = document.querySelector("#targetBookmarkText");
    const previewEl = document.querySelector("#preview");
    if (!target || !previewEl) return;
    const needle = normalizeTextForFind(target.textContent);
    if (!needle) return;

    const node = findTextNodeContaining(previewEl, needle);
    if (!node) return;

    const raw = node.nodeValue;
    const firstWords = needle.split(" ").slice(0, 4).join(" ");
    let start = raw.indexOf(firstWords);
    if (start < 0) start = 0;
    const end = Math.min(raw.length, start + Math.min(raw.length, needle.length));

    try {
      const range = document.createRange();
      range.setStart(node, start);
      range.setEnd(node, end);
      const mark = document.createElement("mark");
      mark.className = "bookmark-target-highlight";
      mark.id = "bookmark-target";
      range.surroundContents(mark);
      setTimeout(() => mark.scrollIntoView({ behavior: "smooth", block: "center" }), 180);
    } catch(e) {
      setTimeout(() => previewEl.scrollIntoView({ behavior: "smooth", block: "start" }), 180);
    }
  }

  function buildBookmarkMinimap() {
    const previewEl = document.querySelector("#preview");
    const map = document.querySelector("#bookmarkMinimap");
    if (!previewEl || !map) return;

    const bookmarkTexts = Array.from(document.querySelectorAll(".bookmark-source-text"))
      .map(el => normalizeTextForFind(el.textContent))
      .filter(Boolean);

    map.innerHTML = "";
    const previewHeight = Math.max(1, previewEl.scrollHeight);

    bookmarkTexts.forEach((text, index) => {
      const node = findTextNodeContaining(previewEl, text);
      if (!node) return;
      const parent = node.parentElement || previewEl;
      const top = Math.max(0, parent.offsetTop);
      const pct = Math.min(96, Math.max(0, (top / previewHeight) * 100));
      const marker = document.createElement("button");
      marker.type = "button";
      marker.className = "bookmark-minimap-marker";
      marker.style.top = pct + "%";
      marker.title = "Jump to bookmark";
      marker.addEventListener("click", () => parent.scrollIntoView({ behavior: "smooth", block: "center" }));
      map.appendChild(marker);
    });
  }



  initImportanceLiveLabel();


  // Robust annotation matching: works better for code blocks and markdown-rendered text.
  function normalizeAnnotationText(value) {
    return (value || "")
      .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")
      .replace(/\s+/g, " ")
      .trim();
  }

  function annotationTokens(value) {
    return normalizeAnnotationText(value)
      .toLowerCase()
      .split(/[^a-z0-9_().+\-=/]+/i)
      .filter(t => t.length >= 2)
      .slice(0, 12);
  }

  function scoreAnnotationNode(text, needle) {
    const hay = normalizeAnnotationText(text).toLowerCase();
    const target = normalizeAnnotationText(needle).toLowerCase();
    if (!hay || !target) return 0;
    if (hay.includes(target)) return 1000 + target.length;
    if (target.includes(hay) && hay.length > 8) return 600 + hay.length;
    const toks = annotationTokens(target);
    if (!toks.length) return 0;
    let score = 0;
    toks.forEach(t => { if (hay.includes(t)) score += 10 + Math.min(t.length, 10); });
    return score;
  }

  function findBestAnnotationElement(needle) {
    const previewEl = document.querySelector("#preview");
    if (!previewEl) return null;

    const candidates = Array.from(previewEl.querySelectorAll("code, pre, p, li, h1, h2, h3, h4, blockquote, td, th, div"));
    let best = null;
    let bestScore = 0;

    for (const el of candidates) {
      const score = scoreAnnotationNode(el.innerText || el.textContent || "", needle);
      if (score > bestScore) {
        best = el;
        bestScore = score;
      }
    }

    if (best && bestScore >= 20) return best;

    const walker = document.createTreeWalker(previewEl, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const score = scoreAnnotationNode(node.nodeValue, needle);
      if (score > bestScore) {
        best = node.parentElement;
        bestScore = score;
      }
    }
    return bestScore >= 20 ? best : null;
  }

  function jumpToAnnotationText(text, kind) {
    const el = findBestAnnotationElement(text);
    if (!el) return false;
    el.classList.add(kind === "comment" ? "comment-target-highlight" : "annotation-target-highlight");
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    setTimeout(() => {
      el.classList.remove("annotation-target-highlight");
      el.classList.remove("comment-target-highlight");
    }, 3200);
    return true;
  }

  function highlightBookmarkTarget() {
    const target = document.querySelector("#targetBookmarkText");
    if (!target) return;
    jumpToAnnotationText(target.textContent, "bookmark");
  }

  function buildBookmarkMinimap() {
    const previewEl = document.querySelector("#preview");
    const map = document.querySelector("#bookmarkMinimap");
    if (!previewEl || !map) return;
    map.innerHTML = "";

    const items = Array.from(document.querySelectorAll(".annotation-source")).map(el => ({
      text: el.dataset.text || el.textContent || "",
      kind: el.dataset.kind || "bookmark",
      label: el.dataset.label || "Annotation"
    })).filter(x => normalizeAnnotationText(x.text));

    const previewHeight = Math.max(1, previewEl.scrollHeight);

    items.forEach((item) => {
      const targetEl = findBestAnnotationElement(item.text);
      if (!targetEl) return;
      const top = Math.max(0, targetEl.offsetTop);
      const pct = Math.min(96, Math.max(0, (top / previewHeight) * 100));
      const marker = document.createElement("button");
      marker.type = "button";
      marker.className = "annotation-marker " + item.kind;
      marker.style.top = pct + "%";
      marker.title = item.label;
      marker.textContent = item.kind === "comment" ? "C" : (item.kind === "memory" ? "M" : "B");
      marker.addEventListener("click", () => jumpToAnnotationText(item.text, item.kind));
      map.appendChild(marker);
    });
  }

  window.openQuickComment = () => {
    const selected = currentSelectionText();
    if (!selected) return;
    const panel = document.querySelector("#quickCommentPanel");
    const text = document.querySelector("#quickCommentText");
    const menu = document.querySelector("#selectionMenu");
    if (text) text.value = selected;
    if (menu) menu.classList.remove("visible");
    if (panel) {
      panel.classList.add("visible");
      const rect = window.getSelection().rangeCount ? window.getSelection().getRangeAt(0).getBoundingClientRect() : {left: 80, bottom: 80};
      const maxLeft = Math.max(12, window.innerWidth - panel.offsetWidth - 14);
      const maxTop = Math.max(12, window.innerHeight - panel.offsetHeight - 14);
      panel.style.left = Math.min(Math.max(12, rect.left), maxLeft) + "px";
      panel.style.top = Math.min(Math.max(12, rect.bottom + 12), maxTop) + "px";
      const comment = document.querySelector("#quickCommentBody");
      if (comment) comment.focus();
    }
  };

  window.closeQuickComment = () => {
    const panel = document.querySelector("#quickCommentPanel");
    if (panel) panel.classList.remove("visible");
  };

  // Rebuild minimap after markdown render and after page settles.
  setTimeout(() => {
    if (typeof buildBookmarkMinimap === "function") buildBookmarkMinimap();
    if (typeof highlightBookmarkTarget === "function") highlightBookmarkTarget();
  }, 700);


  function annotationKindLabel(kind) {
    if (kind === "memory") return "Memorized";
    if (kind === "comment") return "Comment";
    return "Bookmark";
  }

  function annotationIcon(kind) {
    if (kind === "memory") return "M";
    if (kind === "comment") return "C";
    return "B";
  }

  function showAnnotationPopover(anchor, item) {
    let pop = document.querySelector("#annotationPopover");
    if (!pop) {
      pop = document.createElement("div");
      pop.id = "annotationPopover";
      pop.className = "annotation-popover";
      document.body.appendChild(pop);
    }
    pop.innerHTML = `
      <button class="close-pop" type="button" onclick="document.querySelector('#annotationPopover').classList.remove('visible')">×</button>
      <div class="kind">${annotationKindLabel(item.kind)}</div>
      <strong>${item.label || annotationKindLabel(item.kind)}</strong>
      <blockquote>${escapeHtml(item.text || "")}</blockquote>
      ${item.comment ? `<div class="comment-text">${escapeHtml(item.comment)}</div>` : ""}
    `;
    const rect = anchor.getBoundingClientRect();
    const left = Math.min(Math.max(12, rect.left), window.innerWidth - 440);
    const top = Math.min(Math.max(12, rect.bottom + 10), window.innerHeight - 260);
    pop.style.left = left + "px";
    pop.style.top = top + "px";
    pop.classList.add("visible");
  }

  function escapeHtml(value) {
    return (value || "").replace(/[&<>"']/g, ch => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
    }[ch]));
  }

  function getAnnotationItems() {
    return Array.from(document.querySelectorAll(".annotation-source")).map(el => ({
      text: el.dataset.text || el.textContent || "",
      kind: el.dataset.kind || "bookmark",
      label: el.dataset.label || "Annotation",
      comment: el.dataset.comment || ""
    })).filter(x => normalizeAnnotationText(x.text));
  }

  function addInlineAnnotationIcons() {
    const previewEl = document.querySelector("#preview");
    if (!previewEl || previewEl.dataset.inlineAnnotationsDone === "1") return;
    previewEl.dataset.inlineAnnotationsDone = "1";

    const items = getAnnotationItems();
    items.forEach((item, idx) => {
      const targetEl = findBestAnnotationElement(item.text);
      if (!targetEl || targetEl.querySelector?.(`.annotation-inline[data-ann-index="${idx}"]`)) return;

      const icon = document.createElement("button");
      icon.type = "button";
      icon.className = "annotation-inline " + item.kind;
      icon.dataset.annIndex = String(idx);
      icon.title = annotationKindLabel(item.kind) + ": " + (item.label || "");
      icon.textContent = annotationIcon(item.kind);
      icon.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        showAnnotationPopover(icon, item);
      });

      // Place icon beside the block/code where annotation was found.
      if (targetEl.tagName === "CODE" && targetEl.parentElement?.tagName === "PRE") {
        targetEl.parentElement.insertAdjacentElement("afterend", icon);
      } else {
        targetEl.insertAdjacentElement("afterend", icon);
      }
    });
  }

  // Override minimap builder so inline icons and right bar stay in sync.
  const previousBuildBookmarkMinimap = window.buildBookmarkMinimap || buildBookmarkMinimap;
  window.buildBookmarkMinimap = function() {
    if (typeof previousBuildBookmarkMinimap === "function") previousBuildBookmarkMinimap();
    addInlineAnnotationIcons();
  };

  setTimeout(addInlineAnnotationIcons, 500);
  setTimeout(addInlineAnnotationIcons, 1200);

</script>
</body>
</html>
"""


def esc(value) -> str:
    if value is None:
        return ""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def markdown_excerpt(value: str, limit: int = 210) -> str:
    """Create a clean dashboard preview instead of showing raw markdown syntax."""
    text = value or ""
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"^[#>\-*+\s]+", "", text, flags=re.M)
    text = re.sub(r"[*_~]{1,3}", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[: limit - 1].rstrip() + "…"
    return text


def render(body: str) -> HTMLResponse:
    page = HTML.replace("{{ app_name }}", APP_NAME).replace("{{ body }}", body)
    return HTMLResponse(page)


def layout(request: Request, content: str, page_title: str = "Dashboard") -> HTMLResponse:
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    q = request.query_params.get("q", "").strip()
    sq = request.query_params.get("sq", "").strip()
    spage = max(1, int(request.query_params.get("spage", "1") or "1"))
    selected_space_id = request.query_params.get("space")
    space_limit = 6
    space_offset = (spage - 1) * space_limit

    with db() as conn:
        if sq:
            space_like = f"%{sq}%"
            space_total = conn.execute(
                "SELECT COUNT(*) AS c FROM spaces WHERE user_id=? AND name LIKE ?",
                (user["id"], space_like),
            ).fetchone()["c"]
            spaces = conn.execute(
                "SELECT s.*, COUNT(n.id) AS note_count FROM spaces s LEFT JOIN notes n ON n.space_id=s.id "
                "WHERE s.user_id=? AND s.name LIKE ? GROUP BY s.id ORDER BY s.name ASC LIMIT ? OFFSET ?",
                (user["id"], space_like, space_limit, space_offset),
            ).fetchall()
        else:
            space_total = conn.execute("SELECT COUNT(*) AS c FROM spaces WHERE user_id=?", (user["id"],)).fetchone()["c"]
            spaces = conn.execute(
                "SELECT s.*, COUNT(n.id) AS note_count FROM spaces s LEFT JOIN notes n ON n.space_id=s.id "
                "WHERE s.user_id=? GROUP BY s.id ORDER BY s.created_at DESC LIMIT ? OFFSET ?",
                (user["id"], space_limit, space_offset),
            ).fetchall()

        if q:
            like = f"%{q}%"
            notes = conn.execute(
                "SELECT n.*, s.name AS space_name FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
                "WHERE n.user_id=? AND (n.title LIKE ? OR n.body LIKE ? OR n.tags LIKE ?) "
                "ORDER BY n.importance DESC, n.updated_at DESC LIMIT 30",
                (user["id"], like, like, like),
            ).fetchall()
        else:
            notes = conn.execute(
                "SELECT n.*, s.name AS space_name FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
                "WHERE n.user_id=? ORDER BY n.updated_at DESC LIMIT 30",
                (user["id"],),
            ).fetchall()

        bookmarks = conn.execute(
            "SELECT b.*, n.title AS note_title FROM bookmarks b LEFT JOIN notes n ON n.id=b.note_id "
            "WHERE b.user_id=? ORDER BY b.created_at DESC LIMIT 20",
            (user["id"],),
        ).fetchall()

    note_links = "".join(
        f"""
        <a class="note-link" data-search="{esc(n['title'] + ' ' + (n['tags'] or '') + ' ' + (n['space_name'] or ''))}" href="/notes/{n['id']}">
          <strong>{'★ ' if n['is_favorite'] else ''}{esc(n['title'])}</strong>
          <span class="small">{esc(n['space_name'] or 'No space')} · visits {n['visit_count']} · memory {n['memory_level']}</span>
        </a>
        """
        for n in notes
    ) or '<div class="empty">No notes yet. Create your first note.</div>'

    space_links = "".join(
        f"""
        <a class="space-link {'active' if str(s['id']) == str(selected_space_id) else ''}" data-search="{esc(s['name'])}" href="/?space={s['id']}&tab=notes">
          <strong>{esc(s['name'])}</strong>
          <span class="small">{s['note_count']} notes</span>
        </a>
        """
        for s in spaces
    ) or '<div class="empty">No spaces found.</div>'

    prev_link = f"/?sq={esc(sq)}&spage={spage-1}" if spage > 1 else ""
    next_link = f"/?sq={esc(sq)}&spage={spage+1}" if (space_offset + space_limit) < space_total else ""
    space_pager = f"""
      <div class="sidebar-pager">
        <span>{space_offset + 1 if space_total else 0}-{min(space_offset + space_limit, space_total)} of {space_total}</span>
        <span>
          {f'<a href="{prev_link}">Prev</a>' if prev_link else ''}
          {f'<a href="{next_link}">Next</a>' if next_link else ''}
        </span>
      </div>
    """



    bookmark_links = "".join(
        f"""
        <a class="bookmark-link" data-search="{esc(b['text'] + ' ' + (b['label'] or '') + ' ' + (b['memory_bucket'] or ''))}" href="/notes/{b['note_id'] or ''}?bookmark={b['id']}">
          <strong>{esc((b['label'] or b['text'])[:45])}</strong>
          <span class="small">{esc(b['memory_bucket'])} · {esc((b['note_title'] or 'Detached'))}</span>
        </a>
        """
        for b in bookmarks
    ) or '<div class="empty">No bookmarks yet.</div>'

    body = f"""
    <button id="sidebarRestoreToggle" class="sidebar-restore-toggle" type="button" onclick="toggleSidebar()" title="Show sidebar" aria-label="Show sidebar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="M9 6l6 6-6 6"></path>
        <path d="M4 4h3v16H4z"></path>
      </svg>
    </button>
    <div class="scroll-memory"><span id="scrollDot" style="top:0"></span></div>
    <div class="shell">
      <aside class="sidebar card">
        <div class="sidebar-header-row">
          <div class="brand">
            <div class="logo">A</div>
            <div>
              <h1>AstraNotes</h1>
              <p>Notes · spaces · memory buckets</p>
            </div>
          </div>
          <button class="sidebar-pane-toggle" type="button" onclick="toggleSidebar()" title="Hide sidebar" aria-label="Hide sidebar">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path d="M15 6l-6 6 6 6"></path>
              <path d="M20 4h-3v16h3z"></path>
            </svg>
          </button>
        </div>

        <form class="searchbox" method="get" action="/">
          <input id="globalSearch" name="q" placeholder="Search heading, body, tags..." value="{esc(q)}" />
        </form>

        <div class="pillrow">
          <a class="btn primary" href="/notes/new">+ New note</a>
          <a class="btn" href="/spaces/new">+ Space</a>
        </div>

        <div class="navarea">
          <div class="section-title">Spaces</div>
          <form class="sidebar-space-tools" method="get" action="/">
            <input name="sq" value="{esc(sq)}" placeholder="Find space...">
            <button class="btn" type="submit">Go</button>
          </form>
          {space_links}
          {space_pager}

          <div class="section-title">Latest / searched notes</div>
          {note_links}

          <div class="section-title">Memory bookmarks</div>
          {bookmark_links}
        </div>
      </aside>

      <main class="main">
        <header class="topbar card">
          <div>
            <h2>{esc(page_title)}</h2>
            <div class="small">Logged in as {esc(user['name'])}</div>
          </div>
          <div class="topbar-actions">
            <a class="pill" href="/">Dashboard</a>
            <a class="pill" href="/review">Review queue</a>
            <button class="pill" type="button" onclick="resetLayout()">Reset layout</button>
            <a class="pill" href="/logout">Logout</a>
          </div>
        </header>

        {content}
      </main>
    </div>
    """
    return render(body)


# -----------------------------
# Auth routes
# -----------------------------
@app.get("/login")
def login_page(request: Request, error: str = ""):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return render(f"""
    <div class="auth-wrap">
      <div class="auth card">
        <section class="hero">
          <div class="logo">A</div>
          <h1>Capture. Search. Memorize.</h1>
          <p>A metallic, local-first knowledge workspace for notes, formulas, highlights, projects, bookmarks, review queues and markdown reading continuity.</p>
          <div class="pillrow">
            <span class="pill">SQLite local DB</span>
            <span class="pill">Markdown preview</span>
            <span class="pill">Memory buckets</span>
          </div>
        </section>
        <section class="auth-form">
          <h2>Quick login</h2>
          <div class="error">{esc(error)}</div>
          <form method="post" action="/login">
            <input class="field" name="email" type="email" placeholder="Email" required>
            <input class="field" name="password" type="password" placeholder="Password" required>
            <button class="btn primary" type="submit">Login</button>
          </form>
          <hr style="border-color:rgba(255,255,255,.12); margin:28px 0">
          <h2>Create account</h2>
          <form method="post" action="/signup">
            <input class="field" name="name" placeholder="Name" required>
            <input class="field" name="email" type="email" placeholder="Email" required>
            <input class="field" name="password" type="password" placeholder="Password" minlength="4" required>
            <button class="btn" type="submit">Sign up</button>
          </form>
        </section>
      </div>
    </div>
    """)


@app.post("/signup")
def signup(name: str = Form(...), email: str = Form(...), password: str = Form(...)):
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
                (name.strip(), email.strip().lower(), hash_password(password), now_iso()),
            )
            user_id = cur.lastrowid
            conn.execute(
                "INSERT INTO spaces(user_id,name,description,created_at) VALUES(?,?,?,?)",
                (user_id, "Personal Knowledge Space", "Default space for notes and formulas.", now_iso()),
            )
        return login_response(user_id)
    except sqlite3.IntegrityError:
        return RedirectResponse("/login?error=Email+already+exists", status_code=303)


@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return RedirectResponse("/login?error=Invalid+email+or+password", status_code=303)
    return login_response(user["id"])


@app.get("/logout")
def logout():
    res = RedirectResponse("/login", status_code=303)
    res.delete_cookie(SESSION_COOKIE)
    return res

@app.get("/health")
def health():
    return {
        "status": "ok",
        "db_path": str(DB_PATH),
        "db_exists": DB_PATH.exists(),
        "data_dir": str(DATA_DIR),
    }




# -----------------------------
# App routes
# -----------------------------
@app.get("/")
def dashboard(request: Request, q: str = "", space: int | None = None, filter: str = "", sort: str = "latest", tab: str = "stats"):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    if space and tab == "stats":
        tab = "notes"

    clauses = ["n.user_id=?"]
    args: list = [user["id"]]
    if q:
        clauses.append("(n.title LIKE ? OR n.body LIKE ? OR n.tags LIKE ?)")
        args.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if space:
        clauses.append("n.space_id=?")
        args.append(space)
    if filter == "favorite":
        clauses.append("n.is_favorite=1")
    if filter == "unread":
        clauses.append("n.is_read=0")
    if filter == "read":
        clauses.append("n.is_read=1")
    if filter == "bookmarked":
        clauses.append("EXISTS (SELECT 1 FROM bookmarks b WHERE b.note_id=n.id AND b.user_id=n.user_id)")

    order_map = {
        "latest": "n.updated_at DESC",
        "created": "n.created_at DESC",
        "importance": "n.importance DESC, n.updated_at DESC",
        "most_visited": "n.visit_count DESC, n.updated_at DESC",
        "least_visited": "n.visit_count ASC, n.updated_at DESC",
        "title": "LOWER(n.title) ASC",
    }
    order_by = order_map.get(sort, order_map["latest"])

    where = " AND ".join(clauses)

    with db() as conn:
        stats = {
            "notes": conn.execute("SELECT COUNT(*) c FROM notes WHERE user_id=?", (user["id"],)).fetchone()["c"],
            "spaces": conn.execute("SELECT COUNT(*) c FROM spaces WHERE user_id=?", (user["id"],)).fetchone()["c"],
            "bookmarks": conn.execute("SELECT COUNT(*) c FROM bookmarks WHERE user_id=?", (user["id"],)).fetchone()["c"],
            "review": conn.execute("SELECT COUNT(*) c FROM bookmarks WHERE user_id=? AND memory_bucket!='Mastered'", (user["id"],)).fetchone()["c"],
        }
        selected_space = conn.execute(
            "SELECT * FROM spaces WHERE id=? AND user_id=?",
            (space, user["id"]),
        ).fetchone() if space else None

        all_spaces = conn.execute(
            "SELECT id, name FROM spaces WHERE user_id=? ORDER BY name ASC",
            (user["id"],),
        ).fetchall()

        notes = conn.execute(
            f"SELECT n.*, s.name AS space_name FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            f"WHERE {where} ORDER BY {order_by} LIMIT 40",
            args,
        ).fetchall()
        daily = conn.execute(
            "SELECT substr(created_at,1,10) d, COUNT(*) c FROM notes WHERE user_id=? "
            "GROUP BY d ORDER BY d DESC LIMIT 7",
            (user["id"],),
        ).fetchall()[::-1]

        favorite_topic = conn.execute(
            "SELECT n.id, n.title, COALESCE(s.name, 'No space') AS space_name, n.importance, n.visit_count "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? AND n.is_favorite=1 "
            "ORDER BY n.importance DESC, n.visit_count DESC, n.updated_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()

        least_favorite_topic = conn.execute(
            "SELECT n.id, n.title, COALESCE(s.name, 'No space') AS space_name, n.importance, n.visit_count "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? AND n.is_favorite=0 "
            "ORDER BY n.importance ASC, n.visit_count ASC, n.updated_at ASC LIMIT 1",
            (user["id"],),
        ).fetchone() if stats["notes"] >= 2 else None

        most_generated_space = conn.execute(
            "SELECT COALESCE(s.name, 'No space') AS name, n.space_id AS id, COUNT(n.id) AS note_count "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? GROUP BY n.space_id ORDER BY note_count DESC, name ASC LIMIT 1",
            (user["id"],),
        ).fetchone()

        most_visited_note = conn.execute(
            "SELECT n.id, n.title, COALESCE(s.name, 'No space') AS space_name, n.visit_count "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? AND n.visit_count > 0 ORDER BY n.visit_count DESC, n.updated_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()

        least_visited_note = conn.execute(
            "SELECT n.id, n.title, COALESCE(s.name, 'No space') AS space_name, n.visit_count "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? ORDER BY n.visit_count ASC, n.updated_at ASC LIMIT 1",
            (user["id"],),
        ).fetchone() if stats["notes"] >= 2 else None

        space_count_with_notes = conn.execute(
            "SELECT COUNT(*) AS c FROM (SELECT n.space_id FROM notes n WHERE n.user_id=? GROUP BY n.space_id)",
            (user["id"],),
        ).fetchone()["c"]

        most_visited_space = conn.execute(
            "SELECT COALESCE(s.name, 'No space') AS name, n.space_id AS id, SUM(n.visit_count) AS visits, COUNT(n.id) AS note_count "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? GROUP BY n.space_id HAVING visits > 0 ORDER BY visits DESC, note_count DESC LIMIT 1",
            (user["id"],),
        ).fetchone()

        least_visited_space = conn.execute(
            "SELECT COALESCE(s.name, 'No space') AS name, n.space_id AS id, SUM(n.visit_count) AS visits, COUNT(n.id) AS note_count "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? GROUP BY n.space_id ORDER BY visits ASC, note_count DESC LIMIT 1",
            (user["id"],),
        ).fetchone() if space_count_with_notes >= 2 else None

        activity_rows = conn.execute(
            "WITH RECURSIVE dates(d) AS ("
            "  SELECT date('now','-6 days') "
            "  UNION ALL SELECT date(d,'+1 day') FROM dates WHERE d < date('now')"
            ") "
            "SELECT dates.d, "
            "SUM(CASE WHEN a.action='create' THEN 1 ELSE 0 END) AS created, "
            "SUM(CASE WHEN a.action='read' THEN 1 ELSE 0 END) AS reads "
            "FROM dates LEFT JOIN note_activity a ON substr(a.created_at,1,10)=dates.d AND a.user_id=? "
            "GROUP BY dates.d ORDER BY dates.d",
            (user["id"],),
        ).fetchall()

        # Backfill create counts from notes.created_at so older notes still appear even before note_activity existed.
        created_rows = conn.execute(
            "WITH RECURSIVE dates(d) AS ("
            "  SELECT date('now','-6 days') "
            "  UNION ALL SELECT date(d,'+1 day') FROM dates WHERE d < date('now')"
            ") "
            "SELECT dates.d, COUNT(n.id) AS c "
            "FROM dates LEFT JOIN notes n ON substr(n.created_at,1,10)=dates.d AND n.user_id=? "
            "GROUP BY dates.d ORDER BY dates.d",
            (user["id"],),
        ).fetchall()

        space_rows = conn.execute(
            "SELECT COALESCE(s.name, 'No space') AS name, COUNT(n.id) AS note_count, COALESCE(SUM(n.visit_count),0) AS visits "
            "FROM notes n LEFT JOIN spaces s ON s.id=n.space_id "
            "WHERE n.user_id=? GROUP BY n.space_id ORDER BY note_count DESC, visits DESC LIMIT 6",
            (user["id"],),
        ).fetchall()

        status_counts = conn.execute(
            "SELECT "
            "SUM(CASE WHEN is_favorite=1 THEN 1 ELSE 0 END) AS favorites, "
            "SUM(CASE WHEN is_read=1 THEN 1 ELSE 0 END) AS read_count, "
            "SUM(CASE WHEN is_read=0 THEN 1 ELSE 0 END) AS unread_count "
            "FROM notes WHERE user_id=?",
            (user["id"],),
        ).fetchone()

        bookmarked_note_count = conn.execute(
            "SELECT COUNT(DISTINCT note_id) AS c FROM bookmarks WHERE user_id=? AND note_id IS NOT NULL",
            (user["id"],),
        ).fetchone()["c"]

        memory_rows = conn.execute(
            "SELECT memory_bucket, COUNT(*) AS c FROM bookmarks WHERE user_id=? GROUP BY memory_bucket ORDER BY c DESC",
            (user["id"],),
        ).fetchall()

        create_streak_rows = conn.execute(
            "SELECT DISTINCT substr(created_at,1,10) AS d FROM notes WHERE user_id=? ORDER BY d DESC",
            (user["id"],),
        ).fetchall()
        read_streak_rows = conn.execute(
            "SELECT DISTINCT substr(created_at,1,10) AS d FROM note_activity WHERE user_id=? AND action='read' ORDER BY d DESC",
            (user["id"],),
        ).fetchall()

    labels = [r["d"][5:] for r in daily] or []
    counts = [r["c"] for r in daily] or []

    activity_labels = [r["d"][5:] for r in activity_rows]
    created_counts = [r["c"] for r in created_rows]
    read_counts = [r["reads"] or 0 for r in activity_rows]

    space_labels = [r["name"] for r in space_rows]
    space_note_counts = [r["note_count"] for r in space_rows]
    space_visit_counts = [r["visits"] or 0 for r in space_rows]

    status_values = [
        status_counts["favorites"] or 0,
        status_counts["read_count"] or 0,
        status_counts["unread_count"] or 0,
        bookmarked_note_count or 0,
    ]

    memory_labels = [r["memory_bucket"] for r in memory_rows] or ["No bookmarks"]
    memory_counts = [r["c"] for r in memory_rows] or [0]

    def current_streak(rows) -> int:
        days = {r["d"] for r in rows}
        streak = 0
        probe = datetime.now(timezone.utc).date()
        while probe.isoformat() in days:
            streak += 1
            from datetime import timedelta
            probe = probe - timedelta(days=1)
        return streak

    create_streak = current_streak(create_streak_rows)
    read_streak = current_streak(read_streak_rows)
    total_visits = sum(space_visit_counts)
    average_visits = round(total_visits / stats["notes"], 1) if stats["notes"] else 0

    cards = "".join(
        f"""
        <a class="note-row" data-search="{esc(n['title'] + ' ' + (n['body'] or '') + ' ' + (n['tags'] or ''))}" href="/notes/{n['id']}">
          <div>
            <h3 class="note-row-title"><span class="star">{'★' if n['is_favorite'] else ''}</span>{esc(n['title'])}</h3>
            <div class="note-row-meta">{esc(n['space_name'] or 'No space')} · {esc(n['tags'] or 'untagged')} · updated {esc((n['updated_at'] or '')[:10])}</div>
            <p class="note-row-excerpt">{esc(markdown_excerpt(n['body'], 150))}</p>
          </div>
          <div class="note-row-badges">
            <span class="badge important">Imp {n['importance']}</span>
            <span class="badge">Visits {n['visit_count']}</span>
            <span class="badge">Memory {n['memory_level']}</span>
            <span class="badge">{'Read' if n['is_read'] else 'Unread'}</span>
          </div>
        </a>
        """
        for n in notes
    ) or '<div class="empty">No matching notes. Try changing filters or create a new note.</div>'

    def space_href(row) -> str:
        if not row:
            return ""
        if row["id"] is None:
            return "/?space="
        return f"/?space={row['id']}&tab=notes"

    def insight_card(label: str, title: str | None, value: str = "", href: str = "", tone: str = "tone-steel", hint: str = "") -> str:
        if not title:
            return f'<div class="insight-card empty-insight {tone}"><div class="label">{esc(label)}</div><h3>Not enough data yet</h3><div class="value">{esc(hint or "Add more notes, spaces, favourites, and visits to unlock this insight.")}</div></div>'
        inner = f'<div class="label">{esc(label)}</div><h3>{esc(title)}</h3><div class="value">{esc(value)}</div>'
        if href:
            return f'<a class="insight-card {tone}" href="{esc(href)}">{inner}</a>'
        return f'<div class="insight-card {tone}">{inner}</div>'

    insights = "".join([
        insight_card(
            "Favourite topic",
            favorite_topic["title"] if favorite_topic else None,
            f"{favorite_topic['space_name']} · importance {favorite_topic['importance']} · visits {favorite_topic['visit_count']}" if favorite_topic else "",
            f"/notes/{favorite_topic['id']}" if favorite_topic else "",
            "tone-blue",
            "Mark at least one note as favourite to see this.",
        ),
        insight_card(
            "Least favourite topic",
            least_favorite_topic["title"] if least_favorite_topic else None,
            f"{least_favorite_topic['space_name']} · importance {least_favorite_topic['importance']} · visits {least_favorite_topic['visit_count']}" if least_favorite_topic else "",
            f"/notes/{least_favorite_topic['id']}" if least_favorite_topic else "",
            "tone-graphite",
            "Needs at least two notes before a least-favourite comparison is meaningful.",
        ),
        insight_card(
            "Most notes generated space",
            most_generated_space["name"] if most_generated_space else None,
            f"{most_generated_space['note_count']} notes" if most_generated_space else "",
            space_href(most_generated_space) if most_generated_space else "",
            "tone-platinum",
            "Create notes inside spaces to see the leading space.",
        ),
        insight_card(
            "Most visited note",
            most_visited_note["title"] if most_visited_note else None,
            f"{most_visited_note['space_name']} · {most_visited_note['visit_count']} visits" if most_visited_note else "",
            f"/notes/{most_visited_note['id']}" if most_visited_note else "",
            "tone-violet",
            "Open notes to start building visit history.",
        ),
        insight_card(
            "Least visited note",
            least_visited_note["title"] if least_visited_note else None,
            f"{least_visited_note['space_name']} · {least_visited_note['visit_count']} visits" if least_visited_note else "",
            f"/notes/{least_visited_note['id']}" if least_visited_note else "",
            "tone-slate",
            "Needs at least two notes before a least-visited comparison is meaningful.",
        ),
        insight_card(
            "Most visited space",
            most_visited_space["name"] if most_visited_space else None,
            f"{most_visited_space['visits'] or 0} visits across {most_visited_space['note_count']} notes" if most_visited_space else "",
            space_href(most_visited_space) if most_visited_space else "",
            "tone-violet",
            "Visit notes inside spaces to unlock this.",
        ),
        insight_card(
            "Least visited space",
            least_visited_space["name"] if least_visited_space else None,
            f"{least_visited_space['visits'] or 0} visits across {least_visited_space['note_count']} notes" if least_visited_space else "",
            space_href(least_visited_space) if least_visited_space else "",
            "tone-graphite",
            "Needs notes in at least two spaces before comparison is meaningful.",
        ),
    ])

    active_context = f"space={space}&" if space else ""
    space_title = selected_space["name"] if selected_space else "All spaces"
    stats_active = "active" if tab == "stats" else ""
    notes_active = "active" if tab == "notes" else ""
    q_value = esc(q)
    filter_options = {
        "": "All notes",
        "favorite": "Favorites",
        "unread": "Unread",
        "read": "Read",
        "bookmarked": "Bookmarked",
    }
    sort_options = {
        "latest": "Latest updated",
        "created": "Newest created",
        "importance": "Importance",
        "most_visited": "Most visited",
        "least_visited": "Least visited",
        "title": "Title A-Z",
    }
    filter_select = "".join([f'<option value="{esc(k)}" {"selected" if filter == k else ""}>{esc(v)}</option>' for k, v in filter_options.items()])
    sort_select = "".join([f'<option value="{esc(k)}" {"selected" if sort == k else ""}>{esc(v)}</option>' for k, v in sort_options.items()])
    space_select = '<option value="">All spaces</option>' + "".join([
        f'<option value="{sp["id"]}" {"selected" if space == sp["id"] else ""}>{esc(sp["name"])}</option>'
        for sp in all_spaces
    ])

    stats_html = f"""
      <div class="dashboard-shell-compact">
        <div class="compact-kpis">
          <div class="compact-kpi"><b>{stats['notes']}</b><span>Notes</span></div>
          <div class="compact-kpi"><b>{stats['bookmarks']}</b><span>Saved highlights</span></div>
          <div class="compact-kpi"><b>{create_streak}</b><span>Create streak</span></div>
          <div class="compact-kpi"><b>{read_streak}</b><span>Read streak</span></div>
        </div>

        <div class="stats-layout">
          <div class="chart-card compact-chart">
            <h4>Study activity</h4>
            <p>Creation vs reading over the last 7 days.</p>
            <canvas id="activityChart"
              data-labels='{json.dumps(activity_labels)}'
              data-created='{json.dumps(created_counts)}'
              data-read='{json.dumps(read_counts)}'></canvas>
          </div>

          <div class="study-summary">
            <div class="study-card">
              <div class="label">Focus now</div>
              <h4>{esc(most_visited_note['title']) if most_visited_note else 'Start reading'}</h4>
              <p>{esc(str(most_visited_note['visit_count']) + ' visits') if most_visited_note else 'Open notes to build study history.'}</p>
            </div>
            <div class="study-card">
              <div class="label">Needs attention</div>
              <h4>{esc(least_visited_note['title']) if least_visited_note else 'Not enough data'}</h4>
              <p>{esc(str(least_visited_note['visit_count']) + ' visits') if least_visited_note else 'Create more notes for comparison.'}</p>
            </div>
            <div class="study-card">
              <div class="label">Top space</div>
              <h4>{esc(most_generated_space['name']) if most_generated_space else 'No space yet'}</h4>
              <p>{esc(str(most_generated_space['note_count']) + ' notes') if most_generated_space else 'Add notes inside spaces.'}</p>
            </div>
            <div class="study-card">
              <div class="label">Avg visits</div>
              <h4>{average_visits}</h4>
              <p>Average note revisits.</p>
            </div>
          </div>

          <div class="chart-card compact-chart">
            <h4>Spaces</h4>
            <p>Notes created vs visits.</p>
            <canvas id="spaceChart"
              data-labels='{json.dumps(space_labels)}'
              data-notes='{json.dumps(space_note_counts)}'
              data-visits='{json.dumps(space_visit_counts)}'></canvas>
          </div>

          <div class="chart-card compact-chart">
            <h4>Memory buckets</h4>
            <p>Saved highlights by review bucket.</p>
            <canvas id="memoryChart"
              data-labels='{json.dumps(memory_labels)}'
              data-counts='{json.dumps(memory_counts)}'></canvas>
          </div>
        </div>
      </div>
    """

    notes_html = f"""
      <div class="dashboard-section note-list-section">
        <div class="section-head">
          <div>
            <h3>Notes in {esc(space_title)}</h3>
            <p>Latest notes are shown top-down. Use search, filter, and sort to focus.</p>
          </div>
        </div>

        <form class="filter-panel" method="get" action="/">
          <input type="hidden" name="tab" value="notes">
          <input class="field" name="q" value="{q_value}" placeholder="Search notes...">
          <select class="field" name="space">{space_select}</select>
          <select class="field" name="filter">{filter_select}</select>
          <select class="field" name="sort">{sort_select}</select>
          <button class="btn primary" type="submit">Apply</button>
        </form>

        <div class="note-list">{cards}</div>
      </div>
    """

    content = f"""
    <section class="panel card">
      <div class="section-head">
        <div>
          <h3>{esc(space_title)}</h3>
          <p>Clean workspace for study notes, review, and progress.</p>
        </div>
      </div>
      <div class="section-tabs">
        <a class="pill {notes_active}" href="/?{active_context}tab=notes">Notes</a>
        <a class="pill {stats_active}" href="/?tab=stats">Stats</a>
      </div>
      {notes_html if tab == "notes" else stats_html}
    </section>
    """
    return layout(request, content, "Dashboard")


@app.get("/spaces/new")
def new_space(request: Request):
    content = """
    <section class="panel card">
      <h3>Create project / space</h3>
      <form method="post" action="/spaces/new">
        <input class="field" name="name" placeholder="Space name, e.g. Machine Learning Formulas" required>
        <textarea name="description" placeholder="Short description"></textarea>
        <button class="btn primary" type="submit">Create space</button>
      </form>
    </section>
    """
    return layout(request, content, "New Space")


@app.post("/spaces/new")
def create_space(request: Request, name: str = Form(...), description: str = Form("")):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        conn.execute(
            "INSERT INTO spaces(user_id,name,description,created_at) VALUES(?,?,?,?)",
            (user["id"], name.strip(), description.strip(), now_iso()),
        )
    return RedirectResponse("/", status_code=303)


@app.get("/notes/new")
def new_note(request: Request):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        spaces = conn.execute("SELECT * FROM spaces WHERE user_id=? ORDER BY name", (user["id"],)).fetchall()

    opts = '<option value="">No space</option>' + "".join(f'<option value="{s["id"]}">{esc(s["name"])}</option>' for s in spaces)
    return note_form(request, None, opts, "New Note")


def note_form(request: Request, note: Optional[sqlite3.Row], space_options: str, title: str):
    n_title = esc(note["title"] if note else "")
    n_body = esc(note["body"] if note else "")
    n_tags = esc(note["tags"] if note else "")
    importance = int(note["importance"] if note else 3)
    action = f"/notes/{note['id']}/edit" if note else "/notes/new"
    checked_fav = "checked" if note and note["is_favorite"] else ""
    checked_read = "checked" if note and note["is_read"] else ""

    bookmark_form = ""
    if note:
        bookmark_form = f"""
        <aside class="home-card">
          <h3>Add selected text to memory</h3>
          <p class="small">Select text from preview or editor, click capture, then save it into a memory bucket.</p>
          <form method="post" action="/notes/{note['id']}/bookmark">
            <textarea id="bookmarkText" name="text" placeholder="Important formula or paragraph"></textarea>
            <input class="field" name="label" placeholder="Label, e.g. Bayes theorem">
            <select class="field" name="bucket">
              <option>Review</option>
              <option>Important Formula</option>
              <option>Exam Critical</option>
              <option>Mastered</option>
            </select>
            <button class="btn" type="button" onclick="copySelectedToBookmark()">Capture selected text</button>
            <button class="btn primary" type="submit">Add to memory</button>
          </form>
        </aside>
        """

    content = f"""
    <section class="panel card">
      <form method="post" action="{action}">
        <div class="toolbar">
          <button class="btn primary" type="submit">Save note</button>
          <a class="btn" href="/">Cancel</a>
          {f'<a class="btn" href="/notes/{note["id"]}/delete">Delete</a>' if note else ''}
        </div>
        <input class="field" name="title" placeholder="Heading / note title" value="{n_title}" required>
        <div class="home-grid">
          <select class="field" name="space_id">{space_options}</select>
          <input class="field" name="tags" placeholder="tags: ml, formula, interview" value="{n_tags}">
        </div>
        <div class="home-grid">
          <label class="pill"><input type="checkbox" name="is_favorite" {checked_fav}> Favorite</label>
          <label class="pill"><input type="checkbox" name="is_read" {checked_read}> Mark as read</label>
        </div>
        <label class="small">Importance <span id="importanceValue" class="importance-live">{importance}</span></label>
        <input id="importanceInput" class="field" type="range" min="1" max="5" name="importance" value="{importance}">
        <div class="editor">
          <textarea id="bodyInput" name="body" placeholder="# Write markdown here">{n_body}</textarea>
          <article id="preview" class="preview" onclick="copySelectedToBookmark()"></article>
        </div>
      </form>
    </section>
    {bookmark_form}
    """
    return layout(request, content, title)


@app.post("/notes/new")
def create_note(
    request: Request,
    title: str = Form(...),
    body: str = Form(""),
    tags: str = Form(""),
    space_id: str = Form(""),
    importance: int = Form(3),
    is_favorite: str = Form(None),
    is_read: str = Form(None),
):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    sid = int(space_id) if space_id else None
    with db() as conn:
        created_at = now_iso()
        cur = conn.execute(
            "INSERT INTO notes(user_id,space_id,title,body,tags,is_favorite,is_read,importance,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (user["id"], sid, title.strip(), body, tags.strip(), 1 if is_favorite else 0, 1 if is_read else 0, importance, created_at, created_at),
        )
        conn.execute(
            "INSERT INTO note_activity(user_id,note_id,action,created_at) VALUES(?,?,?,?)",
            (user["id"], cur.lastrowid, "create", created_at),
        )
    return RedirectResponse(f"/notes/{cur.lastrowid}", status_code=303)


@app.get("/notes/{note_id}")
def view_note(request: Request, note_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        note = conn.execute(
            "SELECT n.*, s.name AS space_name FROM notes n LEFT JOIN spaces s ON s.id=n.space_id WHERE n.id=? AND n.user_id=?",
            (note_id, user["id"]),
        ).fetchone()
        if not note:
            return PlainTextResponse("Note not found", status_code=404)
        visited_at = now_iso()
        try:
            conn.execute(
                "UPDATE notes SET visit_count=visit_count+1,last_visited_at=?,last_position=? WHERE id=?",
                (visited_at, int(request.query_params.get("pos", 0) or 0), note_id),
            )
            conn.execute(
                "INSERT INTO note_activity(user_id,note_id,action,created_at) VALUES(?,?,?,?)",
                (user["id"], note_id, "read", visited_at),
            )
        except sqlite3.OperationalError:
            # Reading a note must never fail because visit analytics could not be written.
            # The note still opens; only visit tracking for this request is skipped.
            pass
        bookmarks = conn.execute("SELECT * FROM bookmarks WHERE note_id=? AND user_id=? ORDER BY created_at DESC", (note_id, user["id"])).fetchall()
        comments = conn.execute("SELECT * FROM comments WHERE note_id=? AND user_id=? ORDER BY created_at DESC", (note_id, user["id"])).fetchall()
        target_bookmark = None
        target_comment = None
        target_bookmark_id = request.query_params.get("bookmark")
        target_comment_id = request.query_params.get("comment")
        if target_bookmark_id:
            target_bookmark = conn.execute(
                "SELECT * FROM bookmarks WHERE id=? AND note_id=? AND user_id=?",
                (target_bookmark_id, note_id, user["id"]),
            ).fetchone()
        if target_comment_id:
            target_comment = conn.execute(
                "SELECT * FROM comments WHERE id=? AND note_id=? AND user_id=?",
                (target_comment_id, note_id, user["id"]),
            ).fetchone()

    bookmark_list = "".join(
        f"""
        <div class="home-card">
          <div class="small">{esc(b['memory_bucket'])} · {esc(b['label'])}</div>
          <p>{esc(b['text'])}</p>
          <a class="pill" href="/notes/{note_id}?bookmark={b['id']}">Jump to text</a>
          <a class="pill" href="/bookmarks/{b['id']}/promote">Promote memory level</a>
          <a class="pill" href="/bookmarks/{b['id']}/delete">Remove</a>
        </div>
        """
        for b in bookmarks
    ) or '<div class="empty">No memory bookmarks for this note yet.</div>'

    comment_list = "".join(
        f"""
        <div class="annotation-card">
          <div class="small">Comment · {esc(c['created_at'][:10])}</div>
          <blockquote>{esc(c['selected_text'])}</blockquote>
          <p>{esc(c['comment'])}</p>
          <div class="toolbar">
            <a class="pill" href="/notes/{note_id}?comment={c['id']}">Jump to text</a>
            <a class="pill" href="/comments/{c['id']}/delete">Remove</a>
          </div>
        </div>
        """
        for c in comments
    ) or '<div class="empty">No comments yet. Select text and choose Comment.</div>'

    annotation_sources = "".join(
        [
            f'<span class="annotation-source" data-kind="{"memory" if b["memory_bucket"] != "Review" else "bookmark"}" data-label="{esc(b["memory_bucket"])}" data-text="{esc(b["text"])}">{esc(b["text"])}</span>'
            for b in bookmarks
        ] + [
            f'<span class="annotation-source" data-kind="comment" data-label="Comment" data-comment="{esc(c["comment"])}" data-text="{esc(c["selected_text"])}">{esc(c["selected_text"])}</span>'
            for c in comments
        ]
    )

    target_text = ""
    if target_bookmark:
        target_text = target_bookmark["text"]
    if target_comment:
        target_text = target_comment["selected_text"]

    content = f"""
    <div id="topHoverZone" class="top-hover-zone"></div>

    <div id="selectionMenu" class="selection-menu">
      <button class="btn primary" type="button" onclick="openQuickMemory('Review')">Bookmark</button>
      <button class="btn" type="button" onclick="openQuickMemory('Important Formula')">Memorize</button>
      <button class="btn" type="button" onclick="openQuickComment()">Comment</button>
      <button class="btn" type="button" onclick="closeQuickMemory(); closeQuickComment()">×</button>
    </div>

    <form id="quickMemoryPanel" class="quick-memory-panel" method="post" action="/notes/{note_id}/bookmark">
      <div class="panel-title">Save selection</div>
      <textarea id="quickBookmarkText" name="text" placeholder="Selected text"></textarea>
      <input id="quickBookmarkLabel" class="field" name="label" placeholder="Label, e.g. GAN generator">
      <select id="quickBookmarkBucket" class="field" name="bucket">
        <option>Review</option>
        <option>Important Formula</option>
        <option>Exam Critical</option>
        <option>Mastered</option>
      </select>
      <div class="toolbar">
        <button class="btn primary" type="submit">Save</button>
        <button class="btn" type="button" onclick="closeQuickMemory()">Cancel</button>
      </div>
    </form>

    <form id="quickCommentPanel" class="comment-panel" method="post" action="/notes/{note_id}/comment">
      <div class="panel-title">Add comment</div>
      <textarea id="quickCommentText" name="selected_text" placeholder="Selected text"></textarea>
      <textarea id="quickCommentBody" name="comment" placeholder="Your comment, doubt, reminder, or explanation..." required></textarea>
      <div class="toolbar">
        <button class="btn primary" type="submit">Save comment</button>
        <button class="btn" type="button" onclick="closeQuickComment()">Cancel</button>
      </div>
    </form>

    <div style="display:none">{annotation_sources}</div>

    <section class="panel card note-reader-panel">
      <div class="reader-tools">
        <button class="btn primary" type="button" onclick="toggleReadingFocus()">Reading mode</button>
        <button class="btn" type="button" onclick="toggleFullscreenReader()">Full screen</button>
        <button class="btn" type="button" onclick="speakNote()">🔊 Read aloud</button>
        <button id="speechToggleBtn" class="btn" type="button" onclick="pauseSpeech()">Pause</button>
        <button class="btn" type="button" onclick="stopSpeech()">Stop</button>
        <button class="btn" type="button" onclick="toggleNoteActions()">Actions</button>
        <span id="speechStatus" class="speech-status"></span>
      </div>

      <div class="toolbar note-actions">
        <a class="btn primary" href="/notes/{note_id}/edit">Edit note</a>
        <button class="btn" type="button" onclick="copySelectedToBookmark()">Bookmark selected text</button>
        <a class="btn" href="/notes/{note_id}/toggle_favorite">{'Remove favorite' if note['is_favorite'] else 'Make favorite'}</a>
        <a class="btn" href="/notes/{note_id}/toggle_read">{'Mark unread' if note['is_read'] else 'Mark read'}</a>
      </div>

      <div class="small note-meta">{esc(note['space_name'] or 'No space')} · tags: {esc(note['tags'])} · visits {note['visit_count']} · continue from last position {note['last_position']}</div>
      <h1 class="note-title-main">{esc(note['title'])}</h1>
      <p class="reading-help">Select any text inside the note to instantly show Bookmark/Memorize options.</p>
      <article id="preview" class="preview"></article>
      <script type="text/plain" id="markdownSource">{esc(note['body'])}</script>\n      {f'<script type="text/plain" id="targetBookmarkText">{esc(target_text)}</script>' if target_text else ''}
    </section>

    <section class="panel card">
      <h3>Memory bucket for this note</h3>
      <div class="annotation-list">{bookmark_list}</div>
    </section>

    <section class="panel card">
      <h3>Comments for this note</h3>
      <div class="annotation-list">{comment_list}</div>
    </section>
    """
    return layout(request, content, note["title"])


@app.get("/notes/{note_id}/edit")
def edit_note(request: Request, note_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        note = conn.execute("SELECT * FROM notes WHERE id=? AND user_id=?", (note_id, user["id"])).fetchone()
        spaces = conn.execute("SELECT * FROM spaces WHERE user_id=? ORDER BY name", (user["id"],)).fetchall()
    if not note:
        return PlainTextResponse("Note not found", status_code=404)

    opts = '<option value="">No space</option>'
    for s in spaces:
        selected = "selected" if note["space_id"] == s["id"] else ""
        opts += f'<option value="{s["id"]}" {selected}>{esc(s["name"])}</option>'
    return note_form(request, note, opts, "Edit Note")


@app.post("/notes/{note_id}/edit")
def update_note(
    request: Request,
    note_id: int,
    title: str = Form(...),
    body: str = Form(""),
    tags: str = Form(""),
    space_id: str = Form(""),
    importance: int = Form(3),
    is_favorite: str = Form(None),
    is_read: str = Form(None),
):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    sid = int(space_id) if space_id else None
    with db() as conn:
        conn.execute(
            "UPDATE notes SET space_id=?,title=?,body=?,tags=?,is_favorite=?,is_read=?,importance=?,updated_at=? "
            "WHERE id=? AND user_id=?",
            (sid, title.strip(), body, tags.strip(), 1 if is_favorite else 0, 1 if is_read else 0, importance, now_iso(), note_id, user["id"]),
        )
    return RedirectResponse(f"/notes/{note_id}", status_code=303)


@app.post("/notes/{note_id}/bookmark")
def add_bookmark(request: Request, note_id: int, text: str = Form(...), label: str = Form(""), bucket: str = Form("Review")):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if text.strip():
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO bookmarks(user_id,note_id,text,label,memory_bucket,created_at) VALUES(?,?,?,?,?,?)",
                (user["id"], note_id, text.strip(), label.strip(), bucket.strip(), now_iso()),
            )
            bookmark_id = cur.lastrowid
        return RedirectResponse(f"/notes/{note_id}?bookmark={bookmark_id}", status_code=303)
    return RedirectResponse(f"/notes/{note_id}", status_code=303)



@app.post("/notes/{note_id}/comment")
def add_comment(request: Request, note_id: int, selected_text: str = Form(...), comment: str = Form(...)):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if selected_text.strip() and comment.strip():
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO comments(user_id,note_id,selected_text,comment,created_at) VALUES(?,?,?,?,?)",
                (user["id"], note_id, selected_text.strip(), comment.strip(), now_iso()),
            )
            comment_id = cur.lastrowid
        return RedirectResponse(f"/notes/{note_id}?comment={comment_id}", status_code=303)
    return RedirectResponse(f"/notes/{note_id}", status_code=303)


@app.get("/comments/{comment_id}/delete")
def delete_comment(request: Request, comment_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    note_id = None
    with db() as conn:
        row = conn.execute("SELECT note_id FROM comments WHERE id=? AND user_id=?", (comment_id, user["id"])).fetchone()
        if row:
            note_id = row["note_id"]
            conn.execute("DELETE FROM comments WHERE id=? AND user_id=?", (comment_id, user["id"]))
    return RedirectResponse(f"/notes/{note_id}" if note_id else "/", status_code=303)


@app.get("/review")
def review(request: Request):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        items = conn.execute(
            "SELECT b.*, n.title AS note_title FROM bookmarks b LEFT JOIN notes n ON n.id=b.note_id "
            "WHERE b.user_id=? ORDER BY CASE b.memory_bucket WHEN 'Exam Critical' THEN 1 WHEN 'Important Formula' THEN 2 WHEN 'Review' THEN 3 ELSE 4 END, b.created_at DESC",
            (user["id"],),
        ).fetchall()

    cards = "".join(
        f"""
        <div class="home-card" data-search="{esc(b['text'] + ' ' + b['label'] + ' ' + b['memory_bucket'])}">
          <div class="small">{esc(b['memory_bucket'])} · from {esc(b['note_title'] or 'Detached')}</div>
          <h3>{esc(b['label'] or 'Memory item')}</h3>
          <p>{esc(b['text'])}</p>
          <a class="pill" href="/notes/{b['note_id']}?bookmark={b['id']}">Open exact text</a>
          <a class="pill" href="/bookmarks/{b['id']}/promote">Promote</a>
          <a class="pill" href="/bookmarks/{b['id']}/delete">Remove</a>
        </div>
        """
        for b in items
    ) or '<div class="empty">Nothing in review. Bookmark important formulas or paragraphs from notes.</div>'

    content = f"""
    <section class="panel card">
      <h3>Memorization review queue</h3>
      <p class="small">Use this to go through one bookmark at a time across notes and projects.</p>
      <div class="home-grid">{cards}</div>
    </section>
    """
    return layout(request, content, "Review Queue")


@app.get("/bookmarks/{bookmark_id}/promote")
def promote_bookmark(request: Request, bookmark_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    order = ["Review", "Important Formula", "Exam Critical", "Mastered"]
    with db() as conn:
        b = conn.execute("SELECT * FROM bookmarks WHERE id=? AND user_id=?", (bookmark_id, user["id"])).fetchone()
        if b:
            idx = min(len(order) - 1, order.index(b["memory_bucket"]) + 1) if b["memory_bucket"] in order else 1
            conn.execute("UPDATE bookmarks SET memory_bucket=? WHERE id=?", (order[idx], bookmark_id))
            if b["note_id"]:
                conn.execute("UPDATE notes SET memory_level=memory_level+1 WHERE id=? AND user_id=?", (b["note_id"], user["id"]))
    return RedirectResponse("/review", status_code=303)


@app.get("/bookmarks/{bookmark_id}/delete")
def delete_bookmark(request: Request, bookmark_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        conn.execute("DELETE FROM bookmarks WHERE id=? AND user_id=?", (bookmark_id, user["id"]))
    return RedirectResponse("/review", status_code=303)


@app.get("/notes/{note_id}/toggle_favorite")
def toggle_favorite(request: Request, note_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        conn.execute("UPDATE notes SET is_favorite=1-is_favorite WHERE id=? AND user_id=?", (note_id, user["id"]))
    return RedirectResponse(f"/notes/{note_id}", status_code=303)


@app.get("/notes/{note_id}/toggle_read")
def toggle_read(request: Request, note_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        conn.execute("UPDATE notes SET is_read=1-is_read WHERE id=? AND user_id=?", (note_id, user["id"]))
    return RedirectResponse(f"/notes/{note_id}", status_code=303)


@app.get("/notes/{note_id}/delete")
def delete_note(request: Request, note_id: int):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        conn.execute("DELETE FROM notes WHERE id=? AND user_id=?", (note_id, user["id"]))
    return RedirectResponse("/", status_code=303)


if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8001, reload=True)
