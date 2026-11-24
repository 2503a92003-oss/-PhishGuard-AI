"""PhishGuard AI: Flask app. Run with `python app.py`."""
import csv
import io
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

from flask import Flask, Response, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup, escape

import detector

BASE = Path(__file__).parent
DB_PATH = Path(os.environ.get("PHISHGUARD_DB", BASE / "phishguard.db"))
MAX_LEN = 10_000
STATUSES = ["Open", "In review", "Confirmed phishing", "False alarm", "Closed"]

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PHISHGUARD_SECRET") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Open',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL,
  content TEXT NOT NULL,
  score INTEGER NOT NULL,
  level TEXT NOT NULL,
  ml_score REAL,
  details TEXT NOT NULL,
  investigation_id INTEGER REFERENCES investigations(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_level ON scans(level);
CREATE INDEX IF NOT EXISTS idx_scans_inv ON scans(investigation_id);
"""


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")


# ---------- security ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "").encode()
        if not secrets.compare_digest(session.get("_csrf", "").encode(), sent):
            abort(400, "Your session expired. Go back, refresh the page and try again.")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; frame-ancestors 'none'; form-action 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ---------- template helpers ----------
def defang(value):
    """hxxp://evil[.]example so a link can be shown without being clickable."""
    return re.sub(r"^http", "hxxp", str(value), flags=re.I).replace(".", "[.]")


def defang_text(text):
    return detector.URL_RE.sub(lambda m: defang(m.group(0)), text or "")


def preview(row, n=90):
    text = " ".join(row["content"].split())
    text = defang(text) if row["kind"] == "url" else defang_text(text)
    return text[:n] + ("…" if len(text) > n else "")


def highlight(text, spans):
    merged = []
    for s, e in sorted((s, e) for s, e in spans if 0 <= s < e <= len(text)):
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, pos = [], 0
    for s, e in merged:
        out += [escape(text[pos:s]), Markup("<mark>"), escape(text[s:e]), Markup("</mark>")]
        pos = e
    out.append(escape(text[pos:]))
    return Markup("").join(out)


app.jinja_env.globals.update(csrf_token=csrf_token, level_for=detector.level_for, statuses=STATUSES)
app.jinja_env.filters.update(defang=defang, defang_text=defang_text, preview=preview)


# ---------- data helpers ----------
def get_scan(scan_id):
    row = db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        abort(404)
    return row, json.loads(row["details"])


def get_investigation(inv_id):
    row = db().execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    if not row:
        abort(404)
    return row


def create_investigation(title, notes=""):
    cur = db().execute(
        "INSERT INTO investigations (title, notes, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (title[:120], notes[:5000], now(), now()),
    )
    return cur.lastrowid


def all_investigations():
    return db().execute("SELECT id, title FROM investigations ORDER BY updated_at DESC").fetchall()


# ---------- scanning ----------
class _HTMLTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.ignored += 1
        elif not self.ignored and tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.parts.append(f" {href} ")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.ignored:
            self.ignored -= 1

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def extract_email(content):
    message = BytesParser(policy=policy.default).parsebytes(content)
    parts = [
        f"{name}: {message[name]}"
        for name in ("From", "Reply-To", "Return-Path", "Subject")
        if message[name]
    ]
    plain_bodies, html_bodies = [], []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                body = payload.decode(charset, errors="replace")
            except LookupError:
                body = payload.decode("utf-8", errors="replace")
        if not isinstance(body, str):
            continue
        if part.get_content_type() == "text/plain":
            plain_bodies.append(body)
        else:
            parser = _HTMLTextParser()
            parser.feed(body)
            html_bodies.append(" ".join(parser.parts))
    parts.extend(plain_bodies or html_bodies)
    return "\n\n".join(part for part in parts if part).strip()


def render_index(content="", kind="message", status=200):
    recent = db().execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()
    return render_template("index.html", content=content, kind=kind, recent=recent), status


@app.get("/")
def index():
    return render_index()


@app.post("/scan")
def scan():
    content = request.form.get("content", "").strip()
    kind = request.form.get("kind", "message")
    kind = kind if kind in ("message", "url") else "message"
    upload = request.files.get("email_file")
    error = None
    if upload and upload.filename:
        if Path(upload.filename).suffix.lower() != ".eml":
            error = "Choose an email file with the .eml extension."
        else:
            content = extract_email(upload.read())
            kind = "email"
    if not content:
        error = error or "Paste a message or link, or choose an .eml email file to scan."
    elif len(content) > MAX_LEN:
        error = f"That's too long. Scan up to {MAX_LEN:,} characters at a time."
    elif kind == "url" and re.search(r"\s", content):
        error = "A link can't contain spaces. Choose Message to scan longer text."
    if error:
        flash(error, "error")
        return render_index(content, kind, 400)
    result = detector.analyze(content, kind)
    cur = db().execute(
        "INSERT INTO scans (created_at, kind, content, score, level, ml_score, details) VALUES (?,?,?,?,?,?,?)",
        (now(), kind, content, result["score"], result["level"], result["ml_score"], json.dumps(result)),
    )
    db().commit()
    return redirect(url_for("scan_detail", scan_id=cur.lastrowid))


@app.get("/scan/<int:scan_id>")
def scan_detail(scan_id):
    row, details = get_scan(scan_id)
    spans = [sp for f in details["findings"] for sp in f["spans"]]
    marked = highlight(row["content"], spans) if row["kind"] != "url" else None
    inv = get_investigation(row["investigation_id"]) if row["investigation_id"] else None
    return render_template("scan.html", scan=row, d=details, marked=marked, inv=inv,
                           investigations=all_investigations())


@app.post("/scan/<int:scan_id>/assign")
def assign(scan_id):
    get_scan(scan_id)
    new_title = request.form.get("new_title", "").strip()
    choice = request.form.get("investigation_id", "")
    inv_id = None
    if new_title:
        inv_id = create_investigation(new_title)
    elif choice.isdigit():
        inv_id = get_investigation(int(choice))["id"]
    db().execute("UPDATE scans SET investigation_id = ? WHERE id = ?", (inv_id, scan_id))
    if inv_id:
        db().execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (now(), inv_id))
    db().commit()
    flash("Added to the investigation." if inv_id else "Removed from its investigation.", "ok")
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.post("/scan/<int:scan_id>/delete")
def delete_scan(scan_id):
    get_scan(scan_id)
    db().execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    db().commit()
    flash("Scan deleted.", "ok")
    return redirect(url_for("history"))


# ---------- history ----------
@app.get("/history")
def history():
    level = request.args.get("level", "")
    q = request.args.get("q", "").strip()
    sql, args = "SELECT * FROM scans WHERE 1=1", []
    if level in ("Low", "Medium", "High"):
        sql += " AND level = ?"
        args.append(level)
    if q:
        sql += " AND content LIKE ? ESCAPE '\\'"
        args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    rows = db().execute(sql + " ORDER BY id DESC LIMIT 200", args).fetchall()
    row_count = db().execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return render_template("history.html", rows=rows, level=level, q=q, row_count=row_count)


@app.post("/history/clear")
def clear_history():
    db().execute("DELETE FROM scans")
    db().commit()
    flash("Scan history cleared.", "ok")
    return redirect(url_for("history"))


def safe_cell(value):
    """Stop spreadsheet apps from running a scanned string as a formula."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/export/scans.csv")
def export_csv():
    rows = db().execute(
        "SELECT s.*, i.title AS inv FROM scans s LEFT JOIN investigations i ON i.id = s.investigation_id ORDER BY s.id DESC"
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_utc", "type", "level", "score", "model_score", "warning_signs", "investigation", "content"])
    for r in rows:
        titles = "; ".join(f["title"] for f in json.loads(r["details"])["findings"])
        ml = "" if r["ml_score"] is None else round(r["ml_score"], 3)
        w.writerow([safe_cell(x) for x in (r["id"], r["created_at"], r["kind"], r["level"], r["score"], ml, titles, r["inv"], r["content"])])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=phishguard-scans.csv"})


# ---------- investigations ----------
@app.route("/investigations", methods=["GET", "POST"])
def investigations():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if not title:
            flash("Give the investigation a title.", "error")
        else:
            inv_id = create_investigation(title, request.form.get("notes", "").strip())
            db().commit()
            return redirect(url_for("investigation", inv_id=inv_id))
    rows = db().execute(
        """SELECT i.*, COUNT(s.id) AS scan_count, COALESCE(MAX(s.score), 0) AS top_score
           FROM investigations i LEFT JOIN scans s ON s.investigation_id = i.id
           GROUP BY i.id ORDER BY i.updated_at DESC"""
    ).fetchall()
    return render_template("investigations.html", rows=rows)


@app.get("/investigations/<int:inv_id>")
def investigation(inv_id):
    inv = get_investigation(inv_id)
    scans = db().execute("SELECT * FROM scans WHERE investigation_id = ? ORDER BY id DESC", (inv_id,)).fetchall()
    return render_template("investigation.html", inv=inv, scans=scans)


@app.post("/investigations/<int:inv_id>/update")
def update_investigation(inv_id):
    get_investigation(inv_id)
    title = request.form.get("title", "").strip() or "Untitled investigation"
    status = request.form.get("status")
    status = status if status in STATUSES else "Open"
    db().execute("UPDATE investigations SET title=?, status=?, notes=?, updated_at=? WHERE id=?",
                 (title[:120], status, request.form.get("notes", "")[:5000], now(), inv_id))
    db().commit()
    flash("Investigation saved.", "ok")
    return redirect(url_for("investigation", inv_id=inv_id))


@app.get("/investigations/<int:inv_id>/report")
def report(inv_id):
    inv = get_investigation(inv_id)
    rows = db().execute("SELECT * FROM scans WHERE investigation_id = ? ORDER BY score DESC, id", (inv_id,)).fetchall()
    scans = [(r, json.loads(r["details"])) for r in rows]
    counts = {lv: sum(1 for r in rows if r["level"] == lv) for lv in ("High", "Medium", "Low")}
    return render_template("report.html", inv=inv, scans=scans, counts=counts, generated=now())


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
