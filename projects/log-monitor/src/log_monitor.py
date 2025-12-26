
#!/usr/bin/env python3
"""
Tural Aghabalayev
CYBR-260 Final Project
Date: October 2025
File: final_log_monitor.py

Purpose:
    Cross-platform log monitoring and real-time alerting system.
    Watches authentication logs and raises an email alert when there are
    N failed logins within W minutes. Stores normalized events in SQLite.

How to run:
    Windows  : Open **Command Prompt as Administrator**, then  python final_log_monitor.py
    Linux/mac: sudo python3 final_log_monitor.py

Notes:
    - Windows: reads Security log via 'wevtutil' (requires Administrator).
    - Linux/macOS: tails a text log (default /var/log/auth.log).
    - Email: SMTP over TLS (port 465). Use an app password where required.
"""

import os
import re
import sys
import time
import smtplib
import sqlite3
import platform
import subprocess
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from typing import Optional, Tuple

# =========================
# CONFIG
CONFIG = {
    # Storage
    "DB_FILE": "security_events.db",

    # Alert policy (N failures within W minutes)
    "ALERT_THRESHOLD_COUNT": 5,
    "ALERT_WINDOW_MINUTES": 5,

    # Email (SMTP over TLS)
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 465,
    "SMTP_USERNAME": "taghabalayev@gmail.com",          # <-- fill (e.g., "you@gmail.com")
    "SMTP_PASSWORD": "owtg pkhz keao vdnm",          # <-- fill (Gmail App Password)
    "EMAIL_TO": "taghabalayev@gmail.com",               # <-- fill (e.g., "you@gmail.com")

    # Unix-like input (set to an existing file if different)
    "LOG_FILE": "/var/log/auth.log",

    # Polling cadence
    "POLL_SECONDS": 3,

    # Optional behavior
    "STOP_AFTER_ALERT": False,    # True = exit after first alert is sent
}

IS_WINDOWS = platform.system().lower().startswith("win")
HOSTNAME = platform.node() or "unknown-host"

# Regex for Unix-like auth lines
FAILED_RE = re.compile(
    r"(Failed|Invalid)\s+\w+\s+for\s+(?:invalid user\s+)?(?P<user>\S+).*?(?:from|rhost=)\s*(?P<ip>[\da-fA-F:\.]+)",
    re.IGNORECASE,
)
ACCEPT_RE = re.compile(
    r"(Accepted|session opened).*?for\s+(?P<user>\S+).*?(?:from|rhost=)\s*(?P<ip>[\da-fA-F:\.]+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Function: utc_now_iso
# Purpose:  Current UTC time in ISO 8601 with trailing 'Z'.
# ---------------------------------------------------------------------------
def utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# ---------------------------------------------------------------------------
# Function: init_db
# Purpose:  Open/connect SQLite and ensure tables exist (with safe migration).
# ---------------------------------------------------------------------------
def init_db(db_file: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_file, check_same_thread=False)
    cur = conn.cursor()

    # Base tables
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY,
            ts_utc    TEXT,
            status    TEXT,        -- 'Failed' or 'Accepted'
            username  TEXT,
            ip_address TEXT,
            host      TEXT,
            source    TEXT,        -- 'win/4625', 'win/4624', file path, etc.
            record_id INTEGER,     -- Windows EventRecordID if present
            raw       TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY,
            ts_utc  TEXT NOT NULL,
            summary TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS state(
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        )
    """)

    # Migrate older schemas (idempotent)
    cols = {r[1] for r in cur.execute("PRAGMA table_info(events)").fetchall()}
    def addcol(name, typ):
        if name not in cols:
            cur.execute(f"ALTER TABLE events ADD COLUMN {name} {typ}")
            cols.add(name)
    for name, typ in [
        ("ts_utc", "TEXT"), ("status", "TEXT"), ("username", "TEXT"),
        ("ip_address", "TEXT"), ("host", "TEXT"), ("source", "TEXT"),
        ("record_id", "INTEGER"), ("raw", "TEXT"),
    ]:
        addcol(name, typ)

    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Function: save_state / load_state
# Purpose:  Persist tiny runtime values (e.g., last Windows record id).
# ---------------------------------------------------------------------------
def save_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO state(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (key, value),
    )
    conn.commit()


def load_state(conn: sqlite3.Connection, key: str, default: str = "0") -> str:
    row = conn.execute("SELECT v FROM state WHERE k=?", (key,)).fetchone()
    return row[0] if row else default


# ---------------------------------------------------------------------------
# Function: insert_event
# Purpose:  Insert a normalized event row into SQLite.
# ---------------------------------------------------------------------------
def insert_event(conn: sqlite3.Connection, ts: str, status: str,
                 username: Optional[str], ip: Optional[str],
                 source: str, record_id: Optional[int], raw: str) -> None:
    conn.execute(
        "INSERT INTO events(ts_utc,status,username,ip_address,host,source,record_id,raw) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (ts, status, username, ip, HOSTNAME, source, record_id, raw),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Function: count_failed_in_window
# Purpose:  Number of 'Failed' events in the last W minutes.
# ---------------------------------------------------------------------------
def count_failed_in_window(conn: sqlite3.Connection, minutes: int) -> int:
    cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).replace(microsecond=0).isoformat() + "Z"
    row = conn.execute(
        "SELECT COUNT(*) FROM events WHERE status='Failed' AND ts_utc >= ?",
        (cutoff,),
    ).fetchone()
    return int(row[0] or 0)


# ---------------------------------------------------------------------------
# Function: recent_alert_exists
# Purpose:  Return True if an alert already exists within the window (dedupe).
# ---------------------------------------------------------------------------
def recent_alert_exists(conn: sqlite3.Connection, window_minutes: int) -> bool:
    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).replace(microsecond=0).isoformat() + "Z"
    row = conn.execute("SELECT COUNT(*) FROM alerts WHERE ts_utc >= ?", (cutoff,)).fetchone()
    return bool(row and row[0] > 0)


# ---------------------------------------------------------------------------
# Function: record_alert
# Purpose:  Store alert summary + send email; at most one per window.
# ---------------------------------------------------------------------------
def record_alert(conn: sqlite3.Connection, summary: str) -> None:
    if recent_alert_exists(conn, CONFIG["ALERT_WINDOW_MINUTES"]):
        return
    conn.execute("INSERT INTO alerts(ts_utc, summary) VALUES(?,?)", (utc_now_iso(), summary))
    conn.commit()
    send_email("Security Alert: Failed login burst", summary)
    if CONFIG.get("STOP_AFTER_ALERT"):
        print("[alert] STOP_AFTER_ALERT=True — exiting.")
        sys.exit(0)


# ---------------------------------------------------------------------------
# Function: send_email
# Purpose:  Send an email via SMTP/TLS if configured; otherwise print notice.
# ---------------------------------------------------------------------------
def send_email(subject: str, body: str) -> None:
    user = CONFIG["SMTP_USERNAME"]
    pwd  = CONFIG["SMTP_PASSWORD"]
    to   = CONFIG["EMAIL_TO"]
    if not (user and pwd and to):
        print("[email] SMTP not configured; skipping email.")
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to
    try:
        with smtplib.SMTP_SSL(CONFIG["SMTP_SERVER"], CONFIG["SMTP_PORT"]) as s:
            s.login(user, pwd)
            s.send_message(msg)
        print("[email] Sent.")
    except Exception as e:
        print(f"[email] Error: {e}")


# ---------------------------------------------------------------------------
# Function: parse_unix_line
# Purpose:  Parse a single auth log line; return (status,user,ip) or None.
# ---------------------------------------------------------------------------
def parse_unix_line(line: str) -> Optional[Tuple[str, str, str]]:
    m = FAILED_RE.search(line)
    if m:
        return ("Failed", m.group("user"), m.group("ip"))
    m = ACCEPT_RE.search(line)
    if m:
        return ("Accepted", m.group("user"), m.group("ip"))
    return None


# ---------------------------------------------------------------------------
# Function: tail_unix_file
# Purpose:  Minimal polling tail for a text log (no extra packages).
# ---------------------------------------------------------------------------
def tail_unix_file(conn: sqlite3.Connection, path: str) -> None:
    print(f"[tail] Monitoring {path} (Ctrl+C to stop)")
    try:
        f = open(path, "r", encoding="utf-8", errors="ignore")
        f.seek(0, os.SEEK_END)
    except Exception as e:
        print(f"[tail] Cannot open {path}: {e}")
        sys.exit(1)

    try:
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(CONFIG["POLL_SECONDS"])
                f.seek(where)
                continue

            parsed = parse_unix_line(line)
            if parsed:
                status, user, ip = parsed
                # Best-effort timestamp from syslog prefix (e.g., "Oct 13 14:21:00")
                ts_txt = " ".join(line.split()[:3])
                try:
                    ts = datetime.strptime(
                        f"{datetime.utcnow().year} {ts_txt}",
                        "%Y %b %d %H:%M:%S",
                    ).isoformat() + "Z"
                except Exception:
                    ts = utc_now_iso()
                insert_event(conn, ts, status, user, ip, path, None, line.strip())

            # Threshold check (failures only)
            if count_failed_in_window(conn, CONFIG["ALERT_WINDOW_MINUTES"]) >= CONFIG["ALERT_THRESHOLD_COUNT"]:
                summary = (f"{CONFIG['ALERT_THRESHOLD_COUNT']}+ failed logins within "
                           f"{CONFIG['ALERT_WINDOW_MINUTES']}m on {HOSTNAME} at {utc_now_iso()}")
                record_alert(conn, summary)
    except KeyboardInterrupt:
        pass
    finally:
        f.close()


# ---------------------------------------------------------------------------
# Function: bootstrap_windows_last_record
# Purpose:  Start at the newest 4625 so only future failures count.
# ---------------------------------------------------------------------------
def bootstrap_windows_last_record(conn: sqlite3.Connection) -> int:
    try:
        out = subprocess.check_output(
            ["wevtutil", "qe", "Security",
             "/q:*[System[(EventID=4625)]]",
             "/f:RenderedXml", "/c:1", "/rd:true"],
            text=True, encoding="utf-8", errors="ignore"
        )
        ev = re.search(r"<Event[^>]*>.*?</Event>", out, flags=re.DOTALL)
        if not ev:
            return 0
        rid = _xml_int(ev.group(0), "EventRecordID") or 0
        if rid > 0:
            save_state(conn, "last_record_id", str(rid))
        return rid
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Function: read_windows_events
# Purpose:  Poll Security log via 'wevtutil' (4625 failed).
#           Requires running in an elevated (Administrator) command prompt.
# ---------------------------------------------------------------------------
def read_windows_events(conn: sqlite3.Connection) -> None:
    print("[win] Monitoring Windows Security log via wevtutil (Ctrl+C to stop)")
    query = "/q:*[System[(EventID=4625)]]"

    last_record = int(load_state(conn, "last_record_id", "0"))
    if last_record == 0:  # first run → start from 'now'
        last_record = bootstrap_windows_last_record(conn)

    try:
        while True:
            try:
                out = subprocess.check_output(
                    ["wevtutil", "qe", "Security", query, "/f:RenderedXml", "/c:128", "/rd:true"],
                    text=True, encoding="utf-8", errors="ignore",
                )
            except subprocess.CalledProcessError as e:
                # Common when not run as Administrator
                print(f"[win] wevtutil error: {e}\n{e.stdout or ''}{e.stderr or ''}")
                time.sleep(CONFIG["POLL_SECONDS"])
                continue
            except Exception as e:
                print(f"[win] wevtutil error: {e}")
                time.sleep(CONFIG["POLL_SECONDS"])
                continue

            events = re.findall(r"<Event[^>]*>.*?</Event>", out, flags=re.DOTALL)
            new_high = last_record
            for ev in events:
                rid = _xml_int(ev, "EventRecordID")
                if rid and rid <= last_record:
                    continue
                eid = _xml_int(ev, "EventID") or 0
                status = "Accepted" if eid == 4624 else ("Failed" if eid == 4625 else "")
                ts = _xml_attr(ev, "TimeCreated", "SystemTime") or utc_now_iso()
                user = _xml_data(ev, "TargetUserName") or _xml_data(ev, "SubjectUserName")
                ip = _xml_data(ev, "IpAddress")
                if ip in (None, "::1", "127.0.0.1", "-"):
                    ip = None

                insert_event(conn, ts, status, user, ip, f"win/{eid}", rid, ev)
                if rid and rid > new_high:
                    new_high = rid

            if new_high > last_record:
                save_state(conn, "last_record_id", str(new_high))
                last_record = new_high

            # Threshold check (failures only)
            if count_failed_in_window(conn, CONFIG["ALERT_WINDOW_MINUTES"]) >= CONFIG["ALERT_THRESHOLD_COUNT"]:
                summary = (f"{CONFIG['ALERT_THRESHOLD_COUNT']}+ failed logins within "
                           f"{CONFIG['ALERT_WINDOW_MINUTES']}m on {HOSTNAME} at {utc_now_iso()}")
                record_alert(conn, summary)

            time.sleep(CONFIG["POLL_SECONDS"])
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# Function: _xml_int / _xml_attr / _xml_data
# Purpose:  Minimal XML helpers using regex (sufficient for Event XML).
# ---------------------------------------------------------------------------
def _xml_int(xml: str, tag: str) -> Optional[int]:
    m = re.search(rf"<{tag}>(\d+)</{tag}>", xml)
    try:
        return int(m.group(1)) if m else None
    except Exception:
        return None


def _xml_attr(xml: str, tag: str, attr: str) -> Optional[str]:
    m = re.search(rf"<{tag}[^>]*{attr}=\"([^\"]+)\"", xml)
    return m.group(1) if m else None


def _xml_data(xml: str, name_attr: str) -> Optional[str]:
    m = re.search(rf"<Data[^>]*Name=\"{re.escape(name_attr)}\"[^>]*>(.*?)</Data>", xml, flags=re.DOTALL)
    if not m:
        return None
    return (m.group(1) or "").strip() or None


# ---------------------------------------------------------------------------
# Function: main
# Purpose:  Entry point: init DB, choose OS path, and monitor.
# ---------------------------------------------------------------------------
def main() -> int:
    conn = init_db(CONFIG["DB_FILE"])
    print("=== CYBR-260 Final Project: Log Monitor ===")
    print(f"DB: {CONFIG['DB_FILE']} | threshold={CONFIG['ALERT_THRESHOLD_COUNT']} in {CONFIG['ALERT_WINDOW_MINUTES']}m")

    if IS_WINDOWS:
        print("[i] NOTE: Run this terminal **as Administrator** to read the Security log.")
        read_windows_events(conn)
        return 0

    log_path = CONFIG["LOG_FILE"]
    if not os.path.exists(log_path):
        print(f"[!] Log file not found: {log_path}")
        print("    Set CONFIG['LOG_FILE'] to a readable file (e.g., /var/log/auth.log).")
        return 1

    tail_unix_file(conn, log_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
