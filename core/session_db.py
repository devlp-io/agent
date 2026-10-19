"""
core/session_db.py — Local SQLite Session & Memory Database for SOM-SCAN.
Persists chat sessions, messages, assessment findings, and execution history across runs.
"""

import sqlite3
import os
import contextlib
import json
import pathlib
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_DIR = pathlib.Path(os.environ.get("AG_DATA_DIR", pathlib.Path.home() / ".somscan")).resolve()
DB_PATH = DB_DIR / "sessions.db"


@contextlib.contextmanager
def _get_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=10.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
    except Exception:
        pass
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    """Create schema if not exists."""
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                title TEXT,
                target TEXT,
                created_at TEXT,
                updated_at TEXT,
                metadata TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                role TEXT,
                content TEXT,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                severity TEXT,
                title TEXT,
                evidence TEXT,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        conn.commit()


# Initialize on import
init_db()


class SessionDB:
    """Thread-safe interface for managing local session state in SQLite."""

    @staticmethod
    def create_session(target: str = "", title: str = "") -> str:
        session_id = uuid.uuid4().hex[:12]
        now = datetime.now().isoformat()
        t = title or (f"Session on {target}" if target else "General Chat")
        with _get_db() as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, title, target, created_at, updated_at, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, t, target, now, now, json.dumps({}))
            )
            conn.commit()
        return session_id

    @staticmethod
    def get_or_create_active_session(session_id: Optional[str] = None, target: str = "") -> str:
        if session_id:
            with _get_db() as conn:
                row = conn.execute("SELECT session_id FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
                if row:
                    return session_id
        return SessionDB.create_session(target=target)

    @staticmethod
    def update_session_target(session_id: str, target: str):
        now = datetime.now().isoformat()
        with _get_db() as conn:
            conn.execute(
                "UPDATE sessions SET target = ?, updated_at = ? WHERE session_id = ?",
                (target, now, session_id)
            )
            conn.commit()

    @staticmethod
    def update_session_title(session_id: str, title: str):
        now = datetime.now().isoformat()
        with _get_db() as conn:
            conn.execute(
                "UPDATE sessions SET title = ?, updated_at = ? WHERE session_id = ?",
                (title, now, session_id)
            )
            conn.commit()

    @staticmethod
    def add_message(session_id: str, role: str, content: str):
        now = datetime.now().isoformat()
        with _get_db() as conn:
            conn.execute(
                "INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
                (session_id, role, content, now)
            )
            conn.execute("UPDATE sessions SET updated_at = ? WHERE session_id = ?", (now, session_id))
            conn.commit()

    @staticmethod
    def add_finding(session_id: str, severity: str, title: str, evidence: str):
        now = datetime.now().isoformat()
        with _get_db() as conn:
            conn.execute(
                "INSERT INTO findings (session_id, severity, title, evidence, timestamp) VALUES (?, ?, ?, ?, ?)",
                (session_id, severity, title, evidence, now)
            )
            conn.execute("UPDATE sessions SET updated_at = ? WHERE session_id = ?", (now, session_id))
            conn.commit()

    @staticmethod
    def get_messages(session_id: str) -> List[Dict[str, str]]:
        with _get_db() as conn:
            rows = conn.execute(
                "SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC",
                (session_id,)
            ).fetchall()
            return [{"role": r["role"], "content": r["content"]} for r in rows]

    @staticmethod
    def get_findings(session_id: str) -> List[Dict[str, Any]]:
        with _get_db() as conn:
            rows = conn.execute(
                "SELECT severity, title, evidence, timestamp FROM findings WHERE session_id = ? ORDER BY id ASC",
                (session_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def list_sessions(limit: int = 15) -> List[Dict[str, Any]]:
        with _get_db() as conn:
            rows = conn.execute("""
                SELECT s.session_id, s.title, s.target, s.created_at, s.updated_at,
                       COUNT(DISTINCT m.id) as msg_count,
                       COUNT(DISTINCT f.id) as finding_count
                FROM sessions s
                LEFT JOIN messages m ON s.session_id = m.session_id
                LEFT JOIN findings f ON s.session_id = f.session_id
                GROUP BY s.session_id
                ORDER BY s.updated_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def search_sessions(query: str, limit: int = 10) -> List[Dict[str, Any]]:
        q = f"%{query}%"
        with _get_db() as conn:
            rows = conn.execute("""
                SELECT DISTINCT s.session_id, s.title, s.target, s.updated_at
                FROM sessions s
                LEFT JOIN messages m ON s.session_id = m.session_id
                LEFT JOIN findings f ON s.session_id = f.session_id
                WHERE s.title LIKE ? OR s.target LIKE ? OR m.content LIKE ? OR f.title LIKE ?
                ORDER BY s.updated_at DESC
                LIMIT ?
            """, (q, q, q, q, limit)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def delete_session(session_id: str) -> bool:
        with _get_db() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            return cur.rowcount > 0
