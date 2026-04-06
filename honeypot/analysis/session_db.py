import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

class SessionDB:
    def __init__(self, db_path="analysis.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            cursor = conn.cursor()
            # Sessions Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE,
                    ip_address TEXT,
                    protocol TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    user_agent TEXT,
                    risk_level TEXT DEFAULT 'unknown',
                    analysis_summary TEXT,
                    mitre_mapping TEXT
                )
            ''')
            # Events Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    timestamp TIMESTAMP,
                    event_type TEXT,
                    raw_data TEXT,
                    output TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time DESC)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_session_timestamp ON events(session_id, timestamp ASC)')
            cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_events_unique ON events(session_id, timestamp, event_type, raw_data)')
            conn.commit()

    def upsert_session(self, session_id, ip_address, protocol, start_time, user_agent=None):
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (session_id, ip_address, protocol, start_time, user_agent)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                  ip_address = excluded.ip_address,
                  protocol = excluded.protocol,
                  end_time = excluded.start_time,
                  user_agent = COALESCE(excluded.user_agent, sessions.user_agent)
            ''', (session_id, ip_address, protocol, start_time, user_agent))
            conn.commit()

    def add_event(self, session_id, timestamp, event_type, raw_data, output=None) -> bool:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO events (session_id, timestamp, event_type, raw_data, output)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, timestamp, event_type, raw_data, output))
            inserted = cursor.rowcount > 0
            # Also update session end_time
            cursor.execute('''
                UPDATE sessions SET end_time = ? WHERE session_id = ?
            ''', (timestamp, session_id))
            conn.commit()
            return inserted

    def session_exists(self, session_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM sessions WHERE session_id = ? LIMIT 1', (session_id,))
            return cursor.fetchone() is not None

    def get_sessions(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT session_id, ip_address, protocol, start_time, risk_level,
                       analysis_summary AS summary
                FROM sessions
                ORDER BY start_time DESC
            ''')
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_session_events(self, session_id):
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT event_type, raw_data, output FROM events WHERE session_id = ? ORDER BY timestamp ASC', (session_id,))
            return [tuple(row) for row in cursor.fetchall()]

    def get_session_timeline(self, session_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, event_type, raw_data, output
                FROM events
                WHERE session_id = ?
                ORDER BY timestamp ASC
            ''', (session_id,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def save_analysis(self, session_id: str, risk_level: str, summary: str, mitre_mapping: List[str]) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions
                SET risk_level = ?, analysis_summary = ?, mitre_mapping = ?
                WHERE session_id = ?
            ''', (risk_level, summary, json.dumps(mitre_mapping), session_id))
            conn.commit()
