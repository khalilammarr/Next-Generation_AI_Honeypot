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

            # ── Migrate: add new analysis columns if missing ──
            self._migrate_add_column(cursor, "sessions", "iocs", "TEXT")
            self._migrate_add_column(cursor, "sessions", "kill_chain_phase", "TEXT")
            self._migrate_add_column(cursor, "sessions", "confidence", "REAL")
            self._migrate_add_column(cursor, "sessions", "behavioral_tags", "TEXT")
            self._migrate_add_column(cursor, "sessions", "recommendations", "TEXT")
            conn.commit()

    @staticmethod
    def _migrate_add_column(cursor, table: str, column: str, col_type: str):
        """Add a column if it doesn't already exist (safe migration)."""
        cursor.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cursor.fetchall()}
        if column not in existing:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")

    # ──────────────────── WRITE ────────────────────

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
            cursor.execute('''
                UPDATE sessions SET end_time = ? WHERE session_id = ?
            ''', (timestamp, session_id))
            conn.commit()
            return inserted

    def save_analysis(self, session_id: str, risk_level: str, summary: str,
                      mitre_mapping: List[str], iocs: Optional[List[str]] = None,
                      kill_chain_phase: Optional[str] = None,
                      confidence: Optional[float] = None,
                      behavioral_tags: Optional[List[str]] = None,
                      recommendations: Optional[List[str]] = None) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions
                SET risk_level = ?, analysis_summary = ?, mitre_mapping = ?,
                    iocs = ?, kill_chain_phase = ?, confidence = ?,
                    behavioral_tags = ?, recommendations = ?
                WHERE session_id = ?
            ''', (
                risk_level,
                summary,
                json.dumps(mitre_mapping),
                json.dumps(iocs or []),
                kill_chain_phase,
                confidence,
                json.dumps(behavioral_tags or []),
                json.dumps(recommendations or []),
                session_id,
            ))
            conn.commit()

    # ──────────────────── READ ────────────────────

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

    def get_session_detail(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return full session row including all analysis fields."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            # Deserialize JSON fields
            for key in ("mitre_mapping", "iocs", "behavioral_tags", "recommendations"):
                raw = d.get(key)
                d[key] = json.loads(raw) if raw else []
            return d

    def get_analysis(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT risk_level, analysis_summary, mitre_mapping,
                       iocs, kill_chain_phase, confidence,
                       behavioral_tags, recommendations
                FROM sessions
                WHERE session_id = ?
            ''', (session_id,))
            row = cursor.fetchone()
            if not row:
                return None
            risk = row["risk_level"]
            summary = row["analysis_summary"]
            # Only return if there is actual analysis data
            if not risk or risk == "unknown":
                return None
            return {
                "risk_level": risk,
                "summary": summary,
                "mitre_mapping": json.loads(row["mitre_mapping"] or "[]"),
                "iocs": json.loads(row["iocs"] or "[]"),
                "kill_chain_phase": row["kill_chain_phase"] or "Unknown",
                "confidence": row["confidence"] if row["confidence"] is not None else 0.0,
                "behavioral_tags": json.loads(row["behavioral_tags"] or "[]"),
                "recommendations": json.loads(row["recommendations"] or "[]"),
            }

    # ──────────────────── STATS ────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics for the dashboard overview."""
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM sessions')
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE risk_level = 'critical'")
            critical = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE risk_level = 'high'")
            high = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE risk_level = 'medium'")
            medium = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE risk_level = 'low'")
            low = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE risk_level = 'unknown' OR risk_level IS NULL")
            unknown = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE protocol = 'SSH'")
            ssh_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE protocol = 'HTTP'")
            http_count = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(confidence) FROM sessions WHERE confidence IS NOT NULL")
            avg_conf_row = cursor.fetchone()[0]
            avg_confidence = round(avg_conf_row, 2) if avg_conf_row else 0.0

            cursor.execute("SELECT COUNT(*) FROM sessions WHERE analysis_summary IS NOT NULL AND analysis_summary != ''")
            analyzed = cursor.fetchone()[0]

            return {
                "total_sessions": total,
                "analyzed": analyzed,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "unknown": unknown,
                "ssh": ssh_count,
                "http": http_count,
                "avg_confidence": avg_confidence,
                "risk_distribution": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "unknown": unknown,
                },
                "protocol_distribution": {
                    "SSH": ssh_count,
                    "HTTP": http_count,
                },
            }
