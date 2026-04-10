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
            self._migrate_add_column(cursor, "sessions", "country", "TEXT")
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

    def set_session_country(self, session_id: str, country: str) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE sessions SET country = ? WHERE session_id = ?', (country, session_id))
            conn.commit()

    # ──────────────────── READ ────────────────────

    def session_exists(self, session_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM sessions WHERE session_id = ? LIMIT 1', (session_id,))
            return cursor.fetchone() is not None

    def get_sessions(self, page: int = 1, limit: int = 0, time_range: str = "all", offset: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            cursor = conn.cursor()
            query = '''
                SELECT session_id, ip_address, protocol, start_time, risk_level,
                       analysis_summary AS summary, country
                FROM sessions
            '''
            params = []
            
            # Time range logic
            where_clauses = []
            if time_range == "today":
                where_clauses.append("REPLACE(start_time, 'T', ' ') >= datetime('now', 'start of day')")
            elif time_range == "7d":
                where_clauses.append("REPLACE(start_time, 'T', ' ') >= datetime('now', '-7 days')")
            elif time_range == "30d":
                where_clauses.append("REPLACE(start_time, 'T', ' ') >= datetime('now', '-30 days')")
                
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)

            query += " ORDER BY start_time DESC"
            if limit > 0:
                if offset is None:
                    offset = (page - 1) * limit
                query += " LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_sessions_count(self, time_range: str = "all") -> int:
        with self._connect() as conn:
            cursor = conn.cursor()
            query = "SELECT COUNT(*) FROM sessions"
            if time_range == "today":
                query += " WHERE REPLACE(start_time, 'T', ' ') >= datetime('now', 'start of day')"
            elif time_range == "7d":
                query += " WHERE REPLACE(start_time, 'T', ' ') >= datetime('now', '-7 days')"
            elif time_range == "30d":
                query += " WHERE REPLACE(start_time, 'T', ' ') >= datetime('now', '-30 days')"
                
            cursor.execute(query)
            return cursor.fetchone()[0]

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
                try:
                    d[key] = json.loads(raw) if raw else []
                except Exception:
                    d[key] = []
            return d

    def get_last_session_id(self, ip_address: str, protocol: str) -> Optional[Tuple[str, str]]:
        """Find the most recent session ID and its end time for an IP."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT session_id, COALESCE(end_time, start_time) as last_ts
                FROM sessions
                WHERE ip_address = ? AND protocol = ?
                ORDER BY last_ts DESC LIMIT 1
            ''', (ip_address, protocol))
            row = cursor.fetchone()
            if row:
                return row["session_id"], row["last_ts"]
            return None

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
    def get_unanalyzed_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve sessions that have events but haven't been successfully analyzed yet."""
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT s.session_id, s.ip_address
                FROM sessions s
                JOIN events e ON s.session_id = e.session_id
                WHERE (s.analysis_summary IS NULL OR s.analysis_summary = '')
                ORDER BY s.start_time DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_critical_insights(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve the most recent critical/high-risk analyzed sessions."""
        with self._connect() as conn:
            cursor = conn.cursor()
            query = """
                SELECT session_id, ip_address, start_time, risk_level, 
                       analysis_summary, country
                FROM sessions
                WHERE risk_level IN ('critical', 'high') 
                  AND analysis_summary IS NOT NULL 
                  AND analysis_summary != ''
                ORDER BY start_time DESC
                LIMIT ?
            """
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    # ──────────────────── STATS ────────────────────

    def get_stats(self, time_range: str = "all") -> Dict[str, Any]:
        """Aggregate statistics for the dashboard overview and batch reports."""
        with self._connect() as conn:
            cursor = conn.cursor()
            
            where_clause = ""
            if time_range == "today":
                where_clause = "WHERE REPLACE(start_time, 'T', ' ') >= datetime('now', 'start of day')"
            elif time_range == "7d":
                where_clause = "WHERE REPLACE(start_time, 'T', ' ') >= datetime('now', '-7 days')"
            elif time_range == "30d":
                where_clause = "WHERE REPLACE(start_time, 'T', ' ') >= datetime('now', '-30 days')"
            
            where_and = "AND" if where_clause else "WHERE"

            cursor.execute(f'SELECT COUNT(*) FROM sessions {where_clause}')
            total = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} risk_level = 'critical'")
            critical = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} risk_level = 'high'")
            high = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} risk_level = 'medium'")
            medium = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} risk_level = 'low'")
            low = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} (risk_level = 'unknown' OR risk_level IS NULL)")
            unknown = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} protocol = 'SSH'")
            ssh_count = cursor.fetchone()[0]

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} protocol = 'HTTP'")
            http_count = cursor.fetchone()[0]

            cursor.execute(f"SELECT AVG(confidence) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} confidence IS NOT NULL")
            avg_conf_row = cursor.fetchone()[0]
            avg_confidence = round(avg_conf_row, 2) if avg_conf_row else 0.0

            cursor.execute(f"SELECT COUNT(*) FROM sessions {where_clause} {where_and if where_clause else 'WHERE'} analysis_summary IS NOT NULL AND analysis_summary != ''")
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
                "top_behavioral_tags": self._get_top_behavioral_tags(cursor, where_clause),
                "activity_over_time": self._get_activity_over_time(cursor, where_clause),
                "top_countries": self._get_top_countries(cursor, where_clause),
            }

    def _get_top_countries(self, cursor, where_clause: str = "") -> Dict[str, int]:
        query = f"SELECT country, COUNT(*) as count FROM sessions "
        filter_clause = "WHERE country IS NOT NULL AND country != 'Unknown'"
        if where_clause:
            query += f"{where_clause} AND country IS NOT NULL AND country != 'Unknown'"
        else:
            query += filter_clause
        query += " GROUP BY country ORDER BY count DESC LIMIT 10"
        cursor.execute(query)
        return {row['country']: row['count'] for row in cursor.fetchall()}

    def _get_activity_over_time(self, cursor, where_clause: str = "") -> List[Dict[str, Any]]:
        """Get session counts grouped by hour/day based on the selected range."""
        # Use strftime but handle the ISO 'T' separator if present
        query = f"""
            SELECT strftime('%Y-%m-%d %H:00', REPLACE(start_time, 'T', ' ')) as hour, COUNT(*) as count
            FROM sessions
            {where_clause}
            GROUP BY hour
            ORDER BY hour ASC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def _get_top_behavioral_tags(self, cursor, where_clause: str = "") -> Dict[str, int]:
        """Aggregate behavioral tags from all analyzed sessions within the time range."""
        query = "SELECT behavioral_tags FROM sessions "
        filter_str = "behavioral_tags IS NOT NULL"
        if where_clause:
            query += f"{where_clause} AND {filter_str}"
        else:
            query += f"WHERE {filter_str}"
            
        cursor.execute(query)
        all_tags = cursor.fetchall()
        tag_counts = {}
        for row in all_tags:
            try:
                # row is a sqlite3.Row or tuple
                val = row[0] if isinstance(row, tuple) else row["behavioral_tags"]
                tags = json.loads(val or "[]")
                for t in tags:
                    tag_counts[t] = tag_counts.get(t, 0) + 1
            except Exception:
                continue
        # Sort and return top 10
        sorted_items = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
        top10 = {}
        for i in range(min(len(sorted_items), 10)):
            k, v = sorted_items[i]
            top10[k] = v
        return top10
