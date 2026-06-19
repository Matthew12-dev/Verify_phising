# Paquete: database — registro de peticiones en SQLite

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional


DB_PATH = Path(__file__).parent / "app.db"


class DatabaseLogger:
    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = Path(db_path) if db_path else DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    # ------------------------------------------------------------------
    # Context manager de conexión — evita fugas usando finally
    # ------------------------------------------------------------------

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Inicialización del esquema
    # ------------------------------------------------------------------

    def _init_database(self) -> None:
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS requests (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp       TEXT,
                        url             TEXT NOT NULL,
                        decision        TEXT NOT NULL,
                        reason          TEXT,
                        similarity_score REAL DEFAULT 0.0,
                        client_ip       TEXT,
                        created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS blocked_hosts (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        host        TEXT UNIQUE NOT NULL,
                        count       INTEGER DEFAULT 1,
                        last_attempt TEXT,
                        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS phishing_checks (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        email_or_url    TEXT NOT NULL,
                        is_phishing     INTEGER NOT NULL DEFAULT 0,
                        risk_score      REAL DEFAULT 0.0,
                        reason          TEXT,
                        message_preview TEXT,
                        layers_json     TEXT,
                        created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except Exception as e:
            print(f"[DatabaseLogger] Error al inicializar base de datos: {e}")

    # ------------------------------------------------------------------
    # Escritura
    # ------------------------------------------------------------------

    def log_request(
        self,
        url: str,
        decision: str,
        reason: str = "",
        similarity_score: float = 0.0,
        timestamp: str = "",
        client_ip: str = "",
    ) -> bool:
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO requests (timestamp, url, decision, reason, similarity_score, client_ip)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (timestamp, url, decision, reason, similarity_score, client_ip),
                )

                if decision == "BLOCKED":
                    from urllib.parse import urlparse
                    parsed = urlparse(url if url.startswith("http") else "http://" + url)
                    host = (parsed.hostname or url).lower()
                    conn.execute(
                        """
                        INSERT INTO blocked_hosts (host, count, last_attempt)
                        VALUES (?, 1, ?)
                        ON CONFLICT(host) DO UPDATE SET
                            count = count + 1,
                            last_attempt = excluded.last_attempt
                        """,
                        (host, timestamp),
                    )
            return True
        except Exception as e:
            print(f"[DatabaseLogger] Error al registrar petición: {e}")
            return False

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------

    def get_statistics(self, hours: int = 1) -> dict:
        try:
            with self._get_connection() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM requests WHERE created_at >= datetime('now', ?)",
                    (f"-{hours} hours",),
                ).fetchone()[0]

                blocked = conn.execute(
                    "SELECT COUNT(*) FROM requests WHERE decision='BLOCKED' "
                    "AND created_at >= datetime('now', ?)",
                    (f"-{hours} hours",),
                ).fetchone()[0]

                allowed = total - blocked

                top_blocked = conn.execute(
                    "SELECT host, count FROM blocked_hosts ORDER BY count DESC LIMIT 5"
                ).fetchall()

                return {
                    "period_hours": hours,
                    "total": total,
                    "blocked": blocked,
                    "allowed": allowed,
                    "block_rate": round(blocked / total * 100, 1) if total else 0.0,
                    "top_blocked": [{"host": r["host"], "count": r["count"]} for r in top_blocked],
                }
        except Exception as e:
            print(f"[DatabaseLogger] Error en get_statistics: {e}")
            return {"period_hours": hours, "total": 0, "blocked": 0, "allowed": 0,
                    "block_rate": 0.0, "top_blocked": []}

    def get_recent_logs(self, limit: int = 50) -> list:
        try:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            print(f"[DatabaseLogger] Error en get_recent_logs: {e}")
            return []

    def get_top_blocked_hosts(self, limit: int = 10) -> list:
        try:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT host, count, last_attempt, created_at "
                    "FROM blocked_hosts ORDER BY count DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            print(f"[DatabaseLogger] Error en get_top_blocked_hosts: {e}")
            return []

    def clear_old_logs(self, days: int = 30) -> int:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM requests WHERE created_at < datetime('now', ?)",
                    (f"-{days} days",),
                )
                return cursor.rowcount
        except Exception as e:
            print(f"[DatabaseLogger] Error en clear_old_logs: {e}")
            return 0

    # ------------------------------------------------------------------
    # Phishing checks
    # ------------------------------------------------------------------

    def log_phishing_check(
        self,
        email_or_url: str,
        is_phishing: bool,
        risk_score: float = 0.0,
        reason: str = "",
        message_preview: str = "",
        layers: Optional[dict] = None,
    ) -> bool:
        import json as _json
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO phishing_checks
                        (email_or_url, is_phishing, risk_score, reason, message_preview, layers_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        email_or_url,
                        1 if is_phishing else 0,
                        risk_score,
                        reason,
                        message_preview,
                        _json.dumps(layers or {}, ensure_ascii=False),
                    ),
                )
            return True
        except Exception as e:
            print(f"[DatabaseLogger] Error en log_phishing_check: {e}")
            return False

    def get_phishing_statistics(self, hours: int = 1) -> dict:
        try:
            with self._get_connection() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM phishing_checks WHERE created_at >= datetime('now', ?)",
                    (f"-{hours} hours",),
                ).fetchone()[0]

                phishing = conn.execute(
                    "SELECT COUNT(*) FROM phishing_checks WHERE is_phishing=1 "
                    "AND created_at >= datetime('now', ?)",
                    (f"-{hours} hours",),
                ).fetchone()[0]

                legit = total - phishing

                return {
                    "period_hours":  hours,
                    "total":         total,
                    "phishing":      phishing,
                    "legit":         legit,
                    "phishing_rate": round(phishing / total * 100, 1) if total else 0.0,
                }
        except Exception as e:
            print(f"[DatabaseLogger] Error en get_phishing_statistics: {e}")
            return {"period_hours": hours, "total": 0, "phishing": 0, "legit": 0, "phishing_rate": 0.0}

    def get_recent_phishing_logs(self, limit: int = 50) -> list:
        try:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM phishing_checks ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            print(f"[DatabaseLogger] Error en get_recent_phishing_logs: {e}")
            return []
