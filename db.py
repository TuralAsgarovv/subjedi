from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
PROBE_TTL_SECONDS = 60 * 60  # 1 hour


def get_database_url() -> Optional[str]:
    """Return configured external PostgreSQL DSN if present."""
    url = os.getenv("DATABASE_URL", "").strip()
    return url or None


def resolve_sqlite_path() -> Path:
    """
    Use /tmp/subdomains.db on read-only serverless runtimes (e.g. VERCEL=1)
    or local ./subdomains.db during local development.
    """
    explicit = os.getenv("SUBDOMAINS_DB_PATH", "").strip()
    if explicit:
        return Path(explicit)

    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        return Path("/tmp/subdomains.db")

    return Path(__file__).resolve().parent / "subdomains.db"


@dataclass
class CachedResult:
    apex: str
    rows: list[tuple[str, str]]
    last_fetched_at: float
    is_fresh: bool


class SubdomainStore:
    """
    Clean storage abstraction backed by SQLite (default / Vercel /tmp)
    structured for drop-in PostgreSQL (DATABASE_URL) replacement.
    """

    def __init__(self, db_path: Optional[Path] = None, database_url: Optional[str] = None) -> None:
        self.database_url = database_url or get_database_url()
        self.db_path = db_path or resolve_sqlite_path()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS subdomains (
                    apex TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    PRIMARY KEY (apex, subdomain, first_seen)
                );
                CREATE INDEX IF NOT EXISTS idx_subdomains_apex ON subdomains (apex);
                CREATE TABLE IF NOT EXISTS apex_meta (
                    apex TEXT PRIMARY KEY,
                    last_fetched_at REAL NOT NULL,
                    total_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS probe_cache (
                    subdomain TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    http_code INTEGER,
                    scheme TEXT,
                    label TEXT NOT NULL,
                    latency_ms INTEGER,
                    checked_at REAL NOT NULL
                );
                DELETE FROM apex_meta WHERE total_count = 0;
                """
            )

    def get_cached(self, apex: str, ttl_seconds: int = CACHE_TTL_SECONDS) -> Optional[CachedResult]:
        with self._connect() as conn:
            meta = conn.execute(
                "SELECT last_fetched_at FROM apex_meta WHERE apex = ?",
                (apex,),
            ).fetchone()
            if meta is None:
                return None

            last_fetched_at = float(meta["last_fetched_at"])
            is_fresh = (time.time() - last_fetched_at) < ttl_seconds

            rows = conn.execute(
                "SELECT subdomain, first_seen FROM subdomains WHERE apex = ? ORDER BY subdomain ASC",
                (apex,),
            ).fetchall()

            return CachedResult(
                apex=apex,
                rows=[(str(r["subdomain"]), str(r["first_seen"])) for r in rows],
                last_fetched_at=last_fetched_at,
                is_fresh=is_fresh,
            )

    def save_results(self, apex: str, rows: Iterable[tuple[str, str]]) -> None:
        row_list = list(rows)
        if not row_list:
            return
        now = time.time()
        with self._connect() as conn:
            conn.execute("DELETE FROM subdomains WHERE apex = ?", (apex,))
            if row_list:
                conn.executemany(
                    "INSERT OR IGNORE INTO subdomains (apex, subdomain, first_seen) VALUES (?, ?, ?)",
                    [(apex, sub, first_seen) for sub, first_seen in row_list],
                )
            conn.execute(
                """
                INSERT INTO apex_meta (apex, last_fetched_at, total_count)
                VALUES (?, ?, ?)
                ON CONFLICT(apex) DO UPDATE SET
                    last_fetched_at = excluded.last_fetched_at,
                    total_count = excluded.total_count
                """,
                (apex, now, len(row_list)),
            )

    def get_stats(self) -> dict[str, int]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM apex_meta) AS total_apexes,
                    (SELECT COUNT(*) FROM subdomains) AS total_subdomains
                """
            ).fetchone()
            if row is None:
                return {"total_apexes": 0, "total_subdomains": 0}
            return {
                "total_apexes": int(row["total_apexes"]),
                "total_subdomains": int(row["total_subdomains"]),
            }

    def get_cached_probes(
        self, subdomains: list[str], ttl_seconds: int = PROBE_TTL_SECONDS
    ) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        if not subdomains:
            return result

        min_checked_at = time.time() - ttl_seconds
        chunk_size = 400
        with self._connect() as conn:
            for idx in range(0, len(subdomains), chunk_size):
                chunk = subdomains[idx : idx + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"""
                    SELECT subdomain, state, http_code, scheme, label, latency_ms
                    FROM probe_cache
                    WHERE checked_at >= ? AND subdomain IN ({placeholders})
                    """,
                    [min_checked_at, *chunk],
                ).fetchall()
                for row in rows:
                    result[str(row["subdomain"])] = {
                        "subdomain": str(row["subdomain"]),
                        "state": str(row["state"]),
                        "http_code": int(row["http_code"]) if row["http_code"] is not None else None,
                        "scheme": str(row["scheme"]) if row["scheme"] is not None else None,
                        "label": str(row["label"]),
                        "latency_ms": int(row["latency_ms"]) if row["latency_ms"] is not None else None,
                    }
        return result

    def save_probes(self, results: list[dict[str, Any]]) -> None:
        if not results:
            return
        now = time.time()
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO probe_cache (subdomain, state, http_code, scheme, label, latency_ms, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(subdomain) DO UPDATE SET
                    state = excluded.state,
                    http_code = excluded.http_code,
                    scheme = excluded.scheme,
                    label = excluded.label,
                    latency_ms = excluded.latency_ms,
                    checked_at = excluded.checked_at
                """,
                [
                    (
                        r["subdomain"],
                        r["state"],
                        r.get("http_code"),
                        r.get("scheme"),
                        r["label"],
                        r.get("latency_ms"),
                        now,
                    )
                    for r in results
                ],
            )
