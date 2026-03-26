"""
VibeScan — Scan History Storage
Persists scan results to a local SQLite database (~/.vibescan/history.db).
Zero extra dependencies — uses only stdlib sqlite3.
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .models import ScanResult, Finding, Severity


# ── DB location ───────────────────────────────────────────────────────────────

def default_db_path() -> str:
    return str(Path.home() / ".vibescan" / "history.db")


# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_path   TEXT    NOT NULL,
    scanned_at    TEXT    NOT NULL,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_skipped INTEGER NOT NULL DEFAULT 0,
    scan_duration REAL    NOT NULL DEFAULT 0,
    critical      INTEGER NOT NULL DEFAULT 0,
    high          INTEGER NOT NULL DEFAULT 0,
    medium        INTEGER NOT NULL DEFAULT 0,
    low           INTEGER NOT NULL DEFAULT 0,
    info          INTEGER NOT NULL DEFAULT 0,
    total         INTEGER NOT NULL DEFAULT 0,
    findings_json TEXT    NOT NULL DEFAULT '[]'
);
"""

_CREATE_IDX = """
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_path);
CREATE INDEX IF NOT EXISTS idx_scans_at     ON scans(scanned_at);
"""

_CREATE_SUPPRESSIONS = """
CREATE TABLE IF NOT EXISTS suppressions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_hash  TEXT    NOT NULL UNIQUE,
    title         TEXT    NOT NULL DEFAULT '',
    file_pattern  TEXT    NOT NULL DEFAULT '',
    reason        TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL
);
"""


# ── ScanStore ─────────────────────────────────────────────────────────────────

class ScanStore:
    """Thin wrapper around a SQLite database for persisting ScanResults."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or default_db_path()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    # ── Connection ────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_CREATE_SCANS + _CREATE_IDX + _CREATE_SUPPRESSIONS)

    # ── Write ─────────────────────────────────────────────────────────────────

    def save_scan(self, result: ScanResult) -> int:
        """Persist a ScanResult. Returns the new scan ID."""
        row = {
            "target_path":   result.target_path,
            "scanned_at":    datetime.now().isoformat(timespec="seconds"),
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "scan_duration": round(result.scan_duration, 3),
            "critical":      result.critical_count,
            "high":          result.high_count,
            "medium":        result.medium_count,
            "low":           result.low_count,
            "info":          result.info_count,
            "total":         result.total,
            "findings_json": json.dumps([f.to_dict() for f in result.sorted_findings()]),
        }
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO scans
                    (target_path, scanned_at, files_scanned, files_skipped,
                     scan_duration, critical, high, medium, low, info, total, findings_json)
                VALUES
                    (:target_path, :scanned_at, :files_scanned, :files_skipped,
                     :scan_duration, :critical, :high, :medium, :low, :info, :total, :findings_json)
            """, row)
            return int(cur.lastrowid or 0)

    def delete_scan(self, scan_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0

    # ── Read ──────────────────────────────────────────────────────────────────

    def list_scans(self, target_path: Optional[str] = None, limit: int = 100) -> list[dict]:
        """Return scans without findings_json (lightweight for list views)."""
        sql = """
            SELECT id, target_path, scanned_at, files_scanned, files_skipped,
                   scan_duration, critical, high, medium, low, info, total
            FROM scans
        """
        params: list = []
        if target_path:
            sql += " WHERE target_path = ?"
            params.append(target_path)
        sql += " ORDER BY scanned_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> Optional[dict]:
        """Return a single scan with findings_json parsed."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["findings"] = json.loads(d.pop("findings_json", "[]"))
        return d

    def list_targets(self) -> list[str]:
        """Distinct target paths that have been scanned."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target_path FROM scans ORDER BY target_path"
            ).fetchall()
        return [r[0] for r in rows]

    def trend_data(self, target_path: Optional[str] = None, days: int = 30) -> list[dict]:
        """
        Return daily aggregated severity counts for the last N days.
        Groups by date(scanned_at), ordered ascending.
        """
        cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
        sql = """
            SELECT
                substr(scanned_at, 1, 10) AS date,
                SUM(critical) AS critical,
                SUM(high)     AS high,
                SUM(medium)   AS medium,
                SUM(low)      AS low,
                SUM(info)     AS info,
                SUM(total)    AS total,
                COUNT(*)      AS scan_count
            FROM scans
            WHERE scanned_at >= ?
        """
        params: list = [cutoff]
        if target_path:
            sql += " AND target_path = ?"
            params.append(target_path)
        sql += " GROUP BY date ORDER BY date ASC"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        """High-level DB stats for the dashboard header."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*)          AS total_scans,
                    COUNT(DISTINCT target_path) AS total_projects,
                    SUM(total)        AS total_findings,
                    SUM(critical)     AS total_critical,
                    MAX(scanned_at)   AS last_scan
                FROM scans
            """).fetchone()
        return dict(row) if row else {}

    # ── Suppressions ──────────────────────────────────────────────────────────

    def save_suppression(self, finding_hash: str, title: str = "",
                         file_pattern: str = "", reason: str = "") -> int:
        """Mark a finding hash as suppressed (false positive)."""
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT OR IGNORE INTO suppressions
                    (finding_hash, title, file_pattern, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (finding_hash, title, file_pattern, reason,
                  datetime.now().isoformat(timespec="seconds")))
            return int(cur.lastrowid or 0)

    def list_suppressions(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM suppressions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_suppression(self, supp_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM suppressions WHERE id = ?", (supp_id,))
            return cur.rowcount > 0

    def is_suppressed(self, finding_hash: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM suppressions WHERE finding_hash = ?", (finding_hash,)
            ).fetchone()
        return row is not None

    # ── Analytics ──────────────────────────────────────────────────────────────

    def top_vulns(self, limit: int = 10) -> list[dict]:
        """
        Return the most common finding titles across all scans.
        Parses findings_json to aggregate by title.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT findings_json FROM scans ORDER BY scanned_at DESC LIMIT 200"
            ).fetchall()

        from collections import Counter
        counter: Counter = Counter()
        for row in rows:
            try:
                findings = json.loads(row["findings_json"] or "[]")
                for f in findings:
                    counter[f.get("title", "Unknown")] += 1
            except (json.JSONDecodeError, TypeError):
                pass

        return [
            {"title": title, "count": count}
            for title, count in counter.most_common(limit)
        ]
