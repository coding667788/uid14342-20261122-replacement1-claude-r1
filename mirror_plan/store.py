"""Durable audit storage in SQLite with optimistic concurrency control.

Commit numbers start at 0 and increment by exactly one per successful write.
Writers serialize through an immediate transaction (``BEGIN IMMEDIATE``), so
two processes racing for the same head cannot both succeed: the loser sees a
``database is locked``/busy condition and must retry its version check.

Idempotency is checked inside the transaction *before* the expected-head
check: the same request-id with the same recomputed digest replays the
original receipt; the same request-id with a different digest conflicts.
"""

import json
import sqlite3

from .digest import canonical_json
from .errors import StoreError
from .planner import recompute

SCHEMA = """
CREATE TABLE IF NOT EXISTS commits (
    commit_no   INTEGER PRIMARY KEY,
    request_id  TEXT NOT NULL UNIQUE,
    digest      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    case_json   TEXT NOT NULL,
    receipt_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    commit_no   INTEGER PRIMARY KEY REFERENCES commits(commit_no),
    evidence_json TEXT NOT NULL
);
"""


def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def current_head(conn):
    """Current head: 0 on an empty database, otherwise max commit no + 1."""
    row = conn.execute("SELECT COALESCE(MAX(commit_no), -1) + 1 FROM commits").fetchone()
    return row[0]


def _load_audit_evidence(case, selected_ids):
    result = recompute(case, selected_ids)
    return result, {
        "authorization_evidence": [
            result["evidence_by_id"][i] for i in sorted(selected_ids)
        ],
        "coverage_evidence": result["index"].coverage_evidence(result["selected_mask"]),
    }


def record(case, plan, db_path, request_id, expected_head, now_iso):
    """Transactionally validate, audit and persist a plan.

    Returns a dict ``(receipt, replayed)``. Raises :class:`StoreError` on
    conflicts; all other exceptions roll the transaction back untouched.
    """
    selected_ids = plan["selected_ids"]
    conn = connect(db_path)
    try:
        # Recompute before opening the write transaction: a failed audit never
        # takes any lock and never writes anything.
        result, evidence = _load_audit_evidence(case, selected_ids)
        recomputed_digest = result["digest"]
        if plan["plan_digest"] != recomputed_digest:
            raise StoreError(
                "plan_digest does not match recomputed digest", "digest_mismatch"
            )

        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT commit_no, receipt_json FROM commits WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is not None:
                commit_no, receipt_json = row
                receipt = json.loads(receipt_json)
                if receipt["plan_digest"] != recomputed_digest:
                    raise StoreError(
                        f"request-id {request_id!r} already recorded with a different digest",
                        "request_conflict",
                    )
                conn.execute("COMMIT")
                return {"receipt": receipt, "replayed": True, "commit_no": commit_no}

            head = current_head(conn)
            if head != expected_head:
                raise StoreError(
                    f"expected-head {expected_head} does not match current head {head}",
                    "head_conflict",
                )

            receipt = {
                "commit_no": head,
                "request_id": request_id,
                "plan_digest": recomputed_digest,
                "selected_ids": sorted(selected_ids),
                "cost": sum(a["cost"] for a in result["selected_actions"]),
                "created_at": now_iso,
            }
            conn.execute(
                "INSERT INTO commits (commit_no, request_id, digest, created_at, "
                "case_json, receipt_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    head,
                    request_id,
                    recomputed_digest,
                    now_iso,
                    canonical_json(case).decode("utf-8"),
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True),
                ),
            )
            conn.execute(
                "INSERT INTO entries (commit_no, evidence_json) VALUES (?, ?)",
                (head, json.dumps(evidence, ensure_ascii=False, sort_keys=True)),
            )
            conn.execute("COMMIT")
            return {"receipt": receipt, "replayed": False, "commit_no": head}
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def history(db_path, commit_no):
    """Return the frozen receipt and evidence for one commit number."""
    conn = connect(db_path)
    try:
        row = conn.execute(
            "SELECT receipt_json, case_json FROM commits WHERE commit_no = ?",
            (commit_no,),
        ).fetchone()
        if row is None:
            raise StoreError(f"commit {commit_no} does not exist", "no_such_commit")
        entry = conn.execute(
            "SELECT evidence_json FROM entries WHERE commit_no = ?", (commit_no,)
        ).fetchone()
        receipt = json.loads(row[0])
        return {
            "status": "found",
            "receipt": receipt,
            "case": json.loads(row[1]),
            "evidence": json.loads(entry[0]) if entry else None,
        }
    finally:
        conn.close()
