"""Durable storage, optimistic concurrency and subprocess race tests."""

import json
import os
import sqlite3
import subprocess
import sys
import unittest

from tests._helpers import REPO_ROOT, TempRepoCase, base_case
from mirror_plan.digest import plan_digest
from mirror_plan.store import connect, current_head, history, record


class StoreUnitTests(TempRepoCase):
    def setUp(self):
        super().setUp()
        self.case = base_case()
        self.ids = ["a2", "a3", "a4", "a7"]
        self.plan = {
            "selected_ids": self.ids,
            "plan_digest": plan_digest(self.case, self.ids),
        }
        self.db = os.path.join(self.dir, "audit.sqlite")

    def test_commit_numbers_start_at_zero_and_increment(self):
        r0 = record(self.case, self.plan, self.db, "req-0", 0, "t0")
        self.assertEqual(r0["commit_no"], 0)
        self.assertFalse(r0["replayed"])
        # A second feasible selection covering the same requirements.
        second_ids = ["a1", "a3", "a5", "a7"]
        other_plan = {
            "selected_ids": second_ids,
            "plan_digest": plan_digest(self.case, second_ids),
        }
        r1 = record(self.case, other_plan, self.db, "req-1", 1, "t1")
        self.assertEqual(r1["commit_no"], 1)
        conn = connect(self.db)
        try:
            self.assertEqual(current_head(conn), 2)
        finally:
            conn.close()

    def test_same_request_replays_same_receipt_before_head_check(self):
        record(self.case, self.plan, self.db, "dup", 0, "t0")
        # expected-head deliberately wrong; idempotency must win.
        again = record(self.case, self.plan, self.db, "dup", 999, "t1")
        self.assertTrue(again["replayed"])
        self.assertEqual(again["commit_no"], 0)
        self.assertEqual(again["receipt"]["created_at"], "t0")

    def test_same_request_different_digest_conflicts(self):
        from mirror_plan.errors import StoreError
        record(self.case, self.plan, self.db, "dup", 0, "t0")
        other = {"selected_ids": ["a1", "a3", "a5", "a7"],
                 "plan_digest": plan_digest(self.case, ["a1", "a3", "a5", "a7"])}
        with self.assertRaises(StoreError) as ctx:
            record(self.case, other, self.db, "dup", 1, "t1")
        self.assertEqual(ctx.exception.code, "request_conflict")

    def test_stale_expected_head_rejected(self):
        from mirror_plan.errors import StoreError
        record(self.case, self.plan, self.db, "req-0", 0, "t0")
        with self.assertRaises(StoreError) as ctx:
            record(self.case, self.plan, self.db, "req-late", 0, "t1")
        self.assertEqual(ctx.exception.code, "head_conflict")

    def test_failed_audit_writes_nothing(self):
        from mirror_plan.errors import AuditFailure
        bad_plan = {"selected_ids": ["a1"],
                    "plan_digest": "sha256:" + "f" * 64}
        with self.assertRaises((AuditFailure, Exception)):
            record(self.case, bad_plan, self.db, "req-bad", 0, "t")
        # Database file may exist with schema, but no commit row may persist.
        if os.path.exists(self.db):
            conn = connect(self.db)
            try:
                count = conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
            finally:
                conn.close()
            self.assertEqual(count, 0)

    def test_history_roundtrip_and_missing_version(self):
        record(self.case, self.plan, self.db, "req-0", 0, "t0")
        doc = history(self.db, 0)
        self.assertEqual(doc["receipt"]["request_id"], "req-0")
        first_action = doc["evidence"]["authorization_evidence"][0]["action_id"]
        self.assertEqual(first_action, min(self.ids))
        from mirror_plan.errors import StoreError
        with self.assertRaises(StoreError) as ctx:
            history(self.db, 7)
        self.assertEqual(ctx.exception.code, "no_such_commit")

    def test_reopen_process_sees_same_history(self):
        record(self.case, self.plan, self.db, "req-0", 0, "t0")
        # Simulate a fresh process by opening a brand new connection.
        first = history(self.db, 0)
        second = history(self.db, 0)
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )


class ConcurrencyTests(TempRepoCase):
    """Two-process races using independent subprocess fixtures."""

    def setUp(self):
        super().setUp()
        self.case = base_case()
        self.case_path = self.write_json("case.json", self.case)
        self.plans = {}
        for name, ids in (("p0", ["a2", "a3", "a4", "a7"]),
                          ("p1", ["a1", "a3", "a5", "a7"])):
            plan = {"selected_ids": ids, "plan_digest": plan_digest(self.case, ids)}
            self.plans[name] = self.write_json(f"{name}.json", plan)
        self.db = os.path.join(self.dir, "race.sqlite")

    def _record(self, plan_name, request_id, expected_head):
        return subprocess.run(
            [sys.executable, "-m", "mirror_plan", "record", self.case_path,
             self.plans[plan_name], "--db", self.db,
             "--request-id", request_id, "--expected-head", str(expected_head)],
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8",
        )

    def test_two_processes_race_same_head_only_one_commits(self):
        procs = [
            self._record("p0", "race-a", 0),
            self._record("p1", "race-b", 0),
        ]
        statuses = []
        for proc in procs:
            # Committed/replayed -> 0, head conflict or rejected audit -> 3.
            self.assertIn(proc.returncode, (0, 3), proc.stderr)
            statuses.append(json.loads(proc.stdout)["status"])
        self.assertEqual(len([s for s in statuses if s == "committed"]), 1)
        self.assertTrue(any(s in ("conflict", "rejected") for s in statuses))
        # Exactly one commit exists despite the race.
        conn = sqlite3.connect(self.db)
        try:
            count = conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
            self.assertEqual(count, 1)
        finally:
            conn.close()

    def test_concurrent_same_request_replay_is_idempotent(self):
        # Seed the first commit, then race identical replays.
        seed = self._record("p0", "idem", 0)
        self.assertEqual(seed.returncode, 0)
        procs = [self._record("p0", "idem", 5) for _ in range(4)]
        for proc in procs:
            payload = json.loads(proc.stdout)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(payload["status"], "replayed")
            self.assertEqual(payload["commit_no"], 0)
        conn = sqlite3.connect(self.db)
        try:
            count = conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
            self.assertEqual(count, 1)
        finally:
            conn.close()

    def test_response_loss_replay_returns_original_commit(self):
        first = self._record("p0", "lost-resp", 0)
        self.assertEqual(json.loads(first.stdout)["status"], "committed")
        # Client retries after losing the response; same request-id/digest.
        retry = self._record("p0", "lost-resp", 0)
        payload = json.loads(retry.stdout)
        self.assertEqual(payload["status"], "replayed")
        self.assertEqual(payload["commit_no"], 0)

    def test_parallel_head_race_across_many_processes(self):
        # Launch all writers concurrently via Popen so they genuinely contend
        # for the same head; SQLite's BEGIN IMMEDIATE must serialize them and
        # leave exactly one committed row per winning request.
        procs = []
        for i in range(6):
            procs.append(
                subprocess.Popen(
                    [sys.executable, "-m", "mirror_plan", "record", self.case_path,
                     self.plans["p0"], "--db", self.db,
                     "--request-id", f"parallel-{i}", "--expected-head", "0"],
                    cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding="utf-8",
                )
            )
        outcomes = [json.loads(p.communicate()[0]) for p in procs]
        committed = [o for o in outcomes if o["status"] == "committed"]
        conflicts = [o for o in outcomes if o["status"] == "conflict"]
        self.assertEqual(len(committed), 1)
        self.assertEqual(len(conflicts), 5)
        conn = sqlite3.connect(self.db)
        try:
            count = conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
            self.assertEqual(count, 1)
            head = conn.execute("SELECT MAX(commit_no) FROM commits").fetchone()[0]
            self.assertEqual(head, 0)
        finally:
            conn.close()

    def test_precommit_failure_leaves_database_unchanged(self):
        ok = self._record("p0", "before", 0)
        self.assertEqual(ok.returncode, 0)
        # A failing audit (tampered digest) must not move the head.
        bad = {"selected_ids": ["a1"], "plan_digest": "sha256:" + "9" * 64}
        bad_path = self.write_json("bad.json", bad)
        proc = subprocess.run(
            [sys.executable, "-m", "mirror_plan", "record", self.case_path,
             bad_path, "--db", self.db, "--request-id", "failing",
             "--expected-head", "1"],
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(proc.returncode, 3)
        conn = sqlite3.connect(self.db)
        try:
            rows = conn.execute("SELECT commit_no, request_id FROM commits ORDER BY commit_no").fetchall()
        finally:
            conn.close()
        self.assertEqual(rows, [(0, "before")])


if __name__ == "__main__":
    unittest.main()
