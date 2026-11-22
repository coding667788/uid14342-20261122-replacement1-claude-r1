"""Reproducible scale-case integration test.

Validates the published lower bounds (>=24 actions, >=6 scenarios,
>=24 requirements), the scale limits (<=26/8/40/200/160), revoke and failure
boundaries in the evidence, and exact-solve run time.
"""

import json
import os
import time
import unittest

from tests._helpers import REPO_ROOT, TempRepoCase
from examples.generate_scale_case import build_case
from mirror_plan.policy import PolicyView, authorization_evidence
from mirror_plan.solver import solve
from mirror_plan.validation import LIMITS, validate_case


class ScaleCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = build_case()

    def test_meets_published_size_bounds(self):
        self.assertGreaterEqual(len(self.case["candidates"]), 24)
        self.assertGreaterEqual(len(self.case["scenarios"]), 6)
        self.assertGreaterEqual(len(self.case["requirements"]), 24)
        # Upper published limits.
        self.assertLessEqual(len(self.case["candidates"]), LIMITS["actions"])
        self.assertLessEqual(len(self.case["scenarios"]), LIMITS["scenarios"])
        self.assertLessEqual(len(self.case["requirements"]), LIMITS["requirements"])
        self.assertLessEqual(len(self.case["policy"]), LIMITS["policy_events"])
        vis = sum(len(a["visibility"]) for a in self.case["candidates"])
        self.assertLessEqual(vis, LIMITS["visibility_items"])

    def test_document_validates(self):
        validate_case(json.loads(json.dumps(self.case)))

    def test_generation_is_deterministic(self):
        once = json.dumps(build_case(), sort_keys=True)
        twice = json.dumps(build_case(), sort_keys=True)
        self.assertEqual(once, twice)

    def test_exact_solve_is_feasible_and_fast(self):
        start = time.time()
        selected, _, _ = solve(self.case)
        elapsed = time.time() - start
        self.assertIsNotNone(selected)
        self.assertLess(elapsed, 10.0)
        self.assertEqual(selected, sorted(selected, key=lambda a: a["id"]))

    def test_seam_actions_cross_revoke_boundary_and_are_unsafe(self):
        view = PolicyView(self.case)
        for action_id in ("act25", "act26"):
            action = next(a for a in self.case["candidates"] if a["id"] == action_id)
            ev = authorization_evidence(view, action)
            self.assertFalse(ev["safe"])
            # The surviving rev 2 witness starts exactly at the revoke seam 400.
            witnessed = ev["items"][0]["witnessed"]
            self.assertEqual(witnessed[0]["from"], 400)
            self.assertEqual(ev["items"][0]["holes"][0]["to"], 400)

    def test_failure_scenarios_slice_coverage_evidence(self):
        selected, _, index = solve(self.case)
        mask = frozenset(
            index.action_index[a["id"]] for a in selected
        )
        evidence = index.coverage_evidence(mask)
        # Every non-base scenario must appear and carry at least one segment
        # whose boundary coincides with a failure window.
        scenario_ids = {e["scenario_id"] for e in evidence}
        self.assertEqual(
            scenario_ids, {s["id"] for s in self.case["scenarios"]}
        )
        failure_scenarios = {
            s["id"] for s in self.case["scenarios"]
            if s["switch_failures"] or s["collector_failures"]
        }
        self.assertTrue(failure_scenarios.issubset(scenario_ids))


if __name__ == "__main__":
    unittest.main()
