"""Coverage indexing, failure boundaries and digest stability tests."""

import json
import unittest

from tests._helpers import base_case
from mirror_plan.coverage import CoverageIndex
from mirror_plan.digest import canonical_json, plan_digest
from mirror_plan.policy import PolicyView
from mirror_plan.solver import safe_actions


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.case = base_case()
        self.view = PolicyView(self.case)
        safe, _ = safe_actions(self.case, self.view)
        self.safe = safe
        self.index = CoverageIndex(self.case, self.view, safe)

    def test_collector_counts_once_for_multiple_items(self):
        # An action with several matching visibility items still contributes
        # its single collector once per slice.
        case = self.case
        action = next(a for a in case["candidates"] if a["id"] == "a3")
        action["visibility"].append(
            {"tenant": "tnb", "class": "bulk", "label": "M2", "from": 0, "to": 200}
        )
        # Grant the new label so the action stays safe.
        case["policy"].append(
            {"seq": 6, "event": "grant", "key": "ke", "revision": 1,
             "tap": "tap3", "collector": "c3", "tenant": "tnb", "class": "bulk",
             "label": "M2", "from": 0, "to": 1000}
        )
        case["as_of"] = 6
        view = PolicyView(case)
        safe, _ = safe_actions(case, view)
        index = CoverageIndex(case, view, safe)
        rec = index.slices["base"]["r2"][0]
        self.assertEqual(rec["collectors"], frozenset({"c3"}))

    def test_failure_excludes_action_from_slice(self):
        # The c2 outage at 900..950 sits just beyond r1's [0,900) window; add
        # a dedicated failure window inside the horizon and verify exclusion.
        case = self.case
        case["scenarios"] = [
            {"id": "base", "switch_failures": [], "collector_failures": []},
            {"id": "scn_c2",
             "switch_failures": [],
             "collector_failures": [{"device": "c2", "from": 600, "to": 700}]},
        ]
        view = PolicyView(case)
        index = CoverageIndex(case, view, self.safe)
        slices = index.slices["scn_c2"]["r1"]
        outage = next(s for s in slices if s["from"] == 600)
        collectors = set(outage["per_action"].values())
        self.assertNotIn("c2", collectors)
        outside = next(s for s in slices if s["from"] == 700)
        self.assertIn("c2", set(outside["per_action"].values()))

    def test_switch_failure_excludes_its_taps(self):
        case = self.case
        case["scenarios"].append(
            {"id": "scn_sw1",
             "switch_failures": [{"device": "sw1", "from": 100, "to": 200}],
             "collector_failures": []}
        )
        view = PolicyView(case)
        index = CoverageIndex(case, view, self.safe)
        rec = next(s for s in index.slices["scn_sw1"]["r1"] if s["from"] == 100)
        taps = {self.index.actions[ai]["tap"] for ai in rec["per_action"]}
        self.assertNotIn("tap1", taps)

    def test_first_coverage_failure_ordering(self):
        # Select only the c1 actions: r1 (needs 2) fails on its first slice.
        mask = frozenset(
            self.index.action_index[i] for i in ("a1", "a4", "a3")
        )
        failure = self.index.first_coverage_failure(mask)
        self.assertEqual(failure["scenario_id"], "base")
        self.assertEqual(failure["requirement_id"], "r1")
        self.assertEqual(failure["actual_collectors"], ["c1"])


class DigestTests(unittest.TestCase):
    def test_digest_invariant_to_whitespace_order_and_candidate_order(self):
        case = base_case()
        ids = ["a1", "a2"]
        d1 = plan_digest(case, ids)

        shuffled = json.loads(json.dumps(case))
        shuffled["candidates"] = list(reversed(shuffled["candidates"]))
        shuffled["taps"] = list(reversed(shuffled["taps"]))
        # Re-serialize with different whitespace/field placement.
        re_encoded = json.dumps(shuffled, indent=4)
        reshuffled = json.loads(re_encoded)
        d2 = plan_digest(reshuffled, list(reversed(ids)))
        self.assertEqual(d1, d2)
        self.assertTrue(d1.startswith("sha256:"))
        self.assertEqual(len(d1), len("sha256:") + 64)

    def test_digest_changes_with_different_selection(self):
        case = base_case()
        self.assertNotEqual(plan_digest(case, ["a1"]), plan_digest(case, ["a2"]))

    def test_policy_keeps_seq_order_in_canonical_form(self):
        case = base_case()
        canonical = canonical_json(case).decode("utf-8")
        # seq 1 event must appear before seq 2 regardless of key sorting.
        self.assertLess(canonical.index('"seq":1'), canonical.index('"seq":2'))

    def test_lists_without_order_semantics_are_sorted(self):
        case = base_case()
        reordered = json.loads(json.dumps(case))
        reordered["requirements"] = list(reversed(reordered["requirements"]))
        self.assertEqual(canonical_json(case), canonical_json(reordered))


if __name__ == "__main__":
    unittest.main()
