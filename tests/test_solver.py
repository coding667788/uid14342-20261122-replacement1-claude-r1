"""Solver optimality, port constraints and conflict-set rule tests."""

import unittest

from tests._helpers import base_case
from mirror_plan.coverage import first_port_conflict
from mirror_plan.policy import PolicyView
from mirror_plan.solver import conflict_witnesses, safe_actions, solve


class SolverTests(unittest.TestCase):
    def setUp(self):
        self.case = base_case()
        self.view = PolicyView(self.case)

    def test_optimal_cost_then_count_then_id_order(self):
        selected, _, _ = solve(self.case, self.view)
        ids = sorted(a["id"] for a in selected)
        # r1 needs two collectors across 0..900 in every scenario including
        # the c2 outage 600..700; r2 needs c3. Brute-force every subset and
        # confirm the solver's objective winner independently.
        actions = sorted(self.case["candidates"], key=lambda a: a["id"])
        from mirror_plan.coverage import CoverageIndex
        safe, _ = safe_actions(self.case, self.view)
        index = CoverageIndex(self.case, self.view, safe)
        best = None
        for mask_bits in range(1 << len(actions)):
            mask = frozenset(i for i in range(len(actions)) if mask_bits >> i & 1)
            chosen = [actions[i] for i in mask]
            if first_port_conflict(self.case, chosen) is not None:
                continue
            if not index.is_feasible(mask):
                continue
            objective = (
                sum(actions[i]["cost"] for i in mask),
                len(mask),
                tuple(actions[i]["id"] for i in sorted(mask)),
            )
            if best is None or objective < best:
                best = objective
        self.assertIsNotNone(best)
        self.assertEqual((sum(a["cost"] for a in selected), len(selected), tuple(ids)), best)

    def test_empty_requirements_allows_empty_plan(self):
        case = self.case
        case["requirements"] = []
        selected, _, _ = solve(case)
        self.assertEqual(selected, [])

    def test_port_conflict_blocks_overlapping_same_group(self):
        case = self.case
        # Force a1 and a4 onto the same port group with an overlapping window.
        case["taps"] = [
            {"id": "tap1", "switch": "sw1", "port_group": "pgX"},
            {"id": "tap2", "switch": "sw2", "port_group": "pg2"},
            {"id": "tap3", "switch": "sw3", "port_group": "pg3"},
        ]
        actions_by_id = {a["id"]: a for a in case["candidates"]}
        conflict = first_port_conflict(
            case, [actions_by_id["a1"], actions_by_id["a4"]]
        )
        # a1 spans [0,500), a4 spans [500,900): touching boundaries do not
        # overlap, so there is no conflict. Overlap a4 backward instead.
        self.assertIsNone(conflict)
        actions_by_id["a4"]["start"] = 400
        actions_by_id["a4"]["visibility"][0]["from"] = 400
        conflict = first_port_conflict(
            case, [actions_by_id["a1"], actions_by_id["a4"]]
        )
        self.assertEqual(conflict, ("pgX", 400, 500, "a1", "a4"))

    def test_unsafe_action_never_selected(self):
        case = self.case
        # Remove every voice grant: all voice actions become unsafe, so r1
        # (which needs voice samples) cannot be satisfied.
        case["policy"] = [
            e for e in case["policy"]
            if e["event"] != "grant" or e["class"] != "voice"
        ]
        view = PolicyView(case)
        safe, _ = safe_actions(case, view)
        self.assertNotIn("a1", safe)
        self.assertNotIn("a4", safe)
        selected, _, _ = solve(case, view)
        self.assertIsNone(selected)

    def test_conflict_set_deletion_rule(self):
        case = self.case
        # One impossible requirement no action can observe. The rule tries
        # requirements in descending id order: r9 is tried last among the
        # three and, since r1+r2 stay feasible without it, r9 is retained in
        # the conflict set while r1/r2 get deleted first as the rule walks.
        case["requirements"].append(
            {"id": "r9", "tenant": "ghost", "class": "voice", "from": 0, "to": 100,
             "min_collectors": 1}
        )
        retained, deleted, witnesses = conflict_witnesses(case)
        self.assertEqual(retained, ["r9"])
        self.assertEqual(set(deleted), {"r1", "r2"})
        # The retained requirement's witness is the feasible plan after
        # deleting it (the empty-requirement rule allows an empty plan).
        self.assertEqual(witnesses["r9"], [])

    def test_conflict_when_zero_requirements_remain(self):
        case = self.case
        case["requirements"] = [
            {"id": "rX", "tenant": "ghost", "class": "v", "from": 0, "to": 10,
             "min_collectors": 1},
        ]
        # The sole requirement: deleting it leaves zero requirements, which is
        # feasible with the empty plan, so rX is NOT permanently deleted. It
        # stays in the conflict set and its deletion witness is the empty plan.
        retained, deleted, witnesses = conflict_witnesses(case)
        self.assertEqual(retained, ["rX"])
        self.assertEqual(deleted, [])
        self.assertEqual(witnesses["rX"], [])


if __name__ == "__main__":
    unittest.main()
