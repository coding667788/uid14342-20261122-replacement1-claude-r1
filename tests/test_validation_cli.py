"""Validation field paths and end-to-end CLI behavior tests."""

import json
import os
import subprocess
import sys
import unittest

from tests._helpers import REPO_ROOT, TempRepoCase, base_case
from mirror_plan.digest import plan_digest
from mirror_plan.errors import ValidationError
from mirror_plan.validation import validate_case, validate_plan


class ValidationTests(unittest.TestCase):
    def test_valid_case_passes(self):
        validate_case(base_case())

    def test_missing_field_has_stable_path(self):
        case = base_case()
        del case["taps"][0]["id"]
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.taps[0].id")

    def test_bad_id_pattern(self):
        case = base_case()
        case["candidates"][0]["id"] = "bad id!"
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.candidates[0].id")

    def test_time_out_of_range(self):
        case = base_case()
        case["candidates"][0]["end"] = 10**9 + 1
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.candidates[0].end")

    def test_duplicate_id_rejected(self):
        case = base_case()
        case["candidates"][1]["id"] = case["candidates"][0]["id"]
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.candidates[1].id")

    def test_visibility_outside_action_rejected(self):
        case = base_case()
        case["candidates"][0]["visibility"][0]["to"] = 9999
        with self.assertRaises(ValidationError):
            validate_case(case)

    def test_policy_revision_must_increment(self):
        case = base_case()
        case["policy"].append(
            {"seq": 7, "event": "grant", "key": "ka", "revision": 9,
             "tap": "tap1", "collector": "c1", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 10}
        )
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.policy[6].revision")

    def test_revoke_must_target_latest_revision(self):
        case = base_case()
        case["policy"].append(
            {"seq": 7, "event": "revoke", "key": "ka", "revision": 1,
             "effective_at": 10}
        )
        # ka rev1 is still the latest, so this is valid structurally.
        validate_case(case)
        case["policy"].append(
            {"seq": 8, "event": "revoke", "key": "ka", "revision": 1,
             "effective_at": 20}
        )
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.policy[7].key")

    def test_base_scenario_required(self):
        case = base_case()
        case["scenarios"][0]["id"] = "other"
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.scenarios")

    def test_min_collectors_bounds(self):
        case = base_case()
        case["requirements"][0]["min_collectors"] = 4
        with self.assertRaises(ValidationError) as ctx:
            validate_case(case)
        self.assertEqual(ctx.exception.field, "$.requirements[0].min_collectors")


class CliTests(TempRepoCase):
    def test_plan_and_audit_roundtrip(self):
        case_path = self.write_json("case.json", base_case())
        code, plan, _ = self.run_cli("plan", case_path)
        self.assertEqual(code, 0)
        self.assertEqual(plan["status"], "feasible")
        plan_path = self.write_json("plan.json", plan)
        code, audit, _ = self.run_cli("audit", case_path, plan_path)
        self.assertEqual(code, 0)
        self.assertEqual(audit["status"], "feasible")
        self.assertEqual(audit["plan_digest"], plan["plan_digest"])

    def test_infeasible_exit_zero_with_conflict(self):
        case = base_case()
        case["requirements"].append(
            {"id": "r9", "tenant": "ghost", "class": "v", "from": 0, "to": 10,
             "min_collectors": 1}
        )
        case_path = self.write_json("case.json", case)
        code, out, _ = self.run_cli("plan", case_path)
        self.assertEqual(code, 0)
        self.assertEqual(out["status"], "infeasible")
        # r9 is the unsatisfiable requirement and survives in the conflict set.
        retained = [w["requirement_id"]
                    for w in out["minimal_conflict"]["retained_witnesses"]]
        self.assertIn("r9", retained)
        self.assertNotIn("r9", out["minimal_conflict"]["deleted_requirement_ids"])

    def test_infeasible_descending_deletion_order(self):
        # Two unsatisfiable requirements: the higher id rY is tried first and
        # permanently deleted; rX stays in the conflict set with an empty-plan
        # witness (deleting rX leaves zero requirements, which is feasible).
        case = base_case()
        case["requirements"] = [
            {"id": "rX", "tenant": "g", "class": "v", "from": 0, "to": 10,
             "min_collectors": 1},
            {"id": "rY", "tenant": "h", "class": "v", "from": 0, "to": 10,
             "min_collectors": 1},
        ]
        case_path = self.write_json("case.json", case)
        code, out, _ = self.run_cli("plan", case_path)
        self.assertEqual(code, 0)
        self.assertEqual(out["minimal_conflict"]["deleted_requirement_ids"], ["rY"])
        self.assertEqual(
            out["minimal_conflict"]["retained_witnesses"],
            [{"requirement_id": "rX", "witness_selected_ids": []}],
        )

    def test_malformed_json_exit_2(self):
        bad = os.path.join(self.dir, "bad.json")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        code, out, _ = self.run_cli("plan", bad)
        self.assertEqual(code, 2)
        self.assertEqual(out["reason"], "validation")
        self.assertIn("bad.json", out["field"])

    def test_audit_digest_mismatch_exit_3(self):
        case_path = self.write_json("case.json", base_case())
        _, plan, _ = self.run_cli("plan", case_path)
        plan["plan_digest"] = "sha256:" + "0" * 64
        plan_path = self.write_json("plan.json", plan)
        code, out, _ = self.run_cli("audit", case_path, plan_path)
        self.assertEqual(code, 3)
        self.assertEqual(out["reason"], "digest")

    def test_audit_unknown_action_is_structure_failure(self):
        case_path = self.write_json("case.json", base_case())
        plan = {"selected_ids": ["nope"], "plan_digest": plan_digest(base_case(), ["nope"])}
        plan_path = self.write_json("plan.json", plan)
        code, out, _ = self.run_cli("audit", case_path, plan_path)
        self.assertEqual(code, 3)
        self.assertEqual(out["reason"], "structure")
        self.assertEqual(out["detail"]["field"], "$.selected_ids")

    def test_audit_structure_outranks_authorization(self):
        # An unknown action id must be reported as a structure failure even
        # though recomputation would otherwise hit authorization rules.
        case_path = self.write_json("case.json", base_case())
        plan = {"selected_ids": ["ghost"], "plan_digest": "sha256:" + "1" * 64}
        plan_path = self.write_json("plan.json", plan)
        code, out, _ = self.run_cli("audit", case_path, plan_path)
        self.assertEqual(code, 3)
        self.assertEqual(out["reason"], "structure")

    def test_audit_authorization_failure_priority(self):
        # Tamper the case policy so a1's five-tuple no longer matches any
        # grant; the plan digest is recomputed against the tampered case, so
        # recomputation must surface the authorization failure, not a digest
        # mismatch. Keep every value in the legal value domain.
        tampered = self.clone(base_case())
        for event in tampered["policy"]:
            if event["key"] == "ka":
                event["class"] = "other"
        tampered_path = self.write_json("tampered.json", tampered)
        plan = {"selected_ids": ["a1"], "plan_digest": plan_digest(tampered, ["a1"])}
        plan_path = self.write_json("plan.json", plan)
        code, out, _ = self.run_cli("audit", tampered_path, plan_path)
        self.assertEqual(code, 3)
        self.assertEqual(out["reason"], "authorization")
        self.assertEqual(out["detail"]["action_id"], "a1")
        self.assertEqual(out["detail"]["hole_start"], 0)

    def test_audit_port_conflict_tuple(self):
        case = self.clone(base_case())
        # Collide a1 and a4 on the same group with a real overlap. Keep every
        # referenced tap so the document remains structurally valid.
        case["taps"] = [
            {"id": "tap1", "switch": "sw1", "port_group": "pgX"},
            {"id": "tap2", "switch": "sw2", "port_group": "pg2"},
            {"id": "tap3", "switch": "sw3", "port_group": "pg3"},
            {"id": "tap4", "switch": "sw4", "port_group": "pg4"},
        ]
        for action in case["candidates"]:
            if action["id"] == "a4":
                action["start"] = 400
                action["visibility"][0]["from"] = 400
        case_path = self.write_json("case.json", case)
        ids = ["a1", "a4"]
        plan = {"selected_ids": ids, "plan_digest": plan_digest(case, ids)}
        plan_path = self.write_json("plan.json", plan)
        code, out, _ = self.run_cli("audit", case_path, plan_path)
        self.assertEqual(code, 3)
        self.assertEqual(out["reason"], "port")
        self.assertEqual(
            (out["detail"]["tap_group"], out["detail"]["overlap_start"],
             out["detail"]["overlap_end"], out["detail"]["action_id_1"],
             out["detail"]["action_id_2"]),
            ("pgX", 400, 500, "a1", "a4"),
        )


if __name__ == "__main__":
    unittest.main()
