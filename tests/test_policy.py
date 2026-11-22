"""Policy view, atomic slicing and authorization evidence tests."""

import unittest

from tests._helpers import base_case
from mirror_plan.policy import (
    PolicyView,
    atom_slices,
    authorization_evidence,
    check_visibility_item,
)


class SliceTests(unittest.TestCase):
    def test_boundaries_inside_only(self):
        self.assertEqual(
            atom_slices(0, 10, {3, 7, 100}),
            [(0, 3), (3, 7), (7, 10)],
        )

    def test_no_boundaries(self):
        self.assertEqual(atom_slices(5, 9, set()), [(5, 9)])


class PolicyViewTests(unittest.TestCase):
    def test_replacement_drops_old_revision_scope(self):
        case = {
            "as_of": 3,
            "policy": [
                {"seq": 1, "event": "grant", "key": "k", "revision": 1,
                 "tap": "t", "collector": "c", "tenant": "n", "class": "x",
                 "label": "L", "from": 0, "to": 1000},
                {"seq": 2, "event": "revoke", "key": "k", "revision": 1,
                 "effective_at": 400},
                {"seq": 3, "event": "grant", "key": "k", "revision": 2,
                 "tap": "t", "collector": "c", "tenant": "n", "class": "x",
                 "label": "L", "from": 400, "to": 1000},
            ],
        }
        view = PolicyView(case)
        self.assertEqual(len(view.grants), 1)
        self.assertEqual(view.grants[0]["revision"], 2)
        self.assertIsNone(view.grants[0]["revoked_at"])

    def test_revoke_clips_surviving_revision(self):
        case = {
            "as_of": 2,
            "policy": [
                {"seq": 1, "event": "grant", "key": "k", "revision": 1,
                 "tap": "t", "collector": "c", "tenant": "n", "class": "x",
                 "label": "L", "from": 100, "to": 900},
                {"seq": 2, "event": "revoke", "key": "k", "revision": 1,
                 "effective_at": 400},
            ],
        }
        view = PolicyView(case)
        self.assertEqual(view.effective_window(view.grants[0]), (100, 400))

    def test_as_of_freezes_view(self):
        case = base_case()
        case["as_of"] = 4  # kd grant visible; revoke at seq 5 not yet
        view = PolicyView(case)
        kd = next(g for g in view.grants if g["key"] == "kd")
        self.assertIsNone(kd["revoked_at"])
        case["as_of"] = 5
        view = PolicyView(case)
        kd = next(g for g in view.grants if g["key"] == "kd")
        self.assertEqual(view.effective_window(kd), (0, 400))


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.case = base_case()
        self.view = PolicyView(self.case)

    def test_safe_action_fully_witnessed(self):
        a1 = next(a for a in self.case["candidates"] if a["id"] == "a1")
        ev = authorization_evidence(self.view, a1)
        self.assertTrue(ev["safe"])
        self.assertEqual(ev["items"][0]["witnessed"],
                         [{"key": "ka", "revision": 1, "from": 0, "to": 500}])
        self.assertEqual(ev["items"][0]["holes"], [])

    def test_revoke_leaves_hole_after_effective_at(self):
        # a6 runs 0..300 and kd is clipped at 400, so it stays safe; extend
        # the action past 400 to expose the unauthorized tail.
        a6 = next(a for a in self.case["candidates"] if a["id"] == "a6")
        a6["end"] = 600
        a6["visibility"][0]["to"] = 600
        ev = authorization_evidence(self.view, a6)
        self.assertFalse(ev["safe"])
        self.assertEqual(ev["items"][0]["holes"], [{"from": 400, "to": 600}])
        self.assertEqual(ev["items"][0]["witnessed"],
                         [{"key": "kd", "revision": 1, "from": 0, "to": 400}])

    def test_witness_uses_smallest_key_byte_order(self):
        case = self.case
        # Add a second grant with a byte-wise smaller key for the same tuple.
        case["policy"].append(
            {"seq": 6, "event": "grant", "key": "aa", "revision": 1,
             "tap": "tap1", "collector": "c1", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 1000}
        )
        case["as_of"] = 6
        view = PolicyView(case)
        a1 = next(a for a in case["candidates"] if a["id"] == "a1")
        ev = check_visibility_item(view, a1, a1["visibility"][0])
        self.assertEqual(ev["witnessed"][0]["key"], "aa")

    def test_witness_byte_order_is_utf8_not_alphabetic(self):
        # Uppercase 'K' (0x4b) sorts before lowercase 'k' (0x6b) in bytes.
        case = self.case
        case["policy"].append(
            {"seq": 6, "event": "grant", "key": "Ka", "revision": 1,
             "tap": "tap1", "collector": "c1", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 1000}
        )
        case["as_of"] = 6
        view = PolicyView(case)
        a1 = next(a for a in case["candidates"] if a["id"] == "a1")
        ev = check_visibility_item(view, a1, a1["visibility"][0])
        self.assertEqual(ev["witnessed"][0]["key"], "Ka")
        # Revision is the numeric tie-breaker after key bytes.
        case["policy"].append(
            {"seq": 7, "event": "grant", "key": "Ka", "revision": 2,
             "tap": "tap1", "collector": "c1", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 1000}
        )
        case["as_of"] = 7
        view = PolicyView(case)
        ev = check_visibility_item(view, a1, a1["visibility"][0])
        self.assertEqual(ev["witnessed"][0]["revision"], 2)

    def test_adjacent_slices_with_same_witness_merge(self):
        # Two grants adjacent in time sharing a boundary produce one merged
        # witnessed segment when the byte-wise smallest grant covers all.
        case = {
            "as_of": 2,
            "policy": [
                {"seq": 1, "event": "grant", "key": "k1", "revision": 1,
                 "tap": "t", "collector": "c", "tenant": "n", "class": "x",
                 "label": "L", "from": 0, "to": 300},
                {"seq": 2, "event": "grant", "key": "k2", "revision": 1,
                 "tap": "t", "collector": "c", "tenant": "n", "class": "x",
                 "label": "L", "from": 300, "to": 600},
            ],
        }
        view = PolicyView(case)
        action = {"id": "a", "tap": "t", "collector": "c", "start": 0, "end": 600}
        item = {"tenant": "n", "class": "x", "label": "L", "from": 0, "to": 600}
        ev = check_visibility_item(view, action, item)
        self.assertTrue(not ev["holes"])
        # Two different witnesses -> two segments, each one grant.
        self.assertEqual([w["key"] for w in ev["witnessed"]], ["k1", "k2"])

    def test_five_tuple_must_match_exactly(self):
        # A grant on a different collector never authorizes this action.
        case = self.case
        case["policy"] = [
            {"seq": 1, "event": "grant", "key": "kx", "revision": 1,
             "tap": "tap1", "collector": "c9", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 1000}
        ]
        case["as_of"] = 1
        view = PolicyView(case)
        a1 = next(a for a in case["candidates"] if a["id"] == "a1")
        ev = authorization_evidence(view, a1)
        self.assertFalse(ev["safe"])
        self.assertEqual(ev["items"][0]["holes"], [{"from": 0, "to": 500}])


if __name__ == "__main__":
    unittest.main()
