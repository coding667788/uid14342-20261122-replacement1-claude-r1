"""Deterministically generate the reproducible scale case.

The generated case exercises every boundary in the specification:
  * 26 candidate actions (the published maximum),
  * 6 scenarios (base + five distinct switch/collector failure windows),
  * 24 coverage requirements crossing revoke effective_at boundaries and
    device failure boundaries,
  * grant revision chains (rev 1 clipped by a revoke, then rev 2 replacing
    it), including two intentionally unsafe seam candidates.

Redundancy is built into the layout. Four (tenant, class) pairs own disjoint
six-tap blocks; inside a block two taps feed each collector on different
switches, each tap has its own physical port group, and grants are only
emitted for the five-tuples the actions actually use. Consequently no two
selected actions contend on a port group, any single switch failure leaves
every collector reachable, and any single collector failure still leaves two
distinct collectors. Two extra actions on dedicated taps carry authorization
that crosses a revoke/revision seam at t=400; no requirement depends on them.

Run:
    python examples/generate_scale_case.py examples/output/scale_case.json

The layout is fixed: no randomness, so the file byte content is reproducible.
"""

import json
import sys

TENANTS = ["tnA", "tnB"]
CLASSES = ["voice", "bulk", "mgmt"]
COLLECTORS = ["c1", "c2", "c3"]
# Twenty-six taps, each its own port group: taps 1-24 are the four per-pair
# blocks (six taps each), taps 25-26 host the revoke/revision-seam actions.
TAPS = [
    {"id": f"tap{i}", "switch": f"sw{i}", "port_group": f"pg{i}"}
    for i in range(1, 27)
]
SPAN = (0, 900)
# Requirement windows straddle the revoke point (400) and failure points.
REQ_WINDOWS = [(50, 150), (200, 300), (300, 450), (500, 600), (600, 720), (750, 880)]
# Two taps per collector, on distinct switches.
COLLECTOR_BY_SLOT = ["c1", "c1", "c2", "c2", "c3", "c3"]
PAIRS = [
    ("tnA", "voice"), ("tnA", "bulk"),
    ("tnB", "voice"), ("tnB", "bulk"),
]


def build_actions():
    actions = []
    action_no = 1
    # 24 regular actions: six per (tenant, class) pair.
    for pair_no, (tenant, klass) in enumerate(PAIRS):
        tenant2 = "tnB" if tenant == "tnA" else "tnA"
        base = pair_no * 6
        for slot in range(6):
            tap = TAPS[base + slot]
            collector = COLLECTOR_BY_SLOT[slot]
            mid = 450
            actions.append(
                {
                    "id": f"act{action_no:02d}",
                    "tap": tap["id"],
                    "collector": collector,
                    "start": SPAN[0],
                    "end": SPAN[1],
                    "cost": 1 + ((action_no - 1) * 7) % 11,
                    "visibility": [
                        {
                            "tenant": tenant,
                            "class": klass,
                            "label": f"lbl-{tenant}-{klass}",
                            "from": SPAN[0],
                            "to": mid,
                        },
                        {
                            "tenant": tenant2,
                            "class": klass,
                            "label": f"lbl-{tenant2}-{klass}",
                            "from": mid,
                            "to": SPAN[1],
                        },
                    ],
                }
            )
            action_no += 1

    # Two actions whose only authorization crosses a revoke/revision seam.
    # Under the replacement semantics the view keeps only the latest
    # revision, so rev 2 alone authorizes [400, 800) and the [100, 400)
    # prefix is an intentional hole: these two candidates are therefore
    # unsafe and never selectable, which the solver must prove while still
    # finding a feasible plan from the other 24 actions. The exact clipping
    # of a surviving (non-replaced) revision is covered by the unit tests.
    seam = (("tnA", "voice", "tap25"), ("tnB", "bulk", "tap26"))
    for i, (tenant, klass, tap) in enumerate(seam):
        actions.append(
            {
                "id": f"act{25 + i:02d}",
                "tap": tap,
                "collector": "c3",
                "start": 100,
                "end": 800,
                "cost": 2,
                "visibility": [
                    {
                        "tenant": tenant,
                        "class": klass,
                        "label": f"lbl-{tenant}-{klass}",
                        "from": 100,
                        "to": 800,
                    }
                ],
            }
        )
    return actions


def build_policy(actions):
    """Grants only for five-tuples the actions actually observe."""
    policy = []
    seq = 1
    key_index = 1

    # Regular coverage grants, never revoked: one key per distinct
    # (tap, collector, tenant, class) tuple used by regular visibility items.
    combos = set()
    for action in actions[:24]:
        for item in action["visibility"]:
            combos.add(
                (action["tap"], action["collector"], item["tenant"], item["class"])
            )
    for tap, collector, tenant, klass in sorted(combos):
        policy.append(
            {
                "seq": seq,
                "event": "grant",
                "key": f"k{key_index:02d}",
                "revision": 1,
                "tap": tap,
                "collector": collector,
                "tenant": tenant,
                "class": klass,
                "label": f"lbl-{tenant}-{klass}",
                "from": 0,
                "to": 900,
            }
        )
        seq += 1
        key_index += 1

    # Revoke-boundary chains for the two seam actions. Both revisions share
    # the same five-tuple; rev 1 is clipped at 400 and rev 2 starts at 400.
    seam = (("tnA", "voice", "tap25"), ("tnB", "bulk", "tap26"))
    for i, (tenant, klass, tap) in enumerate(seam):
        key = f"rk{i + 1}"
        label = f"lbl-{tenant}-{klass}"
        policy.append(
            {
                "seq": seq,
                "event": "grant",
                "key": key,
                "revision": 1,
                "tap": tap,
                "collector": "c3",
                "tenant": tenant,
                "class": klass,
                "label": label,
                "from": 0,
                "to": 900,
            }
        )
        seq += 1
        policy.append(
            {"seq": seq, "event": "revoke", "key": key, "revision": 1,
             "effective_at": 400}
        )
        seq += 1
        policy.append(
            {
                "seq": seq,
                "event": "grant",
                "key": key,
                "revision": 2,
                "tap": tap,
                "collector": "c3",
                "tenant": tenant,
                "class": klass,
                "label": label,
                "from": 400,
                "to": 900,
            }
        )
        seq += 1
    return policy


def build_requirements():
    requirements = []
    rid = 1
    for tenant, klass in PAIRS:
        for window_no, (w_from, w_to) in enumerate(REQ_WINDOWS):
            requirements.append(
                {
                    "id": f"req{rid:02d}",
                    "tenant": tenant,
                    "class": klass,
                    "from": w_from,
                    "to": w_to,
                    # First three windows demand two distinct collectors; the
                    # windows overlapping the later failure scenarios demand
                    # one, so a single outage never makes the case infeasible.
                    "min_collectors": 2 if window_no < 3 else 1,
                }
            )
            rid += 1
    return requirements


def build_case():
    actions = build_actions()
    policy = build_policy(actions)
    scenarios = [
        {"id": "base", "switch_failures": [], "collector_failures": []},
        {
            "id": "scn_sw1_gap",
            "switch_failures": [{"device": "sw1", "from": 600, "to": 700}],
            "collector_failures": [],
        },
        {
            "id": "scn_sw2_gap",
            "switch_failures": [{"device": "sw2", "from": 300, "to": 400}],
            "collector_failures": [],
        },
        {
            "id": "scn_c1_gap",
            "switch_failures": [],
            "collector_failures": [{"device": "c1", "from": 600, "to": 750}],
        },
        {
            "id": "scn_c2_gap",
            "switch_failures": [],
            "collector_failures": [{"device": "c2", "from": 250, "to": 350}],
        },
        {
            "id": "scn_mixed",
            "switch_failures": [{"device": "sw3", "from": 650, "to": 750}],
            "collector_failures": [{"device": "c3", "from": 650, "to": 750}],
        },
    ]
    return {
        "as_of": len(policy),
        "taps": TAPS,
        "policy": policy,
        "candidates": actions,
        "requirements": build_requirements(),
        "scenarios": scenarios,
    }


def main(argv):
    out = argv[1] if len(argv) > 1 else "examples/output/scale_case.json"
    case = build_case()
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(case, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(f"wrote {out}: {len(case['candidates'])} actions, "
          f"{len(case['scenarios'])} scenarios, {len(case['requirements'])} requirements, "
          f"{len(case['policy'])} policy events")


if __name__ == "__main__":
    main(sys.argv)
