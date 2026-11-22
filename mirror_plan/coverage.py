"""Port-group constraints and per-scenario requirement coverage."""

from .policy import atom_slices


def overlaps(a_from, a_to, b_from, b_to):
    """Half-open interval overlap."""
    return a_from < b_to and b_from < a_to


def first_port_conflict(case, selected_actions):
    """Return the first port-group conflict tuple, or None.

    Sort key: (tap_group, overlap_start, overlap_end, action_id_1, action_id_2)
    with the two action ids ordered ascending.
    """
    group_of = {tap["id"]: tap["port_group"] for tap in case["taps"]}
    conflicts = []
    chosen = sorted(selected_actions, key=lambda a: a["id"])
    for i in range(len(chosen)):
        for j in range(i + 1, len(chosen)):
            a1, a2 = chosen[i], chosen[j]
            if group_of[a1["tap"]] != group_of[a2["tap"]]:
                continue
            if not overlaps(a1["start"], a1["end"], a2["start"], a2["end"]):
                continue
            lo = max(a1["start"], a2["start"])
            hi = min(a1["end"], a2["end"])
            ids = sorted((a1["id"], a2["id"]))
            conflicts.append((group_of[a1["tap"]], lo, hi, ids[0], ids[1]))
    if not conflicts:
        return None
    return sorted(conflicts)[0]


def _device_is_down(failures, device, s_from, s_to):
    for fail in failures:
        if fail["device"] == device and overlaps(fail["from"], fail["to"], s_from, s_to):
            return True
    return False


class CoverageIndex:
    """Precomputed atomic coverage slices for every scenario/requirement pair.

    For each slice we record, per action, the collector on which that action
    delivers an authorized matching sample. One collector counts once no
    matter how many matching visibility items the action carries.
    """

    def __init__(self, case, view, safe_action_ids):
        self.case = case
        self.tap_by_id = {tap["id"]: tap for tap in case["taps"]}
        self.actions = sorted(case["candidates"], key=lambda a: a["id"])
        self.action_index = {a["id"]: i for i, a in enumerate(self.actions)}
        self.safe_mask = {i for i, a in enumerate(self.actions) if a["id"] in safe_action_ids}
        self.scenarios = sorted(case["scenarios"], key=lambda s: s["id"])
        self.requirements = sorted(case["requirements"], key=lambda r: r["id"])

        # Matching visibility items per action: (from, to) list for tenant/class.
        self._matching = {}
        for ai, action in enumerate(self.actions):
            table = {}
            for item in action["visibility"]:
                table.setdefault((item["tenant"], item["class"]), []).append(
                    (item["from"], item["to"])
                )
            self._matching[ai] = table

        # slices[scenario_id][requirement_id] = list of slice records
        self.slices = {}
        # feasibility views for the solver
        self.contrib = {}
        for scenario in self.scenarios:
            self.slices[scenario["id"]] = {}
            self.contrib[scenario["id"]] = {}
            sw_fail = scenario["switch_failures"]
            col_fail = scenario["collector_failures"]
            for req in self.requirements:
                recs, contribs = self._build_slices(req, sw_fail, col_fail)
                self.slices[scenario["id"]][req["id"]] = recs
                self.contrib[scenario["id"]][req["id"]] = contribs

    def _build_slices(self, req, sw_fail, col_fail):
        boundaries = set()
        for fail in (*sw_fail, *col_fail):
            boundaries.add(fail["from"])
            boundaries.add(fail["to"])
        for ai, action in enumerate(self.actions):
            if ai not in self.safe_mask:
                continue
            for v_from, v_to in self._matching[ai].get((req["tenant"], req["class"]), ()):
                boundaries.add(v_from)
                boundaries.add(v_to)
        raw = atom_slices(req["from"], req["to"], boundaries)

        records, contribs = [], []
        for s_from, s_to in raw:
            # action index -> collector id (one entry per contributing action)
            per_action = {}
            for ai, action in enumerate(self.actions):
                if ai not in self.safe_mask:
                    continue
                if not (action["start"] <= s_from and s_to <= action["end"]):
                    continue
                tap = self.tap_by_id[action["tap"]]
                if _device_is_down(sw_fail, tap["switch"], s_from, s_to):
                    continue
                if _device_is_down(col_fail, action["collector"], s_from, s_to):
                    continue
                covered = any(
                    v_from <= s_from and s_to <= v_to
                    for v_from, v_to in self._matching[ai].get(
                        (req["tenant"], req["class"]), ()
                    )
                )
                if not covered:
                    continue
                per_action[ai] = action["collector"]
            records.append(
                {
                    "from": s_from,
                    "to": s_to,
                    "per_action": per_action,
                    "collectors": frozenset(per_action.values()),
                }
            )
            contribs.append(frozenset(per_action.keys()))
        return records, contribs

    def is_feasible(self, selected_mask):
        """True when selected actions satisfy every requirement in every scenario."""
        for scenario in self.scenarios:
            for req in self.requirements:
                need = req["min_collectors"]
                for rec in self.slices[scenario["id"]][req["id"]]:
                    collectors = {
                        collector
                        for ai, collector in rec["per_action"].items()
                        if ai in selected_mask
                    }
                    if len(collectors) < need:
                        return False
        return True

    def remaining_can_satisfy(self, pos, selected_mask):
        """Prune helper: can selected + every action at index >= pos satisfy all?"""
        remaining = selected_mask | {i for i in range(pos, len(self.actions))}
        return self.is_feasible(remaining)

    def coverage_evidence(self, selected_mask):
        """Merged witness evidence for all scenarios/requirements under a plan."""
        result = []
        for scenario in self.scenarios:
            for req in self.requirements:
                records = self.slices[scenario["id"]][req["id"]]
                merged_runs = []
                run_start = run_end = None
                run_sig = object()
                for rec in records:
                    chosen = sorted(
                        {
                            collector
                            for ai, collector in rec["per_action"].items()
                            if ai in selected_mask
                        }
                    )[: req["min_collectors"]]
                    entries = []
                    for collector in chosen:
                        witness = min(
                            self.actions[ai]["id"]
                            for ai, c in rec["per_action"].items()
                            if ai in selected_mask and c == collector
                        )
                        entries.append({"collector": collector, "action_id": witness})
                    sig = tuple((e["collector"], e["action_id"]) for e in entries)
                    if sig != run_sig:
                        if run_start is not None:
                            merged_runs.append(
                                {"from": run_start, "to": run_end, "witnesses": run_entries}
                            )
                        run_start, run_end, run_sig, run_entries = (
                            rec["from"],
                            rec["to"],
                            sig,
                            entries,
                        )
                    else:
                        run_end = rec["to"]
                if run_start is not None:
                    merged_runs.append(
                        {"from": run_start, "to": run_end, "witnesses": run_entries}
                    )
                result.append(
                    {
                        "scenario_id": scenario["id"],
                        "requirement_id": req["id"],
                        "tenant": req["tenant"],
                        "class": req["class"],
                        "min_collectors": req["min_collectors"],
                        "segments": merged_runs,
                    }
                )
        return result

    def first_coverage_failure(self, selected_mask):
        """First failing atomic slice by (scenario_id, requirement_id, start, end)."""
        for scenario in self.scenarios:
            for req in self.requirements:
                for rec in self.slices[scenario["id"]][req["id"]]:
                    collectors = sorted(
                        {
                            collector
                            for ai, collector in rec["per_action"].items()
                            if ai in selected_mask
                        }
                    )
                    if len(collectors) < req["min_collectors"]:
                        return {
                            "scenario_id": scenario["id"],
                            "requirement_id": req["id"],
                            "start": rec["from"],
                            "end": rec["to"],
                            "min_collectors": req["min_collectors"],
                            "actual_collectors": collectors,
                        }
        return None
