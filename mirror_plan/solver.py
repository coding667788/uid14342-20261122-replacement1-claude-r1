"""Exact plan solver: branch-and-bound over candidate action subsets.

At most 26 candidate actions are published, so exhaustive subset search is
feasible once pruned aggressively. Actions are visited in ascending id order;
the state is ``(position, selected mask)``.

Pruning / indexing strategy:
  * Authorization is evaluated once per action: unsafe actions are removed
    before the search (no plan containing an unsafe action can be valid).
  * :class:`~mirror_plan.coverage.CoverageIndex` precomputes, for every
    scenario/requirement atomic slice, exactly which action contributes which
    collector, so feasibility tests are set lookups rather than interval
    re-scans.
  * Coverage prune: if selected plus every not-yet-decided action cannot
    satisfy a slice, the branch dies immediately.
  * Port prune: an action is only included when it does not overlap an
    already selected action on the same physical port group.
  * Dominance prune: the current objective (cost, count, sorted ids) can never
    improve past the incumbent, so the branch is cut.
  * Memoization of visited ``(pos, mask)`` states removes duplicate branches.
"""

from .coverage import CoverageIndex, overlaps
from .policy import PolicyView, authorization_evidence


def safe_actions(case, view=None):
    """Return (safe_action_ids, evidence_by_id)."""
    view = view or PolicyView(case)
    evidence = {}
    safe = set()
    for action in case["candidates"]:
        detail = authorization_evidence(view, action)
        evidence[action["id"]] = detail
        if detail["safe"]:
            safe.add(action["id"])
    return safe, evidence


def _port_compatible(case, action, selected):
    group_of = {tap["id"]: tap["port_group"] for tap in case["taps"]}
    group = group_of[action["tap"]]
    for other in selected:
        if group_of[other["tap"]] != group:
            continue
        if overlaps(action["start"], action["end"], other["start"], other["end"]):
            return False
    return True


def solve(case, view=None, requirement_ids=None):
    """Find the optimal feasible selected action list.

    Returns a tuple ``(selected_actions, evidence_by_id, coverage_index)`` or
    ``(None, evidence_by_id, coverage_index)`` when infeasible. When
    ``requirement_ids`` is given, only those requirements must be satisfied
    (used for conflict-set witnesses); scenarios, policy and candidates stay
    untouched.
    """
    view = view or PolicyView(case)
    safe_ids, evidence = safe_actions(case, view)
    index = CoverageIndex(case, view, safe_ids)

    if requirement_ids is None:
        reqs = list(index.requirements)
    else:
        keep = set(requirement_ids)
        reqs = [r for r in index.requirements if r["id"] in keep]

    if not reqs:
        # Empty requirement set: the empty plan is the unique optimum.
        return [], evidence, index

    n = len(index.actions)
    costs = [a["cost"] for a in index.actions]

    def feasible(mask):
        for scenario in index.scenarios:
            for req in reqs:
                need = req["min_collectors"]
                for rec in index.slices[scenario["id"]][req["id"]]:
                    collectors = {
                        collector
                        for ai, collector in rec["per_action"].items()
                        if ai in mask
                    }
                    if len(collectors) < need:
                        return False
        return True

    def remaining_possible(pos, mask):
        widened = mask | frozenset(range(pos, n))
        return feasible(widened)

    best = None  # (cost, count, ids_tuple, mask)
    memo = set()

    def dfs(pos, mask, selected):
        nonlocal best
        state = (pos, mask)
        if state in memo:
            return
        memo.add(state)

        if best is not None:
            cur_ids = tuple(index.actions[i]["id"] for i in sorted(mask))
            cur_cost = sum(costs[i] for i in mask)
            if (cur_cost, len(mask), cur_ids) >= best[:3]:
                # Adding actions only raises cost/count and appends ids; the
                # strict optimum cannot live below this node.
                return

        if not remaining_possible(pos, mask):
            return

        if pos == n:
            if feasible(mask):
                ids = tuple(index.actions[i]["id"] for i in sorted(mask))
                total = sum(costs[i] for i in mask)
                objective = (total, len(mask), ids)
                if best is None or objective < best[:3]:
                    best = (total, len(mask), ids, mask)
            return

        action = index.actions[pos]
        # Include branch first (finds a feasible incumbent quickly).
        if action["id"] in safe_ids and _port_compatible(case, action, selected):
            dfs(pos + 1, mask | frozenset([pos]), selected + [action])
        # Exclude branch.
        dfs(pos + 1, mask, selected)

    dfs(0, frozenset(), [])
    if best is None:
        return None, evidence, index
    _, _, ids, mask = best
    selected_actions = [index.actions[i] for i in sorted(mask)]
    return selected_actions, evidence, index


def conflict_witnesses(case, view=None):
    """Run the deterministic requirement-deletion rule for an infeasible case.

    Requirements are tried for deletion in descending id order; a requirement
    is permanently removed only if the remaining set is still infeasible.
    Returns ``(retained_ids, deleted_ids, witness_by_requirement)`` where each
    retained requirement maps to an optimal feasible witness computed after
    deleting it from the final retained set.
    """
    view = view or PolicyView(case)
    all_ids = sorted(r["id"] for r in case["requirements"])
    retained = list(all_ids)
    deleted = []

    for req_id in reversed(all_ids):
        trial = [r for r in retained if r != req_id]
        selected, _, _ = solve(case, view, trial)
        if selected is None:
            retained = trial
            deleted.append(req_id)
    deleted.reverse()

    witnesses = {}
    for req_id in retained:
        trial = [r for r in retained if r != req_id]
        selected, _, _ = solve(case, view, trial)
        witnesses[req_id] = [a["id"] for a in selected]
    if not retained:
        witnesses["__empty__"] = []
    return retained, deleted, witnesses


__all__ = [
    "safe_actions",
    "solve",
    "conflict_witnesses",
]
