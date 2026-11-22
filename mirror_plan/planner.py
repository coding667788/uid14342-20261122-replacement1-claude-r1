"""Plan assembly and full recomputation-based audit."""

from .coverage import CoverageIndex, first_port_conflict
from .digest import plan_digest
from .errors import AuditFailure
from .policy import PolicyView, authorization_evidence, first_hole_tuple
from .solver import conflict_witnesses, safe_actions, solve


def _plan_payload(case, selected_actions, evidence_by_id, index):
    selected_ids = sorted(a["id"] for a in selected_actions)
    total_cost = sum(a["cost"] for a in selected_actions)
    auth_evidence = [evidence_by_id[ident] for ident in selected_ids]
    selected_mask = frozenset(
        i for i, action in enumerate(index.actions) if action["id"] in set(selected_ids)
    )
    return {
        "status": "feasible",
        "cost": total_cost,
        "selected_ids": selected_ids,
        "plan_digest": plan_digest(case, selected_ids),
        "authorization_evidence": auth_evidence,
        "coverage_evidence": index.coverage_evidence(selected_mask),
    }


def build_plan(case):
    """Compute the full plan document for a validated case."""
    view = PolicyView(case)
    selected_actions, evidence_by_id, index = solve(case, view)
    if selected_actions is not None:
        return _plan_payload(case, selected_actions, evidence_by_id, index)

    retained, deleted, witnesses = conflict_witnesses(case, view)
    conflict = [
        {
            "requirement_id": req_id,
            "witness_selected_ids": witnesses[req_id],
        }
        for req_id in retained
    ]
    if not retained:
        conflict.append({"requirement_id": None, "witness_selected_ids": witnesses["__empty__"]})
    return {
        "status": "infeasible",
        "minimal_conflict": {
            "deleted_requirement_ids": deleted,
            "retained_witnesses": conflict,
        },
    }


def recompute(case, selected_ids):
    """Recompute every fact about a plan without trusting its self-report.

    Returns a dict carrying digest, evidence and a coverage index; raises
    :class:`AuditFailure` on the first failure in the documented priority
    order (authorization -> port -> coverage -> digest).
    """
    view = PolicyView(case)
    actions_by_id = {a["id"]: a for a in case["candidates"]}
    unknown = sorted(set(selected_ids) - set(actions_by_id))
    if unknown:
        raise AuditFailure("structure", {"field": "$.selected_ids", "unknown_ids": unknown})
    selected_actions = [actions_by_id[ident] for ident in selected_ids]

    # Authorization (privacy) check.
    evidence_by_id = {}
    first_hole = None
    for action in selected_actions:
        detail = authorization_evidence(view, action)
        evidence_by_id[action["id"]] = detail
        if not detail["safe"]:
            tuple_key = first_hole_tuple(detail)
            if first_hole is None or tuple_key < first_hole:
                first_hole = tuple_key
    if first_hole is not None:
        action_id, tenant, klass, label, v_from, v_to, h_from, h_to = first_hole
        raise AuditFailure(
            "authorization",
            {
                "action_id": action_id,
                "tenant": tenant,
                "class": klass,
                "label": label,
                "visibility_from": v_from,
                "visibility_to": v_to,
                "hole_start": h_from,
                "hole_end": h_to,
            },
        )

    # Port-group physical constraint.
    conflict = first_port_conflict(case, selected_actions)
    if conflict is not None:
        raise AuditFailure(
            "port",
            {
                "tap_group": conflict[0],
                "overlap_start": conflict[1],
                "overlap_end": conflict[2],
                "action_id_1": conflict[3],
                "action_id_2": conflict[4],
            },
        )

    safe_ids, _ = safe_actions(case, view)
    index = CoverageIndex(case, view, safe_ids)
    selected_mask = frozenset(
        i for i, action in enumerate(index.actions) if action["id"] in set(selected_ids)
    )
    failure = index.first_coverage_failure(selected_mask)
    if failure is not None:
        raise AuditFailure("coverage", failure)

    digest = plan_digest(case, selected_ids)
    return {
        "digest": digest,
        "evidence_by_id": evidence_by_id,
        "index": index,
        "selected_mask": selected_mask,
        "selected_actions": selected_actions,
    }


def audit_plan(case, plan):
    """Audit a structurally validated plan document."""
    selected_ids = plan["selected_ids"]
    result = recompute(case, selected_ids)
    if result["digest"] != plan["plan_digest"]:
        raise AuditFailure(
            "digest",
            {"expected": result["digest"], "actual": plan["plan_digest"]},
        )

    return {
        "status": "feasible",
        "reason": None,
        "plan_digest": result["digest"],
        "selected_ids": sorted(selected_ids),
        "authorization_evidence": [result["evidence_by_id"][i] for i in sorted(selected_ids)],
        "coverage_evidence": result["index"].coverage_evidence(result["selected_mask"]),
    }
