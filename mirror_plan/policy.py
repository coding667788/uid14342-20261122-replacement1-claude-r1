"""Policy revision view and per-action authorization evidence.

The view is frozen at ``as_of``: only events with ``seq <= as_of`` exist in the
view, and a later grant for a key completely replaces the earlier revision's
scope and time window. A revoke clips the surviving revision's window to
``effective_at``.
"""


class PolicyView:
    """Effective authorizations visible for a case's ``as_of``."""

    def __init__(self, case):
        as_of = case["as_of"]
        # key -> latest visible grant record, plus its optional revocation
        latest = {}
        for event in case["policy"]:
            if event["seq"] > as_of:
                break
            key = event["key"]
            if event["event"] == "grant":
                latest[key] = {
                    "key": key,
                    "revision": event["revision"],
                    "tap": event["tap"],
                    "collector": event["collector"],
                    "tenant": event["tenant"],
                    "class": event["class"],
                    "label": event["label"],
                    "from": event["from"],
                    "to": event["to"],
                    "revoked_at": None,
                }
            else:  # revoke: validated to target the latest live revision
                latest[key]["revoked_at"] = event["effective_at"]

        self.grants = list(latest.values())
        # five-tuple -> grants carrying exactly that tuple
        self._index = {}
        for grant in self.grants:
            five = (
                grant["tap"],
                grant["collector"],
                grant["tenant"],
                grant["class"],
                grant["label"],
            )
            self._index.setdefault(five, []).append(grant)

    def effective_window(self, grant):
        """Return [from, to) after revocation clipping, or None when empty."""
        end = grant["to"]
        if grant["revoked_at"] is not None:
            end = min(end, grant["revoked_at"])
        if grant["from"] >= end:
            return None
        return grant["from"], end

    def matching_grants(self, tap, collector, tenant, klass, label):
        return self._index.get((tap, collector, tenant, klass, label), ())


def atom_slices(start, end, boundaries):
    """Split [start, end) at integer boundary points lying strictly inside."""
    points = {start, end}
    for point in boundaries:
        if start < point < end:
            points.add(point)
    ordered = sorted(points)
    return list(zip(ordered, ordered[1:]))


def _witness_key(grant):
    """Byte ordering of (key, revision): revision is numeric, tie-broken by key."""
    return grant["key"].encode("utf-8"), grant["revision"]


def check_visibility_item(view, action, item):
    """Check one visibility list item.

    Returns a dict with merged witnessed segments and every unauthorized hole
    (atomic slices are merged across adjacent slices sharing the same status).
    """
    five = (
        action["tap"],
        action["collector"],
        item["tenant"],
        item["class"],
        item["label"],
    )
    grants = view.matching_grants(*five)
    boundaries = set()
    live = []
    for grant in grants:
        window = view.effective_window(grant)
        if window is None:
            continue
        w_from, w_to = window
        if w_to <= item["from"] or w_from >= item["to"]:
            continue
        live.append(grant)
        boundaries.add(w_from)
        boundaries.add(w_to)

    slices = atom_slices(item["from"], item["to"], boundaries)
    # Per-atomic-slice verdicts; later merged on identical witness / hole status.
    verdicts = []
    for s_from, s_to in slices:
        witness = None
        for grant in live:
            window = view.effective_window(grant)
            w_from, w_to = window
            if w_from <= s_from and s_to <= w_to:
                if witness is None or _witness_key(grant) < _witness_key(witness):
                    witness = grant
        verdicts.append((s_from, s_to, witness))

    witnessed, holes = [], []

    def signature(grant):
        return None if grant is None else (grant["key"], grant["revision"])

    run_start = None
    run_end = None
    run_sig = object()
    for s_from, s_to, grant in verdicts:
        sig = signature(grant)
        if sig != run_sig:
            if run_start is not None:
                if run_sig is None:
                    holes.append({"from": run_start, "to": run_end})
                else:
                    key, revision = run_sig
                    witnessed.append(
                        {"key": key, "revision": revision, "from": run_start, "to": run_end}
                    )
            run_start, run_end, run_sig = s_from, s_to, sig
        else:
            run_end = s_to
    if run_start is not None:
        if run_sig is None:
            holes.append({"from": run_start, "to": run_end})
        else:
            key, revision = run_sig
            witnessed.append(
                {"key": key, "revision": revision, "from": run_start, "to": run_end}
            )

    missing = {
        "tap": five[0],
        "collector": five[1],
        "tenant": five[2],
        "class": five[3],
        "label": five[4],
    }
    return {
        "tenant": item["tenant"],
        "class": item["class"],
        "label": item["label"],
        "from": item["from"],
        "to": item["to"],
        "witnessed": witnessed,
        "holes": holes,
        "missing": missing,
    }


def authorization_evidence(view, action):
    """Full authorization detail for one action over all visibility items."""
    items = [check_visibility_item(view, action, item) for item in action["visibility"]]
    safe = all(not item["holes"] for item in items)
    return {"action_id": action["id"], "safe": safe, "items": items}


def first_hole_tuple(evidence):
    """Sort key for audit authorization failures.

    (action_id, tenant, class, label, visibility_from, visibility_to,
    hole_start, hole_end), first hole per item, first item per action.
    """
    for item in evidence["items"]:
        if item["holes"]:
            hole = item["holes"][0]
            return (
                evidence["action_id"],
                item["tenant"],
                item["class"],
                item["label"],
                item["from"],
                item["to"],
                hole["from"],
                hole["to"],
            )
    return None
