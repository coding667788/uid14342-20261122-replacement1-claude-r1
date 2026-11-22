"""Structural validation of case JSON documents.

Every failure raises :class:`ValidationError` with a stable field path so that
bad input always maps to the same JSON pointer.
"""

import re

from .errors import ValidationError

ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_TIME = 10**9

# Published scale limits from the task specification.
LIMITS = {
    "actions": 26,
    "scenarios": 8,
    "requirements": 40,
    "policy_events": 200,
    "visibility_items": 160,
}


def _type_name(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__


def require_type(value, kind, field):
    if kind == "int":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(field, f"expected integer, got {_type_name(value)}")
    elif not isinstance(value, kind):
        names = {str: "string", dict: "object", list: "array"}
        raise ValidationError(field, f"expected {names.get(kind, kind)}, got {_type_name(value)}")
    return value


def require_id(value, field):
    require_type(value, str, field)
    if not ID_RE.match(value):
        raise ValidationError(field, f"invalid id {value!r} (need 1-64 chars of [A-Za-z0-9_.-])")
    return value


def require_time(value, field):
    require_type(value, "int", field)
    if not 0 <= value <= MAX_TIME:
        raise ValidationError(field, f"time {value} out of range [0, 10^9]")
    return value


def _require_keys(obj, required, field):
    require_type(obj, dict, field)
    for key in required:
        if key not in obj:
            raise ValidationError(f"{field}.{key}", "missing required field")
    return obj


def _unique_ids(items, field):
    seen = set()
    for i, item in enumerate(items):
        require_type(item, dict, f"{field}[{i}]")
        if "id" not in item:
            raise ValidationError(f"{field}[{i}].id", "missing required field")
        ident = item["id"]
        if ident in seen:
            raise ValidationError(f"{field}[{i}].id", f"duplicate id {ident!r}")
        seen.add(ident)


def validate_case(raw):
    """Validate a raw decoded case document and return it unchanged."""
    require_type(raw, dict, "$")
    for key in ("as_of", "taps", "policy", "candidates", "requirements", "scenarios"):
        if key not in raw:
            raise ValidationError(f"$.{key}", "missing required field")

    require_time(raw["as_of"], "$.as_of")

    taps = require_type(raw["taps"], list, "$.taps")
    tap_ids, groups, switches = _validate_taps(taps)

    actions = require_type(raw["candidates"], list, "$.candidates")
    if len(actions) > LIMITS["actions"]:
        raise ValidationError("$.candidates", f"at most {LIMITS['actions']} actions allowed")
    if not actions:
        raise ValidationError("$.candidates", "at least one candidate action is required")
    _validate_actions(actions, tap_ids)

    policy = require_type(raw["policy"], list, "$.policy")
    if len(policy) > LIMITS["policy_events"]:
        raise ValidationError("$.policy", f"at most {LIMITS['policy_events']} events allowed")
    _validate_policy(policy, tap_ids, actions)

    requirements = require_type(raw["requirements"], list, "$.requirements")
    if len(requirements) > LIMITS["requirements"]:
        raise ValidationError("$.requirements", f"at most {LIMITS['requirements']} requirements allowed")
    _validate_requirements(requirements)

    scenarios = require_type(raw["scenarios"], list, "$.scenarios")
    if not scenarios:
        raise ValidationError("$.scenarios", "at least one scenario is required")
    if len(scenarios) > LIMITS["scenarios"]:
        raise ValidationError("$.scenarios", f"at most {LIMITS['scenarios']} scenarios allowed")
    _validate_scenarios(scenarios, switches)

    return raw


def _validate_taps(taps):
    _unique_ids(taps, "$.taps")
    tap_ids, groups, switches = set(), set(), set()
    for i, tap in enumerate(taps):
        f = f"$.taps[{i}]"
        _require_keys(tap, ("id", "switch", "port_group"), f)
        require_id(tap["id"], f"{f}.id")
        require_type(tap["switch"], str, f"{f}.switch")
        require_type(tap["port_group"], str, f"{f}.port_group")
        tap_ids.add(tap["id"])
        groups.add(tap["port_group"])
        switches.add(tap["switch"])
    return tap_ids, groups, switches


def _validate_actions(actions, tap_ids):
    _unique_ids(actions, "$.candidates")
    total_vis = 0
    for i, action in enumerate(actions):
        f = f"$.candidates[{i}]"
        _require_keys(action, ("id", "tap", "collector", "start", "end", "cost", "visibility"), f)
        require_id(action["id"], f"{f}.id")
        if action["tap"] not in tap_ids:
            raise ValidationError(f"{f}.tap", f"unknown tap {action['tap']!r}")
        require_type(action["collector"], str, f"{f}.collector")
        require_time(action["start"], f"{f}.start")
        require_time(action["end"], f"{f}.end")
        if action["start"] >= action["end"]:
            raise ValidationError(f, f"action start must be < end")
        require_type(action["cost"], "int", f"{f}.cost")
        if action["cost"] < 0:
            raise ValidationError(f"{f}.cost", "cost must be non-negative")
        vis = require_type(action["visibility"], list, f"{f}.visibility")
        if not vis:
            raise ValidationError(f"{f}.visibility", "at least one visibility item is required")
        total_vis += len(vis)
        for j, item in enumerate(vis):
            vf = f"{f}.visibility[{j}]"
            _require_keys(item, ("tenant", "class", "label", "from", "to"), vf)
            require_type(item["tenant"], str, f"{vf}.tenant")
            require_type(item["class"], str, f"{vf}.class")
            require_type(item["label"], str, f"{vf}.label")
            require_time(item["from"], f"{vf}.from")
            require_time(item["to"], f"{vf}.to")
            if item["from"] >= item["to"]:
                raise ValidationError(vf, "visibility interval start must be < end")
            if item["from"] < action["start"] or item["to"] > action["end"]:
                raise ValidationError(vf, "visibility interval must lie within the action interval")
    if total_vis > LIMITS["visibility_items"]:
        raise ValidationError("$.candidates", f"at most {LIMITS['visibility_items']} visibility items allowed")


def _validate_policy(policy, tap_ids, actions):
    collector_ids = {a["collector"] for a in actions}
    last_rev = {}
    revoked = set()
    for i, event in enumerate(policy):
        f = f"$.policy[{i}]"
        _require_keys(event, ("seq", "event"), f)
        require_type(event["seq"], "int", f"{f}.seq")
        if event["seq"] != i + 1:
            raise ValidationError(f"{f}.seq", f"seq must be consecutive from 1, expected {i + 1}")
        kind = event["event"]
        key = require_id(event["key"], f"{f}.key") if "key" in event else None
        if kind == "grant":
            _require_keys(
                event,
                ("key", "revision", "tap", "collector", "tenant", "class", "label", "from", "to"),
                f,
            )
            require_type(event["revision"], "int", f"{f}.revision")
            expected = last_rev.get(key, 0) + 1
            if event["revision"] != expected:
                raise ValidationError(
                    f"{f}.revision",
                    f"grant revisions for key {key!r} must start at 1 and increment by 1, "
                    f"expected {expected}",
                )
            last_rev[key] = event["revision"]
            revoked.discard(key)
            if event["tap"] not in tap_ids:
                raise ValidationError(f"{f}.tap", f"unknown tap {event['tap']!r}")
            if event["collector"] not in collector_ids:
                raise ValidationError(f"{f}.collector", f"unknown collector {event['collector']!r}")
            for s in ("tenant", "class", "label"):
                require_type(event[s], str, f"{f}.{s}")
            require_time(event["from"], f"{f}.from")
            require_time(event["to"], f"{f}.to")
            if event["from"] >= event["to"]:
                raise ValidationError(f, "grant interval start must be < end")
        elif kind == "revoke":
            _require_keys(event, ("key", "revision", "effective_at"), f)
            require_type(event["revision"], "int", f"{f}.revision")
            require_time(event["effective_at"], f"{f}.effective_at")
            if key not in last_rev:
                raise ValidationError(f"{f}.key", f"revoke for unknown grant key {key!r}")
            if event["revision"] != last_rev[key]:
                raise ValidationError(
                    f"{f}.revision",
                    f"revoke must point at the latest revision {last_rev[key]} of key {key!r}",
                )
            if key in revoked:
                raise ValidationError(f"{f}.key", f"latest revision of key {key!r} is already revoked")
            revoked.add(key)
        else:
            raise ValidationError(f"{f}.event", f"unknown policy event {kind!r}")


def _validate_requirements(requirements):
    _unique_ids(requirements, "$.requirements")
    for i, req in enumerate(requirements):
        f = f"$.requirements[{i}]"
        _require_keys(req, ("id", "tenant", "class", "from", "to", "min_collectors"), f)
        require_id(req["id"], f"{f}.id")
        require_type(req["tenant"], str, f"{f}.tenant")
        require_type(req["class"], str, f"{f}.class")
        require_time(req["from"], f"{f}.from")
        require_time(req["to"], f"{f}.to")
        if req["from"] >= req["to"]:
            raise ValidationError(f, "requirement interval start must be < end")
        require_type(req["min_collectors"], "int", f"{f}.min_collectors")
        if not 1 <= req["min_collectors"] <= 3:
            raise ValidationError(f"{f}.min_collectors", "min_collectors must be in [1, 3]")


def _validate_scenarios(scenarios, switches):
    _unique_ids(scenarios, "$.scenarios")
    base_seen = False
    for i, scn in enumerate(scenarios):
        f = f"$.scenarios[{i}]"
        _require_keys(scn, ("id", "switch_failures", "collector_failures"), f)
        require_id(scn["id"], f"{f}.id")
        if scn["id"] == "base":
            base_seen = True
            if scn["switch_failures"] or scn["collector_failures"]:
                raise ValidationError(f, "the base scenario must have empty failure lists")
        for j, fail in enumerate(scn["switch_failures"]):
            sf = f"{f}.switch_failures[{j}]"
            _require_keys(fail, ("device", "from", "to"), sf)
            require_type(fail["device"], str, f"{sf}.device")
            require_time(fail["from"], f"{sf}.from")
            require_time(fail["to"], f"{sf}.to")
            if fail["from"] >= fail["to"]:
                raise ValidationError(sf, "failure interval start must be < end")
        for j, fail in enumerate(scn["collector_failures"]):
            cf = f"{f}.collector_failures[{j}]"
            _require_keys(fail, ("device", "from", "to"), cf)
            require_type(fail["device"], str, f"{cf}.device")
            require_time(fail["from"], f"{cf}.from")
            require_time(fail["to"], f"{cf}.to")
            if fail["from"] >= fail["to"]:
                raise ValidationError(cf, "failure interval start must be < end")
    if not base_seen:
        raise ValidationError("$.scenarios", "a scenario with id 'base' and empty failure lists is required")


def validate_plan(raw):
    """Validate the structural envelope of a PLAN document."""
    require_type(raw, dict, "$")
    if "selected_ids" not in raw:
        raise ValidationError("$.selected_ids", "missing required field")
    if "plan_digest" not in raw:
        raise ValidationError("$.plan_digest", "missing required field")
    require_type(raw["selected_ids"], list, "$.selected_ids")
    require_type(raw["plan_digest"], str, "$.plan_digest")
    seen = set()
    for i, ident in enumerate(raw["selected_ids"]):
        f = f"$.selected_ids[{i}]"
        require_id(ident, f)
        if ident in seen:
            raise ValidationError(f, f"duplicate action id {ident!r}")
        seen.add(ident)
    return raw
