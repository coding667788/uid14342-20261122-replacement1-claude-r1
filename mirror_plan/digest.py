"""Deterministic canonical JSON and plan digests.

Canonical form uses ``ensure_ascii=False, sort_keys=True,
separators=(",", ":")`` encoded as UTF-8. Lists without order semantics are
sorted by each object's ``id`` or, when the objects have none, by the tuple of
all fields. The ``policy`` list keeps its input ``seq`` order. Whitespace,
field order and candidate order therefore never change the digest.
"""

import hashlib
import json


def _sort_key(value):
    # json.dumps gives a stable, type-homogeneous textual key inside every list.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonicalize(node, in_policy=False):
    if isinstance(node, dict):
        return {key: canonicalize(value, in_policy or key == "policy") for key, value in node.items()}
    if isinstance(node, list):
        rendered = [canonicalize(item, in_policy) for item in node]
        if in_policy:
            return rendered
        return sorted(rendered, key=_sort_key)
    return node


def canonical_json(node):
    """Return the canonical UTF-8 bytes for a JSON-compatible document."""
    canonical = canonicalize(node)
    text = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")


def digest_object(case, selected_ids):
    """Build the object that is hashed for a plan digest."""
    return {"case": canonicalize(case), "selected_ids": sorted(selected_ids)}


def plan_digest(case, selected_ids):
    payload = canonical_json(digest_object(case, selected_ids))
    return "sha256:" + hashlib.sha256(payload).hexdigest()
