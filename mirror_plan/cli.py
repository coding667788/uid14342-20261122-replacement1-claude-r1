"""Command line entry point.

stdout always carries exactly one UTF-8 JSON document.
Exit codes: 0 success / legal-infeasible, 2 structural/field errors,
3 audit failures, record conflicts or missing history versions.
"""

import argparse
import datetime
import json
import sqlite3
import sys

from .errors import AuditFailure, StoreError, ValidationError
from .planner import audit_plan, build_plan
from .store import history, record
from .validation import validate_case, validate_plan


def _emit(payload, stream=sys.stdout):
    stream.write(json.dumps(payload, ensure_ascii=False, indent=2))
    stream.write("\n")


def _load_json(path, kind):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise ValidationError(path, f"{kind} file not found")
    except json.JSONDecodeError as exc:
        raise ValidationError(path, f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}")


def _cmd_plan(args):
    raw = _load_json(args.case, "case")
    validate_case(raw)
    _emit(build_plan(raw))
    return 0


def _cmd_audit(args):
    case = _load_json(args.case, "case")
    validate_case(case)
    plan = _load_json(args.plan, "plan")
    validate_plan(plan)
    try:
        result = audit_plan(case, plan)
    except AuditFailure as exc:
        _emit({"status": "infeasible", "reason": exc.reason, "detail": exc.detail})
        return 3
    _emit(result)
    return 0


def _cmd_record(args):
    case = _load_json(args.case, "case")
    validate_case(case)
    plan = _load_json(args.plan, "plan")
    validate_plan(plan)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        outcome = record(case, plan, args.db, args.request_id, args.expected_head, now_iso)
    except AuditFailure as exc:
        _emit({"status": "rejected", "reason": exc.reason, "detail": exc.detail})
        return 3
    except StoreError as exc:
        _emit({"status": "conflict", "reason": exc.code, "detail": exc.message})
        return 3
    _emit(
        {
            "status": "replayed" if outcome["replayed"] else "committed",
            "commit_no": outcome["commit_no"],
            "receipt": outcome["receipt"],
        }
    )
    return 0


def _cmd_history(args):
    try:
        result = history(args.db, args.commit)
    except StoreError as exc:
        _emit({"status": "not_found", "reason": exc.code, "detail": exc.message})
        return 3
    _emit(result)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="mirror_plan", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="compute an optimal mirroring plan")
    p_plan.add_argument("case")
    p_plan.set_defaults(func=_cmd_plan)

    p_audit = sub.add_parser("audit", help="recompute and audit a plan")
    p_audit.add_argument("case")
    p_audit.add_argument("plan")
    p_audit.set_defaults(func=_cmd_audit)

    p_record = sub.add_parser("record", help="transactionally persist an audited plan")
    p_record.add_argument("case")
    p_record.add_argument("plan")
    p_record.add_argument("--db", required=True)
    p_record.add_argument("--request-id", required=True)
    p_record.add_argument("--expected-head", required=True, type=int)
    p_record.set_defaults(func=_cmd_record)

    p_history = sub.add_parser("history", help="read a frozen commit and its evidence")
    p_history.add_argument("--db", required=True)
    p_history.add_argument("--commit", required=True, type=int)
    p_history.set_defaults(func=_cmd_history)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValidationError as exc:
        _emit({"status": "error", "reason": "validation", "field": exc.field, "detail": exc.message})
        return 2
    except (AuditFailure, StoreError) as exc:
        reason = getattr(exc, "reason", getattr(exc, "code", "error"))
        _emit({"status": "error", "reason": reason, "detail": str(exc)})
        return 3
    except (OSError, sqlite3.Error) as exc:
        _emit({"status": "error", "reason": "storage", "detail": str(exc)})
        return 3


if __name__ == "__main__":
    sys.exit(main())
