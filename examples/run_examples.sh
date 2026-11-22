#!/usr/bin/env bash
# Reproducible end-to-end demo using only the standard library and SQLite.
# Run from the repository root: bash examples/run_examples.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
WORK="examples/output"
mkdir -p "$WORK"

echo "== 1. generate the scale case (26 actions / 6 scenarios / 24 requirements) =="
python examples/generate_scale_case.py "$WORK/scale_case.json"

echo "== 2. plan the small feasible case =="
python -m mirror_plan plan examples/small_case.json > "$WORK/small_plan.json"
cat "$WORK/small_plan.json"

echo "== 3. recompute and audit that plan (no trust in self-reported evidence) =="
python -m mirror_plan audit examples/small_case.json "$WORK/small_plan.json"

echo "== 4. plan the infeasible case and print its minimal conflict set =="
python -m mirror_plan plan examples/infeasible_case.json

echo "== 5. solve the scale case exactly =="
python -m mirror_plan plan "$WORK/scale_case.json" > "$WORK/scale_plan.json"
python - "$WORK/scale_plan.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
print({k: doc[k] for k in ("status", "cost", "selected_ids")})
PY

echo "== 6. durable record + history across two process invocations =="
DB="$WORK/audit.sqlite"
rm -f "$DB"
python -m mirror_plan record examples/small_case.json "$WORK/small_plan.json" \
    --db "$DB" --request-id req-001 --expected-head 0
python -m mirror_plan record examples/small_case.json "$WORK/small_plan.json" \
    --db "$DB" --request-id req-001 --expected-head 999
python -m mirror_plan history --db "$DB" --commit 0 \
    | python -c 'import json,sys; d=json.load(sys.stdin); print("history:", d["status"], d["receipt"]["commit_no"])'

echo "all examples finished; artifacts in $WORK"
