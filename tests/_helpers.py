"""Shared test fixtures and tiny hand-built cases."""

import copy
import json
import os
import sys
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def base_case():
    """A small fully feasible case used across the test suite.

    r1 needs two distinct collectors across [0, 900). Three collectors serve
    voice, each through its own tap/port group, so the c2 outage in scn_c2
    still leaves c1 and c3. r2 needs one collector for bulk on c3.
    """
    return {
        "as_of": 6,
        "taps": [
            {"id": "tap1", "switch": "sw1", "port_group": "pg1"},
            {"id": "tap2", "switch": "sw2", "port_group": "pg2"},
            {"id": "tap3", "switch": "sw3", "port_group": "pg3"},
            {"id": "tap4", "switch": "sw4", "port_group": "pg4"},
        ],
        "policy": [
            {"seq": 1, "event": "grant", "key": "ka", "revision": 1,
             "tap": "tap1", "collector": "c1", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 1000},
            {"seq": 2, "event": "grant", "key": "kb", "revision": 1,
             "tap": "tap2", "collector": "c2", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 1000},
            {"seq": 3, "event": "grant", "key": "kc", "revision": 1,
             "tap": "tap3", "collector": "c3", "tenant": "tnb", "class": "bulk",
             "label": "M", "from": 0, "to": 1000},
            {"seq": 4, "event": "grant", "key": "kd", "revision": 1,
             "tap": "tap1", "collector": "c1", "tenant": "tna", "class": "ops",
             "label": "O", "from": 0, "to": 1000},
            {"seq": 5, "event": "revoke", "key": "kd", "revision": 1,
             "effective_at": 400},
            {"seq": 6, "event": "grant", "key": "ke", "revision": 1,
             "tap": "tap4", "collector": "c3", "tenant": "tna", "class": "voice",
             "label": "L", "from": 0, "to": 1000},
        ],
        "candidates": [
            {"id": "a1", "tap": "tap1", "collector": "c1", "start": 0, "end": 500,
             "cost": 3,
             "visibility": [{"tenant": "tna", "class": "voice", "label": "L",
                             "from": 0, "to": 500}]},
            {"id": "a2", "tap": "tap2", "collector": "c2", "start": 0, "end": 500,
             "cost": 2,
             "visibility": [{"tenant": "tna", "class": "voice", "label": "L",
                             "from": 0, "to": 500}]},
            {"id": "a3", "tap": "tap3", "collector": "c3", "start": 0, "end": 500,
             "cost": 1,
             "visibility": [{"tenant": "tnb", "class": "bulk", "label": "M",
                             "from": 0, "to": 500}]},
            {"id": "a4", "tap": "tap1", "collector": "c1", "start": 500, "end": 900,
             "cost": 4,
             "visibility": [{"tenant": "tna", "class": "voice", "label": "L",
                             "from": 500, "to": 900}]},
            {"id": "a5", "tap": "tap2", "collector": "c2", "start": 500, "end": 900,
             "cost": 5,
             "visibility": [{"tenant": "tna", "class": "voice", "label": "L",
                             "from": 500, "to": 900}]},
            {"id": "a6", "tap": "tap1", "collector": "c1", "start": 0, "end": 300,
             "cost": 1,
             "visibility": [{"tenant": "tna", "class": "ops", "label": "O",
                             "from": 0, "to": 300}]},
            {"id": "a7", "tap": "tap4", "collector": "c3", "start": 0, "end": 900,
             "cost": 6,
             "visibility": [{"tenant": "tna", "class": "voice", "label": "L",
                             "from": 0, "to": 900}]},
        ],
        "requirements": [
            {"id": "r1", "tenant": "tna", "class": "voice", "from": 0, "to": 900,
             "min_collectors": 2},
            {"id": "r2", "tenant": "tnb", "class": "bulk", "from": 0, "to": 500,
             "min_collectors": 1},
        ],
        "scenarios": [
            {"id": "base", "switch_failures": [], "collector_failures": []},
            {"id": "scn_c2",
             "switch_failures": [],
             "collector_failures": [{"device": "c2", "from": 900, "to": 950}]},
        ],
    }


class TempRepoCase(unittest.TestCase):
    """Base class providing an isolated working directory and CLI helpers."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write_json(self, name, doc):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, ensure_ascii=False)
        return path

    def run_cli(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "mirror_plan", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else None
        except json.JSONDecodeError:
            payload = None
        return proc.returncode, payload, proc.stderr

    def clone(self, doc):
        return copy.deepcopy(doc)
