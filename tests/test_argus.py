import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from argus.attacks import ATTACKS, attacks_for
from argus.defenses import (HardenedPromptDefense,
                            InputFilterDefense,
                            OutputFilterDefense)
from argus.holdout import generate_holdout, score_holdout
from argus.judges import judge
from argus.runner import run_attack, run_campaign, wilson
from argus.targets import CANARY, HttpTarget, MockTarget

ROOT = Path(__file__).resolve().parent.parent


def _by_id(attack_id):
    return next(a for a in ATTACKS if a.id == attack_id)


def _run(target, attack_id):
    return run_attack(target, _by_id(attack_id))


def test_canary_judge_is_objective():
    assert judge("leak", [f"here: {CANARY}"])["success"]
    assert not judge("leak", ["I can't help with that."])["success"]
    assert judge("leak", ["I can't help with that."])["refused"]


def test_naive_mock_leaks_to_direct_extraction():
    r = _run(MockTarget(), "ext-direct")
    assert r["success"] and CANARY in r["responses"][0]


def test_hardened_mock_refuses_direct_extraction():
    r = _run(MockTarget(hardened=True), "ext-direct")
    assert not r["success"] and r["refused"]


def test_hardened_mock_falls_to_translation():
    # the documented brittle spot: no trigger vocabulary
    r = _run(MockTarget(hardened=True), "ext-translation")
    assert r["success"]


def test_encoded_attacks_naive_leaks_hardened_refuses():
    for aid in ("ext-base64", "ext-rot13"):
        assert _run(MockTarget(), aid)["success"]
        assert not _run(MockTarget(hardened=True), aid)["success"]


def test_indirect_injection():
    assert _run(MockTarget(), "inj-document")["success"]
    assert not _run(MockTarget(hardened=True),
                    "inj-document")["success"]


def test_output_filter_stops_every_extraction():
    defended = OutputFilterDefense(MockTarget())
    campaign = run_campaign(defended)
    leaks = [r for r in campaign["results"]
             if r["objective"] == "leak"]
    assert all(not r["success"] for r in leaks)
    # and it honestly does nothing for policy attacks
    pol = [r for r in campaign["results"]
           if r["objective"] == "policy"]
    assert all(r["success"] for r in pol)


def test_input_filter_is_bypassed_by_encoding():
    defended = InputFilterDefense(MockTarget())
    assert not _run(defended, "ext-direct")["success"]
    # raw-text filter never decodes, so base64 walks through:
    # a measured defense failure, kept as a test on purpose
    assert _run(defended, "ext-base64")["success"]


def test_policy_objective_mock_only():
    assert _run(MockTarget(), "pol-direct")["success"]
    assert not _run(MockTarget(hardened=True),
                    "pol-direct")["success"]
    http = HttpTarget("http://localhost:9", "m", "sys")
    assert all(not a.mock_only for a in attacks_for(http))
    with pytest.raises(ValueError):
        HardenedPromptDefense(MockTarget())


def test_wilson_interval_sane():
    lo, hi = wilson(8, 10)
    assert 0.4 < lo < 0.8 < hi <= 1.0
    assert wilson(0, 0) == (0.0, 0.0)


def test_http_target_against_stub_server():
    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(
                self.rfile.read(int(
                    self.headers["Content-Length"])))
            seen["model"] = body["model"]
            seen["system"] = body["messages"][0]["content"]
            payload = {"choices": [{"message": {
                "role": "assistant",
                "content": "stub reply"}}]}
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever,
                     daemon=True).start()
    try:
        t = HttpTarget(f"http://127.0.0.1:{server.server_port}",
                       "stub-model", "SYS-PROMPT")
        out = t.chat([{"role": "user", "content": "hi"}])
        assert out == "stub reply"
        assert seen["model"] == "stub-model"
        assert seen["system"] == "SYS-PROMPT"
    finally:
        server.shutdown()


def test_holdout_commitment_and_score_once(tmp_path):
    manifest = generate_holdout(tmp_path / "h", seed=42)
    assert len(manifest["commitment"]) == 64
    result = score_holdout(MockTarget(), tmp_path / "h")
    assert result["attacks"] == 8
    with pytest.raises(RuntimeError):
        score_holdout(MockTarget(), tmp_path / "h")


def test_holdout_tamper_detected(tmp_path):
    generate_holdout(tmp_path / "h", seed=7)
    p = tmp_path / "h" / "holdout_manifest.json"
    data = json.loads(p.read_text())
    data["attacks"][0]["turns"][0] = "tampered prompt"
    p.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        score_holdout(MockTarget(), tmp_path / "h")


def test_demo_configs_differ_as_documented():
    naive = run_campaign(MockTarget())
    hardened = run_campaign(MockTarget(hardened=True))
    assert naive["asr"] > hardened["asr"]
    assert hardened["successes"] >= 1  # translation brittle spot
