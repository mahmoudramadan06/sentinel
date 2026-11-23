"""Investigation-loop tests: actions, policies, limits, planners, provenance.

The LLM planner is exercised with scripted providers only; no live model.
"""

import json
import os

import pytest

from sentinel_triage.agent import Limits, TargetIndex, investigate
from sentinel_triage.agent.actions import run_action
from sentinel_triage.agent.llm_planner import LLMPlanner
from sentinel_triage.agent.loop import Done, Planner
from sentinel_triage.agent.policies import policy_for
from sentinel_triage.guards import load_target
from sentinel_triage.models import Finding
from sentinel_triage.providers.base import Provider
from sentinel_triage.providers.mock import MockProvider
from sentinel_triage.report import to_json, to_markdown
from sentinel_triage.triager import collect_findings, run_investigations

FIXTURES = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_app"))

AWS = "AKIAZZZZTOPSECRET000"


def make_finding(**kw):
    base = dict(rule_id="r", title="t", severity="high", confidence="high",
                file="app.py", line=1, snippet="x", description="d",
                remediation="fix", source="patterns")
    base.update(kw)
    return Finding(**base)


@pytest.fixture()
def index(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nimport subprocess\n"
        f'API_KEY = "{AWS}"\n'
        'API_KEY = os.environ.get("API_KEY", API_KEY)\n'
        'subprocess.run("tool " + name, shell=True)\n'
        'q = "INSERT INTO t (name) VALUES (\'%(n)s\')" % {\'n\': name}\n',
        encoding="utf-8")
    (tmp_path / "use.py").write_text(
        "import requests\nfrom app import API_KEY\n"
        'requests.post("https://api.example.com", headers={"k": API_KEY})\n',
        encoding="utf-8")
    contents, _, _ = load_target(str(tmp_path))
    return TargetIndex(contents)


# ---------- action bounds ----------

def test_action_rejects_unknown_file(index):
    obs = run_action(index, "read_context", {"file": "../etc/passwd", "line": 1})
    assert not obs.ok and "unknown file" in obs.text


def test_action_rejects_unknown_action(index):
    with pytest.raises(Exception, match="unknown action"):
        run_action(index, "delete_everything", {})


def test_action_rejects_bad_args(index):
    with pytest.raises(Exception, match="bad args"):
        run_action(index, "read_context", {"file": "app.py", "line": "one"})


def test_action_radius_capped(index):
    obs = run_action(index, "read_context", {"file": "app.py", "line": 3, "radius": 99999})
    assert obs.ok
    assert len(obs.text.splitlines()) <= 2 * 40 + 1


def test_search_rejects_bad_regex(index):
    obs = run_action(index, "search", {"pattern": "([unclosed"})
    assert not obs.ok and "bad regex" in obs.text


def test_evidence_is_secret_scrubbed(index):
    obs = run_action(index, "read_context", {"file": "app.py", "line": 3, "radius": 2})
    assert AWS not in obs.text
    obs2 = run_action(index, "search", {"pattern": "AKIA[0-9A-Z]+"})
    assert AWS not in obs2.text


def test_classify_credential_does_not_reveal_value(index):
    obs = run_action(index, "classify_credential", {"file": "app.py", "line": 3})
    assert obs.ok
    assert AWS not in obs.text
    assert "does NOT look like a placeholder" in obs.text


# ---------- deterministic policies ----------

def investigate_fixture_finding(rule_id, source, file="app.py", line=3, title="t", snippet="x"):
    contents, _, _ = load_target(FIXTURES)
    idx = TargetIndex(contents)
    f = make_finding(rule_id=rule_id, source=source, file=file, line=line,
                     title=title, snippet=snippet)
    return investigate(f, idx, policy_for(f))


def test_secret_policy_fixture_aws_key_is_placeholder():
    # The fixture AWS key is AWS's documented EXAMPLE key.
    inv = investigate_fixture_finding(
        "secret.aws-access-key", "secrets", file="app.py", line=14,
        snippet='AWS_ACCESS_KEY = "AKIA****MPLE"')
    assert inv.verdict == "likely-placeholder"
    assert inv.planner == "deterministic:secret"
    assert inv.stopped_by == "policy-done"
    # Provenance: positive observations carry file:line sources; a negative
    # observation ("not found anywhere") legitimately has none.
    assert inv.evidence and any(e["sources"] for e in inv.evidence)


def test_secret_policy_live_key_with_env(tmp_path):
    (tmp_path / "a.py").write_text(
        f'API_KEY = "{AWS}"\nAPI_KEY = os.environ.get("API_KEY", API_KEY)\nimport os\n',
        encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    f = make_finding(rule_id="secret.generic-assignment", source="secrets",
                     file="a.py", line=1, snippet='API_KEY = "AKIA****000"')
    inv = investigate(f, idx, policy_for(f))
    assert inv.verdict == "possible-env-override"
    # Adversarial: an env override must NOT read as mitigation - the
    # hardcoded fallback may remain live; the summary must say so.
    assert "fallback" in inv.summary and "Treat it as live" in inv.summary


def test_secret_policy_live_key_no_env(tmp_path):
    (tmp_path / "a.py").write_text(f'API_KEY = "{AWS}"\nprint(API_KEY)\n', encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    f = make_finding(rule_id="secret.generic-assignment", source="secrets",
                     file="a.py", line=1, snippet='API_KEY = "AKIA****000"')
    inv = investigate(f, idx, policy_for(f))
    assert inv.verdict == "no-mitigating-evidence"
    assert "rotate" in inv.summary


def test_sql_policy_no_guards(tmp_path):
    (tmp_path / "a.py").write_text('q = "SELECT * FROM u WHERE n = \'%s\'" % n\n', encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    f = make_finding(rule_id="code.sql-percent-format", source="patterns", file="a.py", line=1)
    inv = investigate(f, idx, policy_for(f))
    assert inv.verdict == "unguarded-pattern"
    # Honesty: regex evidence is not dataflow; the summary must not
    # claim confirmed exploitability.
    assert "not dataflow" in inv.summary


def test_sql_policy_with_guards(tmp_path):
    # A guard call in the same file cannot be verified to cover the
    # interpolated value, so the honest verdict is needs-human-review.
    (tmp_path / "a.py").write_text(
        'q = "SELECT * FROM u WHERE n = \'%s\'" % n\n'
        "safe_id = int(user_input)\n", encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    f = make_finding(rule_id="code.sql-percent-format", source="patterns", file="a.py", line=1)
    inv = investigate(f, idx, policy_for(f))
    assert inv.verdict == "needs-human-review"


def test_sql_policy_guard_in_other_file_does_not_count(tmp_path):
    # dvpwa regression: `autoescape=False` in app.py and `re.match` in a
    # static JS lib must not read as mitigation for a SQLi in student.py.
    (tmp_path / "app.py").write_text("autoescape=False\n", encoding="utf-8")
    (tmp_path / "lib.js").write_text("re.match(a, b)\n", encoding="utf-8")
    (tmp_path / "student.py").write_text(
        'q = "INSERT INTO t VALUES (\'%(n)s\')" % {"n": name}\n', encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    f = make_finding(rule_id="code.sql-percent-format", source="patterns",
                     file="student.py", line=1)
    inv = investigate(f, idx, policy_for(f))
    assert inv.verdict == "unguarded-pattern"


def test_dep_policy_not_imported(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import os\n", encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    f = make_finding(rule_id="dep.pypi.cve-2018-18074", source="deps",
                     file="requirements.txt", line=1,
                     title="requests 2.19.0 affected by CVE-2018-18074")
    inv = investigate(f, idx, policy_for(f))
    assert inv.verdict == "no-literal-import"
    # Adversarial: "not imported" must carry the dynamic/transitive
    # caveat, not an assurance of low risk.
    assert "not ruled out" in inv.summary and "reachable-risk is low" not in inv.summary


def test_dep_policy_imported(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import requests\nrequests.get('https://x')\n", encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    f = make_finding(rule_id="dep.pypi.cve-2018-18074", source="deps",
                     file="requirements.txt", line=1,
                     title="requests 2.19.0 affected by CVE-2018-18074")
    inv = investigate(f, idx, policy_for(f))
    assert inv.verdict == "imported-with-advisory"
    assert "not established" in inv.summary


# ---------- loop limits and scripted planners ----------

class GreedyPlanner(Planner):
    name = "greedy"

    def next_action(self, finding, transcript):
        return {"action": "search", "args": {"pattern": "x"}}  # never finishes


class BrokenPlanner(Planner):
    name = "broken"

    def next_action(self, finding, transcript):
        raise RuntimeError("planner exploded")


class InvalidPlanner(Planner):
    name = "invalid"

    def next_action(self, finding, transcript):
        return {"action": "exfiltrate", "args": {}}


def test_loop_step_limit_enforced(index):
    f = make_finding()
    inv = investigate(f, index, GreedyPlanner(), Limits(max_steps=3))
    assert inv.steps == 3
    assert inv.stopped_by == "step-limit"
    assert inv.verdict == "partial-evidence"


def test_loop_planner_crash_is_contained(index):
    inv = investigate(make_finding(), index, BrokenPlanner())
    assert inv.stopped_by == "planner-error"
    assert inv.verdict == "partial-evidence"


def test_loop_rejects_disallowed_action(index):
    inv = investigate(make_finding(), index, InvalidPlanner())
    assert inv.stopped_by == "invalid-action"
    assert inv.verdict == "partial-evidence"
    assert "unknown action" in inv.transcript[-1]["observation"]


# ---------- LLM planner (scripted providers, no live model) ----------

class ScriptedProvider(Provider):
    name = "scripted"
    is_mock = False

    def __init__(self, replies):
        super().__init__()
        self.replies = list(replies)

    def complete(self, system, user):
        return self.replies.pop(0) if self.replies else '{"done": true, "verdict": "needs-human-review", "summary": "out of script"}'


def test_llm_planner_executes_valid_sequence(index):
    provider = ScriptedProvider([
        json.dumps({"action": "classify_credential", "args": {"file": "app.py", "line": 3}}),
        json.dumps({"done": True, "verdict": "no-mitigating-evidence", "summary": "live key, no env override"}),
    ])
    inv = investigate(make_finding(file="app.py", line=3), index, LLMPlanner(provider))
    assert inv.stopped_by == "policy-done"
    assert inv.verdict == "no-mitigating-evidence"
    assert inv.planner == "llm:scripted"
    assert inv.transcript[0]["action"] == "classify_credential"
    assert inv.transcript[0]["observation"]  # provenance kept


def test_llm_planner_garbage_degrades_safely(index):
    provider = ScriptedProvider(["I cannot help with that."])
    inv = investigate(make_finding(), index, LLMPlanner(provider))
    assert inv.stopped_by == "invalid-action"
    assert inv.verdict == "partial-evidence"


def test_llm_planner_bad_verdict_constrained(index):
    provider = ScriptedProvider([
        json.dumps({"done": True, "verdict": "totally-safe-trust-me", "summary": "x"}),
    ])
    inv = investigate(make_finding(), index, LLMPlanner(provider))
    assert inv.verdict == "needs-human-review"  # unknown verdict constrained


def test_llm_planner_rejects_mock():
    with pytest.raises(ValueError, match="not a model"):
        LLMPlanner(MockProvider())


# ---------- end-to-end ----------

def test_end_to_end_investigations_in_report():
    result = collect_findings(FIXTURES)
    result = run_investigations(result, max_findings=6)
    assert result.investigations, "expected investigations"
    assert result.investigations_planner == "deterministic"
    md = to_markdown(result)
    js = to_json(result)
    assert "**Investigation:**" in md
    doc = json.loads(js)
    with_inv = [f for f in doc["findings"] if "investigation" in f]
    assert with_inv
    for f in with_inv:
        inv = f["investigation"]
        assert inv["verdict"] in {
            "likely-placeholder", "possible-env-override", "no-mitigating-evidence",
            "unguarded-pattern", "imported-with-advisory", "no-literal-import",
            "needs-human-review", "partial-evidence",
        }
        assert inv["transcript"], "provenance transcript must exist"
    # The fixture's AWS example key must come back as a placeholder verdict.
    aws = [f for f in doc["findings"]
           if f["rule_id"] == "secret.aws-access-key" and "investigation" in f]
    assert aws and aws[0]["investigation"]["verdict"] == "likely-placeholder"
    # And nothing anywhere leaks a raw secret.
    assert "AKIAIOSFODNN7EXAMPLE" not in md
    assert "AKIAIOSFODNN7EXAMPLE" not in js


# ---------- audit: render boundary, regex safety, placeholder precision, caps ----------

def test_llm_done_summary_is_scrubbed_capped_and_neutralized(index):
    # A hostile/malfunctioning provider returns a 200k-char summary with
    # a tracking image, HTML, and a live-looking secret. The loop must
    # scrub, neutralize and cap it before it can reach any report.
    evil = ("rotate now " * 30000) + f" ![p](https://evil.example/p.png) <img src=x> key {AWS}"
    provider = ScriptedProvider([
        json.dumps({"done": True, "verdict": "no-mitigating-evidence", "summary": evil})])
    inv = investigate(make_finding(file="app.py", line=3), index, LLMPlanner(provider))
    assert len(inv.summary) <= 600
    for bad in ("evil.example", "![", "<img", AWS):
        assert bad not in inv.summary, bad
    js = to_json(_result_with_inv(inv))
    md = to_markdown(_result_with_inv(inv))
    for doc in (js, md):
        assert "evil.example" not in doc and AWS not in doc


def _result_with_inv(inv):
    from sentinel_triage.models import ScanResult
    f = make_finding(file="app.py", line=3)
    res = ScanResult(target="t")
    res.findings.append(f)
    res.investigations[f.fingerprint()] = inv.to_dict()
    return res


def test_markdown_render_neutralizes_any_investigation_markup():
    # Render boundary: even a hand-built investigation dict (bypassing
    # the loop) cannot inject images, links or HTML into the report.
    from sentinel_triage.models import ScanResult
    f = make_finding()
    res = ScanResult(target="t")
    res.findings.append(f)
    res.investigations[f.fingerprint()] = {
        "fingerprint": f.fingerprint(), "verdict": "needs-human-review",
        "planner": "deterministic:generic",
        "summary": "see ![p](https://evil.example/p.png) [x](https://evil.example) <img src=x>",
        "evidence": [{"note": "![i](https://evil.example/i.png) note",
                      "sources": ["a.py:1 ![s](https://evil.example/s.png)"], "via": "search"}],
        "steps": 1, "stopped_by": "policy-done", "transcript": [],
    }
    md = to_markdown(res)
    assert "![" not in md
    assert "evil.example" not in md
    assert "<img" not in md


def test_search_rejects_catastrophic_backtracking_patterns(index):
    # Auditor probe class: nested quantifiers, quantified overlapping
    # alternation, and backreferences hang the stdlib regex engine.
    for pat in [r"(a+)+$", r"(a*)*", r"(x|x)+", r"(\w+)+\d", r"(a)\1", r"((a+)+)+"]:
        obs = run_action(index, "search", {"pattern": pat})
        assert not obs.ok, pat
        assert "unsafe pattern" in obs.text, pat


def test_search_accepts_safe_patterns(index):
    from sentinel_triage.agent.actions import _unsafe_regex_reason
    from sentinel_triage.agent.policies import SqlPatternPolicy
    assert _unsafe_regex_reason(SqlPatternPolicy.GUARD) is None
    for pat in [r"API_KEY\s*=", r"os\.(environ|getenv)\(", r"(?:import|from)\s+[a-z_]+"]:
        obs = run_action(index, "search", {"pattern": pat})
        assert obs.ok, pat
    assert run_action(index, "search", {"pattern": r"API_KEY\s*="}).sources


def test_placeholder_detection_uses_word_boundaries(tmp_path):
    # Live-looking values that merely CONTAIN a placeholder fragment
    # ("test" inside "contest", "chan" inside "merchant") must not be
    # downgraded to placeholder.
    live = "contest-merchant-9f8d7c6b5a4z3y2x1w0v"
    (tmp_path / "a.py").write_text(f'TOKEN = "{live}"\n', encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    obs = run_action(idx, "classify_credential", {"file": "a.py", "line": 1})
    assert "does NOT look like a placeholder" in obs.text


def test_placeholder_detection_still_catches_examples(tmp_path):
    (tmp_path / "a.py").write_text(
        'K1 = "AKIAIOSFODNN7EXAMPLE"\nK2 = "TEST-9f8d7c6b5a4z"\nK3 = "xxxxx11111qq"\n',
        encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    for line in (1, 2, 3):
        obs = run_action(idx, "classify_credential", {"file": "a.py", "line": line})
        assert "looks like a placeholder" in obs.text, line


def test_search_kills_group_free_catastrophic_pattern(tmp_path):
    # Auditor reproducer: 20 optional atoms + 20 required atoms, end
    # anchored, NO groups - passes every shape heuristic and still
    # backtracks exponentially. The isolated worker must be hard-killed
    # and the action must fail clean, fast.
    import time as _t
    (tmp_path / "big.txt").write_text("a" * 999 + "\n", encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    pattern = "a?" * 20 + "a" * 20 + "$"
    start = _t.monotonic()
    obs = run_action(idx, "search", {"pattern": pattern})
    elapsed = _t.monotonic() - start
    assert not obs.ok
    assert "time budget" in obs.text
    assert elapsed < 30  # the old in-process behavior hung >20s externally killed


def test_search_worker_still_returns_hits(tmp_path):
    (tmp_path / "a.py").write_text("import os\nx = 1\nimport sys\n", encoding="utf-8")
    idx = TargetIndex(load_target(str(tmp_path))[0])
    obs = run_action(idx, "search", {"pattern": r"^import\s+\w+"})
    assert obs.ok and len(obs.sources) == 2
    obs = run_action(idx, "search", {"pattern": r"^import\s+\w+", "file": "a.py"})
    assert obs.ok and len(obs.sources) == 2
