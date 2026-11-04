"""The headline numbers in the write-up must match `eval/results.json`.

Written after finding that `docs/SUBMISSION.md` claimed "97 clean,
3 needs review, 4 could not verify" for the 104 benign controls while the stamped evaluation
said 95/3/6 - and while `docs/WEAKPOINTS.md` W3, in the same repository, was titled "6 of 104
benign packages cannot be verified". The prose had been written when the count was 4 and never
revisited after two more packages began timing out.

That is the most damaging kind of error this project can make. Its entire claim is evidentiary
discipline, so a judge who cross-checks two of its own documents and finds them contradicting
each other has found something worse than a wrong number.

These tests read the numbers out of the stamped results and assert the documents agree, so the
next time the eval is re-run the docs either follow or the suite fails. Prose is matched on
whitespace-normalised text, because markdown line wrapping is not meaningful.
"""

import json
import re
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "eval" / "results.json"
ARM = "full"  # the configuration the write-up's headline numbers describe


def normalised(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _split_on(text: str, marker: str) -> tuple[str, str]:
    """Text before the marker's clause, and the ~200 characters after it. Used to check that a
    package is named next to the cause it actually had."""
    at = text.find(marker)
    assert at != -1, f"the write-up no longer contains {marker!r}"
    return text[:at], text[at : at + 200]


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    if not RESULTS.exists():  # pragma: no cover - the file is committed
        pytest.skip("eval/results.json not present")
    return json.loads(RESULTS.read_text(encoding="utf-8"))["rows"]


def benign_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["kind"] == "benign"]


def unverifiable(rows: list[dict]) -> list[dict]:
    return [r for r in benign_rows(rows) if r["outcomes"][ARM] == "Could not verify"]


@pytest.fixture(scope="module")
def benign(rows) -> Counter:
    return Counter(r["outcomes"][ARM] for r in benign_rows(rows))


def test_the_benign_cohort_is_still_104_cases(benign):
    assert sum(benign.values()) == 104


def test_the_submission_states_the_stamped_benign_tally(benign):
    """The sentence that previously disagreed with the table three sections above it."""
    expected = (
        f"{benign['Clean']} verified clean, {benign['Needs review']} needing review, "
        f"{benign['Could not verify']} unverifiable, {benign['Blocked']} blocked"
    )
    assert expected in normalised(ROOT / "docs" / "SUBMISSION.md"), expected


def test_the_submission_states_the_right_number_of_unverifiable_cases(benign):
    text = normalised(ROOT / "docs" / "SUBMISSION.md")
    assert f"{benign['Could not verify']} of the 104 are" in text


def test_the_weakpoints_w3_heading_counts_the_same_cases(benign):
    text = normalised(ROOT / "docs" / "WEAKPOINTS.md")
    assert f"W3 — {benign['Could not verify']} of 104 benign packages cannot be verified" in text


def test_no_benign_package_is_blocked_in_any_arm(rows):
    """The claim the whole write-up leans on. Asserted across every arm, not just `full`,
    because that is how it is stated."""
    for arm in ("rules", "contract", "analysis", "full"):
        blocked = [r["id"] for r in benign_rows(rows) if r["outcomes"][arm] == "Blocked"]
        assert blocked == [], f"{arm}: {blocked}"


def test_every_unverifiable_package_named_in_the_submission_really_is_one(rows, benign):
    """The write-up names all six and splits them by cause - four compile failures and two
    timeouts. Both the membership and the split are checked, since naming the right count with
    the wrong packages would be just as wrong."""
    unverified = {r["id"] for r in unverifiable(rows)}
    assert len(unverified) == benign["Could not verify"]

    text = normalised(ROOT / "docs" / "SUBMISSION.md")
    for name in unverified:
        assert f"`{name}`" in text, f"{name} is unverifiable but the write-up does not name it"

    exited_nonzero = {r["id"] for r in unverifiable(rows) if r["exit_code"] == 1}
    timed_out = {r["id"] for r in unverifiable(rows) if r["status"] == "timeout"}
    assert exited_nonzero | timed_out == unverified, "a third failure cause appeared"

    # Each group must be attributed to the right cause. Checked by locating the clause that
    # states each cause and requiring that group's names inside it, rather than by matching a
    # count - "4" versus "Four" is a prose choice, and a test should not dictate it.
    compile_clause, timeout_clause = _split_on(text, "hit the install timeout")
    for name in exited_nonzero:
        assert f"`{name}`" in compile_clause, f"{name} exits 1, not listed as a compile failure"
    for name in timed_out:
        assert f"`{name}`" in timeout_clause, f"{name} timed out but is not listed as one"


def test_the_attack_cohorts_block_as_claimed(rows):
    """16/16 malicious and 2/2 incident in the full pipeline - the other headline figures."""
    for kind, expected in (("malicious", 16), ("incident", 2)):
        cohort = [r for r in rows if r["kind"] == kind]
        blocked = [r for r in cohort if r["outcomes"][ARM] == "Blocked"]
        assert len(cohort) == expected, f"{kind} cohort changed size"
        assert len(blocked) == expected, f"{kind}: only {len(blocked)} of {expected} blocked"


def test_the_stamped_commit_is_recorded_in_the_results(rows):
    """Every figure above is only meaningful with the commit it was measured at."""
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert re.fullmatch(r"[0-9a-f]{7,40}", data["commit"] or "")
    assert data.get("scored_at")


# --- W4(a): the grounding caveat is mandatory wherever the number is published -------------

GROUNDING_DOCS = (
    "eval/results.md",
    "eval/REPEAT.md",
    "eval/REPEAT_CORE.md",
    "eval/REPEAT_W2.md",
    "eval/README.md",
    "README.md",
    "docs/SUBMISSION.md",
)


@pytest.mark.parametrize("rel", GROUNDING_DOCS)
def test_every_published_grounding_number_carries_its_caveat(rel):
    """W4(a) in docs/WEAKPOINTS.md: "Every place that number appears says what it covers and
    what it does not. Mandatory regardless of anything else - it is a correction, not an
    improvement."

    It was only three-quarters done. The prose documents carried the caveat, but four
    *generated* eval summaries published the figure bare - including `eval/results.md`, which
    is the first file a reviewer checking the numbers would open. The generators now emit the
    caveat (`brain/evidence.py::GROUNDING_CAVEAT`) so a re-run cannot drop it; this test covers
    the committed copies and the hand-written docs, which no generator will fix.

    Matched on the distinguishing phrases rather than the exact string, so rewording the
    caveat for a particular audience does not fail the test while deleting it does.
    """
    text = normalised(ROOT / rel)
    # "452/452" and "452 of 452" are both in use across these documents.
    ratio = r"\b\d+\s*(?:/|of)\s*\d+\b"
    publishes_number = re.search(rf"{ratio}.{{0,80}}claims", text) or re.search(
        rf"claims.{{0,80}}{ratio}", text
    )
    if not publishes_number:
        pytest.skip(f"{rel} no longer publishes a grounding ratio")

    assert "citation discipline" in text, (
        f"{rel} publishes the grounding ratio without saying what it measures; see W4(a)"
    )
    # The connective varies ("not", "not as", "rather than"); the clause is what matters.
    assert re.search(r"(?:not(?: as)?|rather than) total factual accuracy", text), (
        f"{rel} does not say what the grounding ratio excludes; see W4(a)"
    )


# --- the demo script says numbers out loud, so they get the same treatment ----------------
#
# A wrong figure in a document can be corrected after a judge reads it. A wrong figure spoken
# on camera cannot. The script had claimed "nothing benign hard-blocked" of the 500-package
# sweep while eval/SWEEP500.md's own table recorded "Blocked 1/421" - the same kind of
# self-contradiction that test_the_submission_states_the_stamped_benign_tally exists to stop,
# in the one artefact nobody can edit afterwards.

SCRIPT = ROOT / "demo" / "DEMO_SCRIPT.md"


def _sweep_rows(name: str) -> list[dict]:
    path = ROOT / "eval" / name
    if not path.exists():  # pragma: no cover - committed
        pytest.skip(f"eval/{name} not present")
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["rows"] if isinstance(data, dict) else data


def test_the_demo_script_does_not_claim_the_500_sweep_had_no_benign_blocks():
    """The corpus is unlabelled and one package was blocked, so neither "no false positives"
    nor "nothing benign blocked" is supportable about it."""
    rows = _sweep_rows("SWEEP500.json")
    blocked = [r for r in rows if r.get("verdict") == "Blocked"]
    assert len(blocked) == 1, "if the sweep changed, this guard needs rewriting"

    text = normalised(SCRIPT).lower()
    # The script also *forbids* these phrases in its own pre-flight notes, so a bare substring
    # search matches the prohibition and fails on the very text that prevents the mistake.
    # Only an occurrence that is not introduced by a "do not say"-style warning is a claim.
    allowed_before = ("do not say", "don't say", "never say", "avoid saying", "not going to")
    for forbidden in ("nothing benign hard-blocked", "zero false positives",
                      "no false positives", "nothing benign blocked"):  # fmt: skip
        for at in (m.start() for m in re.finditer(re.escape(forbidden), text)):
            context = text[max(0, at - 60) : at]
            assert any(w in context for w in allowed_before), (
                f"demo script claims {forbidden!r}, but eval/SWEEP500.json records "
                f"{len(blocked)} blocked and the corpus has no labels"
            )
    assert "unlabelled" in text, "the script should say the 500-package corpus is unlabelled"


def test_the_demo_scripts_sweep_figures_match_the_sweep_data():
    """ "73 of 73 that installed" and "413 of the 421" are spoken aloud in the cold open and
    the evidence beat. Both are recomputed here rather than trusted."""
    small = _sweep_rows("SWEEP.json")
    installed = [r for r in small if r.get("status") == "completed" and r.get("exit_code") == 0]
    clean = [r for r in installed if r.get("verdict") == "Clean"]
    assert len(installed) == len(clean) == 73, "the 100-package sweep figures moved"

    big = _sweep_rows("SWEEP500.json")
    big_installed = [r for r in big if r.get("status") == "completed" and r.get("exit_code") == 0]
    big_clean = [r for r in big_installed if r.get("verdict") == "Clean"]
    assert (len(big_clean), len(big_installed)) == (413, 421)

    text = normalised(SCRIPT)
    assert "73 of 73" in text or "Seventy-three of them" in text
    assert "413 of the 421" in text


@pytest.mark.parametrize("rel", ("README.md", "docs/SUBMISSION.md", "demo/DEMO_SCRIPT.md"))
def test_the_headline_sweep_claim_does_not_mix_denominators(rel):
    """An outside audit caught this: the flagged package is **not** one of the 73 that
    installed. It timed out, so it sits among the 27 that never completed. Saying "cleared 73
    of 73 that installed, and flagged one" in one breath reads as though 74 packages were
    assessed, which a judge could call an arithmetic conflict.

    Verified from the data rather than assumed, so if a future sweep changes the shape this
    test fails instead of silently permitting the old phrasing.
    """
    sweep = _sweep_rows("SWEEP.json")
    installed = [r for r in sweep if r.get("status") == "completed" and r.get("exit_code") == 0]
    blocked = [r for r in sweep if r.get("verdict") == "Blocked"]
    assert len(installed) == 73 and len(blocked) == 1
    assert blocked[0] not in installed, (
        "the flagged package now IS among those that installed; this guard needs rewriting "
        "and the headline wording can be simplified"
    )

    text = normalised(ROOT / rel)
    # The two denominators must both be present near the claim.
    assert "73" in text and "27" in text, (
        f"{rel} states the 73 without accounting for the 27 that did not install"
    )
    for mixed in ("73 of 73 that installed, and flagged one",
                  "cleared 73 of 73 that installed, and flagged one"):  # fmt: skip
        assert mixed not in text, f"{rel} still mixes the denominators: {mixed!r}"


def test_the_demo_script_withholds_the_disclosed_package():
    """The cold open puts eval/SWEEP.md on screen. That file must keep the identifier out, and
    the script must not carry it either. W11: the name is still under embargo."""
    sweep_md = (ROOT / "eval" / "SWEEP.md").read_text(encoding="utf-8")
    assert "withheld pending disclosure" in sweep_md or "withheld" in sweep_md
    blocked = [r for r in _sweep_rows("SWEEP.json") if r.get("verdict") == "Blocked"]
    assert len(blocked) == 1
    assert "withheld" in blocked[0]["package"], (
        "the 100-package sweep's blocked row names the package pending disclosure; the demo "
        "script shows this file on camera"
    )


# --- the ablation table and the cost/latency line -----------------------------------------
#
# All three documents carried "benign needs-review 5 -> 3" for the Intent Contract when the
# stamped arms say 4 -> 3, and the same three carried cost $0.0149/PR with detonation p50 4.5 s
# and model p50 12.5 s when `eval/results.md` - the generated summary they cite - says $0.0181,
# 5.9 s and 36.5 s. Both were figures from an earlier, smaller run that nobody refreshed. The
# "5 -> 3" one mattered most: it made the model's contribution look twice its real size, in the
# section whose whole job is justifying the model.

ABLATION_DOCS = ("docs/SUBMISSION.md", "eval/README.md")


@pytest.mark.parametrize("rel", ABLATION_DOCS)
def test_no_document_overstates_the_intent_contract(rel, rows):
    """The contract's effect is the difference between the `rules` and `contract` arms on the
    benign cohort, recomputed here rather than trusted."""
    benign = benign_rows(rows)
    before = sum(1 for r in benign if r["outcomes"].get("rules") == "Needs review")
    after = sum(1 for r in benign if r["outcomes"].get("contract") == "Needs review")
    text = normalised(ROOT / rel)
    assert f"{before} to {after}" in text or f"{before} → {after}" in text, (
        f"{rel} should say the contract takes benign needs-review {before} -> {after}"
    )
    for wrong in (f"{before + 1} to {after}", f"{before + 1} → {after}"):
        assert wrong not in text, f"{rel} still claims {wrong!r}; the stamped arms say {before}"


def test_the_contract_moves_exactly_one_benign_case(rows):
    """Guards the prose that names it. If a second case ever moves, the documents that say
    "one case, prisma" become wrong."""
    moved = [
        r["id"] for r in benign_rows(rows)
        if r["outcomes"].get("rules") != r["outcomes"].get("contract")
    ]  # fmt: skip
    assert moved == ["prisma"], f"the contract now moves {moved}"


@pytest.mark.parametrize("rel", ABLATION_DOCS)
def test_the_published_cost_per_pr_matches_the_stamped_runs(rel, rows):
    import statistics

    costs = [r["cost_usd"] for r in rows if r.get("cost_usd")]
    mean = statistics.mean(costs)
    text = normalised(ROOT / rel)
    assert f"{mean:.4f}" in text, f"{rel} does not carry the stamped mean cost ${mean:.4f} per PR"
    # Figures from the earlier, smaller run. `$0.015` is listed separately because rejecting
    # only `0.0149` let a rounded restatement survive for another day: a document can carry
    # the corrected number in one place and the superseded one in another.
    for superseded in ("0.0149", "$0.015 per PR", "~$0.015"):
        assert superseded not in text, f"{rel} still carries the superseded cost {superseded!r}"


@pytest.mark.parametrize("rel", ABLATION_DOCS)
def test_the_cost_figure_is_scoped_to_model_spend(rel):
    """An outside audit noted the figure is model API spend and excludes the detonation host's
    compute and network, which dominates at this volume. Quoting it as "cost per PR" with no
    scope reads as total cost of ownership."""
    text = normalised(ROOT / rel)
    if "0.0181" not in text:  # pragma: no cover - all three currently quote it
        pytest.skip(f"{rel} no longer quotes the cost")
    assert "model API spend" in text, f"{rel} quotes the cost without scoping it to API spend"


@pytest.mark.parametrize("rel", ABLATION_DOCS)
def test_no_document_carries_the_superseded_latency_figures(rel):
    text = normalised(ROOT / rel)
    for stale in ("p50 12.5", "p95 24.2", "p50 4.5 s", "p95 13.8"):
        assert stale not in text, f"{rel} still carries the superseded latency figure {stale!r}"


def test_nothing_claims_the_model_is_fully_overlapped_with_the_sandbox(rows):
    """It is not: the analysis reads the telemetry, so it cannot start until the sandbox is
    done, and it took longer than the detonation in almost every case."""
    slower = sum(
        1 for r in rows
        if (r.get("model_latency_s") or 0) > (r.get("detonation_s") or 0)
    )  # fmt: skip
    assert slower > len(rows) * 0.8, "if the model is now usually faster, re-check this claim"
    for rel in ABLATION_DOCS:
        text = normalised(ROOT / rel)
        assert "fully overlapped with the sandbox" not in text, f"{rel} claims full overlap"


def test_the_documented_rule_count_matches_the_code():
    """`docs/SUBMISSION.md` claimed "15 deterministic rules" while the code had 16, and nobody
    noticed because nothing derived the number. Counted from the source instead."""
    import re
    from pathlib import Path as _Path

    ids: set[str] = set()
    for module in sorted((ROOT / "brain").glob("*.py")):
        src = _Path(module).read_text(encoding="utf-8")
        ids |= set(re.findall(r"""RuleHit\(\s*["']([A-Z][A-Z0-9_]+)""", src))
        ids |= set(re.findall(r"""hit\(\s*["']([A-Z][A-Z0-9_]+)""", src))
    assert len(ids) >= 10, f"the rule-id scan found only {sorted(ids)}; the pattern has rotted"

    # Every document that states a rule count must agree with the source. SUBMISSION once said
    # 15 while the code had 16; the claim ledger once said 18 while the code had 19 — the ledger
    # was not covered, so it drifted. Now both are.
    for rel in ("docs/SUBMISSION.md", "eval/CLAIM_LEDGER.md", "docs/FRAMING.md"):
        text = normalised(ROOT / rel)
        m = re.search(r"(\d+) deterministic rules", text)
        assert m, f"{rel} no longer states a rule count"
        assert int(m.group(1)) == len(ids), (
            f"{rel} says {m.group(1)} deterministic rules; brain/ defines {len(ids)}: "
            f"{', '.join(sorted(ids))}"
        )


def test_the_caveat_the_generators_emit_says_both_required_things():
    """Guards the constant itself: the per-document test above would pass vacuously if the
    generators started emitting a caveat that no longer made either point."""
    from brain.evidence import GROUNDING_CAVEAT

    caveat = " ".join(GROUNDING_CAVEAT.split())
    assert "citation discipline" in caveat
    assert "not total factual accuracy" in caveat
    assert caveat.startswith(">"), "it renders as a markdown blockquote in the eval summaries"
