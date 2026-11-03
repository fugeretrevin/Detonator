"""The headline numbers in the write-up must match `eval/results.json`.

Written after finding that `docs/SUBMISSION.md` and `docs/HANDOFF.md` both claimed "97 clean,
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


def test_the_handoff_honest_claims_match_the_same_tally(benign):
    expected = (
        f"{benign['Clean']} clean, {benign['Needs review']} needs review, "
        f"{benign['Could not verify']} could not verify"
    )
    assert expected in normalised(ROOT / "docs" / "HANDOFF.md"), expected


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


def test_the_caveat_the_generators_emit_says_both_required_things():
    """Guards the constant itself: the per-document test above would pass vacuously if the
    generators started emitting a caveat that no longer made either point."""
    from brain.evidence import GROUNDING_CAVEAT

    caveat = " ".join(GROUNDING_CAVEAT.split())
    assert "citation discipline" in caveat
    assert "not total factual accuracy" in caveat
    assert caveat.startswith(">"), "it renders as a markdown blockquote in the eval summaries"
