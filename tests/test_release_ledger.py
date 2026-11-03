"""`scripts.release_ledger` - which code, model and measurements a claim actually refers to.

The failure this guards against is a category error rather than a crash: describing a feature as
live because it is in the repository. So the properties worth asserting are that the fields it
cannot know locally are printed as TODO rather than guessed or omitted, and that it never
authenticates as the owner unless asked.
"""

import re

import pytest

from scripts import release_ledger as rl


def test_the_contract_version_is_read_from_the_source_not_hardcoded():
    from shared.contract import CONTRACT_VERSION

    assert rl.contract_version() == str(CONTRACT_VERSION)


def test_the_eval_stamp_and_cohorts_come_from_the_results_file():
    facts = rl.eval_facts()
    assert re.match(r"[0-9a-f]{7,40}", facts["Evaluation stamped at"])
    assert "142" in facts["Evaluation cases"]
    assert "benign 104" in facts["Evaluation cases"]
    assert facts["Contract version"].isdigit()


def test_the_stamped_model_is_reported():
    assert "muse" in rl.model_facts()["Model(s) in the stamped eval"].lower()


def test_git_facts_report_the_working_tree_state():
    facts = rl.git_facts()
    assert re.fullmatch(r"[0-9a-f]{40}", facts["Commit (HEAD)"])
    assert facts["Working tree"] in ("clean",) or "DIRTY" in facts["Working tree"]


def test_every_owner_only_field_names_the_command_that_answers_it():
    """A TODO without the command is the thing that gets skipped at 2am before a deadline."""
    assert rl.OWNER_FIELDS
    for field, how in rl.OWNER_FIELDS:
        assert field and how, field
        assert len(how) > 15, f"{field}: {how!r} is not actionable"


def test_the_plain_output_lists_known_facts_and_outstanding_todos(capsys):
    assert rl.main([]) == 0
    out = capsys.readouterr().out
    assert "RELEASE LEDGER" in out
    assert "Contract version" in out and "Evaluation stamped at" in out
    for field, _ in rl.OWNER_FIELDS:
        assert field in out, f"{field} missing from the ledger"
    assert "TODO" in out
    # The point of the whole script.
    assert "not necessarily deployed" in out


def test_the_markdown_output_is_a_table(capsys):
    assert rl.main(["--markdown"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("| Field | Value |")
    assert out.count("\n") > len(rl.OWNER_FIELDS)
    assert "**TODO**" in out


def test_the_deployed_brain_version_is_never_queried_without_the_flag(capsys, monkeypatch):
    """`--modal` authenticates as the owner, so the default path must not reach it. Agents are
    not permitted to use the owner's credentials unasked, and a ledger that silently did would
    be exactly the wrong tool to add."""
    monkeypatch.setattr(
        rl, "modal_version", lambda: pytest.fail("must not authenticate without --modal")
    )
    assert rl.main([]) == 0
    out = capsys.readouterr().out
    assert "Brain deployed version" in out and "TODO" in out
    assert "modal_cli.py app history" in out  # tells the owner how, instead of doing it


def test_the_modal_flag_is_what_fills_that_field(capsys, monkeypatch):
    monkeypatch.setattr(rl, "modal_version", lambda: "v99 deployed 2026-11-03 04:00")
    assert rl.main([]) == 0  # sanity: still TODO without the flag
    assert "v99" not in capsys.readouterr().out

    assert rl.main(["--modal"]) == 0
    out = capsys.readouterr().out
    assert "v99 deployed 2026-11-03 04:00" in out
    assert "Brain deployed version   " not in out.split("Needs the owner")[-1]


def test_drift_against_the_eval_stamp_is_reported_either_way():
    """Listing changed code files prompts the behavioural check; it does not conclude it. A
    comment-only edit to brain/rules.py appears here and changes no number, which is why the
    wording asks for review rather than declaring the numbers stale."""
    stamped = rl.eval_facts()["Evaluation stamped at"]
    assert "REVIEW whether these changed behaviour" in stamped or "no code changed" in stamped
