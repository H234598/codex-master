from __future__ import annotations

import runpy
from pathlib import Path

import pytest


MODULE = runpy.run_path(
    Path(__file__).parents[1] / "bin/codex-master-publish-plan-path"
)


def test_handoff_has_thirty_additional_message_principles():
    assert len(MODULE["GRUNDSAETZE"]) >= 60
    assert all(
        "{nom}" in template
        or "{acc}" in template
        or "{dat}" in template
        or "{poss}" in template
        for template in MODULE["GRUNDSAETZE"]
    )


def test_message_generation_multiplies_principles_and_word_lists():
    messages = {MODULE["random_message"]() for _ in range(500)}
    assert len(messages) >= 100
    assert all(
        message and "{" not in message and "}" not in message for message in messages
    )


def test_handoff_never_discovers_or_mutates_existing_clipboard(monkeypatch, tmp_path):
    plan = tmp_path / "plan.md"
    plan.write_text("# Plan\n", encoding="utf-8")
    existing_clipboard = {"value": "pre-existing clipboard content"}
    seen = []

    def fake_which(command):
        seen.append(("which", command))
        return command

    def fake_run(command, **kwargs):
        seen.append(("run", command))
        return object()

    monkeypatch.setattr(MODULE["shutil"], "which", fake_which)
    monkeypatch.setattr(MODULE["subprocess"], "run", fake_run)
    monkeypatch.setitem(MODULE["main"].__globals__, "notify", lambda message: None)
    monkeypatch.setattr(MODULE["sys"], "argv", ["publish-plan-path", str(plan)])

    assert MODULE["main"]() == 0
    assert existing_clipboard == {"value": "pre-existing clipboard content"}
    assert seen == []


def test_valid_handoff_prints_exact_absolute_path_and_notifies_with_path(
    monkeypatch, tmp_path, capsys
):
    plan = tmp_path / "plan.md"
    plan.write_text("# Plan\n", encoding="utf-8")
    messages = []

    monkeypatch.setitem(MODULE["main"].__globals__, "notify", messages.append)
    monkeypatch.setattr(MODULE["sys"], "argv", ["publish-plan-path", str(plan)])

    assert MODULE["main"]() == 0

    captured = capsys.readouterr()
    absolute_path = str(plan.resolve())
    assert captured.out == f"{absolute_path}\n"
    assert captured.err == ""
    assert len(messages) == 1
    assert absolute_path in messages[0]
    message = messages[0].casefold()
    for forbidden in (
        "clipboard",
        "zwischenablage",
        "wl-copy",
        "xclip",
        "xsel",
        "kopier",
        "copy",
        "einfüg",
    ):
        assert forbidden not in message


@pytest.mark.parametrize("kind", ["missing", "wrong_suffix", "directory"])
def test_invalid_handoff_paths_fail_closed(monkeypatch, tmp_path, capsys, kind):
    if kind == "missing":
        invalid = tmp_path / "missing.md"
    elif kind == "wrong_suffix":
        invalid = tmp_path / "plan.txt"
        invalid.write_text("# Plan\n", encoding="utf-8")
    else:
        invalid = tmp_path / "plan.md"
        invalid.mkdir()
    messages = []

    monkeypatch.setitem(MODULE["main"].__globals__, "notify", messages.append)
    monkeypatch.setattr(MODULE["sys"], "argv", ["publish-plan-path", str(invalid)])

    assert MODULE["main"]() == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Markdowndatei" in captured.err
    assert messages == []


def test_notification_language_docs_forbid_positive_clipboard_handoff_claim():
    document = " ".join(
        Path("docs/operations/notification-language-uses.md")
        .read_text(encoding="utf-8")
        .casefold()
        .split()
    )

    assert (
        "clipboard-aktion bleibt dabei ausschließlich der plan-/dokumentübergabe"
        " vorbehalten"
    ) not in document
    assert (
        "bei der plan-/dokumentübergabe werden keinerlei clipboard-operationen"
        " ausgeführt"
    ) in document
