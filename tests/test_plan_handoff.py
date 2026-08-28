from __future__ import annotations

import runpy
from pathlib import Path


MODULE = runpy.run_path(Path(__file__).parents[1] / "bin/codex-master-publish-plan-path")


def test_handoff_has_thirty_additional_message_principles():
    assert len(MODULE["GRUNDSAETZE"]) >= 60
    assert all("{nom}" in template or "{acc}" in template or "{dat}" in template or "{poss}" in template
               for template in MODULE["GRUNDSAETZE"])


def test_message_generation_multiplies_principles_and_word_lists():
    messages = {MODULE["random_message"]() for _ in range(500)}
    assert len(messages) >= 100
    assert all(message and "{" not in message and "}" not in message for message in messages)


def test_copy_clipboard_tries_no_unlisted_backend(monkeypatch):
    seen = []

    def fake_which(command):
        return command if command == "wl-copy" else None

    def fake_run(command, **kwargs):
        seen.append(command)
        return object()

    monkeypatch.setattr(MODULE["shutil"], "which", fake_which)
    monkeypatch.setattr(MODULE["subprocess"], "run", fake_run)

    assert MODULE["copy_clipboard"]("/tmp/example.md") == "wayland"
    assert seen == [["wl-copy"]]
