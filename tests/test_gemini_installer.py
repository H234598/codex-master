from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "install-gemini-cli"


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o700)


def test_installer_uses_only_latest_channel_and_checks_version(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    prefix = tmp_path / "npm-prefix"
    prefix.mkdir()
    log = tmp_path / "npm.log"
    _write_executable(fake_bin / "node", "#!/bin/sh\nexit 0\n")
    _write_executable(
        fake_bin / "npm",
        "#!/bin/sh\n"
        f"if [ \"$1\" = config ]; then printf '%s\\n' '{prefix}'; exit 0; fi\n"
        f"printf '%s\\n' \"$*\" > '{log}'\n"
        f"cat > '{fake_bin / 'gemini'}' <<'EOF'\n#!/bin/sh\nprintf 'gemini-cli 0.53.1\\n'\nEOF\n"
        f"chmod 700 '{fake_bin / 'gemini'}'\n",
    )
    env = {"PATH": f"{fake_bin}:/usr/bin:/bin", "HOME": str(tmp_path / "home")}

    result = subprocess.run([str(SCRIPT)], env=env, text=True, capture_output=True, check=False)

    assert result.returncode == 0
    assert result.stdout.strip() == '{"status":"installed","version":"gemini-cli 0.53.1"}'
    assert log.read_text(encoding="utf-8").strip() == "install -g @google/gemini-cli@latest"


def test_installer_fails_before_install_when_node_is_missing(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "npm", "#!/bin/sh\nexit 99\n")
    real_bash = shutil.which("bash")
    assert real_bash is not None
    _write_executable(fake_bin / "bash", f"#!/bin/sh\nexec '{real_bash}' \"$@\"\n")
    env = {"PATH": str(fake_bin), "HOME": str(tmp_path / "home")}

    result = subprocess.run([str(SCRIPT)], env=env, text=True, capture_output=True, check=False)

    assert result.returncode == 1
    assert result.stdout.strip() == '{"status":"failed","reason":"node_or_npm_missing"}'
