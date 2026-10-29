import os
from pathlib import Path
import shutil
import subprocess
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_SOURCE = REPO_ROOT / "bin" / "the-hive-plugin-hook-stable"
ABI_LAUNCHER = "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
ABI_CORE = "/usr/local/libexec/the-hive/hook-abi/v1/hook_abi_v1_core.py"


def test_stable_launcher_loads_only_the_fixed_immutable_abi_core() -> None:
    source = LAUNCHER_SOURCE.read_text(encoding="utf-8")

    assert ABI_LAUNCHER not in source
    assert ABI_CORE in source
    assert "dispatch_hook_v1" in source
    assert "hook_fd" in source
    assert "bundle_fd" in source
    assert "PLUGIN_DATA" not in source
    assert "$HOME" not in source
    assert ".codex/plugins/cache" not in source
    assert "hook_session_pin_store.py" not in source
    assert "runtime_layout" not in source
    assert "from the_hive" not in source
    assert "Path(__file__)" not in source
    assert "BASH_SOURCE" not in source


def test_stable_launcher_rejects_a_non_allowlisted_hook_before_state_or_release_access() -> (
    None
):
    with tempfile.TemporaryDirectory() as temporary:
        copied_launcher = Path(temporary) / "launcher"
        shutil.copyfile(LAUNCHER_SOURCE, copied_launcher)
        copied_launcher.chmod(0o755)
        completed = subprocess.run(
            [str(copied_launcher), "not-an-allowed-hook"],
            input=b'{"session_id":"test","hook_event_name":"SessionStart"}\n',
            capture_output=True,
            env={"PATH": os.environ["PATH"]},
            timeout=10,
            check=False,
        )

    assert completed.returncode == 64
    assert completed.stdout == b""
    assert completed.stderr == b""
