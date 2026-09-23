from __future__ import annotations

import ast
import inspect
from pathlib import Path

from the_hive import server


PUBLISHER_SYMBOLS = frozenset(
    {
        "_prune_plugin_cache_versions_unlocked",
        "_sync_plugin_cache_from_repo_unlocked",
        "copy_plugin_cache_dir_fd",
        "copy_plugin_cache_path",
        "copy_regular_plugin_file_from_dir_no_follow",
        "copy_regular_plugin_file_no_follow",
        "open_plugin_destination_directory",
        "open_plugin_destination_directory_at",
        "open_plugin_destination_parent",
        "open_plugin_source_dir_no_follow",
        "plugin_cache_lock",
        "plugin_cache_name_excluded",
        "plugin_source_root_operation",
        "prune_plugin_cache_versions",
        "remove_created_plugin_file_if_same",
        "remove_real_plugin_cache_dir",
        "sync_plugin_cache_from_repo",
        "valid_plugin_cache_entry_version",
    }
)


def test_server_exposes_no_hive_native_plugin_cache_publisher_or_install_switch() -> (
    None
):
    source = Path(server.__file__).read_text(encoding="utf-8")
    definitions = {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
    }

    assert not definitions & PUBLISHER_SYMBOLS
    for publisher_identifier in (
        "MAX_PLUGIN_CACHE_RETAINED_VERSIONS",
        "PLUGIN_CACHE_ALLOWED_",
        "PLUGIN_CACHE_EXCLUDED_",
        "PLUGIN_CACHE_OPTIONAL_",
        "could_not_sync_plugin_cache",
        "no_plugin_cache",
        "plugin-cache.lock",
        "sync_plugin_cache",
    ):
        assert publisher_identifier not in source
    for install_entrypoint in (
        server.install,
        server._install_unlocked,
        server._install_enrolled_unlocked,
    ):
        assert (
            "sync_plugin_cache" not in inspect.signature(install_entrypoint).parameters
        )
