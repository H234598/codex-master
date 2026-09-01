from pathlib import Path

from codex_master.hive.evidence_service import load_test_index
from codex_master.hive.indexed_test_inventory import PythonTestIndexBuilder
from codex_master.hive.indexed_tests import TestIndexV1 as IndexV1, combine_test_indexes
from codex_master.hive.javascript_test_inventory import JavaScriptTestIndexBuilder


ROOT = Path(__file__).resolve().parents[1]


def test_repository_index_matches_current_source_and_collectible_tests() -> None:
    index = load_test_index(ROOT)
    functions = {item.function_id: item for item in index.functions}
    tests = {item.test_id: item for item in index.tests}

    function_metadata = {
        function_id: {
            "cooldown_class": item.cooldown_class,
            "risk": item.risk,
            "generated": item.generated,
        }
        for function_id, item in functions.items()
    }
    test_metadata = {
        test_id: {
            "kind": item.kind,
            "timeout_seconds": item.timeout_seconds,
            "hermeticity": item.hermeticity,
            "required_resources": item.required_resources,
        }
        for test_id, item in tests.items()
    }

    def bindings(language: str) -> dict[str, tuple[str, ...]]:
        return {
            function_id: item.test_ids
            for function_id, item in functions.items()
            if item.language == language
        }

    python = PythonTestIndexBuilder(ROOT).build(
        repository_id=index.repository_id,
        generation=index.generation,
        source_paths=sorted(
            {item.path for item in functions.values() if item.language == "python"}
        ),
        test_paths=sorted(
            {item.path for item in tests.values() if item.runner == "pytest"}
        ),
        bindings=bindings("python"),
        function_metadata=function_metadata,
        test_metadata=test_metadata,
    )
    javascript = JavaScriptTestIndexBuilder(ROOT).build(
        repository_id=index.repository_id,
        generation=index.generation,
        source_paths=sorted(
            {
                item.path
                for item in functions.values()
                if item.language in {"javascript", "typescript"}
            }
        ),
        test_paths=sorted(
            {item.path for item in tests.values() if item.runner == "node_test"}
        ),
        bindings={
            function_id: item.test_ids
            for function_id, item in functions.items()
            if item.language in {"javascript", "typescript"}
        },
        function_metadata=function_metadata,
        test_metadata=test_metadata,
    )
    rebuilt = combine_test_indexes(python, javascript).public()
    rebuilt["gates"] = [item.public() for item in index.gates]

    assert IndexV1.from_mapping(rebuilt).canonical_bytes() == index.canonical_bytes()
