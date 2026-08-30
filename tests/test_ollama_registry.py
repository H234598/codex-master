from __future__ import annotations

import json
import threading

import pytest

from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaModelV1,
    OllamaRegistryError,
    OllamaRegistryV1,
    OllamaRegistryStore,
)


def valid_model(ref: str = "llama-small", *, simple_only: bool = True) -> OllamaModelV1:
    return OllamaModelV1(
        ref=ref,
        provider_model_id=f"provider/{ref}",
        installed=True,
        hive_enabled=True,
        simple_only=simple_only,
        evidence_at_utc="2026-08-28T12:00:00Z",
    )


def valid_instance(
    *, selected_model_refs: tuple[str, ...] = ("llama-small",)
) -> OllamaInstanceV1:
    return OllamaInstanceV1(
        ref="ollama-1",
        label="Ollama 1",
        host_ref="local",
        ollama_executable="/usr/bin/ollama",
        models_directory="/var/lib/ollama/models",
        selected_model_refs=selected_model_refs,
        allowed_cpus="0-3",
        cpu_quota_percent=400,
        cpu_weight=100,
        lifecycle_state="stopped",
        readiness_state="unknown",
    )


def test_instance_references_models_without_copying_model_metadata(tmp_path):
    store = OllamaRegistryStore.for_test(tmp_path)
    instance = valid_instance(selected_model_refs=("llama-small", "qwen-small"))
    store.replace(
        models=(valid_model("llama-small"), valid_model("qwen-small")),
        instances=(instance,),
        expected_generation=0,
    )
    loaded = store.load()
    assert loaded.instances[0].selected_model_refs == ("llama-small", "qwen-small")


def test_instance_requires_at_least_one_model():
    with pytest.raises(OllamaRegistryError, match="ollama.instance_models_invalid"):
        valid_instance(selected_model_refs=())


def test_model_rejects_non_simple_only():
    with pytest.raises(OllamaRegistryError, match="ollama.model_invalid"):
        valid_model(simple_only=False)


def test_model_capabilities_survive_registry_round_trip(tmp_path):
    store = OllamaRegistryStore.for_test(tmp_path)
    model = OllamaModelV1(
        ref="llama-small",
        provider_model_id="provider/llama-small",
        installed=True,
        hive_enabled=True,
        simple_only=True,
        evidence_at_utc="2026-08-28T12:00:00Z",
        capabilities=("chat", "tools"),
    )

    store.replace(models=(model,), instances=(), expected_generation=0)

    assert store.load().models[0].capabilities == ("chat", "tools")


def test_registry_rejects_unknown_major_schema_version(tmp_path):
    store = OllamaRegistryStore.for_test(tmp_path)
    (tmp_path / "ollama-registry.json").write_text(
        json.dumps({"schema_version": 2, "generation": 0, "models": [], "instances": []}),
        encoding="utf-8",
    )

    with pytest.raises(OllamaRegistryError, match="ollama.registry_version_invalid"):
        store.load()


def test_registry_rejects_duplicate_refs(tmp_path):
    store = OllamaRegistryStore.for_test(tmp_path)

    with pytest.raises(OllamaRegistryError, match="ollama.registry_ref_duplicate"):
        store.replace(
            models=(valid_model("llama-small"), valid_model("llama-small")),
            instances=(),
            expected_generation=0,
        )


def test_registry_rejects_instance_reference_to_missing_model(tmp_path):
    store = OllamaRegistryStore.for_test(tmp_path)

    with pytest.raises(OllamaRegistryError, match="ollama.instance_model_missing"):
        store.replace(
            models=(valid_model("llama-small"),),
            instances=(valid_instance(selected_model_refs=("qwen-small",)),),
            expected_generation=0,
        )


def test_registry_rejects_more_than_four_local_instances(tmp_path):
    store = OllamaRegistryStore.for_test(tmp_path)
    instances = tuple(
        OllamaInstanceV1(
            ref=f"ollama-{number}",
            label=f"Ollama {number}",
            host_ref="local",
            ollama_executable="/usr/bin/ollama",
            models_directory="/var/lib/ollama/models",
            selected_model_refs=("llama-small",),
            allowed_cpus="0-3",
            cpu_quota_percent=400,
            cpu_weight=100,
            lifecycle_state="running",
            readiness_state="ready",
        )
        for number in range(1, 6)
    )

    with pytest.raises(OllamaRegistryError, match="ollama.instance_count_invalid"):
        store.replace(
            models=(valid_model("llama-small"),),
            instances=instances,
            expected_generation=0,
        )


def test_replace_rejects_stale_generation(tmp_path):
    store = OllamaRegistryStore.for_test(tmp_path)
    store.replace(models=(valid_model(),), instances=(valid_instance(),), expected_generation=0)

    with pytest.raises(OllamaRegistryError, match="ollama.registry_generation_conflict"):
        store.replace(models=(valid_model(),), instances=(valid_instance(),), expected_generation=0)


def test_concurrent_replace_allows_exactly_one_matching_generation(tmp_path):
    first = OllamaRegistryStore.for_test(tmp_path)
    second = OllamaRegistryStore.for_test(tmp_path)
    start = threading.Barrier(2)
    results: list[object] = []

    def replace(store: OllamaRegistryStore) -> None:
        start.wait()
        try:
            results.append(
                store.replace(
                    models=(valid_model(),),
                    instances=(valid_instance(),),
                    expected_generation=0,
                )
            )
        except OllamaRegistryError as error:
            results.append(error)

    threads = (
        threading.Thread(target=replace, args=(first,)),
        threading.Thread(target=replace, args=(second,)),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(isinstance(result, OllamaRegistryError) for result in results) == 1
    assert sum(isinstance(result, OllamaRegistryV1) for result in results) == 1
    assert (
        next(
            result.code
            for result in results
            if isinstance(result, OllamaRegistryError)
        )
        == "ollama.registry_generation_conflict"
    )
    assert first.load().generation == 1
