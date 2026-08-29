import pytest

import codex_master.remote_queen_bootstrap as rb
from codex_master.remote_queen_bootstrap import (
    RemoteQueenBootstrapError,
    SshTargetV1,
    parse_ssh_target,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("host.example.net", SshTargetV1(user=None, host="host.example.net")),
        ("192.0.2.17", SshTargetV1(user=None, host="192.0.2.17")),
        ("[2001:db8::17]", SshTargetV1(user=None, host="[2001:db8::17]")),
        ("queen@host.example.net", SshTargetV1(user="queen", host="host.example.net")),
        ("queen@[2001:db8::17]", SshTargetV1(user="queen", host="[2001:db8::17]")),
    ],
)
def test_parse_ssh_target_accepts_direct_targets(value, expected):
    assert parse_ssh_target(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "-oProxyCommand=x",
        "queen@https://host",
        "ssh://host",
        "queen:password@host",
        "queen@host -oProxyCommand=x",
        "queen@host\nnext",
        "queen@host\x00next",
        "queen@host,hop",
        "queen@2001:db8::17",
        "queen@@host",
    ],
)
def test_parse_ssh_target_rejects_unsafe_targets(value):
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        parse_ssh_target(value)

    assert exc_info.value.code == "RQ_E_SSH_TARGET_INVALID"


@pytest.mark.parametrize(
    ("distribution_id", "package_manager", "expected"),
    [
        (
            "fedora",
            "dnf",
            (
                "ca-certificates",
                "curl",
                "dbus-python3",
                "gcc",
                "git",
                "glib2-devel",
                "pkgconf-pkg-config",
                "python3",
                "python3-devel",
                "python3-gobject",
                "syncthing",
                "systemd",
            ),
        ),
        (
            "ubuntu",
            "apt",
            (
                "build-essential",
                "ca-certificates",
                "curl",
                "git",
                "libgirepository1.0-dev",
                "pkg-config",
                "python3",
                "python3-dbus",
                "python3-dev",
                "python3-gi",
                "python3-venv",
                "syncthing",
                "systemd",
            ),
        ),
        ("almalinux", "dnf", None),
        ("debian", "apt", None),
    ],
)
def test_package_plan_for_supported_hosts(
    distribution_id, package_manager, expected
):
    host_facts = rb.HostFactsV1(
        distribution_id=distribution_id,
        distribution_version="41",
        architecture="x86_64",
        package_manager=package_manager,
    )

    package_plan = rb.package_plan_for(host_facts)

    assert package_plan.manager == package_manager
    if expected is None:
        expected = rb.DNF_PACKAGES if package_manager == "dnf" else rb.APT_PACKAGES
    assert package_plan.packages == expected
    assert package_plan.packages == tuple(sorted(set(package_plan.packages)))


@pytest.mark.parametrize(
    ("distribution_id", "package_manager"),
    [("ubuntu", "dnf"), ("arch", "pacman")],
)
def test_package_plan_for_rejects_unsupported_hosts(
    distribution_id, package_manager
):
    host_facts = rb.HostFactsV1(
        distribution_id=distribution_id,
        distribution_version="41",
        architecture="x86_64",
        package_manager=package_manager,
    )

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rb.package_plan_for(host_facts)

    assert exc_info.value.code == "RQ_E_HOST_UNSUPPORTED"


OBJECT_IDS = (
    "packages",
    "release-artifacts",
    "user-services",
    "syncthing-folder:Teladi_Programming",
    "queen-binding",
)
DESIRED_GENERATION = "rq-bootstrap-2026-08-29"


def _object_states(generations, owners=None):
    if owners is None:
        owners = {object_id: None for object_id in OBJECT_IDS}
    return tuple(
        rb.ManagedObjectStateV1(
            object_id=object_id,
            owner=owners[object_id],
            generation=generations[object_id],
        )
        for object_id in OBJECT_IDS
    )


def _plan_for(states):
    return rb.build_remote_queen_bootstrap_plan(
        ssh_target=SshTargetV1(user="queen", host="host.example.net"),
        host_facts=rb.HostFactsV1(
            distribution_id="fedora",
            distribution_version="41",
            architecture="x86_64",
            package_manager="dnf",
        ),
        desired_generation=rb.ManifestGenerationV1(
            generation=DESIRED_GENERATION,
            sha256="a" * 64,
        ),
        object_states=states,
        queen_binding=rb.QueenBindingV1(
            repo_id="codex-master",
            topic_id="g18-vertex-overflow",
            role="queen",
            scope=("plan", "exclusive-g18-files"),
        ),
    )


def test_build_plan_for_complete_state_has_no_steps():
    states = _object_states(
        {object_id: DESIRED_GENERATION for object_id in OBJECT_IDS},
        {object_id: "remote-queen-bootstrap" for object_id in OBJECT_IDS},
    )

    plan = _plan_for(states)

    assert plan.steps == ()


def test_build_plan_for_empty_state_ensures_objects_in_fixed_order():
    states = _object_states({object_id: None for object_id in OBJECT_IDS})

    plan = _plan_for(states)

    assert tuple((step.object_id, step.action) for step in plan.steps) == tuple(
        (object_id, "ensure") for object_id in OBJECT_IDS
    )


def test_build_plan_for_partial_state_ensures_only_missing_objects():
    generations = {
        object_id: DESIRED_GENERATION
        if object_id in {"packages", "queen-binding"}
        else None
        for object_id in OBJECT_IDS
    }
    owners = {
        object_id: "remote-queen-bootstrap"
        if object_id in {"packages", "queen-binding"}
        else None
        for object_id in OBJECT_IDS
    }

    plan = _plan_for(_object_states(generations, owners))

    assert tuple(step.object_id for step in plan.steps) == (
        "release-artifacts",
        "user-services",
        "syncthing-folder:Teladi_Programming",
    )
    assert tuple(step.action for step in plan.steps) == ("ensure",) * 3


def test_build_plan_for_stale_state_replaces_old_generation():
    generations = {
        object_id: (
            "rq-bootstrap-2026-08-28"
            if object_id == "release-artifacts"
            else DESIRED_GENERATION
        )
        for object_id in OBJECT_IDS
    }
    owners = {object_id: "remote-queen-bootstrap" for object_id in OBJECT_IDS}

    plan = _plan_for(_object_states(generations, owners))

    assert [(step.object_id, step.action) for step in plan.steps] == [
        ("release-artifacts", "replace")
    ]
    rollback = next(
        item for item in plan.rollback_objects if item.object_id == "release-artifacts"
    )
    assert rollback.prior_generation == "rq-bootstrap-2026-08-28"


def test_build_plan_for_contradictory_state_rejects_missing_generation():
    generations = {object_id: None for object_id in OBJECT_IDS}
    owners = {object_id: None for object_id in OBJECT_IDS}
    owners["packages"] = "remote-queen-bootstrap"

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        _plan_for(_object_states(generations, owners))

    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"


def test_build_plan_rejects_foreign_owner():
    generations = {object_id: None for object_id in OBJECT_IDS}
    owners = {object_id: None for object_id in OBJECT_IDS}
    owners["packages"] = "another-owner"

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        _plan_for(_object_states(generations, owners))

    assert exc_info.value.code == "RQ_E_FOREIGN_STATE"


def test_build_plan_digest_is_stable_and_has_canonical_shape():
    states = _object_states(
        {object_id: DESIRED_GENERATION for object_id in OBJECT_IDS},
        {object_id: "remote-queen-bootstrap" for object_id in OBJECT_IDS},
    )

    first = _plan_for(states)
    second = _plan_for(states)

    assert first.plan_digest == second.plan_digest
    assert first.plan_digest.startswith("sha256:")
    assert len(first.plan_digest.removeprefix("sha256:")) == 64
    assert all(
        character in "0123456789abcdef"
        for character in first.plan_digest.removeprefix("sha256:")
    )
