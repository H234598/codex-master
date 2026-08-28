from pathlib import Path
import re


REPO_ROOT = Path(__file__).parents[1]
POLICY = REPO_ROOT / "systemd/selinux/codex_master_home_broker.te"
FILECONTEXTS = REPO_ROOT / "systemd/selinux/codex_master_home_broker.fc"

BROKER_DOMAIN = "codex_master_home_broker_t"
BROKER_EXEC = "codex_master_home_broker_exec_t"
BROKER_PACKAGE = "codex_master_home_broker_package_t"
BROKER_CONFIG = "codex_master_home_broker_config_t"
BROKER_STATE = "codex_master_home_broker_state_t"
AGENT_DOMAIN = "codex_master_agent_t"
AGENT_EXEC = "codex_master_agent_exec_t"
AGENT_HOME = "codex_master_agent_home_t"
AGENT_ENDPOINT = "codex_master_agent_endpoint_t"

TYPE_NAMES = {
    BROKER_DOMAIN,
    BROKER_EXEC,
    BROKER_PACKAGE,
    BROKER_CONFIG,
    BROKER_STATE,
    AGENT_DOMAIN,
    AGENT_EXEC,
    AGENT_HOME,
    AGENT_ENDPOINT,
}

TYPE_ATTRIBUTES = {
    (BROKER_DOMAIN, "domain"),
    (BROKER_EXEC, "exec_type"),
    (BROKER_EXEC, "file_type"),
    (BROKER_PACKAGE, "file_type"),
    (BROKER_CONFIG, "file_type"),
    (BROKER_STATE, "file_type"),
    (AGENT_DOMAIN, "domain"),
    (AGENT_EXEC, "exec_type"),
    (AGENT_EXEC, "file_type"),
    (AGENT_HOME, "file_type"),
    (AGENT_ENDPOINT, "file_type"),
}

REQUIRED_CLASSES = {
    "process": {"transition"},
    "file": {
        "append",
        "create",
        "entrypoint",
        "execute",
        "getattr",
        "map",
        "open",
        "read",
        "setattr",
        "unlink",
        "write",
    },
    "dir": {
        "add_name",
        "getattr",
        "open",
        "read",
        "remove_name",
        "search",
        "setattr",
        "write",
    },
    "sock_file": {"create", "getattr", "open", "read", "setattr", "unlink", "write"},
}


def _allow(subject: str, target: str, object_class: str, *permissions: str) -> tuple:
    return subject, target, object_class, frozenset(permissions)


EXPECTED_ALLOWS = (
    _allow("init_t", BROKER_EXEC, "file", "execute", "getattr", "map", "open", "read"),
    _allow("init_t", BROKER_DOMAIN, "process", "transition"),
    _allow("init_t", AGENT_EXEC, "file", "execute", "getattr", "map", "open", "read"),
    _allow("init_t", AGENT_DOMAIN, "process", "transition"),
    _allow(BROKER_DOMAIN, BROKER_PACKAGE, "dir", "getattr", "open", "read", "search"),
    _allow(BROKER_DOMAIN, BROKER_PACKAGE, "file", "getattr", "map", "open", "read"),
    _allow(BROKER_DOMAIN, BROKER_CONFIG, "dir", "getattr", "open", "read", "search"),
    _allow(BROKER_DOMAIN, BROKER_CONFIG, "file", "getattr", "open", "read"),
    _allow(
        BROKER_DOMAIN,
        BROKER_STATE,
        "dir",
        "add_name",
        "getattr",
        "open",
        "read",
        "remove_name",
        "search",
        "setattr",
        "write",
    ),
    _allow(
        BROKER_DOMAIN,
        BROKER_STATE,
        "file",
        "append",
        "create",
        "getattr",
        "open",
        "read",
        "setattr",
        "unlink",
        "write",
    ),
    _allow(
        AGENT_DOMAIN,
        AGENT_HOME,
        "dir",
        "add_name",
        "getattr",
        "open",
        "read",
        "remove_name",
        "search",
        "setattr",
        "write",
    ),
    _allow(
        AGENT_DOMAIN,
        AGENT_HOME,
        "file",
        "append",
        "create",
        "getattr",
        "open",
        "read",
        "setattr",
        "unlink",
        "write",
    ),
    _allow(
        AGENT_DOMAIN,
        AGENT_ENDPOINT,
        "dir",
        "add_name",
        "getattr",
        "open",
        "read",
        "remove_name",
        "search",
        "setattr",
        "write",
    ),
    _allow(
        AGENT_DOMAIN,
        AGENT_ENDPOINT,
        "sock_file",
        "create",
        "getattr",
        "open",
        "read",
        "setattr",
        "unlink",
        "write",
    ),
    _allow(BROKER_DOMAIN, BROKER_EXEC, "file", "entrypoint"),
    _allow(AGENT_DOMAIN, AGENT_EXEC, "file", "entrypoint"),
)


def _read(path: Path) -> str:
    assert path.is_file(), f"missing SELinux source: {path}"
    return path.read_bytes().decode("utf-8")


def _parse_required_classes(policy: str) -> dict[str, set[str]]:
    require = re.search(r"^require\s*\{(.*?)^\}", policy, re.MULTILINE | re.DOTALL)
    assert require is not None
    block = require.group(1)
    assert set(re.findall(r"^\s*type\s+([a-z0-9_]+);", block, re.MULTILINE)) == {
        "init_t"
    }
    classes = re.findall(
        r"^\s*class\s+([a-z0-9_]+)(?:\s+\{([^}]*)\}|\s+([a-z0-9_]+))\s*;",
        block,
        re.MULTILINE,
    )
    return {name: set((many or one).split()) for name, many, one in classes}


def _parse_allows(policy: str) -> list[tuple]:
    allow_pattern = re.compile(
        r"^\s*allow\s+(?P<subject>[a-z0-9_]+)\s+(?P<target>[a-z0-9_]+):"
        r"(?P<object_class>[a-z0-9_]+)\s+(?:\{(?P<many>[^}]*)\}|(?P<one>[a-z0-9_]+))\s*;",
        re.MULTILINE,
    )
    return [
        (
            match.group("subject"),
            match.group("target"),
            match.group("object_class"),
            frozenset((match.group("many") or match.group("one")).split()),
        )
        for match in allow_pattern.finditer(policy)
    ]


def test_policy_declares_exact_domains_types_requirements_and_allow_matrix() -> None:
    policy = _read(POLICY)

    assert set(re.findall(r"^type\s+([a-z0-9_]+);", policy, re.MULTILINE)) == TYPE_NAMES
    assert (
        set(
            re.findall(
                r"^typeattribute\s+([a-z0-9_]+)\s+([a-z0-9_]+);", policy, re.MULTILINE
            )
        )
        == TYPE_ATTRIBUTES
    )
    assert re.findall(r"^\s*([a-z_][a-z0-9_]*)\(", policy, re.MULTILINE) == [
        "policy_module"
    ]

    assert _parse_required_classes(policy) == REQUIRED_CLASSES
    assert set(re.findall(r"^type_transition\s+([^;]+);", policy, re.MULTILINE)) == {
        f"init_t {BROKER_EXEC}:process {BROKER_DOMAIN}",
        f"init_t {AGENT_EXEC}:process {AGENT_DOMAIN}",
    }
    assert len(_parse_allows(policy)) == len(EXPECTED_ALLOWS)
    assert set(_parse_allows(policy)) == set(EXPECTED_ALLOWS)

    forbidden_policy_tokens = (
        "unconfined_t",
        "unconfined_domain",
        "permissive",
        "dontaudit",
        "auditallow",
        "optional_policy",
        "fallback",
        "mls",
        "mcs",
        "range_transition",
        "range_change",
        "category",
        "user_home_t",
        "home_root_t",
        "system_bus_t",
        "dbus",
        "netif",
        "node_t",
        "port_t",
        "tcp_socket",
        "udp_socket",
        "rawip_socket",
        "netlink",
        "uid_t",
        "gid_t",
    )
    lowered_policy = policy.lower()
    for token in forbidden_policy_tokens:
        assert token not in lowered_policy
    assert not re.search(r"\bwal\b|\bmanifest\b", lowered_policy)

    for line in policy.splitlines():
        if line.lstrip().startswith("allow "):
            assert "*" not in line
            assert not re.search(
                r"\b(file_type|dir_type|file_t|var_t|etc_t|usr_t|default_t):", line
            )


def _parse_filecontexts(filecontexts: str) -> list[tuple[str, str | None, str]]:
    line_pattern = re.compile(
        r"^(?P<path>\S+)(?:\s+(?P<ftype>--|-d))?\s+"
        r"gen_context\(system_u:object_r:(?P<type>[a-z0-9_]+),s0\)$"
    )
    entries = []
    for line in filecontexts.splitlines():
        match = line_pattern.fullmatch(line)
        assert match is not None, f"invalid filecontext line: {line}"
        entries.append((match.group("path"), match.group("ftype"), match.group("type")))
    return entries


def test_filecontexts_use_exact_paths_and_distinct_file_type_selectors() -> None:
    filecontexts = _read(FILECONTEXTS)
    expected = [
        ("/usr/lib/codex-master-home-broker(/.*)?", None, BROKER_PACKAGE),
        ("/usr/libexec/codex-master-home-broker", "--", BROKER_EXEC),
        ("/usr/libexec/codex-master-broker-verify", "--", BROKER_EXEC),
        ("/var/lib/codex-master-home-broker(/.*)?", None, BROKER_STATE),
        ("/etc/codex-master/home-broker.conf", "--", BROKER_CONFIG),
        ("/usr/libexec/codex-master-agent-launcher", "--", AGENT_EXEC),
        ("/run/codex-master-agent", "-d", AGENT_ENDPOINT),
        ("/run/codex-master-agent/home(/.*)?", None, AGENT_HOME),
    ]

    assert _parse_filecontexts(filecontexts) == expected
    assert sum(ftype is None for _, ftype, _ in expected) == 3
    assert sum(ftype == "--" for _, ftype, _ in expected) == 4
    assert sum(ftype == "-d" for _, ftype, _ in expected) == 1
    assert not re.search(
        r"s0:c\d|\bcategory\b|\bmls\b|\bmcs\b|unconfined|default_t|user_home_t|var_t|etc_t",
        filecontexts,
        re.IGNORECASE,
    )
    assert not re.search(
        r"\.\.|//|\\\\|agent[_-]?\d|fallback", filecontexts, re.IGNORECASE
    )
