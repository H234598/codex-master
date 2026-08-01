import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = fs.readFileSync(
  path.join(root, "cinnamon/applets/codex-master@H234598/applet.js"),
  "utf8"
);

function makeBytes(value) {
  return typeof value === "string" ? new TextEncoder().encode(value) : value;
}

function makeInvalidUtf8PayloadBytes(payload, replaceAt = null) {
  const raw = JSON.stringify(payload);
  const rawBytes = makeBytes(raw);
  const marker = '"raw_output":"';
  const index = raw.indexOf(marker);
  if (index === -1) {
    return rawBytes;
  }
  const payloadOffset = index + marker.length;
  if (payloadOffset >= rawBytes.length) {
    return rawBytes;
  }
  const bytes = new Uint8Array(rawBytes);
  const target = replaceAt === null ? payloadOffset : replaceAt;
  if (target >= 0 && target < bytes.length) {
    bytes[target] = 0xff;
  }
  return bytes;
}

function samplePayload() {
  return {
    schema_version: 1,
    mode: "read_only",
    activity_state: "mixed",
    backend_state: "degraded",
    control_state: "mixed",
    counts: {
      tracked: 2,
      running: 1,
      sleeping: 1,
      ready: 1,
      blocked: 1,
      issues: 1,
    },
    agents: [
      {
        agent: "a1",
        activity_state: "running",
        backend_state: "ok",
        control_state: "ready",
        auth_state: "ready",
        identity_state: "verified",
        lease_state: "unclaimed",
      },
      {
        agent: "b1",
        activity_state: "sleeping",
        backend_state: "error",
        control_state: "blocked",
        auth_state: "blocked",
        identity_state: "stopped",
        lease_state: "held",
      },
    ],
    raw_output: "not_returned",
  };
}

function loadApplet() {
  const spawned = [];
  const launcherSpawns = [];
  const subprocesses = [];
  const pendingFactories = [];
  const timeouts = [];
  let home = "/home/tester";
  let timeoutId = 1;

  const TextEncoder = globalThis.TextEncoder;
  class TextApplet {}
  TextApplet.prototype._init = function () {
    this.labels = [];
    this.tooltips = [];
    this._applet_context_menu = new AppletPopupMenu();
    this._menuManager = new PopupMenuManager();
    this._menuManager.addMenu(this._applet_context_menu);
  };
  TextApplet.prototype.set_applet_label = function (value) {
    this.labels.push(value);
  };
  TextApplet.prototype.set_applet_tooltip = function (value) {
    this.tooltips.push(value);
  };

  class PopupMenuItem {
    constructor(label) {
      this.label = label;
      this.handlers = new Map();
      this.nextHandlerId = 1;
    }
    connect(signal, callback) {
      const id = this.nextHandlerId++;
      this.handlers.set(id, { signal, callback });
      return id;
    }
    disconnect(id) { this.handlers.delete(id); }
    activate() {
      for (const handler of this.handlers.values()) {
        if (handler.signal === "activate") {
          handler.callback();
        }
      }
    }
  }

  class AppletPopupMenu {
    constructor() {
      this.isOpen = false;
      this.items = [];
      this.destroyed = false;
      this.actor = { is_finalized: () => this.destroyed };
      this.failCloseCount = 0;
      this.failDestroyCount = 0;
      this.closeCount = 0;
      this.destroyCount = 0;
    }
    addMenuItem(item) { this.items.push(item); }
    toggle() { this.isOpen = !this.isOpen; }
    close() {
      this.closeCount += 1;
      if (this.failCloseCount > 0) {
        this.failCloseCount -= 1;
        throw new Error("injected close failure");
      }
      this.isOpen = false;
    }
    destroy() {
      this.destroyCount += 1;
      if (this.failDestroyCount > 0) {
        this.failDestroyCount -= 1;
        throw new Error("injected destroy failure");
      }
      this.destroyed = true;
    }
  }

  class PopupMenuManager {
    constructor() {
      this.menus = [];
      this.removed = [];
      this.grabbed = false;
      this._activeMenu = null;
      this.ungrabCount = 0;
      this.destroyed = false;
      this.failRemoveCount = 0;
      this.failDestroyCount = 0;
      this.destroyCount = 0;
    }
    addMenu(menu) { this.menus.push(menu); }
    _ungrab() {
      if (!this.grabbed) return;
      this.ungrabCount += 1;
      this.grabbed = false;
    }
    removeMenu(menu) {
      if (this.failRemoveCount > 0) {
        this.failRemoveCount -= 1;
        throw new Error("injected remove failure");
      }
      if (!this.menus.includes(menu)) return;
      if (this._activeMenu === menu) {
        this._activeMenu = null;
        this._ungrab();
      }
      this.removed.push(menu);
      this.menus = this.menus.filter((entry) => entry !== menu);
      if (this.menus.length === 0) {
        this.destroy();
      }
    }
    destroy() {
      this.destroyCount += 1;
      if (this.failDestroyCount > 0) {
        this.failDestroyCount -= 1;
        throw new Error("injected manager destroy failure");
      }
      this.destroyed = true;
    }
  }

  class FakeInputStream {
    constructor(chunks) {
      this._chunks = chunks.slice();
      this._index = 0;
      this.readBytesAsyncArgs = null;
      this.lastAsyncArgc = 0;
      this.failSyncRead = false;
      this.throwFinish = false;
      this.readBytesSyncCount = 0;
      this.readBytesAsyncCount = 0;
      this.readBytesFinishCount = 0;
      this.holdEof = false;
      this._holdCallbacks = [];
    }

    read_bytes() {
      this.readBytesSyncCount += 1;
      if (this._index >= this._chunks.length) {
        return { get_data: () => new Uint8Array(), get_size: () => 0 };
      }
      const chunk = this._chunks[this._index++];
      return { get_data: () => chunk, get_size: () => chunk.length };
    }

    read_bytes_async(size, ioPriority, cancellable, callback) {
      this.readBytesAsyncCount += 1;
      this.lastAsyncArgc = arguments.length;
      this.readBytesAsyncArgs = Array.from(arguments).slice(0, 4);
      if (this.failSyncRead) {
        throw new Error("forced read_bytes_async fail");
      }
      if (this._index >= this._chunks.length) {
        if (this.holdEof) {
          this._holdCallbacks.push(callback);
          return;
        }
        if (callback) {
          callback(this, { get_data: () => new Uint8Array(), get_size: () => 0 });
        }
        return;
      }
      const chunk = this._chunks[this._index++];
      if (callback) {
        callback(this, { get_data: () => chunk, get_size: () => chunk.length });
      }
    }

    read_bytes_finish(packet) {
      this.readBytesFinishCount += 1;
      if (this.throwFinish) {
        throw new Error("forced read_bytes_finish fail");
      }
      return packet;
    }

    releaseEof() {
      this.holdEof = false;
      const callbacks = [...this._holdCallbacks];
      this._holdCallbacks.length = 0;
      for (const callback of callbacks) {
        if (typeof callback === "function") {
          callback(this, { get_data: () => new Uint8Array(), get_size: () => 0 });
        }
      }
    }
  }

  class FakeSubprocess {
    constructor({ argv, stdout = [], stderr = [], exitCode = 0 }) {
      this.argv = argv;
      this.forceExitCount = 0;
      this.waitCallbacks = [];
      this.stdout = new FakeInputStream(stdout);
      this.stderr = new FakeInputStream(stderr);
      this.exitCode = exitCode;
    }
    get_stdout_pipe() { return this.stdout; }
    get_stderr_pipe() { return this.stderr; }
    get_successful() { return this.exitCode === 0; }
    get_exit_status() { return this.exitCode; }
    force_exit() { this.forceExitCount += 1; }
    wait_async(_cancellable, callback) {
      this.waitCallbacks.push(callback);
    }
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const callback of callbacks) {
        callback(this, null);
      }
    }
    close() {}
    close_async(_cancellable, _callback) {
      if (_callback) _callback(this, null);
    }
  }

  class FakeSubprocessLauncher {
    constructor() {
      this.unsetCalls = [];
      this.envCalls = [];
      this.spawnRequests = [];
    }
    setenv(key, value, overwrite = true) {
      this.envCalls.push({ key, value, overwrite });
    }
    unsetenv(key) {
      this.unsetCalls.push(key);
    }
    spawnv(argv) {
      const factory = pendingFactories.shift();
      const process = factory
        ? factory(argv)
        : new FakeSubprocess({ argv, stdout: [], stderr: [] });
      this.spawnRequests.push({ argv, unsetCalls: [...this.unsetCalls], process });
      launcherSpawns.push(this.spawnRequests.at(-1));
      subprocesses.push(process);
      return process;
    }
  }

  const GLib = {
    PRIORITY_DEFAULT: 0,
    get_home_dir() { return home; },
    timeout_add(_priority, _ms, callback) {
      const id = timeoutId += 1;
      timeouts.push({ id, callback, cancelled: false });
      return id;
    },
    source_remove(id) {
      const entry = timeouts.find((entry) => entry.id === id);
      if (!entry) {
        return false;
      }
      entry.cancelled = true;
      return true;
    },
  };

  const Mainloop = {
    runTimeouts() {
      const due = timeouts.filter((entry) => !entry.cancelled);
      for (const entry of due) {
        if (entry.cancelled) {
          continue;
        }
        const keep = entry.callback();
        if (keep === true) {
          continue;
        }
        entry.cancelled = true;
      }
      return due.length;
    },
  };

  const Gio = {
    SubprocessLauncher: {
      new: function () {
        const launcher = new FakeSubprocessLauncher();
        return launcher;
      },
    },
    SubprocessFlags: {
      STDOUT_PIPE: 1,
      STDERR_PIPE: 2,
    },
  };

  const context = {
    imports: {
      gi: { Gio, GLib },
      mainloop: Mainloop,
      ui: {
        applet: { TextApplet, AppletPopupMenu },
        popupMenu: { PopupMenuItem, PopupMenuManager },
      },
      misc: { util: { spawn(args) { spawned.push(args); } } },
      byteArray: {
        toString(data) {
          return new TextDecoder("utf-8").decode(data);
        },
      },
    },
    TextEncoder,
  };

  vm.runInNewContext(source, context, { filename: "applet.js" });

  return {
    main: context.main,
    spawned,
    launcherSpawns,
    subprocesses,
    pendingFactories,
    timeouts,
    runTimeouts() { return Mainloop.runTimeouts(); },
    setHome(value) { home = value; },
    setProcessFactory(factory) { pendingFactories.push(factory); },
    resetFactories() { pendingFactories.length = 0; },
    makeStream(chunks, holdEof = false) {
      const stream = new FakeInputStream(chunks);
      stream.holdEof = holdEof;
      return stream;
    },
  };
}

test("metadata failure is safe", () => {
  const { main } = loadApplet();
  const applet = main({ uuid: "wrong" }, "top", 24, 1);
  assert.equal(applet.labels.at(-1), "Applet-Fehler");
  assert.doesNotThrow(() => applet.on_applet_clicked());
  assert.doesNotThrow(() => applet.on_applet_removed_from_panel());
  assert.doesNotThrow(() => applet.on_applet_removed_from_panel());
});

test("status click still uses menu cleanup cleanup paths", () => {
  const { main, spawned } = loadApplet();
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const menu = applet.menu;
  const manager = applet.menuManager;
  const contextMenu = applet._applet_context_menu;
  const contextManager = applet._menuManager;
  const [statusItem, settingsItem] = menu.items;

  applet.on_applet_clicked();
  assert.equal(menu.isOpen, true);
  contextMenu.toggle();
  contextManager.grabbed = true;
  contextManager._activeMenu = contextMenu;
  statusItem.activate();
  settingsItem.activate();
  assert.equal(spawned.length, 1, "only settings applet action uses Util.spawn");

  applet.on_applet_removed_from_panel();
  applet.on_applet_removed_from_panel();
  statusItem.activate();
  settingsItem.activate();

  assert.equal(spawned.length, 1);
  assert.equal(menu.isOpen, false);
  assert.equal(menu.destroyed, true);
  assert.equal(contextMenu.isOpen, false);
  assert.equal(contextMenu.destroyed, true);
  assert.equal(contextManager.grabbed, false);
  assert.equal(contextManager.ungrabCount, 1);
  assert.deepEqual(manager.removed, [menu]);
  assert.deepEqual(contextManager.removed, [contextMenu]);
  assert.equal(applet.menu, null);
  assert.equal(applet.menuManager, null);
  assert.equal(applet._applet_context_menu, null);
  assert.equal(applet._menuManager, null);
  assert.doesNotThrow(() => applet.on_applet_clicked());
});

test("menu cleanup failures are retried and not lost", () => {
  for (const failure of ["close", "remove", "menu-destroy", "manager-destroy"]) {
    const { main } = loadApplet();
    const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    const menu = applet.menu;
    const manager = applet.menuManager;
    menu.isOpen = true;
    manager.grabbed = true;
    manager._activeMenu = menu;
    if (failure === "close") menu.failCloseCount = 1;
    if (failure === "remove") manager.failRemoveCount = 1;
    if (failure === "menu-destroy") menu.failDestroyCount = 1;
    if (failure === "manager-destroy") manager.failDestroyCount = 1;

    applet.on_applet_removed_from_panel();

    assert.equal(applet.menu, menu);
    assert.equal(applet.menuManager, manager);
    assert.equal(manager.grabbed, false);

    applet.on_applet_removed_from_panel();

    assert.equal(menu.destroyed, true);
    assert.equal(manager.destroyed, true);
    assert.equal(menu.isOpen, false);
    assert.equal(applet.menu, null);
    assert.equal(applet.menuManager, null);
  }
});

test("builds fixed mcp argv and validierte ids", async () => {
  const fixture = loadApplet();
  fixture.setHome("/tmp/home");
  fixture.setProcessFactory(() => {
    return new (class {
      constructor() {
        this.forceExitCount = 0;
        this.waitCallbacks = [];
        this.stdout = fixture.makeStream([makeBytes(JSON.stringify(samplePayload()))]);
        this.stderr = fixture.makeStream([new Uint8Array()]);
      }
      get_stdout_pipe() { return this.stdout; }
      get_stderr_pipe() { return this.stderr; }
      get_successful() { return true; }
      get_exit_status() { return 0; }
      force_exit() { this.forceExitCount += 1; }
      wait_async(_, cb) { this.waitCallbacks.push(cb); }
      emitDone() {
        for (const callback of this.waitCallbacks) callback(this, null);
        this.waitCallbacks = [];
      }
    })();
  });

  const { main, launcherSpawns } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();

  const launch = launcherSpawns.at(-1);
  assert.equal(launch.argv[0], "/tmp/home/.local/bin/codex-master-mcp");
  assert.equal(launch.argv[1], "applet-status");
  assert.equal(launch.argv[2], "a1");
  assert.equal(launch.argv[3], "b1");
  for (const key of ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "GJS_PATH"]) {
    assert.ok(launch.unsetCalls.includes(key), `strips ${key}`);
  }
});

test("single-flight keeps one pending refresh", async () => {
  const fixture = loadApplet();
  fixture.setHome("/tmp/home");
  let created = 0;
  fixture.setProcessFactory(() => {
    created += 1;
        const payload = samplePayload();
        return {
          forceExitCount: 0,
          waitCallbacks: [],
          get_stdout_pipe() { return fixture.makeStream([makeBytes(JSON.stringify(payload))]); },
          get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
          get_successful: () => true,
          get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) {
          cb(this, null);
        }
      },
    };
  });
  fixture.setProcessFactory(() => {
    const payload = samplePayload();
    payload.activity_state = "running";
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return fixture.makeStream([makeBytes(JSON.stringify(payload))]); },
      get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) {
          cb(this, null);
        }
      },
    };
  });

  const { main, subprocesses } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  statusItem.activate();
  statusItem.activate();
  assert.equal(applet._statusPendingRefresh, true);

  subprocesses[0].emitDone();
  await Promise.resolve();

  assert.equal(fixture.subprocesses.length, 2);
  assert.equal(applet._statusPendingRefresh, false);
});

test("stdout cap, stderr cap, and timeout each force_exit exactly once", () => {
  for (const failure of ["stdout", "stderr", "timeout"]) {
    const fixture = loadApplet();
    fixture.setProcessFactory(() => ({
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() {
        return fixture.makeStream(failure === "stdout" ? [makeBytes("A".repeat(64 * 1024 + 1))] : []);
      },
      get_stderr_pipe() {
        return fixture.makeStream(failure === "stderr" ? [makeBytes("B".repeat(8 * 1024 + 1))] : []);
      },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
    }));

    const { main, subprocesses, runTimeouts } = fixture;
    const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    applet.menu.items[0].activate();
    if (failure === "timeout") runTimeouts();

    assert.equal(subprocesses[0].forceExitCount, 1, `${failure}: exactly once`);
  }
});

test("invalid utf8/json/schema/types do not overwrite last-good", async () => {
  const fixture = loadApplet();
  const good = samplePayload();
  const payloads = [
    null,
    makeBytes("{"),
    makeBytes(JSON.stringify({ ...good, schema_version: 2 })),
    makeBytes(JSON.stringify({ ...good, agents: [{ ...good.agents[0], control_state: "weird" }] })),
    makeBytes("{}"),
    makeBytes(JSON.stringify({ ...good, counts: "bad" })),
    new Uint8Array([0xff, 0x00]),
  ];
  fixture.setProcessFactory(() => {
    const data = makeBytes(JSON.stringify(good));
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return fixture.makeStream([data]); },
      get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) cb(this, null);
      },
    };
  });

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();
  const baseline = JSON.stringify(applet._statusLastGood);

  for (const invalid of payloads) {
    fixture.setProcessFactory(() => ({
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return fixture.makeStream([invalid ?? makeBytes("{}")]); },
      get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) cb(this, null);
      },
    }));
    statusItem.activate();
    fixture.subprocesses.at(-1).emitDone();
    await Promise.resolve();
  }

  assert.equal(JSON.stringify(applet._statusLastGood), baseline);
});

test("stale generation callback cannot overwrite fresh result", async () => {
  const fixture = loadApplet();
  const newer = samplePayload();
  newer.activity_state = "running";
  fixture.setProcessFactory(() => {
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return fixture.makeStream([makeBytes(JSON.stringify(newer))]); },
      get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) cb(this, null);
      },
    };
  });

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet._statusLastGood = newer;
  applet._statusActiveGeneration = 2;
  applet._finalizeStatusProcess({
    generation: 1,
    process: null,
    timeoutSource: 0,
    finalizing: false,
    waitDone: true,
    stdoutDone: true,
    stderrDone: true,
    timedOut: false,
    waitFailed: false,
    stdoutLimitExceeded: false,
    stderrLimitExceeded: false,
  });
  assert.equal(applet._statusLastGood.activity_state, "running");
});

test("readers run via async before wait completion", async () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([makeBytes(JSON.stringify(samplePayload()))], false);
    const stderr = fixture.makeStream([new Uint8Array()]);
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, callback) {
        this.waitCallbacks.push(callback);
        return 0;
      },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) {
          callback(this, null);
        }
      },
    };
  });

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  const proc = fixture.subprocesses[0];
  const stdout = proc.get_stdout_pipe();
  const stderr = proc.get_stderr_pipe();
  assert.equal(stdout.readBytesAsyncCount > 0, true);
  assert.equal(stdout.readBytesSyncCount, 0);
  assert.equal(stderr.readBytesAsyncCount > 0, true);
  assert.equal(stderr.readBytesSyncCount, 0);

  proc.waitCallbacks.at(-1)(proc, null);
  await Promise.resolve();
  assert.equal(applet._statusLastGood.schema_version, 1);
});

test("finalize waits for wait + both stream EOFs", async () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([makeBytes(JSON.stringify(samplePayload()))], true);
    const stderr = fixture.makeStream([new Uint8Array()], true);
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) cb(this, null);
      },
      releaseEof() {
        stdout.releaseEof();
        stderr.releaseEof();
      },
    };
  });

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  const process = fixture.subprocesses[0];
  process.emitDone();
  await Promise.resolve();
  assert.equal(applet._statusLastGood, null);

  process.releaseEof();
  await Promise.resolve();
  assert.equal(applet._statusLastGood.schema_version, 1);
});

test("real backend payload with sleep/available states is accepted", async () => {
  const fixture = loadApplet();
  const payload = samplePayload();
  payload.activity_state = "sleeping";
  payload.backend_state = "unavailable";
  payload.agents[0].backend_state = "error";
  payload.agents[0].identity_state = "unverified";
  payload.agents[1].lease_state = "expired";
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return fixture.makeStream([makeBytes(JSON.stringify(payload))]); },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const cb of callbacks) cb(this, null);
    },
  }));

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;
  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();

  assert.equal(applet._statusLastGood.activity_state, "sleeping");
  assert.equal(applet._statusLastGood.agents[1].lease_state, "expired");
});

test("menu title remains exactly Flottenmanagement", async () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return fixture.makeStream([makeBytes(JSON.stringify(samplePayload()))]); },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const cb of callbacks) cb(this, null);
    },
  }));

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;
  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();

  assert.equal(applet.labels.at(-1), "Flottenmanagement");
});

test("read_bytes_async uses count,priority,cancellable,callback signature", async () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([makeBytes(JSON.stringify(samplePayload()))]);
    const stderr = fixture.makeStream([new Uint8Array()]);
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) {
          callback(this, null);
        }
      },
    };
  });

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  const proc = fixture.subprocesses[0];
  const stdout = proc.get_stdout_pipe();
  const stderr = proc.get_stderr_pipe();

  proc.emitDone();
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(stdout.lastAsyncArgc, 4);
  assert.equal(stderr.lastAsyncArgc, 4);
  assert.equal(stdout.readBytesAsyncArgs[1], 0);
  assert.equal(stderr.readBytesAsyncArgs[1], 0);
});

test("reader callback/finish exception triggers stream failure and no payload", async () => {
  const fixture = loadApplet();
  const payloadText = makeBytes(JSON.stringify(samplePayload()));
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([payloadText]);
    const stderr = fixture.makeStream([new Uint8Array()]);
    stdout.failSyncRead = true;
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) cb(this, null);
      },
    };
  });

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;
  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();
  assert.equal(applet._statusLastGood, null);
  assert.equal(fixture.subprocesses[0].forceExitCount, 1);

  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([payloadText]);
    const stderr = fixture.makeStream([new Uint8Array()]);
    stdout.throwFinish = true;
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) cb(this, null);
      },
    };
  });

  statusItem.activate();
  fixture.subprocesses[1].emitDone();
  await Promise.resolve();
  assert.equal(applet._statusLastGood, null);
  assert.equal(fixture.subprocesses[1].forceExitCount, 1);
});

test("validator rejects missing snapshot state fields", async () => {
  const fixture = loadApplet();
  const payload = samplePayload();
  delete payload.activity_state;
  delete payload.backend_state;
  delete payload.control_state;
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return fixture.makeStream([makeBytes(JSON.stringify(payload))]); },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const cb of callbacks) cb(this, null);
    },
  }));

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;
  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();

  assert.equal(applet._statusLastGood, null);
});

test("validator rejects missing/invalid counts, raw_output and duplicate/foreign agents", async () => {
  const fixture = loadApplet();
  const good = samplePayload();
  const badMissing = JSON.parse(JSON.stringify(good));
  delete badMissing.counts;

  const badNegative = JSON.parse(JSON.stringify(good));
  badNegative.counts.running = -1;

  const badFraction = JSON.parse(JSON.stringify(good));
  badFraction.counts.ready = 1.2;

  const badAgent = JSON.parse(JSON.stringify(good));
  badAgent.agents[0].agent = "a3";

  const badDup = JSON.parse(JSON.stringify(good));
  badDup.agents[1].agent = "a1";

  const badRaw = JSON.parse(JSON.stringify(good));
  badRaw.raw_output = "other";

  const badTopLevelExtra = JSON.parse(JSON.stringify(good));
  badTopLevelExtra.secret = "must-not-be-stored";

  const badRowExtra = JSON.parse(JSON.stringify(good));
  badRowExtra.agents[0].secret = "must-not-be-stored";

  const badRowAggregateState = JSON.parse(JSON.stringify(good));
  badRowAggregateState.agents[0].control_state = "mixed";

  const badMissingAgent = JSON.parse(JSON.stringify(good));
  badMissingAgent.agents.pop();
  badMissingAgent.counts.tracked = 1;

  const badTrackedCount = JSON.parse(JSON.stringify(good));
  badTrackedCount.counts.tracked = 1;

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  const bads = [
    { name: "missing counts", payload: badMissing },
    { name: "negative count", payload: badNegative },
    { name: "fractional count", payload: badFraction },
    { name: "foreign agent", payload: badAgent },
    { name: "duplicate agent", payload: badDup },
    { name: "raw output", payload: badRaw },
    { name: "top-level extra", payload: badTopLevelExtra },
    { name: "row extra", payload: badRowExtra },
    { name: "row aggregate state", payload: badRowAggregateState },
    { name: "missing requested agent", payload: badMissingAgent },
    { name: "tracked count mismatch", payload: badTrackedCount },
  ];

  for (const invalid of bads) {
    fixture.resetFactories();
    fixture.setProcessFactory(() => ({
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return fixture.makeStream([makeBytes(JSON.stringify(invalid.payload))]); },
      get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const cb of callbacks) cb(this, null);
      },
      wait_finish() {},
    }));
    statusItem.activate();
    fixture.subprocesses.at(-1).emitDone();
    assert.equal(applet._statusLastGood, null, invalid.name);
  }
});

test("invalid utf8 byte in stdout is rejected even if JSON shape stays parseable", async () => {
  const fixture = loadApplet();
  const payload = samplePayload();
  const bytes = makeInvalidUtf8PayloadBytes(payload);
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return fixture.makeStream([bytes]); },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const callback of callbacks) callback(this, null);
    },
  }));

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();

  assert.equal(applet._statusLastGood, null);
});

test("reader exceptions set streamFailed, force_exit once, and finalize", async () => {
  const fixture = loadApplet();
  const payload = makeBytes(JSON.stringify(samplePayload()));
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() {
      const stream = fixture.makeStream([payload]);
      stream.failSyncRead = true;
      return stream;
    },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const callback of callbacks) callback(this, null);
    },
  }));

  const { main } = fixture;
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const [statusItem] = applet.menu.items;

  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusLastGood, null);
  assert.equal(fixture.subprocesses[0].forceExitCount, 1);

  fixture.resetFactories();
  fixture.setProcessFactory(() => {
    const stream = fixture.makeStream([payload]);
    stream.throwFinish = true;
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return stream; },
      get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_, cb) { this.waitCallbacks.push(cb); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) callback(this, null);
      },
    };
  });

  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(fixture.subprocesses[0].forceExitCount, 1);
  assert.equal(applet._statusLastGood, null);
});
