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
        backend_state: "degraded",
        control_state: "blocked",
        auth_state: "ready",
        identity_state: "unverified",
        lease_state: "unclaimed",
      },
      {
        agent: "b1",
        activity_state: "sleeping",
        backend_state: "ok",
        control_state: "ready",
        auth_state: "ready",
        identity_state: "stopped",
        lease_state: "unclaimed",
      },
    ],
    raw_output: "not_returned",
  };
}

function realignCounts(payload) {
  const activityStates = payload.agents.map((row) => row.activity_state);
  const controlStates = payload.agents.map((row) => row.control_state);
  const backendStates = payload.agents.map((row) => row.backend_state);
  payload.counts.running = activityStates.filter((state) => state === "running").length;
  payload.counts.sleeping = activityStates.filter((state) => state === "sleeping").length;
  payload.counts.ready = controlStates.filter((state) => state === "ready").length;
  payload.counts.blocked = controlStates.filter((state) => state === "blocked").length;
  payload.counts.issues = payload.agents.filter(
    (row) => row.backend_state !== "ok" || row.control_state !== "ready",
  ).length;
  payload.counts.tracked = payload.agents.length;
  if (activityStates.every((state) => state === "running")) payload.activity_state = "running";
  else if (activityStates.every((state) => state === "sleeping")) payload.activity_state = "sleeping";
  else if (activityStates.every((state) => state === "unknown")) payload.activity_state = "unknown";
  else payload.activity_state = "mixed";
  if (backendStates.every((state) => state === "ok")) payload.backend_state = "ok";
  else if (backendStates.every((state) => state === "error")) payload.backend_state = "unavailable";
  else payload.backend_state = "degraded";
  if (controlStates.every((state) => state === "ready")) payload.control_state = "ready";
  else if (controlStates.every((state) => state === "blocked")) payload.control_state = "blocked";
  else if (controlStates.every((state) => state === "unknown")) payload.control_state = "unknown";
  else payload.control_state = "mixed";
}

function loadApplet() {
  const spawned = [];
  let spawnError = null;
  const launcherSpawns = [];
  const subprocesses = [];
  const pendingFactories = [];
  const timeouts = [];
  const settingsInstances = [];
  const settingsBindFailures = new Set();
  let settingsFinalizeFailures = 0;
  const settingsValues = {
    "tracked-agents": "a1,b1",
    "refresh-on-open": true,
    "background-refresh": false,
    "refresh-interval-seconds": 60,
  };
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
    constructor(label, options = {}) {
      this.label = label;
      this.reactive = options.reactive !== false;
      this.actor = {
        visible: true,
        show: () => { this.actor.visible = true; },
        hide: () => { this.actor.visible = false; },
      };
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
      this.spawnRequests.push({
        argv,
        envCalls: [...this.envCalls],
        unsetCalls: [...this.unsetCalls],
        process,
      });
      launcherSpawns.push(this.spawnRequests.at(-1));
      subprocesses.push(process);
      return process;
    }
  }

  class FakeAppletSettings {
    constructor(target, uuid, instanceId) {
      this.target = target;
      this.uuid = uuid;
      this.instanceId = instanceId;
      this.bindings = new Map();
      this.finalizeCount = 0;
      this.saveCount = 0;
      settingsInstances.push(this);
    }
    bindProperty(_direction, key, property, callback) {
      if (settingsBindFailures.has(key)) return false;
      this.bindings.set(key, { property, callback });
      Object.defineProperty(this.target, property, {
        configurable: true,
        enumerable: true,
        get: () => settingsValues[key],
        set: (value) => {
          if (settingsValues[key] !== value) {
            settingsValues[key] = value;
            this.saveCount += 1;
          }
        },
      });
      return true;
    }
    finalize() {
      this.finalizeCount += 1;
      if (settingsFinalizeFailures > 0) {
        settingsFinalizeFailures -= 1;
        throw new Error("injected settings finalize failure");
      }
      for (const binding of this.bindings.values()) {
        delete this.target[binding.property];
      }
      this.bindings.clear();
    }
    set(key, value) {
      settingsValues[key] = value;
      const binding = this.bindings.get(key);
      if (!binding) return;
      if (binding.callback) binding.callback();
    }
  }

  class FakeCancellable {
    constructor() { this.cancelCount = 0; }
    cancel() { this.cancelCount += 1; }
  }

  const GLib = {
    PRIORITY_DEFAULT: 0,
    SOURCE_REMOVE: false,
    SOURCE_CONTINUE: true,
    get_home_dir() { return home; },
    timeout_add(_priority, _ms, callback) {
      const id = timeoutId += 1;
      timeouts.push({ id, callback, cancelled: false, kind: "timeout" });
      return id;
    },
    timeout_add_seconds(_priority, seconds, callback) {
      const id = timeoutId += 1;
      timeouts.push({ id, callback, cancelled: false, kind: "background", seconds });
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
    Cancellable: FakeCancellable,
  };

  const Settings = {
    AppletSettings: FakeAppletSettings,
    BindingDirection: { IN: 1 },
  };

  const context = {
    imports: {
      gi: { Gio, GLib },
      mainloop: Mainloop,
      ui: {
        applet: { TextApplet, AppletPopupMenu },
        popupMenu: { PopupMenuItem, PopupMenuManager },
        settings: Settings,
      },
      misc: { util: { spawn(args) {
        if (spawnError) throw spawnError;
        spawned.push(args);
      } } },
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
    Gio,
    GLib,
    spawned,
    launcherSpawns,
    subprocesses,
    pendingFactories,
    timeouts,
    settingsInstances,
    runTimeouts() { return Mainloop.runTimeouts(); },
    setSpawnError(message) { spawnError = new Error(message); },
    setGlobalLogger(logger) { context.global = { logError: logger }; },
    setHome(value) { home = value; },
    guardOversizedStringSplit(maxLength) {
      context.__splitGuardMaxLength = maxLength;
      vm.runInNewContext(`
        globalThis.__originalStringSplit = String.prototype.split;
        String.prototype.split = function (...args) {
          if (this.length > globalThis.__splitGuardMaxLength) {
            throw new Error("oversized string reached split");
          }
          return globalThis.__originalStringSplit.apply(this, args);
        };
      `, context);
    },
    rejectSettingsBinding(key) { settingsBindFailures.add(key); },
    failSettingsFinalizes(count) { settingsFinalizeFailures = count; },
    setProcessFactory(factory) { pendingFactories.push(factory); },
    resetFactories() { pendingFactories.length = 0; },
    setSetting(key, value) {
      const settings = settingsInstances.at(-1);
      if (settings) settings.set(key, value);
      else settingsValues[key] = value;
    },
    activeTimers(kind) {
      return timeouts.filter((entry) => !entry.cancelled && (!kind || entry.kind === kind));
    },
    makeStream(chunks, holdEof = false) {
      const stream = new FakeInputStream(chunks);
      stream.holdEof = holdEof;
      return stream;
    },
  };
}

function queuePayloadProcess(fixture, payload, { exitCode = 0, holdEof = false } = {}) {
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([makeBytes(JSON.stringify(payload))], holdEof);
    const stderr = fixture.makeStream([], holdEof);
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => exitCode === 0,
      get_exit_status: () => exitCode,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) callback(this, null);
      },
    };
  });
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

test("settings launcher failure stays inside menu callback", () => {
  const fixture = loadApplet();
  fixture.setSpawnError("injected cinnamon-settings spawn failure");
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  assert.doesNotThrow(() => applet.menu.items[1].activate());
  assert.equal(fixture.spawned.length, 0);
  assert.equal(applet.labels.at(-1), "Flottenmanagement");
});

test("single removal retries transient menu cleanup failures", () => {
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

    assert.equal(applet._cleanupComplete, true);
    assert.equal(menu.destroyed, true);
    assert.equal(manager.destroyed, true);
    assert.equal(menu.isOpen, false);
    assert.equal(applet.menu, null);
    assert.equal(applet.menuManager, null);
    assert.equal(manager.grabbed, false);
    assert.doesNotThrow(() => applet.on_applet_removed_from_panel());
  }
});

test("removal releases status actor wrapper references", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  assert.notEqual(applet._statusSummaryItem, null);
  assert.equal(applet._statusRowItems.length, 6);

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, true);
  assert.equal(applet._statusSummaryItem, null);
  assert.equal(applet._statusRowItems.length, 0);
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
  assert.deepEqual(Array.from(launch.envCalls), [
    { key: "PATH", value: "/usr/bin:/bin", overwrite: true },
    { key: "HOME", value: "/tmp/home", overwrite: true },
  ]);
  for (const key of ["BASH_ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "GJS_PATH"]) {
    assert.ok(launch.unsetCalls.includes(key), `strips ${key}`);
  }
});

test("argv preparation failure stays inside refresh callback", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.GLib.get_home_dir = () => { throw new Error("injected home lookup failure"); };

  assert.doesNotThrow(() => applet.menu.items[0].activate());

  assert.equal(fixture.launcherSpawns.length, 0);
  assert.equal(fixture.subprocesses.length, 0);
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusViewState, "unavailable");
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

test("stdout cap, stderr cap, and timeout each cancel and force_exit exactly once", () => {
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
    const cancellable = applet._statusActiveState.cancellable;
    if (failure === "timeout") runTimeouts();

    assert.equal(subprocesses[0].forceExitCount, 1, `${failure}: exactly once`);
    assert.equal(cancellable.cancelCount, 1, `${failure}: cancellation exactly once`);
  }
});

test("status buffering retains chunks instead of one JS array element per byte", () => {
  const fixture = loadApplet();
  const stdout = fixture.makeStream(
    Array.from({ length: 32 }, () => makeBytes("A".repeat(1024))),
    true
  );
  const stderr = fixture.makeStream([], true);
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return stdout; },
    get_stderr_pipe() { return stderr; },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, callback) { this.waitCallbacks.push(callback); },
  }));

  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();

  const state = applet._statusActiveState;
  assert.equal(state.stdoutByteCount, 32 * 1024);
  assert.equal(state.stdoutChunks.length, 32);
  assert.ok(state.stdoutChunks.every((chunk) => chunk.byteLength === 1024));
});

test("stdout overflow releases accumulated status data before process exit", () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() {
      return fixture.makeStream([makeBytes("A".repeat(64 * 1024 + 1))], true);
    },
    get_stderr_pipe() { return fixture.makeStream([], true); },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, callback) { this.waitCallbacks.push(callback); },
  }));

  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();

  const state = applet._statusActiveState;
  assert.equal(state.stdoutLimitExceeded, true);
  assert.equal(state.stdoutByteCount, 0);
  assert.equal(state.stdoutChunks.length, 0);
});

test("late stdout after timeout is drained without rebuilding the status buffer", () => {
  const fixture = loadApplet();
  let delayedStdoutCallback = null;
  const stdout = {
    read_bytes_async(_size, _priority, _cancellable, callback) {
      delayedStdoutCallback = callback;
    },
    read_bytes_finish(packet) { return packet; },
  };
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return stdout; },
    get_stderr_pipe() { return fixture.makeStream([], true); },
    get_successful: () => true,
    get_exit_status: () => 0,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, callback) { this.waitCallbacks.push(callback); },
  }));

  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  fixture.runTimeouts();

  const data = makeBytes("A".repeat(1024));
  delayedStdoutCallback(stdout, {
    get_data: () => data,
    get_size: () => data.length,
  });

  assert.equal(applet._statusActiveState.stdoutByteCount, 0);
  assert.equal(applet._statusActiveState.stdoutChunks.length, 0);
});

test("status timeout registration failure fails closed without leaking process state", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload(), { holdEof: true });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.GLib.timeout_add = () => { throw new Error("injected timeout registration failure"); };

  assert.doesNotThrow(() => applet.menu.items[0].activate());

  const process = fixture.subprocesses[0];
  assert.equal(process.forceExitCount, 1);
  assert.equal(fixture.activeTimers("timeout").length, 0);
  assert.equal(applet._statusLastGood, null);

  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
});

test("cancellable construction failure keeps the process managed", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload());
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.Gio.Cancellable = class {
    constructor() { throw new Error("injected cancellable construction failure"); }
  };

  assert.doesNotThrow(() => applet.menu.items[0].activate());

  assert.equal(fixture.subprocesses[0].forceExitCount, 0);
  assert.equal(applet._statusInFlight, true);
  assert.equal(applet._statusActiveState.cancellable, null);
  fixture.subprocesses[0].emitDone();
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(fixture.activeTimers().length, 0);
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

test("timeout removal failure defers finalization to timer without wedging", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload());
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];
  fixture.GLib.source_remove = () => { throw new Error("injected timeout removal failure"); };

  assert.doesNotThrow(() => process.emitDone());

  assert.equal(applet._statusInFlight, true);
  assert.equal(applet._statusActiveState.finalizing, false);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  fixture.runTimeouts();
  assert.equal(process.forceExitCount, 1);
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusLastGood, null);
  assert.equal(fixture.activeTimers("timeout").length, 0);
});

test("real backend payload with sleeping and expired states is accepted", async () => {
  const fixture = loadApplet();
  const payload = samplePayload();
  payload.activity_state = "sleeping";
  payload.backend_state = "ok";
  payload.agents[0].activity_state = "sleeping";
  payload.agents[0].control_state = "ready";
  payload.agents[0].auth_state = "ready";
  payload.agents[0].identity_state = "stopped";
  payload.agents[0].backend_state = "ok";
  payload.agents[1].backend_state = "ok";
  payload.agents[1].lease_state = "expired";
  payload.agents[1].control_state = "ready";
  payload.agents[1].auth_state = "ready";
  realignCounts(payload);
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

test("exact python error row is accepted and aggregates to python unavailable snapshot", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = {
    schema_version: 1,
    mode: "read_only",
    activity_state: "unknown",
    backend_state: "unavailable",
    control_state: "unknown",
    counts: {
      tracked: 2,
      running: 0,
      sleeping: 0,
      ready: 0,
      blocked: 0,
      issues: 2,
    },
    agents: [
      {
        agent: "a1",
        activity_state: "unknown",
        backend_state: "error",
        control_state: "unknown",
        auth_state: "unknown",
        identity_state: "unknown",
        lease_state: "unreadable",
      },
      {
        agent: "b1",
        activity_state: "unknown",
        backend_state: "error",
        control_state: "unknown",
        auth_state: "unknown",
        identity_state: "unknown",
        lease_state: "unreadable",
      },
    ],
    raw_output: "not_returned",
  };

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(applet._statusLastGood.activity_state, "unknown");
  assert.equal(applet._statusLastGood.backend_state, "unavailable");
  assert.equal(applet._statusLastGood.control_state, "unknown");
  assert.equal(applet._statusLastGood.counts.issues, 2);
});

test("exact python error row mixed with a normal row is accepted", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = {
    schema_version: 1,
    mode: "read_only",
    activity_state: "mixed",
    backend_state: "degraded",
    control_state: "mixed",
    counts: {
      tracked: 2,
      running: 0,
      sleeping: 1,
      ready: 1,
      blocked: 0,
      issues: 1,
    },
    agents: [
      {
        agent: "a1",
        activity_state: "unknown",
        backend_state: "error",
        control_state: "unknown",
        auth_state: "unknown",
        identity_state: "unknown",
        lease_state: "unreadable",
      },
      {
        agent: "b1",
        activity_state: "sleeping",
        backend_state: "ok",
        control_state: "ready",
        auth_state: "ready",
        identity_state: "stopped",
        lease_state: "unclaimed",
      },
    ],
    raw_output: "not_returned",
  };

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.deepEqual(
    {
      activity_state: applet._statusLastGood.activity_state,
      backend_state: applet._statusLastGood.backend_state,
      control_state: applet._statusLastGood.control_state,
      counts: applet._statusLastGood.counts,
    },
    {
      activity_state: "mixed",
      backend_state: "degraded",
      control_state: "mixed",
      counts: {
        tracked: 2,
        running: 0,
        sleeping: 1,
        ready: 1,
        blocked: 0,
        issues: 1,
      },
    },
  );
});

test("exact python stopped-orphan row is accepted", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();
  payload.agents[0].activity_state = "sleeping";
  realignCounts(payload);

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(applet._statusLastGood.activity_state, "sleeping");
  assert.deepEqual(applet._statusLastGood.agents[0], {
    agent: "a1",
    activity_state: "sleeping",
    backend_state: "degraded",
    control_state: "blocked",
    auth_state: "ready",
    identity_state: "unverified",
    lease_state: "unclaimed",
  });
});

test("validator rejects syntactically valid but backend-impossible row combinations", async () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const base = samplePayload();
  const valid = JSON.parse(JSON.stringify(base));
  assert.equal(applet._maybeApplyStatusPayload(valid), true);

  const stale = JSON.parse(JSON.stringify(base));
  stale.agents[0].activity_state = "running";
  stale.agents[0].identity_state = "stopped";
  stale.agents[0].backend_state = "degraded";
  stale.agents[0].control_state = "ready";
  stale.agents[0].auth_state = "ready";
  stale.agents[1].control_state = "ready";
  stale.agents[1].auth_state = "ready";
  realignCounts(stale);

  const mixedRow = JSON.parse(JSON.stringify(base));
  mixedRow.agents[1].activity_state = "sleeping";
  mixedRow.agents[1].identity_state = "verified";
  mixedRow.agents[1].backend_state = "ok";
  mixedRow.agents[1].control_state = "blocked";
  mixedRow.agents[1].auth_state = "blocked";
  mixedRow.agents[1].lease_state = "unclaimed";
  mixedRow.agents[1].control_state = "blocked";
  realignCounts(mixedRow);

  const backendError = JSON.parse(JSON.stringify(base));
  backendError.agents[1].backend_state = "error";
  realignCounts(backendError);

  const wrongControl = JSON.parse(JSON.stringify(base));
  wrongControl.agents[0].identity_state = "unverified";
  wrongControl.agents[0].control_state = "ready";
  realignCounts(wrongControl);

  const wrongSleepingBackend = JSON.parse(JSON.stringify(base));
  wrongSleepingBackend.agents[0].activity_state = "sleeping";
  wrongSleepingBackend.agents[0].backend_state = "ok";
  realignCounts(wrongSleepingBackend);

  const invalidErrorShape = JSON.parse(JSON.stringify(base));
  invalidErrorShape.agents[0].activity_state = "unknown";
  invalidErrorShape.agents[0].backend_state = "error";
  invalidErrorShape.agents[0].control_state = "ready";
  invalidErrorShape.agents[0].lease_state = "held";
  invalidErrorShape.agents[0].identity_state = "unknown";
  invalidErrorShape.agents[0].auth_state = "ready";
  realignCounts(invalidErrorShape);

  const cases = [
    { name: "running with stopped identity", payload: stale },
    { name: "sleeping with verified identity", payload: mixedRow },
    { name: "backend error with non-error shape", payload: backendError },
    { name: "running unverified not blocked", payload: wrongControl },
    { name: "sleeping unverified with healthy backend", payload: wrongSleepingBackend },
    { name: "non-exact error row", payload: invalidErrorShape },
  ];

  for (const { name, payload } of cases) {
    assert.equal(applet._maybeApplyStatusPayload(payload), false, name);
    assert.equal(applet._statusLastGood?.schema_version, 1);
  }
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

  const badRunningCount = JSON.parse(JSON.stringify(good));
  badRunningCount.counts.running = 0;

  const badIssueCount = JSON.parse(JSON.stringify(good));
  badIssueCount.counts.issues = 0;

  const badActivityAggregate = JSON.parse(JSON.stringify(good));
  badActivityAggregate.activity_state = "running";

  const badBackendAggregate = JSON.parse(JSON.stringify(good));
  badBackendAggregate.backend_state = "ok";

  const badControlAggregate = JSON.parse(JSON.stringify(good));
  badControlAggregate.control_state = "ready";

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
    { name: "running count mismatch", payload: badRunningCount },
    { name: "issue count mismatch", payload: badIssueCount },
    { name: "activity aggregate mismatch", payload: badActivityAggregate },
    { name: "backend aggregate mismatch", payload: badBackendAggregate },
    { name: "control aggregate mismatch", payload: badControlAggregate },
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

test("packet accessor exceptions fail closed and refresh recovers", async () => {
  const fixture = loadApplet();
  const brokenStream = {
    callback: null,
    read_bytes_async(_size, _priority, _cancellable, callback) {
      this.callback = callback;
    },
    read_bytes_finish() {
      return {
        get_data() { throw new Error("injected packet data failure"); },
        get_size() { return 1; },
      };
    },
    emitPacket() {
      const callback = this.callback;
      this.callback = null;
      callback(this, {});
    },
  };
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return brokenStream; },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful: () => false,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const callback of callbacks) callback(this, null);
    },
  }));

  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusItem = applet.menu.items[0];

  assert.doesNotThrow(() => statusItem.activate());
  assert.doesNotThrow(() => brokenStream.emitPacket());
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();
  assert.equal(fixture.subprocesses[0].forceExitCount, 1);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusInFlight, false);

  queuePayloadProcess(fixture, samplePayload());
  statusItem.activate();
  fixture.subprocesses[1].emitDone();
  await Promise.resolve();
  assert.equal(applet._statusLastGood.schema_version, 1);
});

test("pipe accessor exceptions fail closed and refresh recovers", async () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { throw new Error("injected stdout accessor failure"); },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful: () => false,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const callback of callbacks) callback(this, null);
    },
  }));

  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusItem = applet.menu.items[0];

  assert.doesNotThrow(() => statusItem.activate());
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();

  assert.equal(fixture.subprocesses[0].forceExitCount, 1);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusLastGood, null);

  queuePayloadProcess(fixture, samplePayload());
  statusItem.activate();
  fixture.subprocesses[1].emitDone();
  await Promise.resolve();
  assert.equal(applet._statusLastGood.schema_version, 1);
});

test("process success accessor exceptions fail closed and pending refresh recovers", async () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() {
      return fixture.makeStream([makeBytes(JSON.stringify(samplePayload()))]);
    },
    get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
    get_successful() { throw new Error("injected process success failure"); },
    force_exit() { this.forceExitCount += 1; },
    wait_async(_, cb) { this.waitCallbacks.push(cb); },
    wait_finish() {},
    emitDone() {
      const callbacks = [...this.waitCallbacks];
      this.waitCallbacks = [];
      for (const callback of callbacks) callback(this, null);
    },
  }));

  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusItem = applet.menu.items[0];
  statusItem.activate();
  const failedProcess = fixture.subprocesses[0];
  queuePayloadProcess(fixture, samplePayload());
  statusItem.activate();

  assert.doesNotThrow(() => failedProcess.emitDone());
  await Promise.resolve();
  assert.equal(fixture.subprocesses.length, 2);
  assert.equal(applet._statusViewState, "initializing");

  fixture.subprocesses[1].emitDone();
  await Promise.resolve();
  assert.equal(applet._statusLastGood.schema_version, 1);
  assert.equal(applet._statusViewState, "ready");
});

test("final render exception cannot block cleanup or pending refresh", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload());
  queuePayloadProcess(fixture, samplePayload());
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const originalRender = applet._renderStatus.bind(applet);
  let renderCalls = 0;
  applet._renderStatus = () => {
    renderCalls += 1;
    if (renderCalls === 2) throw new Error("injected final render failure");
    return originalRender();
  };

  const statusItem = applet.menu.items[0];
  statusItem.activate();
  statusItem.activate();

  assert.doesNotThrow(() => fixture.subprocesses[0].emitDone());
  assert.equal(fixture.subprocesses.length, 2);
  assert.equal(applet._statusPendingRefresh, false);

  fixture.subprocesses[1].emitDone();
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusViewState, "ready");
});

test("logger failure cannot pierce the status render boundary", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload());
  queuePayloadProcess(fixture, samplePayload());
  fixture.setGlobalLogger(() => { throw new Error("injected logger failure"); });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const originalRender = applet._renderStatus.bind(applet);
  let renderCalls = 0;
  applet._renderStatus = () => {
    renderCalls += 1;
    if (renderCalls === 2) throw new Error("injected final render failure");
    return originalRender();
  };

  const statusItem = applet.menu.items[0];
  statusItem.activate();
  statusItem.activate();

  assert.doesNotThrow(() => fixture.subprocesses[0].emitDone());
  assert.equal(fixture.subprocesses.length, 2);
  fixture.subprocesses[1].emitDone();
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusViewState, "ready");
});

test("cleanup logging has a fixed Cinnamon heap budget", () => {
  const fixture = loadApplet();
  let logCalls = 0;
  fixture.setGlobalLogger(() => { logCalls += 1; });
  const applets = [
    fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1),
    fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 2),
  ];
  for (const applet of applets) {
    applet._renderStatus = () => { throw new Error("persistent render failure"); };
  }

  for (let attempt = 0; attempt < 100; attempt += 1) {
    assert.equal(applets[attempt % applets.length]._renderStatusSafely(), false);
  }

  assert.equal(logCalls, 8);
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

test("task 5 settings schema contains exactly four bounded settings", () => {
  const schemaPath = path.join(root, "cinnamon/applets/codex-master@H234598/settings-schema.json");
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

  assert.deepEqual(Object.keys(schema).sort(), [
    "background-refresh",
    "refresh-interval-seconds",
    "refresh-on-open",
    "tracked-agents",
  ]);
  assert.equal(schema["tracked-agents"].default, "a1,b1");
  assert.equal(schema["refresh-on-open"].default, true);
  assert.equal(schema["background-refresh"].default, false);
  assert.deepEqual(
    {
      default: schema["refresh-interval-seconds"].default,
      min: schema["refresh-interval-seconds"].min,
      max: schema["refresh-interval-seconds"].max,
    },
    { default: 60, min: 15, max: 3600 },
  );
});

test("settings parser canonicalizes bounded concrete ids and never launches attacker text", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  assert.equal(fixture.settingsInstances.length, 1);
  assert.deepEqual(Array.from(applet._trackedAgents), ["a1", "b1"]);

  fixture.setSetting("tracked-agents", " A2, b3, a2, C100 ");
  assert.deepEqual(Array.from(applet._trackedAgents), ["a2", "b3", "c100"]);
  applet.menu.items[0].activate();
  assert.deepEqual(Array.from(fixture.launcherSpawns.at(-1).argv.slice(2)), ["a2", "b3", "c100"]);

  fixture.setSetting("tracked-agents", "a1;--force /tmp/owned");
  assert.deepEqual(Array.from(applet._trackedAgents), ["a1", "b1"]);
  assert.equal(applet._settingsValid, false);
  assert.match(applet._statusSummaryItem.label, /Konfiguration/);
  applet.menu.items[0].activate();
  fixture.subprocesses[0].emitDone();
  const argv = fixture.launcherSpawns.at(-1).argv;
  assert.deepEqual(Array.from(argv.slice(2)), ["a1", "b1"]);
  assert.ok(!argv.join(" ").includes("--force"));
  assert.ok(!argv.join(" ").includes("/tmp/owned"));
  fixture.setSetting("background-refresh", true);
  assert.equal(fixture.activeTimers("background").length, 0, "invalid settings disable background work");
});

test("oversized tracked-agent setting is rejected before string splitting", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.guardOversizedStringSplit(128);
  const oversized = "a1,".repeat(64) + "a1";

  assert.doesNotThrow(() => fixture.setSetting("tracked-agents", oversized));
  assert.equal(applet._settingsValid, false);
  assert.deepEqual(Array.from(applet._trackedAgents), ["a1", "b1"]);
  assert.equal(fixture.activeTimers("background").length, 0);
});

test("rejected settings binding finalizes partial settings and fails closed", () => {
  const fixture = loadApplet();
  fixture.rejectSettingsBinding("background-refresh");

  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  assert.equal(fixture.settingsInstances[0].finalizeCount, 1);
  assert.equal(applet.settings, null);
  assert.equal(applet._settingsValid, false);
  assert.deepEqual(Array.from(applet._trackedAgents), ["a1", "b1"]);
  assert.equal(fixture.activeTimers("background").length, 0);
  assert.match(applet._statusSummaryItem.label, /Konfiguration/);
});

test("failed partial settings finalization stays owned and retryable", () => {
  for (const finalizeFailures of [1, 2]) {
    const fixture = loadApplet();
    fixture.rejectSettingsBinding("background-refresh");
    fixture.failSettingsFinalizes(finalizeFailures);

    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, finalizeFailures);
    const settings = fixture.settingsInstances[0];

    assert.equal(settings.finalizeCount, 2);
    assert.equal(applet.settings, null);
    assert.equal(applet._settingsValid, false);
    assert.equal(fixture.activeTimers("background").length, 0);
    if (finalizeFailures === 1) {
      assert.equal(applet._settingsCleanupPending, null);
      assert.equal(settings.bindings.size, 0);
    } else {
      assert.equal(applet._settingsCleanupPending, settings);
      assert.ok(settings.bindings.size > 0);
      settings.set("refresh-on-open", false);
      assert.equal(applet._settingsValid, false);
      assert.equal(fixture.activeTimers("background").length, 0);
    }

    applet.on_applet_removed_from_panel();
    assert.equal(applet._cleanupComplete, true);
    assert.equal(applet._settingsCleanupPending, null);
    assert.equal(settings.bindings.size, 0);
  }
});

test("scalar setting normalization never writes through Cinnamon bindings", () => {
  const cases = [
    { key: "refresh-on-open", value: "yes", property: "refreshOnOpen", expected: true, valid: false },
    { key: "background-refresh", value: "yes", property: "backgroundRefresh", expected: false, valid: false },
    { key: "refresh-interval-seconds", value: 5, property: "refreshIntervalSeconds", expected: 15, valid: true },
    { key: "refresh-interval-seconds", value: "5", property: "refreshIntervalSeconds", expected: 60, valid: false },
  ];

  for (const item of cases) {
    const fixture = loadApplet();
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    const settings = fixture.settingsInstances[0];

    fixture.setSetting(item.key, item.value);

    assert.equal(settings.saveCount, 0, item.key);
    assert.equal(applet[item.property], item.expected, item.key);
    assert.equal(applet._settingsValid, item.valid, item.key);
    assert.equal(fixture.activeTimers("background").length, 0, item.key);
  }
});

test("read-only UI keeps title and separates activity backend and stale state", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(applet.labels.at(-1), "Flottenmanagement");
  assert.match(applet.tooltips.at(-1), /Aktivität/);
  assert.match(applet.tooltips.at(-1), /Backend/);
  assert.match(applet.tooltips.at(-1), /Nur Lesen/);
  assert.match(applet._statusSummaryItem.label, /Nur Lesen/);
  assert.equal(applet._statusRowItems.filter((item) => item.actor.visible).length, 2);
  assert.ok(applet._statusRowItems[0].label.startsWith("a1:"));
  assert.ok(applet._statusRowItems[1].label.startsWith("b1:"));
  assert.ok(!applet.menu.items.some((item) => /Start|Stop|Interrupt/.test(item.label)));

  applet._markRefreshFailed();
  assert.match(applet._statusSummaryItem.label, /veraltet/i);
  assert.equal(applet.labels.at(-1), "Flottenmanagement");

  fixture.setSetting("tracked-agents", "a2");
  assert.equal(applet._statusLastGood, null, "fleet change clears old fleet snapshot");
  assert.equal(applet._statusRowItems.filter((item) => item.actor.visible).length, 1);
  assert.ok(applet._statusRowItems[0].label.startsWith("a2:"));
});

test("refresh-on-open and bounded opt-in background timer preserve single-flight", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  applet.on_applet_clicked();
  assert.equal(fixture.subprocesses.length, 1, "default refresh-on-open starts one refresh");

  fixture.setSetting("refresh-interval-seconds", 5);
  fixture.setSetting("background-refresh", true);
  const background = fixture.activeTimers("background");
  assert.equal(background.length, 1);
  assert.equal(background[0].seconds, 15);
  background[0].callback();
  assert.equal(fixture.subprocesses.length, 1, "timer cannot overlap active refresh");
  assert.equal(applet._statusPendingRefresh, true);

  fixture.subprocesses[0].emitDone();
  assert.equal(fixture.subprocesses.length, 2, "pending refresh is coalesced once");
  fixture.setSetting("background-refresh", false);
  assert.equal(fixture.activeTimers("background").length, 0);
});

test("background timer registration failure does not prevent applet load", () => {
  const fixture = loadApplet();
  fixture.setSetting("background-refresh", true);
  fixture.GLib.timeout_add_seconds = () => { throw new Error("injected background timer failure"); };
  let applet = null;

  assert.doesNotThrow(() => {
    applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  });

  assert.equal(applet._backgroundRefreshSource, 0);
  assert.equal(fixture.activeTimers("background").length, 0);
  assert.equal(applet._settingsValid, false);
  assert.match(applet._statusSummaryItem.label, /Konfigurationsfehler/);
});

test("background timer removal failure cannot keep disabled refresh running", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.setSetting("background-refresh", true);
  assert.equal(fixture.activeTimers("background").length, 1);
  fixture.GLib.source_remove = () => { throw new Error("injected background removal failure"); };

  assert.doesNotThrow(() => fixture.setSetting("background-refresh", false));

  assert.equal(applet._settingsValid, false);
  assert.equal(applet._backgroundRefreshSource > 0, true);
  assert.equal(fixture.subprocesses.length, 0);
  fixture.runTimeouts();
  assert.equal(applet._backgroundRefreshSource, 0);
  assert.equal(fixture.activeTimers("background").length, 0);
  assert.equal(fixture.subprocesses.length, 0);
});

test("failed refresh keeps last-good visibly stale", () => {
  const fixture = loadApplet();
  const payload = samplePayload();
  queuePayloadProcess(fixture, payload);
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusItem = applet.menu.items[0];

  statusItem.activate();
  fixture.subprocesses[0].emitDone();
  assert.equal(applet._statusLastGood.activity_state, payload.activity_state);
  assert.doesNotMatch(applet._statusSummaryItem.label, /veraltet/i);

  queuePayloadProcess(fixture, payload, { exitCode: 1 });
  statusItem.activate();
  fixture.subprocesses[1].emitDone();
  assert.equal(applet._statusLastGood.activity_state, payload.activity_state);
  assert.match(applet._statusSummaryItem.label, /veraltet/i);
});

test("removal during stream timeout and pending refresh tears down once", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload(), { holdEof: true });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.setSetting("background-refresh", true);
  const statusItem = applet.menu.items[0];

  statusItem.activate();
  statusItem.activate();
  const process = fixture.subprocesses[0];
  const cancellable = applet._statusActiveState.cancellable;
  assert.equal(applet._statusPendingRefresh, true);

  applet.on_applet_removed_from_panel();
  applet.on_applet_removed_from_panel();

  assert.equal(process.forceExitCount, 1);
  assert.equal(cancellable.cancelCount, 1);
  assert.equal(fixture.activeTimers().length, 0);
  assert.equal(applet._statusPendingRefresh, false);
  assert.equal(fixture.settingsInstances[0].finalizeCount, 1);
  assert.equal(applet.menu, null);

  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();
  assert.equal(fixture.subprocesses.length, 1, "stale callbacks start no follow-up process");
  assert.equal(process.forceExitCount, 1);
  assert.equal(fixture.settingsInstances[0].finalizeCount, 1);
});

test("background cleanup failure does not retain cleaned status process", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload(), { holdEof: true });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.setSetting("background-refresh", true);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];
  const cancellable = applet._statusActiveState.cancellable;
  const backgroundId = fixture.activeTimers("background")[0].id;
  const realSourceRemove = fixture.GLib.source_remove;
  fixture.GLib.source_remove = (id) => {
    if (id === backgroundId) throw new Error("injected background cleanup failure");
    return realSourceRemove(id);
  };

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, false);
  assert.equal(process.forceExitCount, 1);
  assert.equal(cancellable.cancelCount, 1);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._activeStatusProcess, null);
  fixture.runTimeouts();
  assert.equal(applet._backgroundRefreshSource, 0);
  assert.equal(fixture.activeTimers().length, 0);
});

test("single removal retries a failed force_exit without losing process state", () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([], true);
    const stderr = fixture.makeStream([], true);
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() {
        this.forceExitCount += 1;
        if (this.forceExitCount === 1) throw new Error("injected force_exit failure");
      },
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() {},
    };
  });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];

  applet.on_applet_removed_from_panel();
  assert.equal(process.forceExitCount, 2);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._cleanupComplete, true);
  applet.on_applet_removed_from_panel();
  assert.equal(process.forceExitCount, 2);
});

test("timeout retries force_exit failure and refresh recovers", () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([], true);
    const stderr = fixture.makeStream([], true);
    return {
      forceExitCount: 0,
      waitCallbacks: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() {
        this.forceExitCount += 1;
        if (this.forceExitCount === 1) throw new Error("injected timeout force failure");
      },
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) callback(this, null);
      },
    };
  });
  queuePayloadProcess(fixture, samplePayload());
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusItem = applet.menu.items[0];
  statusItem.activate();
  const process = fixture.subprocesses[0];

  assert.doesNotThrow(() => fixture.runTimeouts());
  assert.equal(process.forceExitCount, 1);
  assert.equal(applet._statusActiveState.forceExitCalled, false);
  assert.equal(fixture.activeTimers("timeout").length, 1, "failed force_exit keeps retry timer");

  statusItem.activate();
  assert.equal(applet._statusPendingRefresh, true);
  fixture.runTimeouts();
  assert.equal(process.forceExitCount, 2);
  assert.equal(applet._statusActiveState.forceExitCalled, true);
  assert.equal(applet._statusActiveState.timeoutSource, 0);
  assert.equal(fixture.activeTimers("timeout").length, 0);

  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();
  assert.equal(fixture.subprocesses.length, 2, "pending refresh starts after recovered timeout cleanup");
  fixture.subprocesses[1].emitDone();
  assert.equal(applet._statusInFlight, false);
});

test("500 completed refreshes leave no active resources", async () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusItem = applet.menu.items[0];

  for (let cycle = 0; cycle < 500; cycle += 1) {
    queuePayloadProcess(fixture, samplePayload());
    statusItem.activate();
    const process = fixture.subprocesses.at(-1);
    process.emitDone();
    await Promise.resolve();

    assert.equal(applet._statusInFlight, false, `cycle ${cycle}: in-flight`);
    assert.equal(applet._statusPendingRefresh, false, `cycle ${cycle}: pending`);
    assert.equal(applet._statusActiveState, null, `cycle ${cycle}: active state`);
    assert.equal(applet._activeStatusProcess, null, `cycle ${cycle}: active process`);
    assert.equal(fixture.activeTimers().length, 0, `cycle ${cycle}: timer`);
    assert.equal(process.waitCallbacks.length, 0, `cycle ${cycle}: wait callback`);
    assert.equal(process.stdout._holdCallbacks.length, 0, `cycle ${cycle}: stdout callback`);
    assert.equal(process.stderr._holdCallbacks.length, 0, `cycle ${cycle}: stderr callback`);
  }

  assert.equal(fixture.subprocesses.length, 500);
});

test("100 injected add-remove cycles release processes streams signals timers and grabs", () => {
  const failures = ["close", "remove", "menu-destroy", "manager-destroy"];

  for (let cycle = 0; cycle < 100; cycle += 1) {
    const fixture = loadApplet();
    queuePayloadProcess(fixture, samplePayload(), { holdEof: true });
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, cycle + 1);
    const menu = applet.menu;
    const manager = applet.menuManager;
    const contextMenu = applet._applet_context_menu;
    const contextManager = applet._menuManager;
    const failure = failures[cycle % failures.length];

    fixture.setSetting("background-refresh", true);
    applet.on_applet_clicked();
    contextMenu.toggle();
    manager.grabbed = true;
    manager._activeMenu = menu;
    contextManager.grabbed = true;
    contextManager._activeMenu = contextMenu;
    if (failure === "close") menu.failCloseCount = 1;
    if (failure === "remove") manager.failRemoveCount = 1;
    if (failure === "menu-destroy") menu.failDestroyCount = 1;
    if (failure === "manager-destroy") manager.failDestroyCount = 1;

    const process = fixture.subprocesses[0];
    const cancellable = applet._statusActiveState.cancellable;
    applet.on_applet_removed_from_panel();
    process.stdout.releaseEof();
    process.stderr.releaseEof();
    process.emitDone();

    assert.equal(applet._cleanupComplete, true, `cycle ${cycle}: cleanup`);
    assert.equal(process.forceExitCount, 1, `cycle ${cycle}: process`);
    assert.equal(cancellable.cancelCount, 1, `cycle ${cycle}: cancellable`);
    assert.equal(process.waitCallbacks.length, 0, `cycle ${cycle}: wait callback`);
    assert.equal(process.stdout._holdCallbacks.length, 0, `cycle ${cycle}: stdout callback`);
    assert.equal(process.stderr._holdCallbacks.length, 0, `cycle ${cycle}: stderr callback`);
    assert.equal(fixture.activeTimers().length, 0, `cycle ${cycle}: timer`);
    assert.equal(applet._signalConnections.length, 0, `cycle ${cycle}: signal`);
    assert.equal(fixture.settingsInstances[0].finalizeCount, 1, `cycle ${cycle}: settings`);
    assert.equal(applet.menu, null, `cycle ${cycle}: applet menu`);
    assert.equal(applet._applet_context_menu, null, `cycle ${cycle}: context menu`);
    assert.equal(manager.grabbed, false, `cycle ${cycle}: applet grab`);
    assert.equal(contextManager.grabbed, false, `cycle ${cycle}: context grab`);
  }
});

test("hostile settings matrix never reaches argv or background work", () => {
  const hostileValues = [
    "   ",
    "a1\u0000,b1",
    "--flag",
    "/tmp/a1",
    "a1;touch /tmp/owned",
    "a１",
    "a1,a2,a3,a4,a5,a6,a7",
    "all",
    "a-series",
  ];

  for (const value of hostileValues) {
    const fixture = loadApplet();
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    fixture.setSetting("tracked-agents", value);
    fixture.setSetting("background-refresh", true);
    applet.menu.items[0].activate();

    assert.equal(applet._settingsValid, false, JSON.stringify(value));
    assert.deepEqual(Array.from(applet._trackedAgents), ["a1", "b1"], JSON.stringify(value));
    assert.deepEqual(
      Array.from(fixture.launcherSpawns.at(-1).argv.slice(2)),
      ["a1", "b1"],
      JSON.stringify(value),
    );
    assert.equal(fixture.activeTimers("background").length, 0, JSON.stringify(value));
  }
});

test("hostile backend matrix is rejected without retaining attacker data", async () => {
  const good = samplePayload();
  const deep = JSON.stringify(good).slice(0, -1) + `,"nested":${"[".repeat(2000)}0${"]".repeat(2000)}}`;
  const unknownField = { ...good, prompt: "SECRET_PROMPT" };
  const unknownEnum = { ...good, backend_state: "super_ok" };
  const wrongType = { ...good, agents: [{ ...good.agents[0], auth_state: 1 }, good.agents[1]] };
  const payloads = [
    makeBytes("A".repeat(64 * 1024 + 1)),
    makeBytes(deep),
    makeInvalidUtf8PayloadBytes(good),
    makeBytes("{"),
    makeBytes(JSON.stringify(unknownField)),
    makeBytes(JSON.stringify(unknownEnum)),
    makeBytes(JSON.stringify(wrongType)),
  ];

  for (const payload of payloads) {
    const fixture = loadApplet();
    fixture.setProcessFactory(() => ({
      forceExitCount: 0,
      waitCallbacks: [],
      get_stdout_pipe() { return fixture.makeStream([payload]); },
      get_stderr_pipe() { return fixture.makeStream([new Uint8Array()]); },
      get_successful: () => true,
      get_exit_status: () => 0,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() {},
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) callback(this, null);
      },
    }));
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    applet.menu.items[0].activate();
    fixture.subprocesses[0].emitDone();
    await Promise.resolve();

    assert.equal(applet._statusLastGood, null);
    assert.ok(!JSON.stringify({
      lastGood: applet._statusLastGood,
      summary: applet._statusSummaryItem.label,
    }).includes("SECRET_PROMPT"));
  }
});
