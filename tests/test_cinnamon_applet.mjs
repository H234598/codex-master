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
const settingsSchema = JSON.parse(fs.readFileSync(
  path.join(root, "cinnamon/applets/codex-master@H234598/settings-schema.json"),
  "utf8"
));
const START_CONTEXT_VALUE = "c3RhcnQ.c2ln";
const STOP_CONTEXT_VALUE = "c3RvcA.c2ln";
const OTHER_CONTEXT_VALUE = "YW5kZXJl.c2ln";
const MALFORMED_CONTEXT_VALUE = "attacker token";
const EXTRA_FIELD = "secret";
const EXTRA_VALUE = "must-not-be-stored";

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

function getMenuItemText(item) {
  if (!item) return "";
  if (item.label && typeof item.label.text === "string") return item.label.text;
  return typeof item.label === "string" ? item.label : "";
}

function sampleResource(overrides = {}) {
  return {
    schema_version: 1,
    generation: 7,
    state: "ready",
    bottleneck: "cpu",
    trend: { cpu: "stable", io: "rising", memory: "falling" },
    confidence: "high",
    preferred_profiles: ["cpu_low"],
    avoid_profiles: ["io_high"],
    raw_output: "not_returned",
    ...overrides,
  };
}

function samplePayload() {
  return {
    schema_version: 4,
    mode: "read_only",
    counts: {
      tracked: 2,
      running: 1,
      sleeping: 1,
      overflow: 0,
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
        allowed_action: "none",
        context_token: "",
        limit_state: "clear",
        blocked_until_utc: null,
      },
      {
        agent: "b1",
        activity_state: "sleeping",
        backend_state: "ok",
        control_state: "ready",
        auth_state: "ready",
        identity_state: "stopped",
        lease_state: "unclaimed",
        allowed_action: "start",
        context_token: START_CONTEXT_VALUE,
        limit_state: "clear",
        blocked_until_utc: null,
      },
    ],
    native_agents: {
      bridge_state: "ready",
      counts: {
        active: 0,
        unconfirmed: 0,
        overflow: 0,
      },
      agents: [],
      truncated: false,
    },
    resource: sampleResource(),
    raw_output: "not_returned",
  };
}

function sampleNativeAgent(overrides = {}) {
  return {
    display_id: "019fc541",
    agent_type: "explorer",
    activity_state: "active",
    updated_at_utc: "1970-01-01T00:16:40+00:00",
    ...overrides,
  };
}

function sampleOverviewPayload(overrides = {}) {
  const limitWindows = [
    { pool: "primary", window_seconds: 18000, used_percent: 24.5, remaining_percent: 75.5, reset_at: "2026-08-15T13:00:00+00:00" },
    { pool: "primary", window_seconds: 604800, used_percent: 10, remaining_percent: 90, reset_at: "2026-08-22T12:00:00+00:00" },
    { pool: "spark", window_seconds: 18000, used_percent: 5, remaining_percent: 95, reset_at: "2026-08-15T13:00:00+00:00" },
    { pool: "primary", window_seconds: 2592000, used_percent: 12, remaining_percent: 88, reset_at: "2026-09-14T12:00:00+00:00" },
  ];
  return {
    generation: 7,
    created_at: "2026-08-15T12:00:00+00:00",
    integration_freshness: "fresh",
    series: [
      {
        prefix: "a",
        display_name: "Alpha",
        provider: "openai",
        runner: "codex",
        model: "gpt-5",
        active_count: 1,
        total_count: 1,
        agent_ids: ["a1"],
      },
    ],
    agents: [
      {
        agent_id: "a1",
        series_display: "Alpha",
        provider: "openai",
        runner: "codex",
        model: "gpt-5",
        account_id: "acct-1",
        account_label: "Primary",
        state: "running",
        principal_role: null,
        dispatch_id: null,
        limit_short_remaining_percent: 75.5,
        limit_short_reset_at: "2026-08-15T13:00:00+00:00",
        limit_week_remaining_percent: 90,
        limit_week_reset_at: "2026-08-22T12:00:00+00:00",
        cost_last_hour_percentage_points: 2.5,
        usage_freshness: "fresh",
        limit_windows: limitWindows,
      },
    ],
    account_limits: [
      {
        account_id: "acct-1",
        account_label: "Primary",
        provider: "openai",
        short_remaining_percent: 75.5,
        short_reset_at: "2026-08-15T13:00:00+00:00",
        week_remaining_percent: 90,
        week_reset_at: "2026-08-22T12:00:00+00:00",
        cost_last_hour_percentage_points: 2.5,
        usage_freshness: "fresh",
        limit_windows: limitWindows,
      },
    ],
    warnings: [],
    ...overrides,
  };
}

function realignCounts(payload) {
  const activityStates = payload.agents.map((row) => row.activity_state);
  payload.counts.running = activityStates.filter((state) => state === "running").length;
  payload.counts.sleeping = activityStates.filter((state) => state === "sleeping").length;
  payload.counts.tracked = payload.agents.length;
}

function queuePayloadProcessV2(fixture, payload, options) {
  queuePayloadProcess(fixture, payload, options);
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
    "overview-interval-seconds": 30,
    "overview-session-no-active-only": false,
    "overview-compact": true,
    "overview-detail": true,
    "terminal-command": "ghostty",
    "panel-icon": "hive-01-core",
    "settings-icon": "hive-02-queen-crown",
    "panel-display": "icon-text",
  };
  let home = "/home/tester";
  let timeoutId = 1;
  let createdNativeRows = 0;
  let createdQuickControlRows = 0;
  const environmentKeys = [
    "DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "CODEX_USAGE_INTEGRATION_STATE_HOME",
    "XDG_STATE_HOME",
    "DESKTOP_STARTUP_ID",
    "XDG_ACTIVATION_TOKEN",
    "LANG",
    "PATH",
    "HOME",
    "BASH_ENV",
    "GCONV_PATH",
    "GIO_EXTRA_MODULES",
    "GIO_MODULE_DIR",
    "GI_TYPELIB_PATH",
    "GJS_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_LIBRARY_PATH",
    "GTK_MODULES",
    "GTK_PATH",
    "GDK_PIXBUF_MODULE_FILE",
    "LD_PRELOAD",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_TRACE_LOADED_OBJECTS",
    "PYTHONHOME",
    "PYTHONPATH",
    "UNEXPECTED_INJECTOR",
  ];

  const TextEncoder = globalThis.TextEncoder;
  function makeLabel(text) {
    return {
      text,
      set_text(value) {
        this.text = value;
      },
    };
  }
  class TextApplet {}
  TextApplet.prototype._init = function () {
    this.labels = [];
    this.tooltips = [];
    this.iconPaths = [];
    this.iconVisible = false;
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
  class TextIconApplet extends TextApplet {}
  TextIconApplet.prototype.set_applet_icon_path = function (value) {
    this.iconPaths.push(value);
    this.iconVisible = true;
  };
  TextIconApplet.prototype.hide_applet_icon = function () {
    this.iconVisible = false;
  };

  class PopupMenuItem {
    constructor(label, options = {}) {
      this.label = makeLabel(label);
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

  class PopupIconMenuItem extends PopupMenuItem {
    constructor(label, iconName, iconType) {
      super(label);
      this.iconName = iconName;
      this.iconType = iconType;
      this._icon = {
        path: iconName,
        iconType,
        set_gicon: (gicon) => { this._icon.path = gicon.path; },
      };
    }
    setIconName(iconName) {
      this.iconName = iconName;
      this._icon.path = iconName;
    }
  }

  class PopupSubMenuMenuItem extends PopupMenuItem {
    constructor(label, options = {}) {
      super(label, options);
      this.menu = new AppletPopupMenu();
      const originalAddMenuItem = this.menu.addMenuItem.bind(this.menu);
      this.menu.addMenuItem = (item) => {
        if (label === "Native Bienen") createdNativeRows += 1;
        if (label === "Schnellsteuerung") createdQuickControlRows += 1;
        originalAddMenuItem(item);
      };
    }

    destroy() {
      this.menu.destroy();
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
      this.failToggleCount = 0;
      this.closeCount = 0;
      this.destroyCount = 0;
    }
    addMenuItem(item) { this.items.push(item); }
    toggle() {
      if (this.failToggleCount > 0) {
        this.failToggleCount -= 1;
        throw new Error("injected toggle failure");
      }
      this.isOpen = !this.isOpen;
    }
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
      for (const item of this.items) {
        if (item && typeof item.destroy === "function") {
          item.destroy();
        }
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
        flags: this.flags,
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
    listenv() { return [...environmentKeys]; },
    timeout_add(_priority, _ms, callback) {
      const id = timeoutId += 1;
      timeouts.push({ id, callback, cancelled: false, kind: "timeout" });
      return id;
    },
    timeout_add_seconds(_priority, seconds, callback) {
      const id = timeoutId += 1;
      timeouts.push({
        id,
        callback,
        cancelled: false,
        kind: callback && callback.__codexOverviewTimer ? "overview" : "background",
        seconds,
      });
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
    icon_new_for_string(path) { return { path }; },
    SubprocessLauncher: {
      new: function (flags) {
        const launcher = new FakeSubprocessLauncher();
        launcher.flags = flags;
        return launcher;
      },
    },
    SubprocessFlags: {
      STDOUT_PIPE: 1,
      STDERR_PIPE: 2,
      STDOUT_SILENCE: 4,
      STDERR_SILENCE: 8,
    },
    Cancellable: FakeCancellable,
  };

  const Settings = {
    AppletSettings: FakeAppletSettings,
    BindingDirection: { IN: 1 },
  };
  const St = { IconType: { FULLCOLOR: 1, SYMBOLIC: 2 } };

  const context = {
    imports: {
      gi: { Gio, GLib, St },
      mainloop: Mainloop,
      ui: {
        applet: { TextApplet, TextIconApplet, AppletPopupMenu },
        popupMenu: { PopupMenuItem, PopupIconMenuItem, PopupSubMenuMenuItem, PopupMenuManager },
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
    createdNativeRows() { return createdNativeRows; },
    createdQuickControlRows() { return createdQuickControlRows; },
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

function queuePayloadProcess(fixture, payload, { exitCode = 0, holdEof = false, forceExitFailures = 0 } = {}) {
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([makeBytes(JSON.stringify(payload))], holdEof);
    const stderr = fixture.makeStream([], holdEof);
    return {
      forceExitCount: 0,
      forceExitAttempts: 0,
      waitCallbacks: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => exitCode === 0,
      get_exit_status: () => exitCode,
      force_exit() {
        this.forceExitAttempts += 1;
        if (this.forceExitAttempts <= forceExitFailures) throw new Error("injected force_exit failure");
        this.forceExitCount += 1;
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
}

test("overview settings expose the approved defaults", () => {
  assert.equal(settingsSchema["overview-interval-seconds"].default, 30);
  assert.equal(settingsSchema["overview-session-no-active-only"].default, false);
  assert.equal(settingsSchema["overview-compact"].default, true);
  assert.equal(settingsSchema["overview-detail"].default, true);

  const { main } = loadApplet();
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  assert.equal(applet.overviewIntervalSeconds, 30);
  assert.equal(applet.overviewSessionNoActiveOnly, false);
  assert.equal(applet.overviewCompact, true);
  assert.equal(applet.overviewDetail, true);
});

test("ollama menu shows bounded readiness summary", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  assert.equal(applet.renderOllamaSummary({
    ready_instances: 2,
    ready_lanes: 4,
    blocked_instances: 1,
  }), true);
  assert.equal(applet.ollamaText(), "Ollama: 2 Instanzen · 4 Lanes · 1 blockiert");
  assert.equal(getMenuItemText(applet._ollamaSummaryItem), applet.ollamaText());
  assert.equal(applet.renderOllamaSummary({
    ready_instances: 65,
    ready_lanes: 4,
    blocked_instances: 1,
  }), false);
  assert.equal(applet.ollamaText(), "Ollama: nicht verfügbar");
});

test("ollama action opens exact control center page", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  applet.activateOllamaManage();

  assert.deepEqual(Array.from(fixture.launcherSpawns[0].argv), [
    "/home/tester/.local/bin/codex-master-mcp",
    "control-center-launch",
    "--page",
    "ollama",
  ]);
});

test("overview argv is shell-free and adds only explicit session flag", () => {
  const first = loadApplet();
  first.setHome("/tmp/overview-home");
  const firstApplet = first.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  firstApplet._refreshOverview();
  assert.deepEqual(Array.from(first.launcherSpawns[0].argv), [
    "/tmp/overview-home/.local/bin/codex-master-mcp",
    "fleet",
    "overview",
    "--format",
    "json",
  ]);

  const second = loadApplet();
  second.setSetting("overview-session-no-active-only", true);
  const secondApplet = second.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  secondApplet._refreshOverview();
  assert.deepEqual(Array.from(second.launcherSpawns[0].argv), [
    "/home/tester/.local/bin/codex-master-mcp",
    "fleet",
    "overview",
    "--format",
    "json",
    "--no-active-only",
  ]);
});

test("overview launcher preserves only approved state roots and strips foreign environment", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet._refreshOverview();
  const launch = fixture.launcherSpawns[0];
  assert.ok(!launch.unsetCalls.includes("CODEX_USAGE_INTEGRATION_STATE_HOME"));
  assert.ok(!launch.unsetCalls.includes("XDG_STATE_HOME"));
  assert.ok(launch.unsetCalls.includes("UNEXPECTED_INJECTOR"));
  assert.equal(launch.envCalls.some((call) => call.key === "CODEX_USAGE_INTEGRATION_STATE_HOME"), false);
  assert.equal(launch.envCalls.some((call) => call.key === "XDG_STATE_HOME"), false);
});

test("overview refresh is single-flight and separate from status state", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusState = applet._statusViewState;
  applet._refreshOverview();
  applet._refreshOverview();
  assert.equal(fixture.subprocesses.length, 1);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  assert.equal(applet._statusViewState, statusState);
  assert.equal(applet._statusLastGood, null);
  applet.on_applet_removed_from_panel();
  assert.equal(fixture.activeTimers("timeout").length, 0);
  assert.equal(fixture.subprocesses[0].forceExitCount, 1);
});

test("malformed overview stays unavailable and preserves status state", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusPayload = samplePayload();
  applet._statusLastGood = statusPayload;
  applet._statusViewState = "ready";
  queuePayloadProcess(fixture, { ...sampleOverviewPayload(), account_limits: "bad" });
  applet._refreshOverview();
  fixture.subprocesses[0].emitDone();
  assert.equal(applet._overviewViewState, "unavailable");
  assert.equal(applet._statusViewState, "ready");
  assert.deepEqual(applet._statusLastGood, statusPayload);
});

test("overview accepts fresh, stale, and unavailable data with data-sparse rendering", () => {
  for (const [freshness, expectedText] of [["fresh", "frisch"], ["stale", "veraltet"]]) {
    const fixture = loadApplet();
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    queuePayloadProcess(fixture, sampleOverviewPayload({
      integration_freshness: freshness,
      agents: sampleOverviewPayload().agents.map((row) => ({ ...row, usage_freshness: freshness })),
      account_limits: sampleOverviewPayload().account_limits.map((row) => ({ ...row, usage_freshness: freshness })),
    }));
    applet._refreshOverview();
    fixture.subprocesses[0].emitDone();
    assert.match(getMenuItemText(applet._overviewSummaryItem), new RegExp(expectedText));
    assert.match(getMenuItemText(applet._overviewSummaryItem), /acct-1/);
  }

  const unavailable = loadApplet();
  const unavailableApplet = unavailable.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  queuePayloadProcess(unavailable, sampleOverviewPayload({
    integration_freshness: "unavailable",
    series: [],
    agents: [],
    account_limits: [],
    warnings: ["usage_unavailable"],
  }));
  unavailableApplet._refreshOverview();
  unavailable.subprocesses[0].emitDone();
  assert.match(getMenuItemText(unavailableApplet._overviewSummaryItem), /nicht verfügbar/);
  assert.equal(getMenuItemText(unavailableApplet._overviewDetailItem), "Übersicht Details: —");
});

test("overview settings validate strictly and restart only overview work", () => {
  const cases = [
    ["overview-interval-seconds", "30", 30],
    ["overview-session-no-active-only", "true", false],
    ["overview-compact", 1, true],
    ["overview-detail", 0, true],
  ];
  for (const [key, value, expected] of cases) {
    const fixture = loadApplet();
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    fixture.setSetting(key, value);
    const property = {
      "overview-interval-seconds": "overviewIntervalSeconds",
      "overview-session-no-active-only": "overviewSessionNoActiveOnly",
      "overview-compact": "overviewCompact",
      "overview-detail": "overviewDetail",
    }[key];
    assert.equal(applet[property], expected, key);
    assert.equal(applet._settingsValid, false, key);
    assert.equal(fixture.subprocesses.length, 0, key);
  }
});

test("overview timeout and late callbacks never touch status state", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const statusPayload = samplePayload();
  applet._statusLastGood = statusPayload;
  applet._statusViewState = "ready";
  queuePayloadProcess(fixture, sampleOverviewPayload(), { holdEof: true });
  applet._refreshOverview();
  const process = fixture.subprocesses[0];
  fixture.runTimeouts();
  assert.equal(process.forceExitCount, 1);
  assert.equal(applet._statusViewState, "ready");
  assert.deepEqual(applet._statusLastGood, statusPayload);
  applet.on_applet_removed_from_panel();
  applet._statusLastGood = statusPayload;
  applet._statusViewState = "ready";
  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();
  assert.equal(applet._statusViewState, "ready");
  assert.deepEqual(applet._statusLastGood, statusPayload);
});

test("opening menu starts first overview refresh and then one overview timer", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload());
  queuePayloadProcess(fixture, sampleOverviewPayload());
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  applet.on_applet_clicked();
  assert.equal(fixture.subprocesses.length, 2);
  assert.equal(applet._overviewInFlight, true);
  assert.equal(fixture.activeTimers("overview").length, 0);

  fixture.subprocesses[0].emitDone();
  fixture.subprocesses[1].emitDone();
  assert.equal(applet._overviewInFlight, false);
  assert.equal(fixture.activeTimers("overview").length, 1);
});

test("overview rejects null created_at and non-exact series totals", () => {
  for (const payload of [
    sampleOverviewPayload({ created_at: null }),
    sampleOverviewPayload({
      series: sampleOverviewPayload().series.map((row) => ({ ...row, total_count: row.agent_ids.length + 1 })),
    }),
    sampleOverviewPayload({ integration_freshness: "fresh", warnings: ["usage_unavailable"] }),
    sampleOverviewPayload({
      integration_freshness: "fresh",
      agents: sampleOverviewPayload().agents.map((row) => ({ ...row, usage_freshness: "stale" })),
    }),
  ]) {
    const fixture = loadApplet();
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    queuePayloadProcess(fixture, payload);
    applet._refreshOverview();
    fixture.subprocesses[0].emitDone();
    assert.equal(applet._overviewViewState, "unavailable");
    assert.equal(getMenuItemText(applet._overviewSummaryItem), "Übersicht: nicht verfügbar");
  }
});

test("overview UTC validation compares calendar components and keeps null reset optional", () => {
  const { main } = loadApplet();
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  for (const value of [
    "2026-02-29T00:00:00Z",
    "2026-02-31T00:00:00Z",
    "2026-04-31T00:00:00+00:00",
    "2026-01-01T24:00:00Z",
    "2026-01-01T00:60:00Z",
    "2026-01-01T00:00:60Z",
  ]) {
    assert.equal(applet._overviewUtc(value), false, value);
  }
  assert.equal(applet._overviewUtc("2024-02-29T00:00:00Z"), true);
  assert.equal(applet._overviewUtc("2026-01-01T00:00:00+00:00"), true);
  assert.equal(applet._overviewUtc(null), true);
});

test("overview agents must map into series while inactive series members may be omitted", () => {
  const { main } = loadApplet();
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const foreignAgent = sampleOverviewPayload({
    agents: sampleOverviewPayload().agents.map((row) => ({ ...row, agent_id: "b1" })),
  });
  assert.equal(applet._isValidOverviewPayload(foreignAgent), false);

  const activeSubset = sampleOverviewPayload({
    series: sampleOverviewPayload().series.map((row) => ({
      ...row,
      agent_ids: ["a1", "b1"],
      total_count: 2,
      active_count: 1,
    })),
  });
  assert.equal(applet._isValidOverviewPayload(activeSubset), true);
});

test("overview setting changes replace timer or cancel active IO without status mutation", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  queuePayloadProcess(fixture, sampleOverviewPayload());
  applet._refreshOverview();
  fixture.subprocesses[0].emitDone();
  const firstTimer = fixture.activeTimers("overview")[0];
  assert.equal(firstTimer.seconds, 30);

  fixture.setSetting("overview-interval-seconds", 60);
  const secondTimers = fixture.activeTimers("overview");
  assert.equal(secondTimers.length, 1);
  assert.equal(secondTimers[0].seconds, 60);
  assert.notEqual(secondTimers[0].id, firstTimer.id);

  fixture.setProcessFactory(() => new (class {
    constructor() {
      this.forceExitCount = 0;
      this.waitCallbacks = [];
      this.stdout = fixture.makeStream([], true);
      this.stderr = fixture.makeStream([], true);
    }
    get_stdout_pipe() { return this.stdout; }
    get_stderr_pipe() { return this.stderr; }
    get_successful() { return true; }
    force_exit() { this.forceExitCount += 1; }
    wait_async(_, callback) { this.waitCallbacks.push(callback); }
  })());
  secondTimers[0].callback();
  assert.equal(applet._overviewInFlight, true);
  const process = fixture.subprocesses.at(-1);
  fixture.setSetting("overview-detail", false);
  assert.equal(process.forceExitCount, 1);
  assert.equal(applet._overviewInFlight, false);
  assert.equal(applet._statusInFlight, false);
});

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

test("applet click actor and toggle failures stay inside the UI callback", () => {
  for (const failure of ["actor", "toggle"]) {
    const fixture = loadApplet();
    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
    if (failure === "actor") {
      applet.menu.actor.is_finalized = () => { throw new Error("injected actor state failure"); };
    } else {
      applet.menu.failToggleCount = 1;
    }

    assert.doesNotThrow(() => applet.on_applet_clicked());
    assert.equal(applet.menu.isOpen, false);
    assert.equal(applet.menuManager.grabbed, false);
    assert.equal(fixture.subprocesses.length, 0);
  }
});

test("settings launcher failure stays inside menu callback", () => {
  const fixture = loadApplet();
  fixture.setSpawnError("injected cinnamon-settings spawn failure");
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  assert.doesNotThrow(() => applet.menu.items[1].activate());
  assert.equal(fixture.spawned.length, 0);
  assert.equal(applet.labels.at(-1), "Flottenmanagement");
});

test("signal connection failures do not escape or retain invalid handles", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const baseline = applet._signalConnections.length;
  const targets = [
    { connect() { return 1; } },
    { connect() { throw new Error("injected connect failure"); } },
    { connect() { return -1; } },
    { connect() { return 1.5; } },
    { connect() { return Number.MAX_SAFE_INTEGER + 1; } },
    { connect() { return "1"; } },
  ];

  for (const target of targets) {
    let result = null;
    assert.doesNotThrow(() => { result = applet._connectTracked(target, "activate", () => {}); });
    assert.equal(result, 0);
    assert.equal(applet._signalConnections.length, baseline);
  }
});

test("removal drops signal handles Cinnamon already disconnected", () => {
  const fixture = loadApplet();
  let logCalls = 0;
  fixture.setGlobalLogger(() => { logCalls += 1; });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  for (const connection of applet._signalConnections) {
    connection.target.handlers.delete(connection.id);
    connection.target.disconnect = () => { throw new Error("connection is undefined"); };
  }

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, true);
  assert.equal(applet._signalConnections.length, 0);
  assert.equal(applet.menu, null);
  assert.equal(applet.menuManager, null);
  assert.equal(logCalls, 0);
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

test("native submenu references survive failed main menu cleanup retry", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const menu = applet.menu;
  const manager = applet.menuManager;
  const nativeSubmenuItem = applet._nativeSubmenuItem;
  const nativeBeeRowItems = applet._nativeBeeRowItems.slice();
  menu.failDestroyCount = 2;

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, false);
  assert.equal(applet._nativeSubmenuItem, nativeSubmenuItem);
  assert.equal(applet._nativeBeeRowItems.length, 6);
  for (let index = 0; index < nativeBeeRowItems.length; index += 1) {
    assert.equal(applet._nativeBeeRowItems[index], nativeBeeRowItems[index]);
  }
  assert.equal(nativeSubmenuItem.menu.destroyCount, 0);
  assert.equal(manager.destroyCount, 1);

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, true);
  assert.equal(applet._nativeSubmenuItem, null);
  assert.equal(applet._nativeBeeRowItems.length, 0);
  assert.equal(nativeSubmenuItem.menu.destroyCount, 1);
  assert.equal(manager.destroyCount, 1);

  applet.on_applet_removed_from_panel();
  assert.equal(nativeSubmenuItem.menu.destroyCount, 1);
  assert.equal(manager.destroyCount, 1);
});

test("removal releases status actor wrapper references", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet._statusLastGood = samplePayload();
  assert.notEqual(applet._statusSummaryItem, null);
  assert.equal(applet._statusRowItems.length, 6);
  assert.notEqual(applet._statusLastGood, null);

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, true);
  assert.equal(applet._statusSummaryItem, null);
  assert.equal(applet._statusRowItems.length, 0);
  assert.equal(applet._statusLastGood, null);
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
  assert.equal(launch.argv[2], "--schema-version");
  assert.equal(launch.argv[3], "4");
  assert.equal(launch.argv[4], "a1");
  assert.equal(launch.argv[5], "b1");
  assert.deepEqual(Array.from(launch.envCalls), [
    { key: "PATH", value: "/usr/bin:/bin", overwrite: true },
    { key: "HOME", value: "/tmp/home", overwrite: true },
  ]);
  for (const key of [
    "BASH_ENV",
    "GCONV_PATH",
    "GIO_EXTRA_MODULES",
    "GIO_MODULE_DIR",
    "GI_TYPELIB_PATH",
    "GJS_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_TRACE_LOADED_OBJECTS",
    "PYTHONHOME",
    "PYTHONPATH",
    "GTK_MODULES",
    "GTK_PATH",
    "GDK_PIXBUF_MODULE_FILE",
    "UNEXPECTED_INJECTOR",
  ]) {
    assert.ok(launch.unsetCalls.includes(key), `strips ${key}`);
  }
  for (const key of [
    "DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "DESKTOP_STARTUP_ID",
    "XDG_ACTIVATION_TOKEN",
    "LANG",
  ]) {
    assert.ok(!launch.unsetCalls.includes(key), `preserves allowlisted ${key}`);
  }
});

test("control-center uses one fixed bounded detach helper", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const controlCenterItem = applet.menu.items[2];

  assert.equal(getMenuItemText(controlCenterItem), "Steuerzentrale öffnen");
  controlCenterItem.activate();
  assert.equal(fixture.subprocesses.length, 1);
  assert.deepEqual(Array.from(fixture.launcherSpawns[0].argv), [
    "/home/tester/.local/bin/codex-master-mcp",
    "control-center-launch",
  ]);
  assert.deepEqual(Array.from(fixture.launcherSpawns[0].envCalls), [
    { key: "PATH", value: "/usr/bin:/bin", overwrite: true },
    { key: "HOME", value: "/home/tester", overwrite: true },
  ]);
  for (const key of ["GTK_MODULES", "GTK_PATH", "GDK_PIXBUF_MODULE_FILE", "UNEXPECTED_INJECTOR"]) {
    assert.ok(fixture.launcherSpawns[0].unsetCalls.includes(key), `helper strips ${key}`);
  }
  assert.equal(applet._launcherInFlight, true);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  assert.equal(fixture.subprocesses.length, 1);
  controlCenterItem.activate();
  assert.equal(fixture.subprocesses.length, 1, "helper is single-flight");

  fixture.subprocesses[0].emitDone();
  assert.equal(applet._launcherInFlight, false);
  assert.equal(fixture.activeTimers("timeout").length, 0);
  applet.menu.items[0].activate();
  assert.equal(fixture.subprocesses.length, 2, "status works after helper exits");
});

test("control-center detach helper timeout is bounded and never retries", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const controlCenterItem = applet.menu.items[2];

  controlCenterItem.activate();

  assert.equal(applet._launcherInFlight, true);
  assert.equal(fixture.subprocesses.length, 1);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  fixture.runTimeouts();
  assert.equal(fixture.subprocesses[0].forceExitCount, 1);
  assert.equal(fixture.subprocesses.length, 1, "helper timeout never retries");
});

test("removal terminates only active detach helper and clears its resources", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[2].activate();
  const helper = fixture.subprocesses[0];

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, true);
  assert.equal(applet._launcherInFlight, false);
  assert.equal(helper.forceExitCount, 1);
  assert.equal(fixture.activeTimers().length, 0);
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
    payload.agents[1].activity_state = "running";
    payload.agents[1].backend_state = "ok";
    payload.agents[1].control_state = "ready";
    payload.agents[1].identity_state = "verified";
    realignCounts(payload);
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

test("stderr is bounded by byte count without retaining diagnostic chunks", () => {
  const fixture = loadApplet();
  const stdout = fixture.makeStream([], true);
  const stderr = fixture.makeStream(
    Array.from({ length: 4 }, () => makeBytes("E".repeat(1024))),
    true
  );
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return stdout; },
    get_stderr_pipe() { return stderr; },
    get_successful: () => false,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
    wait_finish() {},
  }));
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const state = applet._statusActiveState;

  assert.equal(state.stderrByteCount, 4 * 1024);
  assert.equal(Object.hasOwn(state, "stderrChunks"), false);
  applet.on_applet_removed_from_panel();
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

test("invalid timeout source id fails closed without an unbounded process", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload(), { holdEof: true, forceExitFailures: 1 });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.GLib.timeout_add = () => 0;

  applet.menu.items[0].activate();

  const process = fixture.subprocesses[0];
  const state = applet._statusActiveState;
  assert.equal(process.forceExitAttempts, 2);
  assert.equal(process.forceExitCount, 1);
  assert.equal(state.cancellable.cancelCount, 1);
  assert.equal(state.timedOut, true);
  assert.equal(state.timeoutSource, 0);
  assert.equal(fixture.activeTimers("timeout").length, 0);

  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
});

test("invalid timeout handle retries a failed replacement wait once", () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([], true);
    const stderr = fixture.makeStream([], true);
    return {
      forceExitCount: 0,
      waitAsyncCount: 0,
      waitFinishCount: 0,
      waitCallbacks: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() { this.forceExitCount += 1; },
      wait_async(_cancellable, callback) {
        this.waitAsyncCount += 1;
        this.waitCallbacks.push(callback);
      },
      wait_finish() {
        this.waitFinishCount += 1;
        if (this.waitFinishCount <= 2) throw new Error("injected wait failure");
      },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) callback(this, null);
      },
    };
  });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  fixture.GLib.timeout_add = () => 0;
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];

  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();
  process.emitDone();
  assert.equal(process.waitCallbacks.length, 1, "failed replacement wait is retried once");
  process.emitDone();

  assert.equal(process.waitAsyncCount, 3);
  assert.equal(process.forceExitCount, 1);
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(fixture.activeTimers("timeout").length, 0);
});

test("timerless replacement wait retries a transient cancellable construction failure", () => {
  const fixture = loadApplet();
  let cancellableConstructions = 0;
  fixture.Gio.Cancellable = class {
    constructor() {
      cancellableConstructions += 1;
      if (cancellableConstructions === 2) throw new Error("injected replacement cancellable failure");
      this.cancelCount = 0;
    }
    cancel() { this.cancelCount += 1; }
  };
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([], true);
    const stderr = fixture.makeStream([], true);
    return {
      waitFinishCount: 0,
      waitCallbacks: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() {},
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() {
        this.waitFinishCount += 1;
        if (this.waitFinishCount === 1) throw new Error("injected original wait failure");
      },
      emitOneWait() {
        const callback = this.waitCallbacks.shift();
        callback(this, null);
      },
    };
  });
  fixture.GLib.timeout_add = () => 0;
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];

  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitOneWait();

  assert.equal(cancellableConstructions, 3, "one bounded immediate constructor retry");
  assert.equal(process.waitCallbacks.length, 1, "retry starts replacement wait");
  process.emitOneWait();
  assert.equal(applet._statusActiveState, null);
  assert.equal(fixture.activeTimers().length, 0);
});

test("timerless replacement wait bounds permanent cancellable construction failures", () => {
  const fixture = loadApplet();
  let cancellableConstructions = 0;
  fixture.Gio.Cancellable = class {
    constructor() {
      cancellableConstructions += 1;
      if (cancellableConstructions > 1) throw new Error("injected permanent replacement cancellable failure");
      this.cancelCount = 0;
    }
    cancel() { this.cancelCount += 1; }
  };
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([], true);
    const stderr = fixture.makeStream([], true);
    return {
      waitCallbacks: [],
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() {},
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() { throw new Error("injected original wait failure"); },
      emitOneWait() {
        const callback = this.waitCallbacks.shift();
        callback(this, null);
      },
    };
  });
  fixture.GLib.timeout_add = () => 0;
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];
  const state = applet._statusActiveState;

  process.emitOneWait();

  assert.equal(cancellableConstructions, 3, "replacement construction stops after two attempts");
  assert.equal(process.waitCallbacks.length, 0);
  assert.equal(applet._statusActiveState, state, "failed state remains bounded and owned");
  assert.equal(fixture.activeTimers().length, 0);
  applet.on_applet_removed_from_panel();
  assert.equal(applet._statusActiveState, null, "removal releases bounded failed state");
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
  newer.agents[1].activity_state = "running";
  newer.agents[1].backend_state = "ok";
  newer.agents[1].control_state = "ready";
  newer.agents[1].identity_state = "verified";
  realignCounts(newer);
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
  assert.equal(applet._statusLastGood.counts.running, 2);
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
  assert.equal(applet._statusLastGood.schema_version, 4);
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
  assert.equal(applet._statusLastGood.schema_version, 4);
});

test("timeout cancels inherited pipes that outlive a confirmed process exit", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload(), { holdEof: true });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];
  const state = applet._statusActiveState;

  process.emitDone();
  assert.equal(state.exitConfirmed, true);
  assert.equal(state.stdoutDone, false);
  assert.equal(state.stderrDone, false);

  fixture.runTimeouts();

  assert.equal(state.timedOut, true);
  assert.equal(state.cancellable.cancelCount, 1);
  assert.equal(fixture.activeTimers("timeout").length, 1, "timer stays until inherited pipes close");
  process.stdout.releaseEof();
  process.stderr.releaseEof();
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusLastGood, null);
  assert.equal(fixture.activeTimers("timeout").length, 0);
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
  assert.equal(process.forceExitCount, 0);
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusLastGood.schema_version, 4);
  assert.equal(fixture.activeTimers("timeout").length, 0);
});

test("reentrant timeout callback during finalization cannot remove a live applet", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload());
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];
  const statusTimer = fixture.activeTimers("timeout")[0];
  const realSourceRemove = fixture.GLib.source_remove;
  let reentrant = false;
  fixture.GLib.source_remove = (id) => {
    if (id === statusTimer.id && !reentrant) {
      reentrant = true;
      if (statusTimer.callback() !== fixture.GLib.SOURCE_CONTINUE) statusTimer.cancelled = true;
      return true;
    }
    return realSourceRemove(id);
  };

  process.emitDone();

  assert.equal(applet._removed, false);
  assert.equal(applet._cleanupComplete, false);
  assert.notEqual(applet.menu, null);
  assert.equal(applet._statusActiveState, null);
  assert.equal(applet._statusLastGood.schema_version, 4);
  assert.equal(fixture.activeTimers("timeout").length, 0);
});

test("real backend payload with sleeping and expired states is accepted", async () => {
  const fixture = loadApplet();
  const payload = samplePayload();
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

  assert.equal(applet._statusLastGood.counts.sleeping, 2);
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
  delete payload.native_agents;
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
    schema_version: 4,
    mode: "read_only",
    counts: {
      tracked: 2,
      running: 0,
      sleeping: 0,
      overflow: 0,
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
        allowed_action: "none",
        context_token: "",
        limit_state: "unknown",
        blocked_until_utc: null,
      },
      {
        agent: "b1",
        activity_state: "unknown",
        backend_state: "error",
        control_state: "unknown",
        auth_state: "unknown",
        identity_state: "unknown",
        lease_state: "unreadable",
        allowed_action: "none",
        context_token: "",
        limit_state: "unknown",
        blocked_until_utc: null,
      },
    ],
    native_agents: {
      bridge_state: "ready",
      counts: { active: 0, unconfirmed: 0, overflow: 0 },
      agents: [],
      truncated: false,
    },
    resource: sampleResource(),
    raw_output: "not_returned",
  };

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(applet._statusLastGood.counts.running, 0);
  assert.equal(applet._statusLastGood.counts.sleeping, 0);
});

test("exact python error row mixed with a normal row is accepted", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = {
    schema_version: 4,
    mode: "read_only",
    counts: {
      tracked: 2,
      running: 0,
      sleeping: 1,
      overflow: 0,
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
        allowed_action: "none",
        context_token: "",
        limit_state: "unknown",
        blocked_until_utc: null,
      },
      {
        agent: "b1",
        activity_state: "sleeping",
        backend_state: "ok",
        control_state: "ready",
        auth_state: "ready",
        identity_state: "stopped",
        lease_state: "unclaimed",
        allowed_action: "start",
        context_token: START_CONTEXT_VALUE,
        limit_state: "clear",
        blocked_until_utc: null,
      },
    ],
    native_agents: {
      bridge_state: "ready",
      counts: { active: 0, unconfirmed: 0, overflow: 0 },
      agents: [],
      truncated: false,
    },
    resource: sampleResource(),
    raw_output: "not_returned",
  };

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.deepEqual(applet._statusLastGood.counts, {
    tracked: 2,
    running: 0,
    sleeping: 1,
    overflow: 0,
  });
});

test("exact python stopped-orphan row is accepted", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();
  payload.agents[0].activity_state = "sleeping";
  realignCounts(payload);

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(applet._statusLastGood.counts.sleeping, 2);
  assert.deepEqual(applet._statusLastGood.agents[0], {
    agent: "a1",
    activity_state: "sleeping",
    backend_state: "degraded",
    control_state: "blocked",
    auth_state: "ready",
    identity_state: "unverified",
    lease_state: "unclaimed",
    allowed_action: "none",
    context_token: "",
    limit_state: "clear",
    blocked_until_utc: null,
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
    assert.equal(applet._statusLastGood?.schema_version, 4);
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
  badFraction.counts.overflow = 1.2;

  const badAgent = JSON.parse(JSON.stringify(good));
  badAgent.agents[0].agent = "z1";

  const badDup = JSON.parse(JSON.stringify(good));
  badDup.agents[1].agent = "a1";

  const badRaw = JSON.parse(JSON.stringify(good));
  badRaw.raw_output = "other";

  const badTopLevelExtra = JSON.parse(JSON.stringify(good));
  badTopLevelExtra[EXTRA_FIELD] = EXTRA_VALUE;

  const badRowExtra = JSON.parse(JSON.stringify(good));
  badRowExtra.agents[0][EXTRA_FIELD] = EXTRA_VALUE;

  const badRowAggregateState = JSON.parse(JSON.stringify(good));
  badRowAggregateState.agents[0].control_state = "mixed";

  const badTrackedCount = JSON.parse(JSON.stringify(good));
  badTrackedCount.counts.tracked = 1;

  const badRunningCount = JSON.parse(JSON.stringify(good));
  badRunningCount.counts.running = 0;

  const badNativeCount = JSON.parse(JSON.stringify(good));
  badNativeCount.native_agents.counts.active = 1;

  const badNativeTimestamp = JSON.parse(JSON.stringify(good));
  badNativeTimestamp.native_agents.counts.unconfirmed = 1;
  badNativeTimestamp.native_agents.agents = [sampleNativeAgent({ activity_state: "unconfirmed", updated_at_utc: "1970-01-01T00:16:41+02:00" })];

  const badNativeDisplay = JSON.parse(JSON.stringify(good));
  badNativeDisplay.native_agents.counts.active = 1;
  badNativeDisplay.native_agents.agents = [sampleNativeAgent({ display_id: "bad/id" })];

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
    { name: "tracked count mismatch", payload: badTrackedCount },
    { name: "running count mismatch", payload: badRunningCount },
    { name: "native count mismatch", payload: badNativeCount },
    { name: "native timestamp", payload: badNativeTimestamp },
    { name: "native display id", payload: badNativeDisplay },
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
  assert.equal(applet._statusLastGood.schema_version, 4);
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
  assert.equal(applet._statusLastGood.schema_version, 4);
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
  assert.equal(applet._statusLastGood.schema_version, 4);
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

test("cancelled stream failure waits for a successful kill retry", () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([makeBytes("broken")]);
    stdout.throwFinish = true;
    const stderr = fixture.makeStream([], true);
    return {
      forceExitAttempts: 0,
      waitFinishAttempts: 0,
      waitCallbacks: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() {
        this.forceExitAttempts += 1;
        if (this.forceExitAttempts <= 2) throw new Error("injected stream kill failure");
      },
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() {
        this.waitFinishAttempts += 1;
        if (this.waitFinishAttempts === 1) throw new Error("injected cancelled wait");
      },
      emitDone() {
        const callbacks = [...this.waitCallbacks];
        this.waitCallbacks = [];
        for (const callback of callbacks) callback(this, null);
      },
    };
  });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];
  const failedState = applet._statusActiveState;

  assert.equal(process.forceExitAttempts, 1);
  process.stderr.releaseEof();
  process.emitDone();

  assert.equal(applet._statusActiveState, failedState);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  fixture.runTimeouts();
  assert.equal(process.forceExitAttempts, 3);
  assert.equal(applet._statusActiveState, failedState);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  process.emitDone();
  assert.equal(applet._statusActiveState, null);
  assert.equal(fixture.activeTimers("timeout").length, 0);
});

test("removal cancels an in-flight replacement wait", () => {
  const fixture = loadApplet();
  fixture.setProcessFactory(() => {
    const stdout = fixture.makeStream([], true);
    const stderr = fixture.makeStream([], true);
    return {
      waitCallbacks: [],
      waitCancellables: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() {},
      wait_async(cancellable, callback) {
        this.waitCancellables.push(cancellable);
        this.waitCallbacks.push(callback);
      },
      wait_finish() {
        throw new Error("injected cancelled wait");
      },
      emitOneWait() {
        const callback = this.waitCallbacks.shift();
        callback(this, null);
      },
    };
  });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];

  process.emitOneWait();
  assert.equal(process.waitCallbacks.length, 1, "replacement wait remains in flight");
  const replacementCancellable = process.waitCancellables[1];
  assert.ok(replacementCancellable, "replacement wait must be cancellable");

  applet.on_applet_removed_from_panel();

  assert.equal(replacementCancellable.cancelCount, 1);
  assert.equal(applet._statusActiveState, null);
  assert.equal(fixture.activeTimers().length, 0);
  process.emitOneWait();
  assert.equal(process.waitCallbacks.length, 0, "cancel callback starts no replacement wait");
  assert.equal(fixture.subprocesses.length, 1, "cancel callback starts no refresh");
});

test("settings schema contains the bounded fleet settings and Ghostty terminal default", () => {
  const schemaPath = path.join(root, "cinnamon/applets/codex-master@H234598/settings-schema.json");
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

  assert.deepEqual(Object.keys(schema).sort(), [
    "background-refresh",
    "overview-compact",
    "overview-detail",
    "overview-interval-seconds",
    "overview-session-no-active-only",
    "panel-display",
    "panel-icon",
    "refresh-interval-seconds",
    "refresh-on-open",
    "settings-icon",
    "terminal-command",
    "tracked-agents",
  ]);
  assert.equal(schema["tracked-agents"].default, "a1,b1");
  assert.equal(schema["refresh-on-open"].default, true);
  assert.equal(schema["background-refresh"].default, false);
  assert.equal(schema["overview-interval-seconds"].default, 30);
  assert.equal(schema["overview-session-no-active-only"].default, false);
  assert.equal(schema["overview-compact"].default, true);
  assert.equal(schema["overview-detail"].default, true);
  assert.equal(schema["terminal-command"].default, "ghostty");
  assert.equal(schema["panel-icon"].default, "hive-01-core");
  assert.equal(schema["settings-icon"].default, "hive-02-queen-crown");
  assert.equal(schema["panel-display"].default, "icon-text");
  assert.equal(Object.keys(schema["panel-icon"].options).length, 25);
  assert.deepEqual(schema["panel-display"].options, {
    "Nur Icon": "icon",
    "Nur Text": "text",
    "Icon + Text": "icon-text",
  });
  assert.deepEqual(
    {
      default: schema["refresh-interval-seconds"].default,
      min: schema["refresh-interval-seconds"].min,
      max: schema["refresh-interval-seconds"].max,
    },
    { default: 60, min: 15, max: 3600 },
  );
});

test("panel and settings icons plus display mode are live-configurable", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const settingsItem = applet.menu.items[1];

  assert.equal(applet.panelIcon, "hive-01-core");
  assert.equal(applet.settingsIcon, "hive-02-queen-crown");
  assert.equal(applet.panelDisplay, "icon-text");
  assert.equal(applet.iconVisible, true);
  assert.match(applet.iconPaths.at(-1), /icons\/hive-01-core\.png$/);
  assert.match(settingsItem._codexIconPath, /icons\/hive-02-queen-crown\.png$/);

  fixture.setSetting("panel-icon", "starwars-04-destroyer");
  fixture.setSetting("settings-icon", "hive-19-honeycomb-star");
  fixture.setSetting("panel-display", "icon");
  assert.equal(applet.panelIcon, "starwars-04-destroyer");
  assert.equal(applet.settingsIcon, "hive-19-honeycomb-star");
  assert.equal(applet.panelDisplay, "icon");
  assert.equal(applet.labels.at(-1), "");
  assert.match(applet.iconPaths.at(-1), /icons\/starwars-04-destroyer\.png$/);
  assert.match(settingsItem._codexIconPath, /icons\/hive-19-honeycomb-star\.png$/);

  fixture.setSetting("panel-display", "text");
  assert.equal(applet.labels.at(-1), "Flottenmanagement");
  assert.equal(applet.iconVisible, false);

  fixture.setSetting("panel-display", "icon-text");
  assert.equal(applet.labels.at(-1), "Flottenmanagement");
  assert.match(applet.iconPaths.at(-1), /icons\/starwars-04-destroyer\.png$/);
  assert.equal(applet._settingsValid, true);
});

test("invalid icon and panel display settings fail closed to safe defaults", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  fixture.setSetting("panel-icon", "../../outside");
  assert.equal(applet.panelIcon, "hive-01-core");
  assert.equal(applet._settingsValid, false);
  assert.match(applet.iconPaths.at(-1), /icons\/hive-01-core\.png$/);

  fixture.setSetting("settings-icon", "not-an-icon");
  fixture.setSetting("panel-display", "icon-only-with-command");
  assert.equal(applet.settingsIcon, "hive-02-queen-crown");
  assert.equal(applet.panelDisplay, "icon-text");
  assert.equal(applet._settingsValid, false);
  assert.match(applet._settingsMenuItem._codexIconPath, /icons\/hive-02-queen-crown\.png$/);
});

test("fleet status terminal uses Ghostty by default and the configured executable", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const terminalStatusItem = applet.menu.items[3];

  assert.equal(getMenuItemText(terminalStatusItem), "Flottenstatus im Terminal");
  terminalStatusItem.activate();
  assert.deepEqual(Array.from(fixture.spawned[0]), [
    "ghostty",
    "-e",
    "/bin/bash",
    "-c",
    "'/home/tester/.local/bin/codex-master-mcp' status all --agents-limit 30 ; printf '\\n\\nZum Schließen Enter drücken ... '; read -r",
  ]);

  fixture.setSetting("terminal-command", "gnome-terminal");
  terminalStatusItem.activate();
  assert.deepEqual(Array.from(fixture.spawned[1]), [
    "gnome-terminal",
    "--",
    "/bin/bash",
    "-c",
    "'/home/tester/.local/bin/codex-master-mcp' status all --agents-limit 30 ; printf '\\n\\nZum Schließen Enter drücken ... '; read -r",
  ]);

  fixture.setSetting("terminal-command", "konsole");
  terminalStatusItem.activate();
  assert.deepEqual(Array.from(fixture.spawned[2]), [
    "konsole",
    "-e",
    "/bin/bash",
    "-c",
    "'/home/tester/.local/bin/codex-master-mcp' status all --agents-limit 30 ; printf '\\n\\nZum Schließen Enter drücken ... '; read -r",
  ]);
});

test("settings parser canonicalizes bounded concrete ids and never launches attacker text", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  assert.equal(fixture.settingsInstances.length, 1);
  assert.deepEqual(Array.from(applet._trackedAgents), ["a1", "b1"]);

  fixture.setSetting("tracked-agents", " A2, b3, a2, C100 ");
  assert.deepEqual(Array.from(applet._trackedAgents), ["a2", "b3", "c100"]);
  applet.menu.items[0].activate();
  assert.deepEqual(Array.from(fixture.launcherSpawns.at(-1).argv.slice(4)), ["a2", "b3", "c100"]);

  fixture.setSetting("tracked-agents", "a1;--force /tmp/owned");
  assert.deepEqual(Array.from(applet._trackedAgents), ["a1", "b1"]);
  assert.equal(applet._settingsValid, false);
  assert.match(getMenuItemText(applet._statusSummaryItem), /Konfiguration/);
  applet.menu.items[0].activate();
  fixture.subprocesses[0].emitDone();
  const argv = fixture.launcherSpawns.at(-1).argv;
  assert.deepEqual(Array.from(argv.slice(4)), ["a1", "b1"]);
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
  assert.match(getMenuItemText(applet._statusSummaryItem), /Konfiguration/);
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
    { key: "terminal-command", value: "ghostty --bad", property: "terminalCommand", expected: "ghostty", valid: false },
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

test("quick-control UI keeps title and separates activity backend and stale state", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(applet.labels.at(-1), "Flottenmanagement");
  assert.match(applet.tooltips.at(-1), /Aktivität/);
  assert.match(applet.tooltips.at(-1), /Backend/);
  assert.match(applet.tooltips.at(-1), /Schnellsteuerung/);
  assert.match(getMenuItemText(applet._statusSummaryItem), /Schnellsteuerung/);
  assert.equal(applet._statusRowItems.filter((item) => item.actor.visible).length, 2);
  assert.ok(getMenuItemText(applet._statusRowItems[0]).startsWith("a1:"));
  assert.ok(getMenuItemText(applet._statusRowItems[1]).startsWith("b1:"));
  assert.equal(getMenuItemText(applet._quickControlSubmenuItem), "Schnellsteuerung (1)");
  assert.equal(getMenuItemText(applet._startActionItem), "b1 starten");
  assert.equal(applet._startActionItem.actor.visible, true);
  assert.ok(!applet.menu.items.some((item) => /Interrupt/.test(getMenuItemText(item))));

  applet._markRefreshFailed();
  assert.match(getMenuItemText(applet._statusSummaryItem), /veraltet/i);
  assert.equal(applet.labels.at(-1), "Flottenmanagement");

  fixture.setSetting("tracked-agents", "a2");
  assert.equal(applet._statusLastGood, null, "fleet change clears old fleet snapshot");
  assert.equal(applet._statusRowItems.filter((item) => item.actor.visible).length, 1);
  assert.ok(getMenuItemText(applet._statusRowItems[0]).startsWith("a2:"));
});

test("quick control preallocates fixed rows and validates one start plus safe stops", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();
  payload.agents[0] = {
    ...payload.agents[0],
    backend_state: "ok",
    control_state: "ready",
    identity_state: "verified",
    allowed_action: "stop",
    context_token: STOP_CONTEXT_VALUE,
  };

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(fixture.createdQuickControlRows(), 10);
  assert.equal(getMenuItemText(applet._quickControlSubmenuItem), "Schnellsteuerung (2)");
  assert.equal(getMenuItemText(applet._startActionItem), "b1 starten");
  assert.equal(getMenuItemText(applet._stopActionItems[0]), "a1 stoppen");
  assert.equal(applet._stopActionItems.filter((item) => item.actor.visible).length, 1);

  const duplicateStart = JSON.parse(JSON.stringify(payload));
  duplicateStart.agents[0] = {
    ...duplicateStart.agents[1],
    agent: "a1",
    context_token: OTHER_CONTEXT_VALUE,
  };
  realignCounts(duplicateStart);
  assert.equal(applet._maybeApplyStatusPayload(duplicateStart), false);

  const malformedToken = JSON.parse(JSON.stringify(payload));
  malformedToken.agents[1].context_token = MALFORMED_CONTEXT_VALUE;
  assert.equal(applet._maybeApplyStatusPayload(malformedToken), false);
});

test("start confirmation launches one fixed action argv then exactly one status refresh", async () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const initial = samplePayload();
  const refreshed = samplePayload();
  refreshed.agents[1] = {
    ...refreshed.agents[1],
    activity_state: "running",
    identity_state: "verified",
    allowed_action: "stop",
    context_token: STOP_CONTEXT_VALUE,
  };
  realignCounts(refreshed);
  queuePayloadProcess(fixture, {
    agent: "b1",
    action: "start",
    status: "completed",
    state: "running",
    raw_output: "not_returned",
  });
  queuePayloadProcessV2(fixture, refreshed);

  assert.equal(applet._maybeApplyStatusPayload(initial), true);
  applet._startActionItem.activate();
  assert.equal(fixture.subprocesses.length, 0, "arming never mutates");
  assert.match(getMenuItemText(applet._confirmationDetailItem), /b1 wirklich starten/);
  assert.equal(applet._confirmationConfirmItem.actor.visible, true);

  applet._confirmationConfirmItem.activate();
  assert.equal(fixture.subprocesses.length, 1);
  assert.deepEqual(Array.from(fixture.launcherSpawns[0].argv).slice(1), [
    "applet-action",
    "start",
    "b1",
    "c3RhcnQ.c2ln",
  ]);
  applet.menu.items[0].activate();
  assert.equal(fixture.subprocesses.length, 1, "manual refresh cannot overlap mutation");

  fixture.subprocesses[0].emitDone();
  await Promise.resolve();
  assert.equal(fixture.subprocesses.length, 2, "one read-only refresh follows mutation");
  assert.equal(fixture.launcherSpawns[1].argv[1], "applet-status");
  applet.menu.items[0].activate();
  assert.equal(applet._statusPendingRefresh, false, "post-action refresh is never duplicated");
  fixture.subprocesses[1].emitDone();
  await Promise.resolve();

  assert.equal(fixture.subprocesses.length, 2);
  assert.equal(applet._actionInFlight, false);
  assert.equal(applet._actionsAwaitingRefresh, false);
  assert.equal(applet._statusLastGood.agents[1].activity_state, "running");
});

test("confirmation cancel and mutation timeout never retry", async () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  assert.equal(applet._maybeApplyStatusPayload(samplePayload()), true);

  applet._startActionItem.activate();
  applet._confirmationCancelItem.activate();
  assert.equal(fixture.subprocesses.length, 0);
  assert.equal(applet._armedAction, null);

  queuePayloadProcess(fixture, { ignored: true }, { holdEof: true });
  queuePayloadProcessV2(fixture, samplePayload());
  applet._startActionItem.activate();
  applet._confirmationConfirmItem.activate();
  assert.equal(fixture.subprocesses.length, 1);
  fixture.runTimeouts();
  assert.equal(fixture.subprocesses[0].forceExitCount, 1);
  fixture.subprocesses[0].stdout.releaseEof();
  fixture.subprocesses[0].stderr.releaseEof();
  fixture.subprocesses[0].emitDone();
  await Promise.resolve();

  assert.equal(
    fixture.launcherSpawns.filter((launch) => launch.argv[1] === "applet-action").length,
    1,
    "timeout never retries mutation"
  );
  assert.equal(fixture.launcherSpawns.filter((launch) => launch.argv[1] === "applet-status").length, 1);
});

test("quick-control object identities survive 500 renders and action removal", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const submenu = applet._quickControlSubmenuItem;
  const startItem = applet._startActionItem;
  const stopItems = applet._stopActionItems.slice();
  const confirmItems = [
    applet._confirmationDetailItem,
    applet._confirmationConfirmItem,
    applet._confirmationCancelItem,
  ];

  for (let cycle = 0; cycle < 500; cycle += 1) {
    assert.equal(applet._maybeApplyStatusPayload(samplePayload()), true);
  }
  assert.equal(applet._quickControlSubmenuItem, submenu);
  assert.equal(applet._startActionItem, startItem);
  assert.deepEqual(applet._stopActionItems, stopItems);
  assert.deepEqual(
    [applet._confirmationDetailItem, applet._confirmationConfirmItem, applet._confirmationCancelItem],
    confirmItems
  );
  assert.equal(fixture.createdQuickControlRows(), 10);

  queuePayloadProcess(fixture, { ignored: true }, { holdEof: true });
  applet._startActionItem.activate();
  applet._confirmationConfirmItem.activate();
  applet.on_applet_removed_from_panel();
  assert.equal(applet._cleanupComplete, true);
  assert.equal(applet._quickControlSubmenuItem, null);
  assert.equal(applet._stopActionItems.length, 0);
  assert.equal(applet._armedAction, null);
  assert.equal(applet._actionInFlight, false);
  assert.equal(fixture.activeTimers().length, 0);
});

test("schema v2 allocates one native submenu with six stable child rows", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();
  payload.native_agents.counts.active = 1;
  payload.native_agents.counts.unconfirmed = 1;
  payload.native_agents.agents = [
    sampleNativeAgent(),
    sampleNativeAgent({
      display_id: "agent_02",
      agent_type: "worker",
      activity_state: "unconfirmed",
      updated_at_utc: "1970-01-01T00:16:41Z",
    }),
  ];

  const nativeRowItems = applet._nativeBeeRowItems?.slice();

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(getMenuItemText(applet._nativeSubmenuItem), "Native Bienen (2)");
  assert.equal(applet._nativeBeeRowItems.length, 6);
  assert.equal(getMenuItemText(applet._nativeBeeRowItems[0]), "explorer · aktiv · 019fc541");
  assert.equal(getMenuItemText(applet._nativeBeeRowItems[1]), "worker · unbestätigt · agent_02");
  assert.equal(fixture.createdNativeRows(), 6);
  assert.equal(applet._nativeBeeRowItems[0], nativeRowItems?.[0]);
  assert.equal(applet._nativeBeeRowItems[5], nativeRowItems?.[5]);
  assert.ok(getMenuItemText(applet._statusRowItems[0]).startsWith("a1:"));
  assert.ok(getMenuItemText(applet._statusRowItems[1]).startsWith("b1:"));
});

test("native submenu keeps six object identities across 500 v2 render cycles", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const readyPayload = samplePayload();
  readyPayload.native_agents.counts.active = 1;
  readyPayload.native_agents.agents = [sampleNativeAgent()];
  const degradedPayload = samplePayload();
  degradedPayload.native_agents.bridge_state = "degraded";
  const nativeSubmenuItem = applet._nativeSubmenuItem;
  const nativeBeeRowItems = applet._nativeBeeRowItems.slice();

  for (let cycle = 0; cycle < 500; cycle += 1) {
    const payload = cycle % 2 === 0 ? readyPayload : degradedPayload;
    assert.equal(applet._maybeApplyStatusPayload(payload), true, `cycle ${cycle}`);
  }

  assert.equal(applet._nativeSubmenuItem, nativeSubmenuItem);
  assert.equal(applet._nativeBeeRowItems.length, 6);
  for (let index = 0; index < nativeBeeRowItems.length; index += 1) {
    assert.equal(applet._nativeBeeRowItems[index], nativeBeeRowItems[index]);
  }
  assert.equal(fixture.createdNativeRows(), 6);
});

test("native overflow reuses sixth row without allocating a seventh", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();
  payload.native_agents = {
    bridge_state: "ready",
    counts: { active: 7, unconfirmed: 0, overflow: 1 },
    agents: Array.from({ length: 6 }, (_value, index) => sampleNativeAgent({
      display_id: `agent_0${index + 1}`,
    })),
    truncated: true,
  };

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.equal(getMenuItemText(applet._nativeSubmenuItem), "Native Bienen (7)");
  assert.equal(applet._nativeBeeRowItems.filter((item) => item.actor.visible).length, 6);
  assert.equal(getMenuItemText(applet._nativeBeeRowItems[5]), "+1 weitere Native Bienen");
  assert.equal(applet._nativeBeeRowItems[6], undefined);
  assert.equal(fixture.createdNativeRows(), 6);
});

test("schema v2 bridge degradation keeps managed rows and shows native diagnostic", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const payload = samplePayload();
  payload.native_agents = {
    bridge_state: "degraded",
    counts: { active: 0, unconfirmed: 0, overflow: 0 },
    agents: [],
    truncated: false,
  };

  assert.equal(applet._maybeApplyStatusPayload(payload), true);
  assert.ok(getMenuItemText(applet._statusRowItems[0]).startsWith("a1:"));
  assert.equal(getMenuItemText(applet._nativeSubmenuItem), "Native Bienen");
  assert.match(getMenuItemText(applet._nativeBeeRowItems[0]), /eingeschränkt/i);
  assert.equal(applet._nativeBeeRowItems[1].actor.visible, false);
});

test("argv uses schema-version 4 before validated pinned ids", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  fixture.setSetting("tracked-agents", " A2, b3, a2, C100 ");
  applet.menu.items[0].activate();

  const argv = Array.from(fixture.launcherSpawns.at(-1).argv);
  assert.deepEqual(argv.slice(1), ["applet-status", "--schema-version", "4", "a2", "b3", "c100"]);
});

test("applet invalid or mismatched resource generation is unavailable", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const good = samplePayload();

  assert.equal(applet._resourceGenerationHighWater, 0);
  assert.equal(applet._maybeApplyStatusPayload(good), true);
  assert.equal(applet._statusLastGood.resource.generation, 7);
  assert.equal(applet._statusLastGood.resource.state, "ready");
  assert.equal(applet._resourceGenerationHighWater, 7);

  const malformed = samplePayload();
  malformed.resource.generation = "7";
  assert.equal(applet._maybeApplyStatusPayload(malformed), true);
  assert.equal(JSON.stringify(applet._statusLastGood.resource), JSON.stringify({
    schema_version: 1,
    generation: 0,
    state: "unavailable",
    bottleneck: "unknown",
    trend: {},
    confidence: "low",
    preferred_profiles: [],
    avoid_profiles: [],
    raw_output: "not_returned",
  }));
  assert.equal(applet._resourceGenerationHighWater, 7);

  const duplicateProfile = samplePayload();
  duplicateProfile.resource.preferred_profiles = ["cpu_low", "cpu_low"];
  assert.equal(applet._maybeApplyStatusPayload(duplicateProfile), true);
  assert.equal(applet._statusLastGood.resource.state, "unavailable");
  assert.equal(applet._resourceGenerationHighWater, 7);

  const mismatched = samplePayload();
  mismatched.resource.generation = 6;
  assert.equal(applet._maybeApplyStatusPayload(mismatched), true);
  assert.equal(applet._statusLastGood.resource.state, "unavailable");
  assert.equal(applet._statusLastGood.resource.generation, 0);
  assert.equal(applet._resourceGenerationHighWater, 7);

  assert.equal(applet._maybeApplyStatusPayload(good), true);
  assert.equal(applet._statusLastGood.resource.generation, 7);
  assert.equal(applet._resourceGenerationHighWater, 7);

  const newer = samplePayload();
  newer.resource.generation = 8;
  assert.equal(applet._maybeApplyStatusPayload(newer), true);
  assert.equal(applet._statusLastGood.resource.generation, 8);
  assert.equal(applet._resourceGenerationHighWater, 8);

  assert.equal(applet._cleanupStatusResources(), true);
  assert.equal(applet._resourceGenerationHighWater, 0);
});

test("applet never reads monitor path or spawns second status process", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const before = fixture.launcherSpawns.length;

  applet._refreshStatus();

  assert.equal(fixture.launcherSpawns.length, before + 1);
  assert.deepEqual(
    Array.from(fixture.launcherSpawns.at(-1).argv).slice(1, 4),
    ["applet-status", "--schema-version", "4"]
  );
  assert.doesNotMatch(source, /resource-snapshot-v1\.json|codex-master-resource-monitor/);
});

test("refresh-on-open and bounded opt-in background timer preserve single-flight", () => {
  const fixture = loadApplet();
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

  applet.on_applet_clicked();
  assert.equal(fixture.subprocesses.length, 2, "menu-open starts status and overview refreshes");

  fixture.setSetting("refresh-interval-seconds", 5);
  fixture.setSetting("background-refresh", true);
  const background = fixture.activeTimers("background");
  assert.equal(background.length, 1);
  assert.equal(background[0].seconds, 15);
  background[0].callback();
  assert.equal(fixture.subprocesses.length, 2, "timer cannot overlap active status refresh");
  assert.equal(applet._statusPendingRefresh, true);

  fixture.subprocesses[0].emitDone();
  assert.equal(fixture.subprocesses.length, 3, "pending status refresh is coalesced once");
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
  assert.match(getMenuItemText(applet._statusSummaryItem), /Konfigurationsfehler/);
});

test("invalid background timer source ids fail settings closed", () => {
  for (const invalidSourceId of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const fixture = loadApplet();
    fixture.setSetting("background-refresh", true);
    fixture.GLib.timeout_add_seconds = () => invalidSourceId;

    const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);

    assert.equal(applet._backgroundRefreshSource, 0);
    assert.equal(fixture.activeTimers("background").length, 0);
    assert.equal(applet._settingsValid, false);
    assert.match(getMenuItemText(applet._statusSummaryItem), /Konfigurationsfehler/);
  }
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
  assert.equal(JSON.stringify(applet._statusLastGood), JSON.stringify(payload));
  assert.doesNotMatch(getMenuItemText(applet._statusSummaryItem), /veraltet/i);

  queuePayloadProcess(fixture, payload, { exitCode: 1 });
  statusItem.activate();
  fixture.subprocesses[1].emitDone();
  assert.equal(JSON.stringify(applet._statusLastGood), JSON.stringify(payload));
  assert.match(getMenuItemText(applet._statusSummaryItem), /veraltet/i);
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

test("successful stream callback after removal starts no further read", () => {
  const fixture = loadApplet();
  const lateBytes = makeBytes("late");
  const stdout = {
    callbacks: [],
    readAsyncCount: 0,
    readFinishCount: 0,
    read_bytes_async(_size, _priority, _cancellable, callback) {
      this.readAsyncCount += 1;
      this.callbacks.push(callback);
    },
    read_bytes_finish(result) {
      this.readFinishCount += 1;
      return result;
    },
    releaseOne() {
      const callback = this.callbacks.shift();
      callback(this, {
        get_data: () => lateBytes,
        get_size: () => lateBytes.length,
      });
    },
  };
  const stderr = fixture.makeStream([], true);
  fixture.setProcessFactory(() => ({
    forceExitCount: 0,
    waitCallbacks: [],
    get_stdout_pipe() { return stdout; },
    get_stderr_pipe() { return stderr; },
    get_successful: () => false,
    force_exit() { this.forceExitCount += 1; },
    wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
    wait_finish() {},
  }));
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];

  applet.on_applet_removed_from_panel();
  stdout.releaseOne();

  assert.equal(stdout.readFinishCount, 1, "completed Gio operation is finished");
  assert.equal(stdout.readAsyncCount, 1, "removed applet schedules no further stream read");
  assert.equal(process.forceExitCount, 1);
  assert.equal(fixture.subprocesses.length, 1);
  assert.equal(fixture.activeTimers().length, 0);
});

test("status timeout self-removes after removal cleanup cannot remove its source", () => {
  const fixture = loadApplet();
  queuePayloadProcess(fixture, samplePayload(), { holdEof: true });
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];
  const statusId = fixture.activeTimers("timeout")[0].id;
  const realSourceRemove = fixture.GLib.source_remove;
  fixture.GLib.source_remove = (id) => {
    if (id === statusId) throw new Error("injected persistent status source removal failure");
    return realSourceRemove(id);
  };

  applet.on_applet_removed_from_panel();

  assert.equal(applet._cleanupComplete, false);
  assert.equal(applet._statusActiveState !== null, true);
  assert.equal(process.forceExitCount, 1);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  fixture.runTimeouts();
  assert.equal(fixture.activeTimers("timeout").length, 0, "callback removes its own failed source");
  assert.equal(applet._statusActiveState, null, "callback retries removal cleanup without source recursion");
  assert.equal(applet._activeStatusProcess, null);
  assert.equal(applet._cleanupComplete, true);
  assert.equal(process.forceExitCount, 1);
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
      waitFinishAttempts: 0,
      waitCallbacks: [],
      stdout,
      stderr,
      get_stdout_pipe() { return stdout; },
      get_stderr_pipe() { return stderr; },
      get_successful: () => false,
      force_exit() {
        this.forceExitCount += 1;
        if (this.forceExitCount <= 2) throw new Error("injected timeout force failure");
      },
      wait_async(_cancellable, callback) { this.waitCallbacks.push(callback); },
      wait_finish() {
        this.waitFinishAttempts += 1;
        if (this.waitFinishAttempts === 1) throw new Error("injected cancelled wait");
      },
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
  const timedOutState = applet._statusActiveState;
  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();
  assert.equal(fixture.subprocesses.length, 1, "cancel callbacks cannot bypass the kill retry");
  assert.equal(applet._statusActiveState, timedOutState);
  assert.equal(fixture.activeTimers("timeout").length, 1);

  fixture.runTimeouts();
  assert.equal(process.forceExitCount, 3);
  assert.equal(timedOutState.forceExitCalled, true);
  assert.equal(applet._statusActiveState, timedOutState);
  assert.equal(fixture.activeTimers("timeout").length, 1);
  assert.equal(fixture.subprocesses.length, 1);
  process.emitDone();
  assert.equal(timedOutState.timeoutSource, 0);
  assert.equal(fixture.subprocesses.length, 2, "pending refresh starts after recovered timeout cleanup");
  fixture.subprocesses[1].emitDone();
  assert.equal(applet._statusInFlight, false);
});

test("successful wait after timeout does not require kill confirmation", () => {
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
        throw new Error("injected permanent force failure");
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
  const applet = fixture.main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  applet.menu.items[0].activate();
  const process = fixture.subprocesses[0];

  fixture.runTimeouts();
  process.stdout.releaseEof();
  process.stderr.releaseEof();
  process.emitDone();

  assert.equal(process.forceExitCount, 1);
  assert.equal(applet._statusInFlight, false);
  assert.equal(applet._statusActiveState, null);
  assert.equal(fixture.activeTimers("timeout").length, 0);
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
      Array.from(fixture.launcherSpawns.at(-1).argv.slice(4)),
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
      summary: getMenuItemText(applet._statusSummaryItem),
    }).includes("SECRET_PROMPT"));
  }
});
