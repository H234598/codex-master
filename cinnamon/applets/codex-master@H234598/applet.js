/* -*- mode: js2; js2-basic-offset: 4; indent-tabs-mode: nil -*- */
const Applet = imports.ui.applet;
const PopupMenu = imports.ui.popupMenu;
const Settings = imports.ui.settings;
const Util = imports.misc.util;
const Gio = imports.gi.Gio;
const GLib = imports.gi.GLib;
const ByteArray = imports.byteArray;

const LABEL = "Flottenmanagement";
const UUID = "codex-master@H234598";
const APPLET_STATUS_TIMEOUT_MILLISECONDS = 10 * 1000;
const APPLET_STDOUT_LIMIT_BYTES = 64 * 1024;
const APPLET_STDERR_LIMIT_BYTES = 8 * 1024;
const APPLET_STATUS_CHUNK_BYTES = 1024;
const APPLET_STATUS_AGENTS = ["a1", "b1"];
const DEFAULT_TRACKED_AGENTS_TEXT = "a1,b1";
const DEFAULT_REFRESH_ON_OPEN = true;
const DEFAULT_BACKGROUND_REFRESH = false;
const DEFAULT_REFRESH_INTERVAL_SECONDS = 60;
const MIN_REFRESH_INTERVAL_SECONDS = 15;
const MAX_REFRESH_INTERVAL_SECONDS = 3600;
const MAX_TRACKED_AGENTS = 6;
const MAX_TRACKED_AGENTS_SETTING_CHARS = 128;
const APPLET_ERROR_LOG_LIMIT = 8;
const APPLET_IMMEDIATE_EXIT_WAIT_LIMIT = 2;
const APPLET_SAFE_PATH = "/usr/bin:/bin";
const APPLET_STATUS_COMMAND = "applet-status";
let appletErrorLogCount = 0;
const APPLET_STATUS_REQUIRED_FIELDS = [
    "schema_version", "mode", "activity_state", "backend_state", "control_state", "counts", "agents", "raw_output",
];
const APPLET_STATUS_REQUIRED_ROW_FIELDS = [
    "agent", "activity_state", "backend_state", "control_state", "auth_state", "identity_state", "lease_state",
];
const APPLET_STATUS_REQUIRED_COUNTS = ["tracked", "running", "sleeping", "ready", "blocked", "issues"];
const APPLET_STATUS_RAW_OUTPUT = "not_returned";
const APPLET_STATUS_ERROR_ROW = {
    activity_state: "unknown",
    backend_state: "error",
    control_state: "unknown",
    auth_state: "unknown",
    identity_state: "unknown",
    lease_state: "unreadable",
};
const APPLET_STATUS_VALID_STRINGS = {
    snapshot: {
        activity_state: new Set(["running", "sleeping", "unknown", "mixed"]),
        backend_state: new Set(["ok", "degraded", "unavailable"]),
        control_state: new Set(["ready", "blocked", "unknown", "mixed"]),
    },
    row: {
        activity_state: new Set(["running", "sleeping", "unknown"]),
        backend_state: new Set(["ok", "degraded", "error"]),
        control_state: new Set(["ready", "blocked", "unknown"]),
        auth_state: new Set(["ready", "blocked", "unknown"]),
        identity_state: new Set(["verified", "unverified", "stopped", "unknown"]),
        lease_state: new Set(["unclaimed", "held", "expired", "unreadable"]),
    },
};
const APPLET_INVALID_ENV_VARS = [
    "BASH_ENV",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "GJS_PATH",
];

function FlottenmanagementApplet(metadata, orientation, panel_height, instance_id) {
    this._init(metadata, orientation, panel_height, instance_id);
}

FlottenmanagementApplet.prototype = {
    __proto__: Applet.TextApplet.prototype,

    _init(metadata, orientation, panel_height, instance_id) {
        Applet.TextApplet.prototype._init.call(this, orientation, panel_height, instance_id);
        this._removed = false;
        this._cleanupComplete = false;
        this._statusInFlight = false;
        this._statusPendingRefresh = false;
        this._statusGeneration = 0;
        this._statusActiveGeneration = 0;
        this._statusLastGood = null;
        this._statusActiveState = null;
        this._statusViewState = "initializing";
        this._backgroundRefreshSource = 0;
        this._trackedAgents = APPLET_STATUS_AGENTS.slice();
        this.trackedAgentsSetting = DEFAULT_TRACKED_AGENTS_TEXT;
        this.refreshOnOpenSetting = DEFAULT_REFRESH_ON_OPEN;
        this.backgroundRefreshSetting = DEFAULT_BACKGROUND_REFRESH;
        this.refreshIntervalSecondsSetting = DEFAULT_REFRESH_INTERVAL_SECONDS;
        this.refreshOnOpen = DEFAULT_REFRESH_ON_OPEN;
        this.backgroundRefresh = DEFAULT_BACKGROUND_REFRESH;
        this.refreshIntervalSeconds = DEFAULT_REFRESH_INTERVAL_SECONDS;
        this._settingsValid = true;
        this._settingsInitializing = false;
        this.settings = null;
        this._settingsCleanupPending = null;
        this._statusSummaryItem = null;
        this._statusRowItems = [];
        this._menuCleanupState = {};
        this._signalConnections = [];
        this.menu = null;
        this.menuManager = null;

        if (!metadata || metadata.uuid !== UUID) {
            this.set_applet_label("Applet-Fehler");
            this.set_applet_tooltip("UUID mismatch");
            return;
        }

        this.set_applet_label(LABEL);
        this.set_applet_tooltip("Flottenmanagement öffnen");

        this.menu = new Applet.AppletPopupMenu(this, orientation);
        this.menuManager = new PopupMenu.PopupMenuManager(this);
        this.menuManager.addMenu(this.menu);

        const statusItem = new PopupMenu.PopupMenuItem("Jetzt aktualisieren");
        this._connectTracked(statusItem, "activate", () => {
            if (this._removed) return;
            this._refreshStatus();
        });
        this.menu.addMenuItem(statusItem);

        const settingsItem = new PopupMenu.PopupMenuItem("Applet-Verwaltung öffnen");
        this._connectTracked(settingsItem, "activate", () => {
            if (this._removed) return;
            try {
                Util.spawn(["cinnamon-settings", "applets"]);
            } catch (error) {
                this._logCleanupError(error);
            }
        });
        this.menu.addMenuItem(settingsItem);

        this._statusSummaryItem = new PopupMenu.PopupMenuItem("", { reactive: false });
        this.menu.addMenuItem(this._statusSummaryItem);
        for (let index = 0; index < MAX_TRACKED_AGENTS; index += 1) {
            const rowItem = new PopupMenu.PopupMenuItem("", { reactive: false });
            this._statusRowItems.push(rowItem);
            this.menu.addMenuItem(rowItem);
        }

        this._initializeSettings(instance_id);
        this._applySettings();
    },

    _initializeSettings(instanceId) {
        this._settingsInitializing = true;
        try {
            this.settings = new Settings.AppletSettings(this, UUID, instanceId);
            const bind = (key, property) => {
                const bound = this.settings.bindProperty(
                    Settings.BindingDirection.IN,
                    key,
                    property,
                    () => this._onSettingsChanged(),
                    null
                );
                if (bound !== true) throw new Error("Applet setting binding failed");
            };
            bind("tracked-agents", "trackedAgentsSetting");
            bind("refresh-on-open", "refreshOnOpenSetting");
            bind("background-refresh", "backgroundRefreshSetting");
            bind("refresh-interval-seconds", "refreshIntervalSecondsSetting");
        } catch (_error) {
            const incompleteSettings = this.settings;
            let settingsFinalized = !incompleteSettings || typeof incompleteSettings.finalize !== "function";
            for (let attempt = 0; attempt < 2 && !settingsFinalized; attempt += 1) {
                try {
                    incompleteSettings.finalize();
                    settingsFinalized = true;
                } catch (error) {
                    this._logCleanupError(error);
                }
            }
            this._settingsCleanupPending = settingsFinalized ? null : incompleteSettings;
            this.settings = null;
            this._settingsValid = false;
        } finally {
            this._settingsInitializing = false;
        }
    },

    _normalizeTrackedAgents(value) {
        if (typeof value !== "string" || value.length > MAX_TRACKED_AGENTS_SETTING_CHARS) return null;
        const entries = value.split(",").map((entry) => entry.trim().toLowerCase());
        if (entries.length < 1 || entries.length > MAX_TRACKED_AGENTS) return null;
        const normalized = [];
        const seen = new Set();
        for (const entry of entries) {
            if (!/^[abc](?:[1-9]|[1-9][0-9]|100)$/.test(entry)) return null;
            if (seen.has(entry)) continue;
            seen.add(entry);
            normalized.push(entry);
        }
        return normalized.length > 0 && normalized.length <= MAX_TRACKED_AGENTS ? normalized : null;
    },

    _applySettings() {
        let valid = this.settings !== null;
        const previousAgents = this._trackedAgents.join(",");
        const agents = this._normalizeTrackedAgents(this.trackedAgentsSetting);
        this._trackedAgents = agents || APPLET_STATUS_AGENTS.slice();
        if (!agents) valid = false;

        if (typeof this.refreshOnOpenSetting !== "boolean") {
            this.refreshOnOpen = DEFAULT_REFRESH_ON_OPEN;
            valid = false;
        } else {
            this.refreshOnOpen = this.refreshOnOpenSetting;
        }
        if (typeof this.backgroundRefreshSetting !== "boolean") {
            this.backgroundRefresh = DEFAULT_BACKGROUND_REFRESH;
            valid = false;
        } else {
            this.backgroundRefresh = this.backgroundRefreshSetting;
        }
        if (!Number.isFinite(this.refreshIntervalSecondsSetting)) {
            this.refreshIntervalSeconds = DEFAULT_REFRESH_INTERVAL_SECONDS;
            valid = false;
        } else {
            this.refreshIntervalSeconds = Math.min(
                MAX_REFRESH_INTERVAL_SECONDS,
                Math.max(MIN_REFRESH_INTERVAL_SECONDS, Math.trunc(this.refreshIntervalSecondsSetting))
            );
        }

        this._settingsValid = valid;
        if (previousAgents !== this._trackedAgents.join(",")) {
            this._statusLastGood = null;
            this._statusViewState = "initializing";
            if (this._statusInFlight) this._statusPendingRefresh = true;
        }
        this._restartBackgroundRefresh();
        this._renderStatusSafely();
    },

    _onSettingsChanged() {
        if (this._removed || this._settingsInitializing) return;
        this._applySettings();
    },

    _restartBackgroundRefresh() {
        if (this._backgroundRefreshSource) {
            try {
                GLib.source_remove(this._backgroundRefreshSource);
            } catch (error) {
                this._settingsValid = false;
                this._logCleanupError(error);
                return;
            }
            this._backgroundRefreshSource = 0;
        }
        if (this._removed || !this._settingsValid || !this.backgroundRefresh) return;
        try {
            const backgroundRefreshSource = GLib.timeout_add_seconds(
                GLib.PRIORITY_DEFAULT,
                this.refreshIntervalSeconds,
                () => {
                    if (this._removed || !this._settingsValid || !this.backgroundRefresh) {
                        this._backgroundRefreshSource = 0;
                        return GLib.SOURCE_REMOVE;
                    }
                    this._refreshStatus();
                    return GLib.SOURCE_CONTINUE;
                }
            );
            if (!Number.isSafeInteger(backgroundRefreshSource) || backgroundRefreshSource <= 0) {
                throw new Error("Invalid background timeout source id");
            }
            this._backgroundRefreshSource = backgroundRefreshSource;
        } catch (error) {
            this._backgroundRefreshSource = 0;
            this._settingsValid = false;
            this._logCleanupError(error);
        }
    },

    _trackedStatusArgv() {
        const home = GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown";
        return [home + "/.local/bin/codex-master-mcp", APPLET_STATUS_COMMAND, ...this._trackedAgents];
    },

    _refreshStatus() {
        if (this._statusInFlight) {
            this._statusPendingRefresh = true;
            return;
        }
        this._startStatusRefresh();
    },

    _startStatusRefresh() {
        if (this._removed) return;

        const generation = ++this._statusGeneration;
        let process;
        try {
            const argv = this._trackedStatusArgv();
            const launcher = Gio.SubprocessLauncher.new(
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
            );
            this._sanitizeLauncherEnvironment(launcher);
            process = launcher.spawnv(argv);
        } catch (_error) {
            this._statusInFlight = false;
            this._markRefreshFailed();
            return;
        }

        let cancellable = null;
        try {
            cancellable = Gio.Cancellable ? new Gio.Cancellable() : null;
        } catch (error) {
            this._logCleanupError(error);
        }

        const state = {
            generation,
            process,
            cancellable,
            cancellableCancelled: false,
            timeoutSource: 0,
            finalizing: false,
            streamFailed: false,
            waitDone: false,
            exitConfirmed: false,
            exitWaitInFlight: false,
            exitWaitAttempts: 0,
            exitWaitCancellable: null,
            exitWaitCancellableCancelled: false,
            stdoutDone: false,
            stderrDone: false,
            stdoutChunks: [],
            stderrChunks: [],
            stdoutByteCount: 0,
            stderrByteCount: 0,
            discardOutput: false,
            waitFailed: false,
            forceExitCalled: false,
            timedOut: false,
            stdoutLimitExceeded: false,
            stderrLimitExceeded: false,
        };

        this._activeStatusProcess = process;
        this._statusActiveState = state;
        this._statusActiveGeneration = generation;
        this._statusInFlight = true;
        this._statusViewState = this._statusLastGood ? "refreshing" : "initializing";
        this._renderStatusSafely();

        const requestForceExit = (stateArg) => {
            if (stateArg.forceExitCalled || !stateArg.process) return true;
            if (typeof stateArg.process.force_exit !== "function") return false;
            try {
                stateArg.process.force_exit();
                stateArg.forceExitCalled = true;
                return true;
            } catch (error) {
                this._logCleanupError(error);
                return false;
            }
        };

        const requestCancel = (stateArg) => {
            if (stateArg.cancellableCancelled || !stateArg.cancellable) return true;
            try {
                stateArg.cancellable.cancel();
                stateArg.cancellableCancelled = true;
                return true;
            } catch (error) {
                this._logCleanupError(error);
                return false;
            }
        };

        const failRefresh = (stateArg) => {
            requestCancel(stateArg);
            stateArg.discardOutput = true;
            this._clearStatusBuffers(stateArg);
            this._markRefreshFailed();
        };

        const attemptFinalize = (stateArg) => {
            if (stateArg.finalizing) return;
            if (!(stateArg.waitDone && stateArg.stdoutDone && stateArg.stderrDone)) {
                return;
            }
            if (stateArg.process && !stateArg.exitConfirmed) return;
            stateArg.finalizing = true;
            if (stateArg.timeoutSource) {
                try {
                    GLib.source_remove(stateArg.timeoutSource);
                } catch (error) {
                    stateArg.finalizing = false;
                    this._logCleanupError(error);
                    return;
                }
                stateArg.timeoutSource = 0;
            }
            this._finalizeStatusProcess(stateArg);
        };

        const ensureExitWait = (stateArg) => {
            if (stateArg.finalizing || stateArg.exitConfirmed || stateArg.exitWaitInFlight || !stateArg.process) return;
            if (typeof stateArg.process.wait_async !== "function") return;
            stateArg.exitWaitAttempts += 1;
            if (!stateArg.exitWaitCancellable) {
                try {
                    stateArg.exitWaitCancellable = Gio.Cancellable ? new Gio.Cancellable() : null;
                } catch (error) {
                    this._logCleanupError(error);
                    if (!stateArg.timeoutSource && stateArg.exitWaitAttempts < APPLET_IMMEDIATE_EXIT_WAIT_LIMIT) {
                        ensureExitWait(stateArg);
                    }
                    return;
                }
            }
            if (!stateArg.exitWaitCancellable || stateArg.exitWaitCancellableCancelled) {
                if (!stateArg.timeoutSource && stateArg.exitWaitAttempts < APPLET_IMMEDIATE_EXIT_WAIT_LIMIT) {
                    ensureExitWait(stateArg);
                }
                return;
            }
            stateArg.exitWaitInFlight = true;
            try {
                stateArg.process.wait_async(stateArg.exitWaitCancellable, (_proc, result) => {
                    try {
                        if (typeof stateArg.process.wait_finish === "function") {
                            stateArg.process.wait_finish(result);
                        }
                        stateArg.exitConfirmed = true;
                        stateArg.waitFailed = false;
                    } catch (_error) {
                        stateArg.waitFailed = true;
                    }
                    stateArg.exitWaitInFlight = false;
                    if (stateArg.finalizing) {
                        stateArg.exitWaitCancellable = null;
                        return;
                    }
                    if (stateArg.exitConfirmed) stateArg.exitWaitCancellable = null;
                    if (
                        !stateArg.exitConfirmed
                        && !stateArg.timeoutSource
                        && stateArg.exitWaitAttempts < APPLET_IMMEDIATE_EXIT_WAIT_LIMIT
                    ) {
                        ensureExitWait(stateArg);
                    }
                    attemptFinalize(stateArg);
                });
            } catch (error) {
                stateArg.exitWaitInFlight = false;
                stateArg.waitFailed = true;
                this._logCleanupError(error);
                if (!stateArg.timeoutSource && stateArg.exitWaitAttempts < APPLET_IMMEDIATE_EXIT_WAIT_LIMIT) {
                    ensureExitWait(stateArg);
                }
            }
        };

        const readStream = (stateArg, key, stream, limit) => {
            if (!stream || typeof stream.read_bytes_async !== "function") {
                stateArg.streamFailed = true;
                stateArg[`${key}Done`] = true;
                requestForceExit(stateArg);
                failRefresh(stateArg);
                attemptFinalize(stateArg);
                return;
            }

            const chunksKey = `${key}Chunks`;
            const byteCountKey = `${key}ByteCount`;
            const doneKey = `${key}Done`;
            const finishKey = key === "stdout" ? "stdoutLimitExceeded" : "stderrLimitExceeded";

            const readChunk = () => {
                try {
                    stream.read_bytes_async(
                        APPLET_STATUS_CHUNK_BYTES,
                        GLib.PRIORITY_DEFAULT,
                        stateArg.cancellable,
                        (reader, result) => {
                            let packet;
                            try {
                                packet = reader.read_bytes_finish(result);
                            } catch (_error) {
                                stateArg.streamFailed = true;
                                stateArg[doneKey] = true;
                                requestForceExit(stateArg);
                                failRefresh(stateArg);
                                attemptFinalize(stateArg);
                                return;
                            }

                            if (stateArg.finalizing) {
                                stateArg[doneKey] = true;
                                return;
                            }

                            if (!packet) {
                                stateArg[doneKey] = true;
                                attemptFinalize(stateArg);
                                return;
                            }

                            let data = null;
                            let size = 0;
                            let bytes = null;
                            try {
                                data = packet.get_data ? packet.get_data() : null;
                                size = packet.get_size ? packet.get_size() : (data ? data.length : 0);
                                bytes = data && size > 0
                                    ? (data instanceof Uint8Array ? data : Uint8Array.from(data))
                                    : null;
                            } catch (_error) {
                                stateArg.streamFailed = true;
                                stateArg[doneKey] = true;
                                requestForceExit(stateArg);
                                failRefresh(stateArg);
                                attemptFinalize(stateArg);
                                return;
                            }
                            if (!data || size <= 0) {
                                stateArg[doneKey] = true;
                                attemptFinalize(stateArg);
                                return;
                            }

                            if (stateArg.discardOutput) {
                                readChunk();
                                return;
                            }

                            const take = Math.max(0, limit - stateArg[byteCountKey]);
                            const exceedsLimit = bytes.length > take;
                            if (take > 0) {
                                const chunk = new Uint8Array(Math.min(bytes.length, take));
                                chunk.set(bytes.subarray(0, chunk.length));
                                stateArg[chunksKey].push(chunk);
                                stateArg[byteCountKey] += chunk.length;
                            }

                            if (exceedsLimit) {
                                stateArg[finishKey] = true;
                                requestForceExit(stateArg);
                                failRefresh(stateArg);
                                stateArg[doneKey] = true;
                                attemptFinalize(stateArg);
                                return;
                            }

                            readChunk();
                        }
                    );
                } catch (_error) {
                    stateArg.streamFailed = true;
                    stateArg[doneKey] = true;
                    requestForceExit(stateArg);
                    failRefresh(stateArg);
                    attemptFinalize(stateArg);
                }
            };

            readChunk();
        };

        try {
            const timeoutSource = GLib.timeout_add(
                GLib.PRIORITY_DEFAULT,
                APPLET_STATUS_TIMEOUT_MILLISECONDS,
                () => {
                    if (state.finalizing || this._removed) {
                        state.timeoutSource = 0;
                        this.on_applet_removed_from_panel();
                        return GLib.SOURCE_REMOVE;
                    }
                    if (!state.exitConfirmed) {
                        state.timedOut = true;
                        requestForceExit(state);
                        failRefresh(state);
                        if (state.waitFailed) ensureExitWait(state);
                    }
                    if (!state.exitConfirmed) {
                        attemptFinalize(state);
                        return GLib.SOURCE_CONTINUE;
                    }
                    state.timeoutSource = 0;
                    attemptFinalize(state);
                    return GLib.SOURCE_REMOVE;
                }
            );
            if (!Number.isSafeInteger(timeoutSource) || timeoutSource <= 0) {
                throw new Error("Invalid status timeout source id");
            }
            state.timeoutSource = timeoutSource;
        } catch (error) {
            state.timedOut = true;
            if (!requestForceExit(state)) requestForceExit(state);
            this._logCleanupError(error);
            failRefresh(state);
        }

        let stdoutStream = null;
        let stderrStream = null;
        try {
            stdoutStream = process.get_stdout_pipe();
            stderrStream = process.get_stderr_pipe();
        } catch (_error) {
            state.streamFailed = true;
            state.stdoutDone = true;
            state.stderrDone = true;
            requestForceExit(state);
            failRefresh(state);
        }
        if (!state.stdoutDone) {
            readStream(state, "stdout", stdoutStream, APPLET_STDOUT_LIMIT_BYTES);
        }
        if (!state.stderrDone) {
            readStream(state, "stderr", stderrStream, APPLET_STDERR_LIMIT_BYTES);
        }

        try {
            process.wait_async(state.cancellable, (_proc, result) => {
                try {
                    if (typeof process.wait_finish === "function") {
                        process.wait_finish(result);
                    }
                } catch (_error) {
                    state.waitFailed = true;
                    requestForceExit(state);
                    failRefresh(state);
                    ensureExitWait(state);
                }
                if (!state.waitFailed) state.exitConfirmed = true;
                state.waitDone = true;
                attemptFinalize(state);
            });
        } catch (_error) {
            state.waitFailed = true;
            state.waitDone = true;
            requestForceExit(state);
            failRefresh(state);
            ensureExitWait(state);
            attemptFinalize(state);
        }
    },

    _sanitizeLauncherEnvironment(launcher) {
        launcher.setenv("PATH", APPLET_SAFE_PATH, true);
        const home = GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown";
        launcher.setenv("HOME", home, true);
        for (const key of APPLET_INVALID_ENV_VARS) {
            if (typeof launcher.unsetenv === "function") {
                launcher.unsetenv(key);
            }
        }
    },

    _clearStatusBuffers(state) {
        if (!state) return;
        state.stdoutChunks = [];
        state.stderrChunks = [];
        state.stdoutByteCount = 0;
        state.stderrByteCount = 0;
    },

    _finalizeStatusProcess(state) {
        const generation = state.generation;
        if (generation !== this._statusActiveGeneration) return;

        this._statusInFlight = false;
        this._statusActiveGeneration = 0;
        this._statusActiveState = null;
        this._activeStatusProcess = null;

        let applied = false;
        if (!state.timedOut && !state.waitFailed && !state.streamFailed && !state.stdoutLimitExceeded && !state.stderrLimitExceeded) {
            const payload = state.process ? this._collectProcessPayload(state) : null;
            if (payload) {
                let processSuccessful = false;
                try {
                    processSuccessful = state.process.get_successful();
                } catch (_error) {
                    processSuccessful = false;
                }
                if (processSuccessful) {
                    applied = this._maybeApplyStatusPayload(payload);
                }
            }
        }
        this._clearStatusBuffers(state);
        if (!applied) this._markRefreshFailed();

        if (state.timeoutSource) {
            GLib.source_remove(state.timeoutSource);
            state.timeoutSource = 0;
        }

        if (this._statusPendingRefresh) {
            this._statusPendingRefresh = false;
            this._startStatusRefresh();
        }
    },

    _collectProcessPayload(state) {
        const stdoutChunks = state.stdoutChunks;
        const stdoutByteCount = state.stdoutByteCount;
        this._clearStatusBuffers(state);
        try {
            const stdoutBytes = new Uint8Array(stdoutByteCount);
            let offset = 0;
            for (const chunk of stdoutChunks) {
                stdoutBytes.set(chunk, offset);
                offset += chunk.length;
            }
            const stdoutText = ByteArray.toString(stdoutBytes);
            if (typeof stdoutText !== "string" || stdoutText.length === 0) {
                return null;
            }
            if (stdoutText.includes("\uFFFD")) {
                return null;
            }
            return JSON.parse(stdoutText);
        } catch (_error) {
            return null;
        }
    },

    _maybeApplyStatusPayload(payload) {
        if (!this._isValidAppletStatusPayload(payload)) {
            return false;
        }
        this._statusLastGood = payload;
        this._statusViewState = "ready";
        return this._renderStatusSafely();
    },

    _isValidAppletStatusPayload(payload) {
        if (!payload || typeof payload !== "object") return false;
        if (!this._hasExactFields(payload, APPLET_STATUS_REQUIRED_FIELDS)) return false;
        if (payload.schema_version !== 1) return false;
        if (payload.mode !== "read_only") return false;
        if (payload.raw_output !== APPLET_STATUS_RAW_OUTPUT) return false;

        for (const field of ["activity_state", "backend_state", "control_state"]) {
            if (typeof payload[field] !== "string") return false;
            if (!this._isValidStateSet("snapshot", field, payload[field])) return false;
        }

        if (!Array.isArray(payload.agents) || payload.agents.length !== this._trackedAgents.length) return false;
        const agents = new Set();
        for (const row of payload.agents) {
            if (!row || typeof row !== "object") return false;
            if (!this._hasExactFields(row, APPLET_STATUS_REQUIRED_ROW_FIELDS)) return false;
            for (const field of APPLET_STATUS_REQUIRED_ROW_FIELDS) {
                if (typeof row[field] !== "string" || row[field].length === 0) return false;
            }
            if (this._trackedAgents.indexOf(row.agent) === -1) return false;
            agents.add(row.agent);
            if (!this._isValidStateSet("row", "activity_state", row.activity_state)) return false;
            if (!this._isValidStateSet("row", "backend_state", row.backend_state)) return false;
            if (!this._isValidStateSet("row", "control_state", row.control_state)) return false;
            if (!this._isValidStateSet("row", "auth_state", row.auth_state)) return false;
            if (!this._isValidStateSet("row", "identity_state", row.identity_state)) return false;
            if (!this._isValidStateSet("row", "lease_state", row.lease_state)) return false;
            if (!this._isValidAppletStatusRow(row)) return false;
        }
        if (agents.size !== this._trackedAgents.length) return false;

        if (typeof payload.counts !== "object" || payload.counts === null) return false;
        if (!this._hasExactFields(payload.counts, APPLET_STATUS_REQUIRED_COUNTS)) return false;
        for (const key of APPLET_STATUS_REQUIRED_COUNTS) {
            const value = payload.counts[key];
            if (!Number.isInteger(value) || value < 0) return false;
        }
        if (payload.counts.tracked !== payload.agents.length) return false;
        if (payload.counts.running + payload.counts.sleeping > payload.counts.tracked) return false;
        if (payload.counts.ready + payload.counts.blocked > payload.counts.tracked) return false;
        if (payload.counts.issues > payload.counts.tracked) return false;

        const activityStates = payload.agents.map((row) => row.activity_state);
        const backendStates = payload.agents.map((row) => row.backend_state);
        const controlStates = payload.agents.map((row) => row.control_state);
        const expectedCounts = {
            tracked: payload.agents.length,
            running: activityStates.filter((state) => state === "running").length,
            sleeping: activityStates.filter((state) => state === "sleeping").length,
            ready: controlStates.filter((state) => state === "ready").length,
            blocked: controlStates.filter((state) => state === "blocked").length,
            issues: payload.agents.filter(
                (row) => row.backend_state !== "ok" || row.control_state !== "ready"
            ).length,
        };
        if (APPLET_STATUS_REQUIRED_COUNTS.some((key) => payload.counts[key] !== expectedCounts[key])) return false;

        const expectedActivity = activityStates.every((state) => state === "running")
            ? "running"
            : activityStates.every((state) => state === "sleeping")
                ? "sleeping"
                : activityStates.every((state) => state === "unknown") ? "unknown" : "mixed";
        const expectedBackend = backendStates.every((state) => state === "ok")
            ? "ok"
            : backendStates.every((state) => state === "error") ? "unavailable" : "degraded";
        const expectedControl = controlStates.every((state) => state === "ready")
            ? "ready"
            : controlStates.every((state) => state === "blocked")
                ? "blocked"
                : controlStates.every((state) => state === "unknown") ? "unknown" : "mixed";
        if (payload.activity_state !== expectedActivity) return false;
        if (payload.backend_state !== expectedBackend) return false;
        if (payload.control_state !== expectedControl) return false;
        return true;
    },

    _isValidAppletStatusRow(row) {
        const isErrorRow = (
            row.activity_state === APPLET_STATUS_ERROR_ROW.activity_state
            && row.backend_state === APPLET_STATUS_ERROR_ROW.backend_state
            && row.control_state === APPLET_STATUS_ERROR_ROW.control_state
            && row.auth_state === APPLET_STATUS_ERROR_ROW.auth_state
            && row.identity_state === APPLET_STATUS_ERROR_ROW.identity_state
            && row.lease_state === APPLET_STATUS_ERROR_ROW.lease_state
        );
        if (isErrorRow) return true;

        if (row.backend_state === "error") return false;

        if (row.activity_state === "running" && row.identity_state === "verified") {
            if (row.backend_state !== "ok") return false;
        } else if (row.activity_state === "running" && row.identity_state === "unverified") {
            if (row.backend_state !== "degraded") return false;
        } else if (row.activity_state === "sleeping" && row.identity_state === "stopped") {
            if (row.backend_state !== "ok") return false;
        } else if (row.activity_state === "sleeping" && row.identity_state === "unverified") {
            if (row.backend_state !== "degraded") return false;
        } else {
            return false;
        }

        const expectedControlState = this._deriveControlStateForAppletRow(row);
        return row.control_state === expectedControlState;
    },

    _deriveControlStateForAppletRow(row) {
        if (row.auth_state === "blocked" || row.identity_state === "unverified" || row.lease_state === "held") {
            return "blocked";
        }
        if (row.auth_state === "unknown" || row.identity_state === "unknown" || row.lease_state === "unreadable") {
            return "unknown";
        }
        if (row.auth_state === "ready" && (row.identity_state === "verified" || row.identity_state === "stopped")) {
            return "ready";
        }
        return "unknown";
    },

    _hasExactFields(value, requiredFields) {
        const keys = Object.keys(value);
        return keys.length === requiredFields.length
            && requiredFields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
    },

    _isValidStateSet(scope, name, value) {
        return APPLET_STATUS_VALID_STRINGS[scope]?.[name]?.has(value);
    },

    _markRefreshFailed() {
        if (this._removed) return;
        this._statusViewState = this._statusLastGood ? "stale" : "unavailable";
        this._renderStatusSafely();
    },

    _stateLabel(scope, value) {
        const labels = {
            activity: {
                running: "laufend",
                sleeping: "schlafend",
                mixed: "gemischt",
                unknown: "unbekannt",
            },
            backend: {
                ok: "ok",
                degraded: "eingeschränkt",
                unavailable: "nicht verfügbar",
                error: "Fehler",
            },
            control: {
                ready: "bereit",
                blocked: "blockiert",
                mixed: "gemischt",
                unknown: "unbekannt",
            },
        };
        return labels[scope]?.[value] || "unbekannt";
    },

    _setMenuItemText(item, text) {
        if (!item) return;
        if (item.label && typeof item.label.set_text === "function") item.label.set_text(text);
        else item.label = text;
    },

    _setMenuItemVisible(item, visible) {
        if (!item) return;
        const actor = item.actor || item;
        if (visible && typeof actor.show === "function") actor.show();
        else if (!visible && typeof actor.hide === "function") actor.hide();
        else actor.visible = visible;
    },

    _renderStatusSafely() {
        try {
            this._renderStatus();
            return true;
        } catch (error) {
            this._logCleanupError(error);
            return false;
        }
    },

    _renderStatus() {
        if (this._removed) return;
        this.set_applet_label(LABEL);
        const payload = this._statusLastGood;
        const activity = this._stateLabel("activity", payload ? payload.activity_state : "unknown");
        const backend = this._stateLabel("backend", payload ? payload.backend_state : "unavailable");
        const stale = this._statusViewState === "stale" ? " · veraltet" : "";
        const unavailable = this._statusViewState === "unavailable" ? " · nicht verfügbar" : "";
        const configuration = this._settingsValid ? "" : "Konfigurationsfehler · ";
        const summary = `${configuration}Aktivität: ${activity} · Backend: ${backend} · Modus: Nur Lesen${stale}${unavailable}`;
        this.set_applet_tooltip(summary);
        this._setMenuItemText(this._statusSummaryItem, summary);

        const rows = payload ? payload.agents : this._trackedAgents.map((agent) => ({
            agent,
            activity_state: "unknown",
            backend_state: "error",
            control_state: "unknown",
        }));
        for (let index = 0; index < this._statusRowItems.length; index += 1) {
            const item = this._statusRowItems[index];
            const row = rows[index];
            if (!row) {
                this._setMenuItemVisible(item, false);
                continue;
            }
            const text = `${row.agent}: ${this._stateLabel("activity", row.activity_state)} · Backend ${this._stateLabel("backend", row.backend_state)} · Steuerung ${this._stateLabel("control", row.control_state)}`;
            this._setMenuItemText(item, text);
            this._setMenuItemVisible(item, true);
        }
    },

    _connectTracked(target, signal, callback) {
        if (this._removed || !target || typeof target.connect !== "function") return 0;
        const id = target.connect(signal, callback);
        if (id) {
            this._signalConnections.push({ target, id });
        }
        return id;
    },

    _logCleanupError(error) {
        try {
            if (
                appletErrorLogCount < APPLET_ERROR_LOG_LIMIT
                && typeof global !== "undefined"
                && global
                && typeof global.logError === "function"
            ) {
                appletErrorLogCount += 1;
                global.logError(error);
            }
        } catch (_loggingError) {}
    },

    _disconnectTrackedSignals() {
        const connections = this._signalConnections;
        const remaining = [];
        for (const connection of connections) {
            try {
                if (connection.target && typeof connection.target.disconnect === "function") {
                    connection.target.disconnect(connection.id);
                }
            } catch (error) {
                this._logCleanupError(error);
                remaining.push(connection);
            }
        }
        this._signalConnections = remaining;
        return remaining.length === 0;
    },

    _cleanupMenuResource(menuProperty, managerProperty) {
        const menu = this[menuProperty];
        const manager = this[managerProperty];
        if (!menu && !manager) return true;

        const stateKey = menuProperty + ":" + managerProperty;
        const state = this._menuCleanupState[stateKey] || {
            managerReleased: !manager,
            managerNeedsDestroy: false,
            menuDestroyed: !menu,
        };
        this._menuCleanupState[stateKey] = state;

        let success = true;
        if (menu && menu.isOpen === true) {
            try {
                if (typeof menu.close !== "function") throw new Error("Menu close operation is unavailable");
                menu.close(false);
                if (menu.isOpen === true) throw new Error("Menu remained open after cleanup");
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        if (manager && manager.grabbed === true) {
            try {
                if (typeof manager._ungrab !== "function") throw new Error("Menu manager ungrab operation is unavailable");
                manager._ungrab();
                if (manager.grabbed === true) throw new Error("Menu manager retained its modal grab");
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        if (success && manager && !state.managerReleased && state.managerNeedsDestroy) {
            try {
                if (typeof manager.destroy !== "function") throw new Error("Menu manager destroy operation is unavailable");
                manager.destroy();
                state.managerNeedsDestroy = false;
                state.managerReleased = true;
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        } else if (success && manager && menu && !state.managerReleased) {
            try {
                if (typeof manager.removeMenu !== "function") throw new Error("Menu manager removal operation is unavailable");
                manager.removeMenu(menu);
                const managedMenus = Array.isArray(manager._menus)
                    ? manager._menus
                    : (Array.isArray(manager.menus) ? manager.menus : null);
                if (managedMenus && managedMenus.indexOf(menu) !== -1) {
                    throw new Error("Menu remained registered after cleanup");
                }
                if (managedMenus && managedMenus.length > 0) {
                    if (typeof manager.destroy !== "function") {
                        throw new Error("Menu manager retained child menus without a destroy operation");
                    }
                    manager.destroy();
                }
                state.managerReleased = true;
            } catch (error) {
                const managedMenus = Array.isArray(manager._menus)
                    ? manager._menus
                    : (Array.isArray(manager.menus) ? manager.menus : null);
                if (managedMenus && managedMenus.indexOf(menu) === -1) {
                    state.managerNeedsDestroy = true;
                }
                this._logCleanupError(error);
                success = false;
            }
        } else if (success && manager && !menu && !state.managerReleased) {
            try {
                if (typeof manager.destroy !== "function") throw new Error("Menu manager destroy operation is unavailable");
                manager.destroy();
                state.managerReleased = true;
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        if (success && menu && !state.menuDestroyed) {
            try {
                if (typeof menu.destroy !== "function") throw new Error("Menu destroy operation is unavailable");
                menu.destroy();
                state.menuDestroyed = true;
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        if (success && state.managerReleased && state.menuDestroyed) {
            this[menuProperty] = null;
            this[managerProperty] = null;
            delete this._menuCleanupState[stateKey];
            return true;
        }
        return false;
    },

    _cleanupStatusResources() {
        let success = true;
        let statusClean = true;
        if (this._backgroundRefreshSource) {
            try {
                GLib.source_remove(this._backgroundRefreshSource);
                this._backgroundRefreshSource = 0;
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        this._statusPendingRefresh = false;
        this._statusGeneration += 1;
        this._statusActiveGeneration = 0;
        const state = this._statusActiveState;
        if (state) {
            state.finalizing = true;
            state.discardOutput = true;
            this._clearStatusBuffers(state);
            if (state.timeoutSource) {
                try {
                    GLib.source_remove(state.timeoutSource);
                    state.timeoutSource = 0;
                } catch (error) {
                    this._logCleanupError(error);
                    success = false;
                    statusClean = false;
                }
            }
            if (state.cancellable && !state.cancellableCancelled) {
                try {
                    state.cancellable.cancel();
                    state.cancellableCancelled = true;
                } catch (error) {
                    this._logCleanupError(error);
                    success = false;
                    statusClean = false;
                }
            }
            if (state.exitWaitCancellable && !state.exitWaitCancellableCancelled) {
                try {
                    state.exitWaitCancellable.cancel();
                    state.exitWaitCancellableCancelled = true;
                } catch (error) {
                    this._logCleanupError(error);
                    success = false;
                    statusClean = false;
                }
            }
            if (!state.forceExitCalled && state.process && typeof state.process.force_exit === "function") {
                try {
                    state.process.force_exit();
                    state.forceExitCalled = true;
                } catch (error) {
                    this._logCleanupError(error);
                    success = false;
                    statusClean = false;
                }
            }
            if (statusClean) {
                this._statusActiveState = null;
                this._activeStatusProcess = null;
            }
        }
        this._statusInFlight = false;
        return success;
    },

    _cleanupSettings() {
        const settings = this.settings || this._settingsCleanupPending;
        if (!settings) return true;
        try {
            settings.finalize();
            if (this.settings === settings) this.settings = null;
            if (this._settingsCleanupPending === settings) this._settingsCleanupPending = null;
            return true;
        } catch (error) {
            this._logCleanupError(error);
            return false;
        }
    },

    on_applet_clicked() {
        if (this._removed) return;
        try {
            if (!this.menu || typeof this.menu.toggle !== "function") return;
            if (this.menu.actor && typeof this.menu.actor.is_finalized === "function" && this.menu.actor.is_finalized()) return;
            const wasOpen = this.menu.isOpen === true;
            this.menu.toggle();
            if (!wasOpen && this.menu.isOpen === true && this.refreshOnOpen) this._refreshStatus();
        } catch (error) {
            this._logCleanupError(error);
        }
    },

    on_applet_removed_from_panel() {
        if (this._cleanupComplete) return;
        this._removed = true;
        for (let attempt = 0; attempt < 2 && !this._cleanupComplete; attempt += 1) {
            const statusClean = this._cleanupStatusResources();
            const settingsClean = this._cleanupSettings();
            const signalsClean = this._disconnectTrackedSignals();
            const appletMenuClean = this._cleanupMenuResource("menu", "menuManager");
            const contextMenuClean = this._cleanupMenuResource("_applet_context_menu", "_menuManager");
            if (appletMenuClean) {
                this._statusSummaryItem = null;
                this._statusRowItems = [];
            }
            this._cleanupComplete = statusClean && settingsClean && signalsClean && appletMenuClean && contextMenuClean;
        }
    },
};

function main(metadata, orientation, panel_height, instance_id) {
    return new FlottenmanagementApplet(metadata, orientation, panel_height, instance_id);
}
