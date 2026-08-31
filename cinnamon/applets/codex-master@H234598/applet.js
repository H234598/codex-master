/* -*- mode: js2; js2-basic-offset: 4; indent-tabs-mode: nil -*- */
const Applet = imports.ui.applet;
const PopupMenu = imports.ui.popupMenu;
const Settings = imports.ui.settings;
const Util = imports.misc.util;
const Gio = imports.gi.Gio;
const GLib = imports.gi.GLib;
const St = imports.gi.St;
const ByteArray = imports.byteArray;

const LABEL = "Flottenmanagement";
const UUID = "codex-master@H234598";
const APPLET_STATUS_TIMEOUT_MILLISECONDS = 10 * 1000;
const APPLET_ACTION_TIMEOUT_MILLISECONDS = 120 * 1000;
const CONTROL_CENTER_LAUNCH_TIMEOUT_MILLISECONDS = 10 * 1000;
const APPLET_STDOUT_LIMIT_BYTES = 64 * 1024;
const APPLET_STDERR_LIMIT_BYTES = 8 * 1024;
const APPLET_STATUS_CHUNK_BYTES = 1024;
const APPLET_STATUS_AGENTS = ["a1", "b1"];
const DEFAULT_TRACKED_AGENTS_TEXT = "a1,b1";
const DEFAULT_REFRESH_ON_OPEN = true;
const DEFAULT_BACKGROUND_REFRESH = false;
const DEFAULT_REFRESH_INTERVAL_SECONDS = 60;
const DEFAULT_OVERVIEW_INTERVAL_SECONDS = 30;
const DEFAULT_OVERVIEW_SESSION_NO_ACTIVE_ONLY = false;
const DEFAULT_OVERVIEW_COMPACT = true;
const DEFAULT_OVERVIEW_DETAIL = true;
const DEFAULT_TERMINAL_COMMAND = "ghostty";
const DEFAULT_PANEL_ICON = "hive-01-core";
const DEFAULT_SETTINGS_ICON = "hive-02-queen-crown";
const DEFAULT_PANEL_DISPLAY = "icon-text";
const MIN_REFRESH_INTERVAL_SECONDS = 15;
const MAX_REFRESH_INTERVAL_SECONDS = 3600;
const MIN_OVERVIEW_INTERVAL_SECONDS = 15;
const MAX_OVERVIEW_INTERVAL_SECONDS = 3600;
const MAX_TRACKED_AGENTS = 6;
const MAX_NATIVE_BEES = 6;
const MAX_TRACKED_AGENTS_SETTING_CHARS = 128;
const MAX_TERMINAL_COMMAND_CHARS = 256;
const APPLET_ERROR_LOG_LIMIT = 8;
const APPLET_IMMEDIATE_EXIT_WAIT_LIMIT = 2;
const APPLET_SAFE_PATH = "/usr/bin:/bin";
const APPLET_ICON_NAMES = new Set([
    "hive-01-core", "hive-02-queen-crown", "hive-03-worker-bee", "hive-04-drone",
    "hive-05-honeycomb-shield", "hive-06-swarm-orbit", "hive-07-hex-command", "hive-08-honey-drop",
    "hive-09-royal-cell", "hive-10-nectar-lance", "hive-11-amber-gateway", "hive-12-guardian-bee",
    "hive-13-six-cell-star", "hive-14-hive-moon", "hive-15-pollen-scout", "hive-16-bee-crown",
    "hive-17-naval-hive", "hive-18-queen-signal", "hive-19-honeycomb-star", "hive-20-swarm-helm",
    "starwars-01-rebel-scout", "starwars-02-imperial-fighter", "starwars-03-freighter",
    "starwars-04-destroyer", "starwars-05-fleet-command",
]);
const APPLET_PANEL_DISPLAY_MODES = new Set(["icon", "text", "icon-text"]);
const APPLET_STATUS_COMMAND = "applet-status";
const APPLET_OVERVIEW_COMMAND = "overview";
const APPLET_OVERVIEW_FORMAT = "json";
const APPLET_OVERVIEW_MAX_ARRAY_LENGTH = 64;
const APPLET_OVERVIEW_MAX_STRING_LENGTH = 128;
const APPLET_OVERVIEW_MAX_WARNING_LENGTH = 64;
const APPLET_ACTION_COMMAND = "applet-action";
const APPLET_STATUS_SCHEMA_VERSION = 4;
const MAX_ENVIRONMENT_KEYS = 256;
let appletErrorLogCount = 0;
const APPLET_STATUS_REQUIRED_FIELDS = [
    "schema_version", "mode", "counts", "agents", "native_agents", "resource", "raw_output",
];
const APPLET_RESOURCE_REQUIRED_FIELDS = [
    "schema_version", "generation", "state", "bottleneck", "trend", "confidence",
    "preferred_profiles", "avoid_profiles", "raw_output",
];
const APPLET_RESOURCE_STATES = new Set(["ready", "blocked", "unavailable"]);
const APPLET_RESOURCE_BOTTLENECKS = new Set(["cpu", "io", "memory", "thermal", "cgroup", "unknown"]);
const APPLET_RESOURCE_TRENDS = new Set(["rising", "stable", "falling"]);
const APPLET_STATUS_REQUIRED_ROW_FIELDS = [
    "agent", "activity_state", "backend_state", "control_state", "auth_state", "identity_state", "lease_state",
    "allowed_action", "context_token", "limit_state", "blocked_until_utc",
];
const APPLET_STATUS_BASE_ROW_STRING_FIELDS = [
    "agent", "activity_state", "backend_state", "control_state", "auth_state", "identity_state", "lease_state",
];
const APPLET_STATUS_REQUIRED_COUNTS = ["tracked", "running", "sleeping", "overflow"];
const APPLET_STATUS_REQUIRED_NATIVE_FIELDS = ["bridge_state", "counts", "agents", "truncated"];
const APPLET_STATUS_REQUIRED_NATIVE_COUNTS = ["active", "unconfirmed", "overflow"];
const APPLET_STATUS_REQUIRED_NATIVE_AGENT_FIELDS = ["display_id", "agent_type", "activity_state", "updated_at_utc"];
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
    row: {
        activity_state: new Set(["running", "sleeping", "unknown"]),
        backend_state: new Set(["ok", "degraded", "error"]),
        control_state: new Set(["ready", "blocked", "unknown"]),
        auth_state: new Set(["ready", "blocked", "unknown"]),
        identity_state: new Set(["verified", "unverified", "stopped", "unknown"]),
        lease_state: new Set(["unclaimed", "held", "expired", "unreadable"]),
        allowed_action: new Set(["start", "stop", "none"]),
        limit_state: new Set(["clear", "blocked", "unknown"]),
    },
    native: {
        bridge_state: new Set(["ready", "disabled", "degraded", "unavailable"]),
        activity_state: new Set(["active", "unconfirmed"]),
    },
};
const APPLET_STATUS_LABELS = {
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
    nativeActivity: {
        active: "aktiv",
        unconfirmed: "unbestätigt",
    },
    nativeBridge: {
        ready: "bereit",
        disabled: "deaktiviert",
        degraded: "eingeschränkt",
        unavailable: "nicht verfügbar",
    },
};
const APPLET_ALLOWED_ENV_VARS = new Set([
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "CODEX_USAGE_INTEGRATION_STATE_HOME",
    "XDG_STATE_HOME",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "XDG_SESSION_TYPE",
    "DESKTOP_STARTUP_ID",
    "XDG_ACTIVATION_TOKEN",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TZ",
]);

function FlottenmanagementApplet(metadata, orientation, panel_height, instance_id) {
    this._init(metadata, orientation, panel_height, instance_id);
}

FlottenmanagementApplet.prototype = {
    __proto__: Applet.TextIconApplet.prototype,

    _init(metadata, orientation, panel_height, instance_id) {
        Applet.TextIconApplet.prototype._init.call(this, orientation, panel_height, instance_id);
        this._removed = false;
        this._cleanupComplete = false;
        this._statusInFlight = false;
        this._statusPendingRefresh = false;
        this._statusGeneration = 0;
        this._statusActiveGeneration = 0;
        this._resourceGenerationHighWater = 0;
        this._statusLastGood = null;
        this._statusActiveState = null;
        this._statusViewState = "initializing";
        this._backgroundRefreshSource = 0;
        this._overviewSource = 0;
        this._overviewInFlight = false;
        this._overviewGeneration = 0;
        this._overviewActiveGeneration = 0;
        this._overviewLastGood = null;
        this._overviewActiveState = null;
        this._overviewViewState = "initializing";
        this._overviewRefreshStarted = false;
        this._launcherInFlight = false;
        this._actionInFlight = false;
        this._armedAction = null;
        this._actionsAwaitingRefresh = false;
        this._startActionBinding = null;
        this._stopActionBindings = Array(MAX_TRACKED_AGENTS).fill(null);
        this._trackedAgents = APPLET_STATUS_AGENTS.slice();
        this.trackedAgentsSetting = DEFAULT_TRACKED_AGENTS_TEXT;
        this.refreshOnOpenSetting = DEFAULT_REFRESH_ON_OPEN;
        this.backgroundRefreshSetting = DEFAULT_BACKGROUND_REFRESH;
        this.refreshIntervalSecondsSetting = DEFAULT_REFRESH_INTERVAL_SECONDS;
        this.overviewIntervalSecondsSetting = DEFAULT_OVERVIEW_INTERVAL_SECONDS;
        this.overviewSessionNoActiveOnlySetting = DEFAULT_OVERVIEW_SESSION_NO_ACTIVE_ONLY;
        this.overviewCompactSetting = DEFAULT_OVERVIEW_COMPACT;
        this.overviewDetailSetting = DEFAULT_OVERVIEW_DETAIL;
        this.terminalCommandSetting = DEFAULT_TERMINAL_COMMAND;
        this.panelIconSetting = DEFAULT_PANEL_ICON;
        this.settingsIconSetting = DEFAULT_SETTINGS_ICON;
        this.panelDisplaySetting = DEFAULT_PANEL_DISPLAY;
        this.refreshOnOpen = DEFAULT_REFRESH_ON_OPEN;
        this.backgroundRefresh = DEFAULT_BACKGROUND_REFRESH;
        this.refreshIntervalSeconds = DEFAULT_REFRESH_INTERVAL_SECONDS;
        this.overviewIntervalSeconds = DEFAULT_OVERVIEW_INTERVAL_SECONDS;
        this.overviewSessionNoActiveOnly = DEFAULT_OVERVIEW_SESSION_NO_ACTIVE_ONLY;
        this.overviewCompact = DEFAULT_OVERVIEW_COMPACT;
        this.overviewDetail = DEFAULT_OVERVIEW_DETAIL;
        this.terminalCommand = DEFAULT_TERMINAL_COMMAND;
        this.panelIcon = DEFAULT_PANEL_ICON;
        this.settingsIcon = DEFAULT_SETTINGS_ICON;
        this.panelDisplay = DEFAULT_PANEL_DISPLAY;
        this._metadataPath = metadata && typeof metadata.path === "string" ? metadata.path : null;
        this._settingsValid = true;
        this._settingsInitializing = false;
        this.settings = null;
        this._settingsCleanupPending = null;
        this._statusSummaryItem = null;
        this._overviewSummaryItem = null;
        this._overviewDetailItem = null;
        this._settingsMenuItem = null;
        this._statusRowItems = [];
        this._nativeSubmenuItem = null;
        this._nativeBeeRowItems = [];
        this._quickControlSubmenuItem = null;
        this._startActionItem = null;
        this._stopActionItems = [];
        this._confirmationDetailItem = null;
        this._confirmationConfirmItem = null;
        this._confirmationCancelItem = null;
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

        const settingsItem = new PopupMenu.PopupIconMenuItem(
            "Applet-Verwaltung öffnen",
            this._iconPath(DEFAULT_SETTINGS_ICON),
            St.IconType.FULLCOLOR
        );
        this._settingsMenuItem = settingsItem;
        this._connectTracked(settingsItem, "activate", () => {
            if (this._removed) return;
            try {
                Util.spawn(["cinnamon-settings", "applets"]);
            } catch (error) {
                this._logCleanupError(error);
            }
        });
        this.menu.addMenuItem(settingsItem);

        const controlCenterItem = new PopupMenu.PopupMenuItem("Steuerzentrale öffnen");
        this._connectTracked(controlCenterItem, "activate", () => this._launchControlCenter());
        this.menu.addMenuItem(controlCenterItem);

        const terminalStatusItem = new PopupMenu.PopupMenuItem("Flottenstatus im Terminal");
        this._connectTracked(terminalStatusItem, "activate", () => this._launchTerminalStatus());
        this.menu.addMenuItem(terminalStatusItem);

        this._statusSummaryItem = new PopupMenu.PopupMenuItem("", { reactive: false });
        this.menu.addMenuItem(this._statusSummaryItem);
        for (let index = 0; index < MAX_TRACKED_AGENTS; index += 1) {
            const rowItem = new PopupMenu.PopupMenuItem("", { reactive: false });
            this._statusRowItems.push(rowItem);
            this.menu.addMenuItem(rowItem);
        }

        this._quickControlSubmenuItem = new PopupMenu.PopupSubMenuMenuItem("Schnellsteuerung");
        this.menu.addMenuItem(this._quickControlSubmenuItem);
        this._startActionItem = new PopupMenu.PopupMenuItem("Biene starten");
        this._connectTracked(this._startActionItem, "activate", () => this._armStartAction());
        this._quickControlSubmenuItem.menu.addMenuItem(this._startActionItem);
        for (let index = 0; index < MAX_TRACKED_AGENTS; index += 1) {
            const rowItem = new PopupMenu.PopupMenuItem("Biene stoppen");
            this._connectTracked(rowItem, "activate", () => this._armStopAction(index));
            this._stopActionItems.push(rowItem);
            this._quickControlSubmenuItem.menu.addMenuItem(rowItem);
        }
        this._confirmationDetailItem = new PopupMenu.PopupMenuItem("", { reactive: false });
        this._quickControlSubmenuItem.menu.addMenuItem(this._confirmationDetailItem);
        this._confirmationConfirmItem = new PopupMenu.PopupMenuItem("Bestätigen");
        this._connectTracked(this._confirmationConfirmItem, "activate", () => this._confirmArmedAction());
        this._quickControlSubmenuItem.menu.addMenuItem(this._confirmationConfirmItem);
        this._confirmationCancelItem = new PopupMenu.PopupMenuItem("Abbrechen");
        this._connectTracked(this._confirmationCancelItem, "activate", () => this._cancelArmedAction());
        this._quickControlSubmenuItem.menu.addMenuItem(this._confirmationCancelItem);

        this._nativeSubmenuItem = new PopupMenu.PopupSubMenuMenuItem("Native Bienen");
        this.menu.addMenuItem(this._nativeSubmenuItem);
        for (let index = 0; index < MAX_NATIVE_BEES; index += 1) {
            const rowItem = new PopupMenu.PopupMenuItem("", { reactive: false });
            this._nativeBeeRowItems.push(rowItem);
            this._nativeSubmenuItem.menu.addMenuItem(rowItem);
        }

        this._overviewSummaryItem = new PopupMenu.PopupMenuItem("Übersicht: nicht verfügbar", { reactive: false });
        this._overviewDetailItem = new PopupMenu.PopupMenuItem("Übersicht Details: —", { reactive: false });
        this.menu.addMenuItem(this._overviewSummaryItem);
        this.menu.addMenuItem(this._overviewDetailItem);

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
            bind("overview-interval-seconds", "overviewIntervalSecondsSetting");
            bind("overview-session-no-active-only", "overviewSessionNoActiveOnlySetting");
            bind("overview-compact", "overviewCompactSetting");
            bind("overview-detail", "overviewDetailSetting");
            bind("terminal-command", "terminalCommandSetting");
            bind("panel-icon", "panelIconSetting");
            bind("settings-icon", "settingsIconSetting");
            bind("panel-display", "panelDisplaySetting");
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

    _normalizeTerminalCommand(value) {
        if (typeof value !== "string" || value.length > MAX_TERMINAL_COMMAND_CHARS) return null;
        const normalized = value.trim();
        if (
            normalized.length === 0
            || normalized.length > MAX_TERMINAL_COMMAND_CHARS
            || !/^(?:[A-Za-z0-9_+.-]+|\/[A-Za-z0-9_+./-]+)$/.test(normalized)
        ) return null;
        return normalized;
    },

    _normalizeIconName(value) {
        return typeof value === "string" && APPLET_ICON_NAMES.has(value) ? value : null;
    },

    _normalizePanelDisplay(value) {
        return typeof value === "string" && APPLET_PANEL_DISPLAY_MODES.has(value) ? value : null;
    },

    _iconPath(iconName) {
        const safeName = this._normalizeIconName(iconName) || DEFAULT_PANEL_ICON;
        const appletPath = this._metadataPath
            || ((GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown")
                + "/.local/share/cinnamon/applets/" + UUID);
        return appletPath + "/icons/" + safeName + ".png";
    },

    _applySettingsMenuIcon() {
        const item = this._settingsMenuItem;
        if (!item) return;
        const iconPath = this._iconPath(this.settingsIcon);
        try {
            if (item._icon && typeof item._icon.set_gicon === "function") {
                item._icon.set_gicon(Gio.icon_new_for_string(iconPath));
                item._codexIconPath = iconPath;
            } else if (typeof item.setIconName === "function") {
                item.setIconName(iconPath);
            }
        } catch (error) {
            this._logCleanupError(error);
        }
    },

    _applyPanelPresentation() {
        const showIcon = this.panelDisplay !== "text";
        const showLabel = this.panelDisplay !== "icon";
        try {
            if (showIcon && typeof this.set_applet_icon_path === "function") {
                this.set_applet_icon_path(this._iconPath(this.panelIcon));
            } else if (!showIcon && typeof this.hide_applet_icon === "function") {
                this.hide_applet_icon();
            }
        } catch (error) {
            this._logCleanupError(error);
        }
        this.set_applet_label(showLabel ? LABEL : "");
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
        if (
            typeof this.overviewIntervalSecondsSetting !== "number"
            || !Number.isFinite(this.overviewIntervalSecondsSetting)
            || !Number.isInteger(this.overviewIntervalSecondsSetting)
            || this.overviewIntervalSecondsSetting < MIN_OVERVIEW_INTERVAL_SECONDS
            || this.overviewIntervalSecondsSetting > MAX_OVERVIEW_INTERVAL_SECONDS
        ) {
            this.overviewIntervalSeconds = DEFAULT_OVERVIEW_INTERVAL_SECONDS;
            valid = false;
        } else {
            this.overviewIntervalSeconds = this.overviewIntervalSecondsSetting;
        }
        if (typeof this.overviewSessionNoActiveOnlySetting !== "boolean") {
            this.overviewSessionNoActiveOnly = DEFAULT_OVERVIEW_SESSION_NO_ACTIVE_ONLY;
            valid = false;
        } else {
            this.overviewSessionNoActiveOnly = this.overviewSessionNoActiveOnlySetting;
        }
        if (typeof this.overviewCompactSetting !== "boolean") {
            this.overviewCompact = DEFAULT_OVERVIEW_COMPACT;
            valid = false;
        } else {
            this.overviewCompact = this.overviewCompactSetting;
        }
        if (typeof this.overviewDetailSetting !== "boolean") {
            this.overviewDetail = DEFAULT_OVERVIEW_DETAIL;
            valid = false;
        } else {
            this.overviewDetail = this.overviewDetailSetting;
        }
        const terminalCommand = this._normalizeTerminalCommand(this.terminalCommandSetting);
        if (!terminalCommand) {
            this.terminalCommand = DEFAULT_TERMINAL_COMMAND;
            valid = false;
        } else {
            this.terminalCommand = terminalCommand;
        }

        const panelIcon = this._normalizeIconName(this.panelIconSetting);
        if (!panelIcon) {
            this.panelIcon = DEFAULT_PANEL_ICON;
            valid = false;
        } else {
            this.panelIcon = panelIcon;
        }
        const settingsIcon = this._normalizeIconName(this.settingsIconSetting);
        if (!settingsIcon) {
            this.settingsIcon = DEFAULT_SETTINGS_ICON;
            valid = false;
        } else {
            this.settingsIcon = settingsIcon;
        }
        const panelDisplay = this._normalizePanelDisplay(this.panelDisplaySetting);
        if (!panelDisplay) {
            this.panelDisplay = DEFAULT_PANEL_DISPLAY;
            valid = false;
        } else {
            this.panelDisplay = panelDisplay;
        }

        this._settingsValid = valid;
        this._applyPanelPresentation();
        this._applySettingsMenuIcon();
        if (previousAgents !== this._trackedAgents.join(",")) {
            this._statusLastGood = null;
            this._armedAction = null;
            this._clearActionBindings();
            this._statusViewState = "initializing";
            if (this._statusInFlight) this._statusPendingRefresh = true;
        }
        this._restartBackgroundRefresh();
        this._restartOverviewRefresh();
        this._renderStatusSafely();
        this._renderOverviewSafely();
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

    _restartOverviewRefresh() {
        if (this._overviewSource) {
            try {
                GLib.source_remove(this._overviewSource);
            } catch (error) {
                this._settingsValid = false;
                this._logCleanupError(error);
            }
            this._overviewSource = 0;
        }
        if (this._overviewInFlight) this._cancelOverviewRefresh();
        if (this._removed || !this._settingsValid || !this._overviewRefreshStarted) return;
        try {
            const overviewTimerCallback = () => {
                if (this._removed || !this._settingsValid) {
                    this._overviewSource = 0;
                    return GLib.SOURCE_REMOVE;
                }
                this._refreshOverview();
                return GLib.SOURCE_CONTINUE;
            };
            overviewTimerCallback.__codexOverviewTimer = true;
            const source = GLib.timeout_add_seconds(
                GLib.PRIORITY_DEFAULT,
                this.overviewIntervalSeconds,
                overviewTimerCallback
            );
            if (!Number.isSafeInteger(source) || source <= 0) throw new Error("Invalid overview timeout source id");
            this._overviewSource = source;
        } catch (error) {
            this._overviewSource = 0;
            this._settingsValid = false;
            this._logCleanupError(error);
        }
    },

    _trackedStatusArgv() {
        const home = GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown";
        return [
            home + "/.local/lib/codex-master-runtime/bin/codex-master-mcp",
            APPLET_STATUS_COMMAND,
            "--schema-version",
            String(APPLET_STATUS_SCHEMA_VERSION),
            ...this._trackedAgents,
        ];
    },

    _launchControlCenter() {
        if (this._removed || this._statusInFlight) return;
        this._startStatusRefresh({ kind: "launcher" });
    },

    _launchTerminalStatus() {
        if (this._removed || !this._settingsValid) return;
        const terminal = this._normalizeTerminalCommand(this.terminalCommand);
        if (!terminal) return;
        const home = GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown";
        const statusCommand = home + "/.local/lib/codex-master-runtime/bin/codex-master-mcp";
        const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
        const terminalName = terminal.split("/").pop();
        const terminalExecutionArgs = terminalName === "gnome-terminal" ? ["--"] : ["-e"];
        const shellCommand = [
            shellQuote(statusCommand),
            "status",
            "all",
            "--agents-limit",
            "30",
            "; printf '\\n\\nZum Schließen Enter drücken ... '; read -r",
        ].join(" ");
        try {
            Util.spawn([
                terminal,
                ...terminalExecutionArgs,
                "/bin/bash",
                "-c",
                shellCommand,
            ]);
        } catch (error) {
            this._logCleanupError(error);
        }
    },

    _controlCenterArgv() {
        const home = GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown";
        return [home + "/.local/lib/codex-master-runtime/bin/codex-master-mcp", "control-center-launch"];
    },

    _appletActionArgv(actionRequest) {
        if (
            !actionRequest
            || !["start", "stop"].includes(actionRequest.action)
            || !this._isCanonicalManagedAgentId(actionRequest.agent)
            || !this._isValidContextToken(actionRequest.contextToken)
        ) {
            throw new Error("Invalid applet action request");
        }
        const home = GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown";
        return [
            home + "/.local/lib/codex-master-runtime/bin/codex-master-mcp",
            APPLET_ACTION_COMMAND,
            actionRequest.action,
            actionRequest.agent,
            actionRequest.contextToken,
        ];
    },

    _clearActionBindings() {
        this._startActionBinding = null;
        for (let index = 0; index < this._stopActionBindings.length; index += 1) {
            this._stopActionBindings[index] = null;
        }
    },

    _updateActionBindings(payload) {
        this._clearActionBindings();
        if (!payload) return;
        let stopIndex = 0;
        for (const row of payload.agents) {
            if (row.allowed_action === "start") {
                this._startActionBinding = {
                    action: "start",
                    agent: row.agent,
                    contextToken: row.context_token,
                };
            } else if (row.allowed_action === "stop" && stopIndex < this._stopActionBindings.length) {
                this._stopActionBindings[stopIndex] = {
                    action: "stop",
                    agent: row.agent,
                    contextToken: row.context_token,
                };
                stopIndex += 1;
            }
        }
    },

    _armStartAction() {
        this._armAction(this._startActionBinding);
    },

    _armStopAction(index) {
        this._armAction(this._stopActionBindings[index]);
    },

    _armAction(binding) {
        if (
            this._removed
            || this._statusInFlight
            || this._actionInFlight
            || this._launcherInFlight
            || this._actionsAwaitingRefresh
            || !binding
            || !["start", "stop"].includes(binding.action)
            || !this._isCanonicalManagedAgentId(binding.agent)
            || !this._isValidContextToken(binding.contextToken)
        ) return;
        this._armedAction = {
            action: binding.action,
            agent: binding.agent,
            contextToken: binding.contextToken,
        };
        this._renderStatusSafely();
    },

    _cancelArmedAction() {
        if (this._removed || this._actionInFlight) return;
        this._armedAction = null;
        this._renderStatusSafely();
    },

    _confirmArmedAction() {
        if (
            this._removed
            || this._statusInFlight
            || this._actionInFlight
            || this._launcherInFlight
            || !this._armedAction
        ) return;
        const request = this._armedAction;
        this._armedAction = null;
        this._statusLastGood = null;
        this._clearActionBindings();
        this._actionsAwaitingRefresh = true;
        this._startStatusRefresh(request);
    },

    _refreshStatus() {
        if (this._actionInFlight || this._launcherInFlight) return;
        if (this._statusInFlight) {
            if (!this._actionsAwaitingRefresh) this._statusPendingRefresh = true;
            return;
        }
        this._startStatusRefresh();
    },

    _overviewArgv() {
        const home = GLib.get_home_dir ? GLib.get_home_dir() : null;
        if (typeof home !== "string" || !home.startsWith("/") || home.includes("\u0000")) {
            throw new Error("Overview home unavailable");
        }
        const argv = [
            home + "/.local/lib/codex-master-runtime/bin/codex-master-mcp",
            "fleet",
            APPLET_OVERVIEW_COMMAND,
            "--format",
            APPLET_OVERVIEW_FORMAT,
        ];
        if (this.overviewSessionNoActiveOnly) argv.push("--no-active-only");
        return argv;
    },

    _refreshOverview() {
        if (this._removed || !this._settingsValid || this._overviewInFlight) return;
        this._overviewRefreshStarted = true;
        this._startStatusRefresh({ kind: "overview" });
    },

    _cancelOverviewRefresh() {
        let clean = true;
        this._overviewGeneration += 1;
        this._overviewActiveGeneration = 0;
        const state = this._overviewActiveState;
        if (!state) {
            this._overviewInFlight = false;
            return true;
        }
        state.finalizing = true;
        state.discardOutput = true;
        this._clearStatusBuffers(state);
        if (state.timeoutSource) {
            try {
                GLib.source_remove(state.timeoutSource);
                state.timeoutSource = 0;
            } catch (error) {
                this._logCleanupError(error);
                clean = false;
            }
        }
        if (state.cancellable && !state.cancellableCancelled) {
            try {
                state.cancellable.cancel();
                state.cancellableCancelled = true;
            } catch (error) {
                this._logCleanupError(error);
                clean = false;
            }
        }
        if (state.exitWaitCancellable && !state.exitWaitCancellableCancelled) {
            try {
                state.exitWaitCancellable.cancel();
                state.exitWaitCancellableCancelled = true;
            } catch (error) {
                this._logCleanupError(error);
                clean = false;
            }
        }
        if (!state.forceExitCalled && state.process && typeof state.process.force_exit === "function") {
            try {
                state.process.force_exit();
                state.forceExitCalled = true;
            } catch (error) {
                this._logCleanupError(error);
                clean = false;
            }
        }
        if (clean) this._overviewActiveState = null;
        this._overviewInFlight = !clean;
        return clean;
    },

    _startStatusRefresh(request = null) {
        if (this._removed) return;
        const commandKind = request && request.kind === "launcher"
            ? "launcher"
            : request && request.kind === "overview"
                ? "overview"
                : request ? "action" : "status";
        const actionRequest = commandKind === "action" ? request : null;
        const overviewRequest = commandKind === "overview";

        const generation = overviewRequest ? ++this._overviewGeneration : ++this._statusGeneration;
        let process;
        try {
            const argv = commandKind === "launcher"
                ? this._controlCenterArgv()
                : overviewRequest ? this._overviewArgv()
                : actionRequest ? this._appletActionArgv(actionRequest) : this._trackedStatusArgv();
            const launcher = Gio.SubprocessLauncher.new(
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_PIPE
            );
            this._sanitizeLauncherEnvironment(launcher);
            process = launcher.spawnv(argv);
        } catch (_error) {
            if (overviewRequest) {
                this._overviewInFlight = false;
                this._markOverviewFailed();
                this._restartOverviewRefresh();
                return;
            }
            this._statusInFlight = false;
            this._actionInFlight = false;
            if (commandKind === "action") {
                this._actionsAwaitingRefresh = true;
                this._renderStatusSafely();
                this._startStatusRefresh();
            } else {
                if (commandKind === "status") this._markRefreshFailed();
            }
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
            commandKind,
            overviewRequest,
            actionRequest,
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
            stdoutByteCount: 0,
            stderrByteCount: 0,
            discardOutput: false,
            waitFailed: false,
            forceExitCalled: false,
            timedOut: false,
            stdoutLimitExceeded: false,
            stderrLimitExceeded: false,
        };

        if (overviewRequest) {
            this._overviewActiveState = state;
            this._overviewActiveGeneration = generation;
            this._overviewInFlight = true;
            this._overviewViewState = this._overviewLastGood ? "refreshing" : "initializing";
            this._renderOverviewSafely();
        } else {
            this._activeStatusProcess = process;
            this._statusActiveState = state;
            this._statusActiveGeneration = generation;
            this._statusInFlight = true;
            this._actionInFlight = commandKind === "action";
            this._launcherInFlight = commandKind === "launcher";
            if (commandKind === "status") {
                this._statusViewState = this._statusLastGood ? "refreshing" : "initializing";
            }
            this._renderStatusSafely();
        }

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
            if (stateArg.commandKind === "overview") this._markOverviewFailed();
            else if (stateArg.commandKind === "status") this._markRefreshFailed();
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

            const chunksKey = key === "stdout" ? "stdoutChunks" : null;
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
                                const chunkLength = Math.min(bytes.length, take);
                                if (chunksKey) {
                                    const chunk = new Uint8Array(chunkLength);
                                    chunk.set(bytes.subarray(0, chunk.length));
                                    stateArg[chunksKey].push(chunk);
                                }
                                stateArg[byteCountKey] += chunkLength;
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
                commandKind === "action"
                    ? APPLET_ACTION_TIMEOUT_MILLISECONDS
                    : commandKind === "launcher"
                        ? CONTROL_CENTER_LAUNCH_TIMEOUT_MILLISECONDS
                        : APPLET_STATUS_TIMEOUT_MILLISECONDS,
                () => {
                    if (this._removed) {
                        state.timeoutSource = 0;
                        this.on_applet_removed_from_panel();
                        return GLib.SOURCE_REMOVE;
                    }
                    if (state.finalizing) {
                        state.timeoutSource = 0;
                        return GLib.SOURCE_REMOVE;
                    }
                    if (!state.exitConfirmed || !state.stdoutDone || !state.stderrDone) {
                        state.timedOut = true;
                        if (!state.exitConfirmed) requestForceExit(state);
                        failRefresh(state);
                        if (state.waitFailed) ensureExitWait(state);
                    }
                    if (!state.exitConfirmed || !state.stdoutDone || !state.stderrDone) {
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
            readStream(
                state,
                "stdout",
                stdoutStream,
                commandKind === "status" || commandKind === "overview"
                    ? APPLET_STDOUT_LIMIT_BYTES
                    : APPLET_STDERR_LIMIT_BYTES
            );
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
        const keys = typeof GLib.listenv === "function" ? GLib.listenv() : null;
        if (!Array.isArray(keys) || keys.length > MAX_ENVIRONMENT_KEYS) {
            throw new Error("Process environment unavailable");
        }
        for (const key of keys) {
            if (typeof key !== "string" || !APPLET_ALLOWED_ENV_VARS.has(key)) launcher.unsetenv(key);
        }
        const home = GLib.get_home_dir ? GLib.get_home_dir() : "/home/unknown";
        launcher.setenv("PATH", APPLET_SAFE_PATH, true);
        launcher.setenv("HOME", home, true);
    },

    _clearStatusBuffers(state) {
        if (!state) return;
        state.stdoutChunks = [];
        state.stdoutByteCount = 0;
        state.stderrByteCount = 0;
    },

    _finalizeStatusProcess(state) {
        if (state.commandKind === "overview") {
            this._finalizeOverviewProcess(state);
            return;
        }
        const generation = state.generation;
        if (generation !== this._statusActiveGeneration) return;

        this._statusInFlight = false;
        this._statusActiveGeneration = 0;
        this._statusActiveState = null;
        this._activeStatusProcess = null;

        if (state.commandKind === "launcher") {
            this._clearStatusBuffers(state);
            this._launcherInFlight = false;
            this._statusPendingRefresh = false;
            if (state.timeoutSource) {
                GLib.source_remove(state.timeoutSource);
                state.timeoutSource = 0;
            }
            return;
        }

        if (state.commandKind === "action") {
            let actionCompleted = false;
            if (!state.timedOut && !state.waitFailed && !state.streamFailed && !state.stdoutLimitExceeded && !state.stderrLimitExceeded) {
                const payload = state.process ? this._collectProcessPayload(state) : null;
                let processSuccessful = false;
                try {
                    processSuccessful = state.process && state.process.get_successful();
                } catch (_error) {
                    processSuccessful = false;
                }
                actionCompleted = processSuccessful && this._isValidAppletActionPayload(payload, state.actionRequest);
            }
            this._clearStatusBuffers(state);
            this._actionInFlight = false;
            this._armedAction = null;
            this._actionsAwaitingRefresh = true;
            this._statusPendingRefresh = false;
            this._setMenuItemText(
                this._confirmationDetailItem,
                actionCompleted ? "Aktion abgeschlossen · Status wird geprüft" : "Ausgang unbekannt · Status wird geprüft"
            );
            this._renderStatusSafely();
            if (state.timeoutSource) {
                GLib.source_remove(state.timeoutSource);
                state.timeoutSource = 0;
            }
            if (!this._removed) this._startStatusRefresh();
            return;
        }

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

    _finalizeOverviewProcess(state) {
        const generation = state.generation;
        if (generation !== this._overviewActiveGeneration) return;

        this._overviewInFlight = false;
        this._overviewActiveGeneration = 0;
        this._overviewActiveState = null;

        let applied = false;
        if (!state.timedOut && !state.waitFailed && !state.streamFailed && !state.stdoutLimitExceeded && !state.stderrLimitExceeded) {
            const payload = state.process ? this._collectProcessPayload(state) : null;
            let processSuccessful = false;
            try {
                processSuccessful = state.process && state.process.get_successful();
            } catch (_error) {
                processSuccessful = false;
            }
            if (processSuccessful && payload) applied = this._maybeApplyOverviewPayload(payload);
        }
        this._clearStatusBuffers(state);
        if (!applied) this._markOverviewFailed();
        if (state.timeoutSource) {
            try {
                GLib.source_remove(state.timeoutSource);
            } catch (error) {
                this._logCleanupError(error);
            }
            state.timeoutSource = 0;
        }
        if (!this._removed) this._restartOverviewRefresh();
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
        const normalized = this._normalizeAppletResource(payload);
        if (!this._isValidAppletStatusPayload(normalized)) {
            return false;
        }
        if (normalized.resource.state !== "unavailable") {
            this._resourceGenerationHighWater = Math.max(
                this._resourceGenerationHighWater,
                normalized.resource.generation
            );
        }
        this._statusLastGood = normalized;
        this._armedAction = null;
        this._actionsAwaitingRefresh = false;
        this._updateActionBindings(normalized);
        this._statusViewState = "ready";
        return this._renderStatusSafely();
    },

    _unavailableResource() {
        return {
            schema_version: 1,
            generation: 0,
            state: "unavailable",
            bottleneck: "unknown",
            trend: {},
            confidence: "low",
            preferred_profiles: [],
            avoid_profiles: [],
            raw_output: APPLET_STATUS_RAW_OUTPUT,
        };
    },

    _normalizeAppletResource(payload) {
        if (!payload || typeof payload !== "object") return payload;
        const resource = payload.resource;
        const resourceValid = this._isValidResourceStatus(resource);
        const generationMismatch = resourceValid
            && resource.state !== "unavailable"
            && resource.generation < this._resourceGenerationHighWater;
        if (resourceValid && !generationMismatch) return payload;
        return { ...payload, resource: this._unavailableResource() };
    },

    _isValidResourceStatus(resource) {
        if (!resource || typeof resource !== "object") return false;
        if (!this._hasExactFields(resource, APPLET_RESOURCE_REQUIRED_FIELDS)) return false;
        if (resource.schema_version !== 1 || resource.raw_output !== APPLET_STATUS_RAW_OUTPUT) return false;
        if (!Number.isSafeInteger(resource.generation) || resource.generation < 0) return false;
        if (!APPLET_RESOURCE_STATES.has(resource.state) || !APPLET_RESOURCE_BOTTLENECKS.has(resource.bottleneck)) return false;
        if (!resource.trend || typeof resource.trend !== "object" || Array.isArray(resource.trend)) return false;
        if (!Array.isArray(resource.preferred_profiles) || resource.preferred_profiles.length > 8) return false;
        if (!Array.isArray(resource.avoid_profiles) || resource.avoid_profiles.length > 8) return false;
        const validProfile = (value) => typeof value === "string" && /^[a-z][a-z0-9_-]{0,31}$/.test(value);
        if (!resource.preferred_profiles.every(validProfile) || !resource.avoid_profiles.every(validProfile)) return false;
        if (new Set(resource.preferred_profiles).size !== resource.preferred_profiles.length) return false;
        if (new Set(resource.avoid_profiles).size !== resource.avoid_profiles.length) return false;
        if (resource.confidence === "high") {
            if (!this._hasExactFields(resource.trend, ["cpu", "io", "memory"])) return false;
            if (![resource.trend.cpu, resource.trend.io, resource.trend.memory].every((value) => APPLET_RESOURCE_TRENDS.has(value))) return false;
        } else if (resource.confidence !== "low" || Object.keys(resource.trend).length !== 0) {
            return false;
        }
        if (resource.state === "unavailable") {
            return resource.generation === 0
                && resource.bottleneck === "unknown"
                && resource.confidence === "low"
                && resource.preferred_profiles.length === 0
                && resource.avoid_profiles.length === 0;
        }
        return resource.generation > 0;
    },

    _isValidAppletActionPayload(payload, request) {
        if (!payload || typeof payload !== "object" || !request) return false;
        if (!this._hasExactFields(payload, ["agent", "action", "status", "state", "raw_output"])) return false;
        return payload.agent === request.agent
            && payload.action === request.action
            && payload.status === "completed"
            && payload.state === (request.action === "start" ? "running" : "sleeping")
            && payload.raw_output === APPLET_STATUS_RAW_OUTPUT;
    },

    _isValidAppletStatusPayload(payload) {
        if (!payload || typeof payload !== "object") return false;
        if (!this._hasExactFields(payload, APPLET_STATUS_REQUIRED_FIELDS)) return false;
        if (payload.schema_version !== APPLET_STATUS_SCHEMA_VERSION) return false;
        if (payload.mode !== "read_only") return false;
        if (payload.raw_output !== APPLET_STATUS_RAW_OUTPUT) return false;

        if (typeof payload.counts !== "object" || payload.counts === null) return false;
        if (!this._hasExactFields(payload.counts, APPLET_STATUS_REQUIRED_COUNTS)) return false;
        for (const key of APPLET_STATUS_REQUIRED_COUNTS) {
            const value = payload.counts[key];
            if (!Number.isInteger(value) || value < 0) return false;
        }

        if (!Array.isArray(payload.agents) || payload.agents.length > MAX_TRACKED_AGENTS) return false;
        const agents = new Set();
        let startOfferCount = 0;
        for (const row of payload.agents) {
            if (!row || typeof row !== "object") return false;
            if (!this._hasExactFields(row, APPLET_STATUS_REQUIRED_ROW_FIELDS)) return false;
            for (const field of APPLET_STATUS_BASE_ROW_STRING_FIELDS) {
                if (typeof row[field] !== "string" || row[field].length === 0) return false;
            }
            if (typeof row.context_token !== "string") return false;
            if (row.blocked_until_utc !== null && !this._isValidUtcTimestamp(row.blocked_until_utc)) return false;
            if (!this._isCanonicalManagedAgentId(row.agent)) return false;
            if (agents.has(row.agent)) return false;
            agents.add(row.agent);
            if (!this._isValidStateSet("row", "activity_state", row.activity_state)) return false;
            if (!this._isValidStateSet("row", "backend_state", row.backend_state)) return false;
            if (!this._isValidStateSet("row", "control_state", row.control_state)) return false;
            if (!this._isValidStateSet("row", "auth_state", row.auth_state)) return false;
            if (!this._isValidStateSet("row", "identity_state", row.identity_state)) return false;
            if (!this._isValidStateSet("row", "lease_state", row.lease_state)) return false;
            if (!this._isValidStateSet("row", "allowed_action", row.allowed_action)) return false;
            if (!this._isValidStateSet("row", "limit_state", row.limit_state)) return false;
            if (!this._isValidAppletStatusRow(row)) return false;
            if (!this._isValidAppletActionOffer(row)) return false;
            if (row.allowed_action === "start") startOfferCount += 1;
        }
        if (startOfferCount > 1) return false;

        if (payload.counts.tracked !== payload.agents.length) return false;
        const expectedCounts = {
            tracked: payload.agents.length,
            running: payload.agents.filter((row) => row.activity_state === "running").length + payload.counts.overflow,
            sleeping: payload.agents.filter((row) => row.activity_state === "sleeping").length,
            overflow: payload.counts.overflow,
        };
        if (APPLET_STATUS_REQUIRED_COUNTS.some((key) => payload.counts[key] !== expectedCounts[key])) return false;
        return this._isValidNativeAgentSnapshot(payload.native_agents);
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

    _isValidContextToken(value) {
        return typeof value === "string"
            && value.length >= 3
            && value.length <= 512
            && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
    },

    _isValidAppletActionOffer(row) {
        const isErrorRow = row.activity_state === "unknown" && row.backend_state === "error";
        if (row.allowed_action === "none") {
            return row.context_token === ""
                && (!isErrorRow || (row.limit_state === "unknown" && row.blocked_until_utc === null));
        }
        if (!this._isValidContextToken(row.context_token) || isErrorRow) return false;
        if (row.allowed_action === "start") {
            return row.activity_state === "sleeping"
                && row.backend_state === "ok"
                && row.control_state === "ready"
                && row.auth_state === "ready"
                && row.identity_state === "stopped"
                && ["unclaimed", "expired"].includes(row.lease_state)
                && row.limit_state === "clear";
        }
        return row.allowed_action === "stop"
            && row.activity_state === "running"
            && row.backend_state === "ok"
            && row.identity_state === "verified"
            && ["unclaimed", "expired"].includes(row.lease_state);
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

    _isCanonicalManagedAgentId(value) {
        return typeof value === "string" && /^[abc](?:[1-9]|[1-9][0-9]|100)$/.test(value);
    },

    _isValidNativeSafeString(value) {
        return typeof value === "string" && /^[A-Za-z0-9_-]{1,32}$/.test(value);
    },

    _isValidUtcTimestamp(value) {
        if (typeof value !== "string" || value.length < 20 || value.length > 40) return false;
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$/.test(value)) return false;
        return Number.isFinite(Date.parse(value));
    },

    _isValidNativeAgentSnapshot(nativeAgents) {
        if (!nativeAgents || typeof nativeAgents !== "object") return false;
        if (!this._hasExactFields(nativeAgents, APPLET_STATUS_REQUIRED_NATIVE_FIELDS)) return false;
        if (!this._isValidStateSet("native", "bridge_state", nativeAgents.bridge_state)) return false;
        if (typeof nativeAgents.counts !== "object" || nativeAgents.counts === null) return false;
        if (!this._hasExactFields(nativeAgents.counts, APPLET_STATUS_REQUIRED_NATIVE_COUNTS)) return false;
        for (const key of APPLET_STATUS_REQUIRED_NATIVE_COUNTS) {
            if (!Number.isInteger(nativeAgents.counts[key]) || nativeAgents.counts[key] < 0) return false;
        }
        if (typeof nativeAgents.truncated !== "boolean") return false;
        if (!Array.isArray(nativeAgents.agents) || nativeAgents.agents.length > MAX_NATIVE_BEES) return false;

        const displayIds = new Set();
        let activeCount = 0;
        let unconfirmedCount = 0;
        for (const row of nativeAgents.agents) {
            if (!row || typeof row !== "object") return false;
            if (!this._hasExactFields(row, APPLET_STATUS_REQUIRED_NATIVE_AGENT_FIELDS)) return false;
            if (!this._isValidNativeSafeString(row.display_id)) return false;
            if (!this._isValidNativeSafeString(row.agent_type)) return false;
            if (!this._isValidStateSet("native", "activity_state", row.activity_state)) return false;
            if (!this._isValidUtcTimestamp(row.updated_at_utc)) return false;
            if (displayIds.has(row.display_id)) return false;
            displayIds.add(row.display_id);
            if (row.activity_state === "active") activeCount += 1;
            else unconfirmedCount += 1;
        }

        if (activeCount > nativeAgents.counts.active) return false;
        if (unconfirmedCount > nativeAgents.counts.unconfirmed) return false;
        const totalCount = nativeAgents.counts.active + nativeAgents.counts.unconfirmed;
        if (totalCount !== nativeAgents.agents.length + nativeAgents.counts.overflow) return false;
        if (nativeAgents.truncated !== (nativeAgents.counts.overflow > 0)) return false;
        return true;
    },

    _deriveSnapshotActivity(rows) {
        if (!rows || rows.length === 0) return "unknown";
        const activityStates = rows.map((row) => row.activity_state);
        return activityStates.every((state) => state === "running")
            ? "running"
            : activityStates.every((state) => state === "sleeping")
                ? "sleeping"
                : activityStates.every((state) => state === "unknown") ? "unknown" : "mixed";
    },

    _deriveSnapshotBackend(rows) {
        if (!rows || rows.length === 0) return "unavailable";
        const backendStates = rows.map((row) => row.backend_state);
        return backendStates.every((state) => state === "ok")
            ? "ok"
            : backendStates.every((state) => state === "error") ? "unavailable" : "degraded";
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
        this._armedAction = null;
        this._clearActionBindings();
        this._statusViewState = this._statusLastGood ? "stale" : "unavailable";
        this._renderStatusSafely();
    },

    _stateLabel(scope, value) {
        return APPLET_STATUS_LABELS[scope]?.[value] || "unbekannt";
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

    _overviewHasExactFields(value, fields) {
        if (!value || typeof value !== "object" || Array.isArray(value)) return false;
        const keys = Object.keys(value);
        return keys.length === fields.length && fields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
    },

    _overviewString(value, maximum = APPLET_OVERVIEW_MAX_STRING_LENGTH) {
        return typeof value === "string"
            && value.length > 0
            && value.length <= maximum
            && !/[\u0000-\u001f\u007f]/.test(value);
    },

    _overviewOptionalString(value) {
        return value === null || this._overviewString(value);
    },

    _overviewAccountId(value) {
        return typeof value === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(value);
    },

    _overviewAgentId(value) {
        return typeof value === "string" && /^(?:[abc](?:[1-9]|[1-9][0-9]|100))$/.test(value);
    },

    _overviewPercent(value) {
        return value === null || (
            typeof value === "number"
            && Number.isFinite(value)
            && value >= 0
            && value <= 100
        );
    },

    _overviewUtc(value) {
        if (value === null) return true;
        if (!this._overviewString(value, 40)) return false;
        const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|\+00:00)$/.exec(value);
        if (!match) return false;
        const year = Number(match[1]);
        const month = Number(match[2]);
        const day = Number(match[3]);
        const hour = Number(match[4]);
        const minute = Number(match[5]);
        const second = Number(match[6]);
        const candidate = new Date(0);
        candidate.setUTCFullYear(year, month - 1, day);
        candidate.setUTCHours(hour, minute, second, 0);
        return Number.isFinite(candidate.valueOf())
            && candidate.getUTCFullYear() === year
            && candidate.getUTCMonth() === month - 1
            && candidate.getUTCDate() === day
            && candidate.getUTCHours() === hour
            && candidate.getUTCMinutes() === minute
            && candidate.getUTCSeconds() === second;
    },

    _overviewLimitWindows(value) {
        if (!Array.isArray(value) || value.length > 32) return false;
        return value.every((window) => this._overviewHasExactFields(window, [
            "pool", "window_seconds", "used_percent", "remaining_percent", "reset_at",
        ])
            && this._overviewString(window.pool, 64)
            && Number.isSafeInteger(window.window_seconds)
            && window.window_seconds >= 1 && window.window_seconds <= 2592000
            && this._overviewPercent(window.used_percent)
            && this._overviewPercent(window.remaining_percent)
            && this._overviewUtc(window.reset_at));
    },

    _overviewLimitLabel(window) {
        const duration = window.window_seconds === 18000 ? "5h"
            : window.window_seconds === 604800 ? "7d"
                : window.window_seconds === 2592000 ? "30d" : `${window.window_seconds}s`;
        return `${window.pool}/${duration}`;
    },

    _isValidOverviewPayload(payload) {
        try {
            if (!this._overviewHasExactFields(payload, [
                "generation", "created_at", "integration_freshness", "series", "agents", "account_limits", "warnings",
            ])) return false;
            if (!Number.isSafeInteger(payload.generation) || payload.generation < 0) return false;
            if (typeof payload.created_at !== "string" || !this._overviewUtc(payload.created_at)) return false;
            if (!["fresh", "stale", "unavailable", "registry_only"].includes(payload.integration_freshness)) return false;
            if (!Array.isArray(payload.series) || payload.series.length > APPLET_OVERVIEW_MAX_ARRAY_LENGTH) return false;
            if (!Array.isArray(payload.agents) || payload.agents.length > APPLET_OVERVIEW_MAX_ARRAY_LENGTH) return false;
            if (!Array.isArray(payload.account_limits) || payload.account_limits.length > APPLET_OVERVIEW_MAX_ARRAY_LENGTH) return false;
            if (!Array.isArray(payload.warnings) || payload.warnings.length > APPLET_OVERVIEW_MAX_ARRAY_LENGTH) return false;
            if (payload.warnings.some((warning) => !this._overviewString(warning, APPLET_OVERVIEW_MAX_WARNING_LENGTH))) return false;

            const seriesIds = new Set();
            const seriesAgentIds = new Set();
            for (const row of payload.series) {
                if (!this._overviewHasExactFields(row, [
                    "prefix", "display_name", "provider", "runner", "model", "active_count", "total_count", "agent_ids",
                ])) return false;
                if (!this._overviewString(row.prefix, 16) || seriesIds.has(row.prefix)) return false;
                if (!this._overviewString(row.display_name) || !this._overviewString(row.provider)
                    || !this._overviewString(row.runner) || !this._overviewString(row.model)) return false;
                if (!Number.isSafeInteger(row.active_count) || row.active_count < 0
                    || !Number.isSafeInteger(row.total_count) || row.total_count < row.active_count) return false;
                if (!Array.isArray(row.agent_ids) || row.agent_ids.length > APPLET_OVERVIEW_MAX_ARRAY_LENGTH) return false;
                const rowIds = new Set();
                for (const agentId of row.agent_ids) {
                    if (!this._overviewAgentId(agentId) || rowIds.has(agentId) || seriesAgentIds.has(agentId)) return false;
                    rowIds.add(agentId);
                    seriesAgentIds.add(agentId);
                }
                if (row.active_count > row.agent_ids.length || row.total_count !== row.agent_ids.length) return false;
                seriesIds.add(row.prefix);
            }

            const agentIds = new Set();
            const usageFreshnesses = [];
            for (const row of payload.agents) {
                if (!this._overviewHasExactFields(row, [
                    "agent_id", "series_display", "provider", "runner", "model", "account_id", "account_label", "state",
                    "principal_role", "dispatch_id", "limit_short_remaining_percent", "limit_short_reset_at",
                    "limit_week_remaining_percent", "limit_week_reset_at", "cost_last_hour_percentage_points", "usage_freshness", "limit_windows",
                ])) return false;
                if (!this._overviewAgentId(row.agent_id)
                    || !seriesAgentIds.has(row.agent_id)
                    || agentIds.has(row.agent_id)) return false;
                if (!this._overviewString(row.series_display) || !this._overviewString(row.provider)
                    || !this._overviewString(row.runner) || !this._overviewString(row.model)) return false;
                if ((row.account_id !== null && !this._overviewAccountId(row.account_id)) || !this._overviewOptionalString(row.account_label)
                    || !["running", "idle", "stopped", "unknown"].includes(row.state)
                    || !this._overviewOptionalString(row.principal_role) || !this._overviewOptionalString(row.dispatch_id)
                    || !this._overviewPercent(row.limit_short_remaining_percent)
                    || !this._overviewUtc(row.limit_short_reset_at)
                    || !this._overviewPercent(row.limit_week_remaining_percent)
                    || !this._overviewUtc(row.limit_week_reset_at)
                    || !this._overviewPercent(row.cost_last_hour_percentage_points)
                    || !this._overviewLimitWindows(row.limit_windows)
                    || !["fresh", "stale", "unavailable"].includes(row.usage_freshness)) return false;
                agentIds.add(row.agent_id);
                usageFreshnesses.push(row.usage_freshness);
            }

            const accountIds = new Set();
            for (const row of payload.account_limits) {
                if (!this._overviewHasExactFields(row, [
                    "account_id", "account_label", "provider", "short_remaining_percent", "short_reset_at",
                    "week_remaining_percent", "week_reset_at", "cost_last_hour_percentage_points", "usage_freshness", "limit_windows",
                ])) return false;
                if (!this._overviewAccountId(row.account_id) || accountIds.has(row.account_id)
                    || !this._overviewString(row.account_label) || !this._overviewString(row.provider)
                    || !this._overviewPercent(row.short_remaining_percent) || !this._overviewUtc(row.short_reset_at)
                    || !this._overviewPercent(row.week_remaining_percent) || !this._overviewUtc(row.week_reset_at)
                    || !this._overviewPercent(row.cost_last_hour_percentage_points)
                    || !this._overviewLimitWindows(row.limit_windows)
                    || !["fresh", "stale", "unavailable"].includes(row.usage_freshness)) return false;
                accountIds.add(row.account_id);
                usageFreshnesses.push(row.usage_freshness);
            }
            const expectedFreshness = payload.integration_freshness === "fresh"
                ? "fresh"
                : payload.integration_freshness === "stale" ? "stale" : "unavailable";
            if (usageFreshnesses.some((value) => value !== expectedFreshness)) return false;
            if (expectedFreshness === "fresh" || expectedFreshness === "stale") {
                if (payload.warnings.length !== 0) return false;
            } else if (payload.warnings.length !== 1 || payload.warnings[0] !== "usage_unavailable") {
                return false;
            }
            return true;
        } catch (_error) {
            return false;
        }
    },

    _maybeApplyOverviewPayload(payload) {
        if (!this._isValidOverviewPayload(payload)) return false;
        this._overviewLastGood = payload;
        this._overviewViewState = "ready";
        return this._renderOverviewSafely();
    },

    _markOverviewFailed() {
        if (this._removed) return;
        this._overviewViewState = "unavailable";
        this._renderOverviewSafely();
    },

    _renderOverviewSafely() {
        try {
            this._renderOverview();
            return true;
        } catch (error) {
            this._logCleanupError(error);
            return false;
        }
    },

    _renderOverview() {
        if (this._removed) return;
        if (this._overviewViewState !== "ready" || !this._overviewLastGood) {
            this._setMenuItemText(this._overviewSummaryItem, "Übersicht: nicht verfügbar");
            this._setMenuItemText(this._overviewDetailItem, "Übersicht Details: —");
            return;
        }
        const payload = this._overviewLastGood;
        const freshness = payload.integration_freshness === "fresh"
            ? "frisch"
            : payload.integration_freshness === "stale" ? "veraltet" : "nicht verfügbar";
        const accountText = payload.account_limits.length === 0
            ? "Konten: —"
            : payload.account_limits.map((row) => (
                `${row.account_id} short=${row.short_remaining_percent === null ? "—" : `${row.short_remaining_percent.toFixed(1)}%`}`
                + ` week=${row.week_remaining_percent === null ? "—" : `${row.week_remaining_percent.toFixed(1)}%`}`
                + ` limits=${row.limit_windows.map((window) => `${this._overviewLimitLabel(window)}=${window.remaining_percent === null ? "—" : `${window.remaining_percent.toFixed(1)}%`}`).join(",") || "—"}`
                + ` cost=${row.cost_last_hour_percentage_points === null ? "—" : `${row.cost_last_hour_percentage_points.toFixed(1)}%`}`
            )).join(" · ");
        const summary = this.overviewCompact
            ? `Übersicht: ${freshness} · ${accountText}`
            : `Übersicht: ${freshness} · Serien ${payload.series.length} · Agenten ${payload.agents.length}`;
        this._setMenuItemText(this._overviewSummaryItem, summary);
        const detail = this.overviewDetail
            ? payload.agents.length === 0
                ? "Übersicht Details: —"
                : `Übersicht Details: ${payload.agents.map((row) => `${row.agent_id} → ${row.account_id || "—"} · ${row.state}`).join(" · ")}`
            : "Übersicht Details: —";
        this._setMenuItemText(this._overviewDetailItem, detail);
    },

    _renderStatus() {
        if (this._removed) return;
        this._applyPanelPresentation();
        const payload = this._statusLastGood;
        const managedRows = payload ? payload.agents : this._trackedAgents.map((agent) => ({
            agent,
            activity_state: "unknown",
            backend_state: "error",
            control_state: "unknown",
        }));
        const activity = this._stateLabel("activity", this._deriveSnapshotActivity(managedRows));
        const backend = this._stateLabel("backend", this._deriveSnapshotBackend(managedRows));
        const stale = this._statusViewState === "stale" ? " · veraltet" : "";
        const unavailable = this._statusViewState === "unavailable" ? " · nicht verfügbar" : "";
        const configuration = this._settingsValid ? "" : "Konfigurationsfehler · ";
        const resourceState = payload && payload.resource ? payload.resource.state : "unavailable";
        const resource = resourceState === "ready" ? "bereit" : resourceState === "blocked" ? "blockiert" : "nicht verfügbar";
        const summary = `${configuration}Aktivität: ${activity} · Backend: ${backend} · Ressourcen: ${resource} · Modus: Schnellsteuerung${stale}${unavailable}`;
        this.set_applet_tooltip(summary);
        this._setMenuItemText(this._statusSummaryItem, summary);

        for (let index = 0; index < this._statusRowItems.length; index += 1) {
            const item = this._statusRowItems[index];
            const row = managedRows[index];
            if (!row) {
                this._setMenuItemVisible(item, false);
                continue;
            }
            let limit = "";
            if (row.limit_state === "blocked") {
                limit = row.blocked_until_utc
                    ? ` · Limit bis ${row.blocked_until_utc}`
                    : " · Limit blockiert";
            } else if (row.limit_state === "unknown") {
                limit = " · Limit unbekannt";
            }
            const text = `${row.agent}: ${this._stateLabel("activity", row.activity_state)} · Backend ${this._stateLabel("backend", row.backend_state)} · Steuerung ${this._stateLabel("control", row.control_state)}${limit}`;
            this._setMenuItemText(item, text);
            this._setMenuItemVisible(item, true);
        }

        this._renderQuickControl(payload);
        this._renderNativeStatus(payload ? payload.native_agents : null);
    },

    _renderQuickControl(payload) {
        if (!this._quickControlSubmenuItem) return;
        this._setMenuItemVisible(this._startActionItem, false);
        for (const item of this._stopActionItems) this._setMenuItemVisible(item, false);
        this._setMenuItemVisible(this._confirmationDetailItem, false);
        this._setMenuItemVisible(this._confirmationConfirmItem, false);
        this._setMenuItemVisible(this._confirmationCancelItem, false);

        if (this._actionInFlight) {
            const action = this._statusActiveState && this._statusActiveState.actionRequest;
            const label = action
                ? `${action.action === "start" ? "Start" : "Stop"} ${action.agent} läuft · kein automatischer Retry`
                : "Aktion läuft · kein automatischer Retry";
            this._setMenuItemText(this._quickControlSubmenuItem, "Schnellsteuerung (läuft)");
            this._setMenuItemText(this._confirmationDetailItem, label);
            this._setMenuItemVisible(this._confirmationDetailItem, true);
            return;
        }
        if (this._actionsAwaitingRefresh) {
            this._setMenuItemText(this._quickControlSubmenuItem, "Schnellsteuerung (Statusprüfung)");
            this._setMenuItemText(this._confirmationDetailItem, "Ausgang wird read-only geprüft");
            this._setMenuItemVisible(this._confirmationDetailItem, true);
            return;
        }
        if (this._armedAction) {
            const verb = this._armedAction.action === "start" ? "starten" : "stoppen";
            this._setMenuItemText(this._quickControlSubmenuItem, "Schnellsteuerung (Bestätigung)");
            this._setMenuItemText(this._confirmationDetailItem, `${this._armedAction.agent} wirklich ${verb}?`);
            this._setMenuItemText(this._confirmationConfirmItem, `Ja, ${this._armedAction.agent} ${verb}`);
            this._setMenuItemVisible(this._confirmationDetailItem, true);
            this._setMenuItemVisible(this._confirmationConfirmItem, true);
            this._setMenuItemVisible(this._confirmationCancelItem, true);
            return;
        }

        let stopCount = 0;
        for (let index = 0; index < this._stopActionBindings.length; index += 1) {
            const binding = this._stopActionBindings[index];
            if (!binding) continue;
            this._setMenuItemText(this._stopActionItems[index], `${binding.agent} stoppen`);
            this._setMenuItemVisible(this._stopActionItems[index], true);
            stopCount += 1;
        }
        if (this._startActionBinding) {
            this._setMenuItemText(this._startActionItem, `${this._startActionBinding.agent} starten`);
            this._setMenuItemVisible(this._startActionItem, true);
        }
        const actionCount = (this._startActionBinding ? 1 : 0) + stopCount;
        this._setMenuItemText(
            this._quickControlSubmenuItem,
            actionCount > 0 ? `Schnellsteuerung (${actionCount})` : "Schnellsteuerung"
        );
        if (actionCount === 0) {
            this._setMenuItemText(this._confirmationDetailItem, "Keine sichere Schnellaktion verfügbar");
            this._setMenuItemVisible(this._confirmationDetailItem, true);
        }
    },

    _renderNativeStatus(nativeAgents) {
        if (!this._nativeSubmenuItem) return;

        let title = "Native Bienen";
        const rows = [];
        if (!nativeAgents) {
            rows.push("Native Bridge nicht verfügbar");
        } else if (nativeAgents.bridge_state !== "ready") {
            rows.push(`Native Bridge ${this._stateLabel("nativeBridge", nativeAgents.bridge_state)}`);
        } else {
            const total = nativeAgents.counts.active + nativeAgents.counts.unconfirmed;
            if (total > 0) title = `Native Bienen (${total})`;
            if (nativeAgents.agents.length === 0) {
                rows.push("Keine aktiven Native Bienen");
            } else {
                for (const agent of nativeAgents.agents) {
                    rows.push(
                        `${agent.agent_type} · ${this._stateLabel("nativeActivity", agent.activity_state)} · ${agent.display_id}`
                    );
                }
                if (nativeAgents.counts.overflow > 0 && rows.length === MAX_NATIVE_BEES) {
                    rows[MAX_NATIVE_BEES - 1] = `+${nativeAgents.counts.overflow} weitere Native Bienen`;
                }
            }
        }

        this._setMenuItemText(this._nativeSubmenuItem, title);
        for (let index = 0; index < this._nativeBeeRowItems.length; index += 1) {
            const item = this._nativeBeeRowItems[index];
            const text = rows[index];
            if (!text) {
                this._setMenuItemVisible(item, false);
                continue;
            }
            this._setMenuItemText(item, text);
            this._setMenuItemVisible(item, true);
        }
    },

    _connectTracked(target, signal, callback) {
        if (
            this._removed
            || !target
            || typeof target.connect !== "function"
            || typeof target.disconnect !== "function"
        ) return 0;
        let id = 0;
        try {
            id = target.connect(signal, callback);
        } catch (error) {
            this._logCleanupError(error);
            return 0;
        }
        if (!Number.isSafeInteger(id) || id <= 0) return 0;
        this._signalConnections.push({ target, id });
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
        this._signalConnections = [];
        for (const connection of connections) {
            try {
                if (connection.target && typeof connection.target.disconnect === "function") {
                    connection.target.disconnect(connection.id);
                }
            } catch (_error) {}
        }
        return true;
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
        this._resourceGenerationHighWater = 0;
        this._statusLastGood = null;
        this._armedAction = null;
        this._actionInFlight = false;
        this._launcherInFlight = false;
        this._actionsAwaitingRefresh = false;
        this._clearActionBindings();
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

    _cleanupOverviewResources() {
        let success = true;
        if (this._overviewSource) {
            try {
                GLib.source_remove(this._overviewSource);
                this._overviewSource = 0;
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }
        if (!this._cancelOverviewRefresh()) success = false;
        if (success) {
            this._overviewLastGood = null;
            this._overviewViewState = "unavailable";
        }
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
            if (!wasOpen && this.menu.isOpen === true) {
                if (this.refreshOnOpen) this._refreshStatus();
                this._refreshOverview();
            }
        } catch (error) {
            this._logCleanupError(error);
        }
    },

    on_applet_removed_from_panel() {
        if (this._cleanupComplete) return;
        this._removed = true;
        for (let attempt = 0; attempt < 2 && !this._cleanupComplete; attempt += 1) {
            const statusClean = this._cleanupStatusResources();
            const overviewClean = this._cleanupOverviewResources();
            const settingsClean = this._cleanupSettings();
            const signalsClean = this._disconnectTrackedSignals();
            const appletMenuClean = this._cleanupMenuResource("menu", "menuManager");
            const contextMenuClean = this._cleanupMenuResource("_applet_context_menu", "_menuManager");
            if (appletMenuClean) {
                this._statusSummaryItem = null;
                this._statusRowItems = [];
                this._overviewSummaryItem = null;
                this._overviewDetailItem = null;
                this._nativeSubmenuItem = null;
                this._nativeBeeRowItems = [];
                this._quickControlSubmenuItem = null;
                this._startActionItem = null;
                this._stopActionItems = [];
                this._confirmationDetailItem = null;
                this._confirmationConfirmItem = null;
                this._confirmationCancelItem = null;
                this._startActionBinding = null;
                this._stopActionBindings = [];
            }
            this._cleanupComplete = statusClean && overviewClean && settingsClean && signalsClean && appletMenuClean && contextMenuClean;
        }
    },
};

function main(metadata, orientation, panel_height, instance_id) {
    return new FlottenmanagementApplet(metadata, orientation, panel_height, instance_id);
}
