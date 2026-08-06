/* Dynamic fleet menu model.  Cinnamon bindings are deliberately kept outside
 * this bounded, Node-testable core. */
(function (root, factory) {
    if (typeof module !== "undefined" && module.exports) {
        module.exports = factory(root);
    } else {
        const exported = factory(root);
        root.CodexMasterApplet = exported;
        root.main = exported.main;
    }
}(typeof globalThis !== "undefined" ? globalThis : this, function (host) {
    "use strict";

    const LABEL = "Flottenmanagement";
    const UUID = "codex-master@H234598";
    const MAX_SERIES = 26;
    const MAX_AGENTS = 1000;
    const MAX_NATIVE_AGENTS = 1000;
    const MAX_VISIBLE_ROWS = 25;
    const MAX_DISPATCH_TARGETS = 6;
    const LIMIT_STATES = new Set(["ready", "limited", "unknown", "probing", "disabled"]);

    function text(value, fallback) {
        return typeof value === "string" && value.length > 0 && value.length <= 120
                && !/[\u0000-\u001F\u007F]/.test(value)
            ? value
            : fallback;
    }

    function normalizeAppletSnapshot(payload) {
        if (!payload || (payload.schema_version !== 2 && payload.schema_version !== 3)) {
            return {schema_version: 3, generation: 0, series: [], native_agents: [], dispatch_targets: []};
        }
        const generation = Number.isInteger(payload.generation) && payload.generation >= 0 ? payload.generation : 0;
        const rawSeries = Array.isArray(payload.series) ? payload.series.slice(0, MAX_SERIES) : [];
        let remainingAgents = MAX_AGENTS;
        const seenPrefixes = new Set();
        const series = rawSeries.flatMap((item) => {
            if (!item || typeof item.prefix !== "string" || !/^[a-z]$/.test(item.prefix)) return [];
            if (seenPrefixes.has(item.prefix)) return [];
            if (remainingAgents <= 0) return [];
            const requestedCount = Number.isInteger(item.count) ? Math.max(0, Math.min(100, item.count)) : 0;
            const count = Math.min(requestedCount, remainingAgents);
            remainingAgents -= count;
            if (count <= 0) return [];
            seenPrefixes.add(item.prefix);
            const running = Number.isInteger(item.running_count) ? Math.max(0, Math.min(count, item.running_count)) : 0;
            const eligible = Number.isInteger(item.eligible_count) ? Math.max(0, Math.min(count, item.eligible_count)) : 0;
            const limitState = typeof item.limit_state === "string" && LIMIT_STATES.has(item.limit_state)
                ? item.limit_state
                : "unknown";
            return [{
                prefix: item.prefix,
                display_name: text(item.display_name, item.prefix.toUpperCase()),
                count,
                polled_count: Number.isInteger(item.polled_count)
                    ? Math.max(0, Math.min(count, item.polled_count))
                    : count,
                running_count: running,
                eligible_count: eligible,
                limit_state: limitState,
                blocked_until_utc: typeof item.blocked_until_utc === "string" ? item.blocked_until_utc : null,
                generation,
            }];
        });
        const rawNative = Array.isArray(payload.native_agents)
            ? payload.native_agents.slice(0, MAX_NATIVE_AGENTS)
            : [];
        const seenNative = new Set();
        const native_agents = rawNative.flatMap((item) => {
            if (remainingAgents <= 0) return [];
            const native = typeof item === "string" ? {id: item} : item;
            if (!native || typeof native.id !== "string"
                    || !/^[a-z](?:[1-9]|[1-9][0-9]|100)$/.test(native.id)) return [];
            if (seenNative.has(native.id)) return [];
            seenNative.add(native.id);
            remainingAgents -= 1;
            const limitState = typeof native.limit_state === "string" && LIMIT_STATES.has(native.limit_state)
                ? native.limit_state
                : "unknown";
            return [{
                id: native.id,
                label: text(native.label, native.id),
                running: native.running === true,
                limit_state: limitState,
            }];
        });
        const targets = Array.isArray(payload.dispatch_targets)
            ? payload.dispatch_targets.filter((item) => typeof item === "string" && /^[a-z](?:[1-9]|[1-9][0-9]|100)$/.test(item)).slice(0, MAX_DISPATCH_TARGETS)
            : [];
        return {schema_version: payload.schema_version, generation, series, native_agents, dispatch_targets: targets};
    }

    class SeriesMenuModel {
        constructor() {
            this.snapshot = normalizeAppletSnapshot(null);
            this.openedSeries = null;
            this.page = 0;
            this.rows = [];
        }

        setSnapshot(payload) {
            const next = normalizeAppletSnapshot(payload);
            if (next.generation !== this.snapshot.generation) {
                this.openedSeries = null;
                this.page = 0;
                this.rows = [];
            }
            this.snapshot = next;
            if (this.openedSeries !== null) {
                if (next.series.some((item) => item.prefix === this.openedSeries)) {
                    this.openSeries(this.openedSeries, this.page);
                } else {
                    this.closeSeries();
                }
            }
            return next;
        }

        seriesRows() {
            return this.snapshot.series.slice(0, MAX_SERIES);
        }

        nativeRows() {
            return this.snapshot.native_agents.slice(0, MAX_NATIVE_AGENTS).map((item) => ({
                ...item,
                reactive: this.snapshot.dispatch_targets.includes(item.id),
            }));
        }

        openSeries(prefix, page) {
            const series = this.snapshot.series.find((item) => item.prefix === prefix);
            if (!series) return [];
            const maxPage = Math.max(0, Math.ceil(series.count / MAX_VISIBLE_ROWS) - 1);
            this.openedSeries = prefix;
            this.page = Math.max(0, Math.min(Number.isInteger(page) ? page : 0, maxPage));
            const first = this.page * MAX_VISIBLE_ROWS;
            const disabled = series.limit_state !== "ready" || series.eligible_count === 0;
            this.rows = Array.from({length: Math.min(MAX_VISIBLE_ROWS, Math.max(0, series.count - first))}, (_, offset) => {
                const ordinal = first + offset + 1;
                const id = `${series.prefix}${ordinal}`;
                const reactive = !disabled && this.snapshot.dispatch_targets.includes(id);
                return {id, reactive, status: disabled ? series.limit_state : (reactive ? "ready" : "idle")};
            });
            return this.rows.slice(0, MAX_VISIBLE_ROWS);
        }

        closeSeries() {
            this.openedSeries = null;
            this.page = 0;
            this.rows = [];
        }
    }

    function cinnamonApi() {
        const imported = (host && host.imports)
            || (typeof imports !== "undefined" ? imports : null);
        if (!imported || !imported.ui || !imported.ui.applet || !imported.ui.popupMenu || !imported.misc) {
            return null;
        }
        if (!imported.ui.applet.TextApplet || !imported.ui.applet.AppletPopupMenu
                || !imported.ui.popupMenu.PopupMenuManager || !imported.ui.popupMenu.PopupMenuItem
                || !imported.misc.util) {
            return null;
        }
        return imported;
    }

    function CinnamonFleetApplet(metadata, orientation, panelHeight, instanceId) {
        this.model = new SeriesMenuModel();
        this._cinnamon = cinnamonApi();
        const textApplet = this._cinnamon && this._cinnamon.ui.applet.TextApplet;
        if (textApplet && textApplet.prototype && typeof textApplet.prototype._init === "function") {
            this._initCinnamon(metadata, orientation, panelHeight, instanceId);
        } else {
            this._cinnamon = null;
        }
    }

    const importedCinnamon = cinnamonApi();
    if (importedCinnamon) {
        CinnamonFleetApplet.prototype = Object.create(importedCinnamon.ui.applet.TextApplet.prototype);
    }
    CinnamonFleetApplet.prototype.constructor = CinnamonFleetApplet;

    CinnamonFleetApplet.prototype._initCinnamon = function (metadata, orientation, panelHeight, instanceId) {
        const Applet = this._cinnamon.ui.applet;
        const PopupMenu = this._cinnamon.ui.popupMenu;
        const Util = this._cinnamon.misc.util;
        Applet.TextApplet.prototype._init.call(this, orientation, panelHeight, instanceId);
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
        this._dynamicItems = [];
        const statusItem = new PopupMenu.PopupMenuItem("Flottenstatus im Terminal");
        statusItem.connect("activate", function () {
            Util.spawn([
                "x-terminal-emulator", "-e", "bash", "-lc",
                "codex-master-mcp status; printf '\\n'; exec bash",
            ]);
        });
        this.menu.addMenuItem(statusItem);
        const settingsItem = new PopupMenu.PopupMenuItem("Applet-Verwaltung öffnen");
        settingsItem.connect("activate", function () {
            Util.spawn(["cinnamon-settings", "applets"]);
        });
        this.menu.addMenuItem(settingsItem);
        this._renderDynamicMenu();
    };

    CinnamonFleetApplet.prototype.setSnapshot = function (payload) {
        const snapshot = this.model.setSnapshot(payload);
        this._renderDynamicMenu();
        return snapshot;
    };

    CinnamonFleetApplet.prototype._clearDynamicMenu = function () {
        if (!this.menu) return;
        this._dynamicItems.forEach((item) => {
            if (typeof this.menu.removeMenuItem === "function") this.menu.removeMenuItem(item);
            if (item && typeof item.destroy === "function") item.destroy();
        });
        this._dynamicItems = [];
    };

    CinnamonFleetApplet.prototype._renderDynamicMenu = function () {
        if (!this.menu) return;
        this._clearDynamicMenu();
        const PopupMenu = this._cinnamon.ui.popupMenu;
        const addItem = (label, onActivate, reactive = true) => {
            const item = new PopupMenu.PopupMenuItem(label);
            if (!reactive && typeof item.setSensitive === "function") item.setSensitive(false);
            item.connect("activate", onActivate);
            this.menu.addMenuItem(item);
            this._dynamicItems.push(item);
        };
        if (this.model.openedSeries !== null) {
            addItem("← Serien", () => {
                this.model.closeSeries();
                this._renderDynamicMenu();
            });
            const opened = this.model.snapshot.series.find(
                (series) => series.prefix === this.model.openedSeries,
            );
            const maxPage = opened
                ? Math.max(0, Math.ceil(opened.count / MAX_VISIBLE_ROWS) - 1)
                : 0;
            if (this.model.page > 0) {
                addItem("← Vorherige Seite", () => {
                    this.model.openSeries(this.model.openedSeries, this.model.page - 1);
                    this._renderDynamicMenu();
                });
            }
            this.model.rows.forEach((row) => {
                addItem(`${row.id} — ${row.status}`, () => {
                    if (row.reactive) this._dispatchAgent(row.id);
                }, row.reactive);
            });
            if (this.model.page < maxPage) {
                addItem("Nächste Seite →", () => {
                    this.model.openSeries(this.model.openedSeries, this.model.page + 1);
                    this._renderDynamicMenu();
                });
            }
            return;
        }
        const seriesEntries = this.model.seriesRows().map((series) => ({
            label: `${series.display_name} — ${series.running_count}/${series.polled_count} von ${series.count} — ${series.limit_state}`,
            reactive: true,
            onActivate: () => {
                this.model.openSeries(series.prefix, 0);
                this._renderDynamicMenu();
            },
        }));
        const nativeEntries = this.model.nativeRows().map((native) => ({
            label: `${native.label} — ${native.limit_state}`,
            reactive: native.reactive,
            onActivate: () => {
                if (native.reactive) this._dispatchAgent(native.id);
            },
        }));
        const addSubmenu = (label, entries) => {
            if (!entries.length) return;
            if (PopupMenu.PopupSubMenuMenuItem) {
                const submenu = new PopupMenu.PopupSubMenuMenuItem(label);
                entries.forEach((entry) => {
                    const item = new PopupMenu.PopupMenuItem(entry.label);
                    if (!entry.reactive && typeof item.setSensitive === "function") item.setSensitive(false);
                    item.connect("activate", entry.onActivate);
                    submenu.menu.addMenuItem(item);
                });
                this.menu.addMenuItem(submenu);
                this._dynamicItems.push(submenu);
                return;
            }
            entries.forEach((entry) => addItem(`${label}: ${entry.label}`, entry.onActivate, entry.reactive));
        };
        addSubmenu("Serien", seriesEntries);
        addSubmenu("Native Bienen", nativeEntries);
    };

    CinnamonFleetApplet.prototype._dispatchAgent = function (agent) {
        if (host && typeof host.codexMasterDispatch === "function") {
            host.codexMasterDispatch(agent);
            return;
        }
        if (!this._cinnamon) return;
        const command = `codex-master-mcp status --agent ${agent}; printf '\\n'; exec bash`;
        this._cinnamon.misc.util.spawn(["x-terminal-emulator", "-e", "bash", "-lc", command]);
    };

    CinnamonFleetApplet.prototype.on_applet_clicked = function () {
        if (this.menu && typeof this.menu.toggle === "function") {
            this.menu.toggle();
        }
    };

    CinnamonFleetApplet.prototype.on_applet_removed_from_panel = function () {
        if (this.menu && this.menu.isOpen && typeof this.menu.close === "function") {
            this.menu.close();
        }
        if (this.menuManager && typeof this.menuManager.removeMenu === "function") {
            this.menuManager.removeMenu(this.menu);
        }
        this.menu = null;
        this.menuManager = null;
    };

    function main(metadata, orientation, panelHeight, instanceId) {
        return new CinnamonFleetApplet(metadata, orientation, panelHeight, instanceId);
    }

    return {
        MAX_SERIES,
        MAX_AGENTS,
        MAX_NATIVE_AGENTS,
        MAX_VISIBLE_ROWS,
        MAX_DISPATCH_TARGETS,
        SeriesMenuModel,
        CinnamonFleetApplet,
        main,
        normalizeAppletSnapshot,
    };
}));
