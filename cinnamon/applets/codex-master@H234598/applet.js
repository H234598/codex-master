/* -*- mode: js2; js2-basic-offset: 4; indent-tabs-mode: nil -*- */
const Applet = imports.ui.applet;
const PopupMenu = imports.ui.popupMenu;
const Util = imports.misc.util;

const LABEL = "Flottenmanagement";
const UUID = "codex-master@H234598";

function FlottenmanagementApplet(metadata, orientation, panel_height, instance_id) {
    this._init(metadata, orientation, panel_height, instance_id);
}

FlottenmanagementApplet.prototype = {
    __proto__: Applet.TextApplet.prototype,

    _init(metadata, orientation, panel_height, instance_id) {
        Applet.TextApplet.prototype._init.call(this, orientation, panel_height, instance_id);
        this._removed = false;
        this._cleanupComplete = false;
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

        const statusItem = new PopupMenu.PopupMenuItem("Flottenstatus im Terminal");
        this._connectTracked(statusItem, "activate", () => {
            if (this._removed) {
                return;
            }
            Util.spawn([
                "x-terminal-emulator",
                "-e",
                "bash",
                "-lc",
                "codex-master-mcp status; printf '\\n'; exec bash"
            ]);
        });
        this.menu.addMenuItem(statusItem);

        const settingsItem = new PopupMenu.PopupMenuItem("Applet-Verwaltung öffnen");
        this._connectTracked(settingsItem, "activate", () => {
            if (this._removed) {
                return;
            }
            Util.spawn(["cinnamon-settings", "applets"]);
        });
        this.menu.addMenuItem(settingsItem);
    },

    _connectTracked(target, signal, callback) {
        if (this._removed || !target || typeof target.connect !== "function") {
            return 0;
        }
        const id = target.connect(signal, callback);
        if (id) {
            this._signalConnections.push({ target, id });
        }
        return id;
    },

    _logCleanupError(error) {
        if (typeof global !== "undefined" && global && typeof global.logError === "function") {
            global.logError(error);
        }
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
        if (!menu && !manager) {
            return true;
        }
        const stateKey = menuProperty + ":" + managerProperty;
        const state = this._menuCleanupState[stateKey] || {
            managerReleased: !manager,
            managerNeedsDestroy: false,
            menuDestroyed: !menu
        };
        this._menuCleanupState[stateKey] = state;

        let success = true;
        if (menu && menu.isOpen === true) {
            try {
                if (typeof menu.close !== "function") {
                    throw new Error("Menu close operation is unavailable");
                }
                menu.close(false);
                if (menu.isOpen === true) {
                    throw new Error("Menu remained open after cleanup");
                }
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        if (manager && manager.grabbed === true) {
            try {
                if (typeof manager._ungrab !== "function") {
                    throw new Error("Menu manager ungrab operation is unavailable");
                }
                manager._ungrab();
                if (manager.grabbed === true) {
                    throw new Error("Menu manager retained its modal grab");
                }
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        if (success && manager && !state.managerReleased && state.managerNeedsDestroy) {
            try {
                if (typeof manager.destroy !== "function") {
                    throw new Error("Menu manager destroy operation is unavailable");
                }
                manager.destroy();
                state.managerNeedsDestroy = false;
                state.managerReleased = true;
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        } else if (success && manager && menu && !state.managerReleased) {
            try {
                if (typeof manager.removeMenu !== "function") {
                    throw new Error("Menu manager removal operation is unavailable");
                }
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
                if (typeof manager.destroy !== "function") {
                    throw new Error("Menu manager destroy operation is unavailable");
                }
                manager.destroy();
                state.managerReleased = true;
            } catch (error) {
                this._logCleanupError(error);
                success = false;
            }
        }

        if (success && menu && !state.menuDestroyed) {
            try {
                if (typeof menu.destroy !== "function") {
                    throw new Error("Menu destroy operation is unavailable");
                }
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

    on_applet_clicked() {
        if (this._removed || !this.menu || typeof this.menu.toggle !== "function") {
            return;
        }
        if (this.menu.actor && typeof this.menu.actor.is_finalized === "function" && this.menu.actor.is_finalized()) {
            return;
        }
        this.menu.toggle();
    },

    on_applet_removed_from_panel() {
        if (this._cleanupComplete) {
            return;
        }
        this._removed = true;
        const signalsClean = this._disconnectTrackedSignals();
        const appletMenuClean = this._cleanupMenuResource("menu", "menuManager");
        const contextMenuClean = this._cleanupMenuResource("_applet_context_menu", "_menuManager");
        this._cleanupComplete = signalsClean && appletMenuClean && contextMenuClean;
    }
};

function main(metadata, orientation, panel_height, instance_id) {
    return new FlottenmanagementApplet(metadata, orientation, panel_height, instance_id);
}
