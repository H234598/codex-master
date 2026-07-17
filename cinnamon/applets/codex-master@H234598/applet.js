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
        statusItem.connect("activate", () => {
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
        settingsItem.connect("activate", () => {
            Util.spawn(["cinnamon-settings", "applets"]);
        });
        this.menu.addMenuItem(settingsItem);
    },

    on_applet_clicked() {
        this.menu.toggle();
    },

    on_applet_removed_from_panel() {
        if (this.menu && this.menu.isOpen) {
            this.menu.close();
        }
        if (this.menuManager) {
            this.menuManager.removeMenu(this.menu);
        }
    }
};

function main(metadata, orientation, panel_height, instance_id) {
    return new FlottenmanagementApplet(metadata, orientation, panel_height, instance_id);
}
