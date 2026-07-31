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

function loadApplet() {
  const spawned = [];

  function TextApplet() {}
  TextApplet.prototype._init = function () {
    this.labels = [];
    this.tooltips = [];
  };
  TextApplet.prototype.set_applet_label = function (value) { this.labels.push(value); };
  TextApplet.prototype.set_applet_tooltip = function (value) { this.tooltips.push(value); };

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
        if (handler.signal === "activate") handler.callback();
      }
    }
  }

  class AppletPopupMenu {
    constructor() {
      this.isOpen = false;
      this.items = [];
      this.destroyed = false;
      this.actor = { is_finalized: () => this.destroyed };
    }
    addMenuItem(item) { this.items.push(item); }
    toggle() { this.isOpen = !this.isOpen; }
    close() { this.isOpen = false; }
    destroy() { this.destroyed = true; }
  }

  class PopupMenuManager {
    constructor() { this.menus = []; this.removed = []; }
    addMenu(menu) { this.menus.push(menu); }
    removeMenu(menu) { this.removed.push(menu); this.menus = this.menus.filter((entry) => entry !== menu); }
  }

  const context = {
    imports: {
      ui: {
        applet: { TextApplet, AppletPopupMenu },
        popupMenu: { PopupMenuItem, PopupMenuManager },
      },
      misc: { util: { spawn(args) { spawned.push(args); } } },
    },
  };
  vm.runInNewContext(source, context, { filename: "applet.js" });
  return { main: context.main, spawned };
}

test("valid applet disconnects actions and destroys its menu exactly once", () => {
  const { main, spawned } = loadApplet();
  const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 1);
  const menu = applet.menu;
  const manager = applet.menuManager;
  const [statusItem, settingsItem] = menu.items;

  applet.on_applet_clicked();
  assert.equal(menu.isOpen, true);
  statusItem.activate();
  settingsItem.activate();
  assert.equal(spawned.length, 2);

  applet.on_applet_removed_from_panel();
  applet.on_applet_removed_from_panel();
  statusItem.activate();
  settingsItem.activate();

  assert.equal(spawned.length, 2, "stale activation handlers are disconnected");
  assert.equal(menu.isOpen, false);
  assert.equal(menu.destroyed, true);
  assert.deepEqual(manager.removed, [menu]);
  assert.equal(applet.menu, null);
  assert.equal(applet.menuManager, null);
  assert.doesNotThrow(() => applet.on_applet_clicked());
});

test("metadata failure remains safe to click and remove", () => {
  const { main } = loadApplet();
  const applet = main({ uuid: "wrong" }, "top", 24, 2);

  assert.equal(applet.labels.at(-1), "Applet-Fehler");
  assert.doesNotThrow(() => applet.on_applet_clicked());
  assert.doesNotThrow(() => applet.on_applet_removed_from_panel());
  assert.doesNotThrow(() => applet.on_applet_removed_from_panel());
});
