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
    this._applet_context_menu = new AppletPopupMenu();
    this._menuManager = new PopupMenuManager();
    this._menuManager.addMenu(this._applet_context_menu);
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
      this.closeCount = 0;
      this.destroyCount = 0;
      this.failCloseCount = 0;
      this.failDestroyCount = 0;
      this.actor = { is_finalized: () => this.destroyed };
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
      this.destroyCount = 0;
      this.destroyed = false;
      this.failRemoveCount = 0;
      this.failDestroyCount = 0;
    }
    addMenu(menu) { this.menus.push(menu); }
    _ungrab() {
      if (!this.grabbed) return;
      this.ungrabCount += 1;
      this.grabbed = false;
    }
    destroy() {
      this.destroyCount += 1;
      if (this.failDestroyCount > 0) {
        this.failDestroyCount -= 1;
        throw new Error("injected manager destroy failure");
      }
      this.destroyed = true;
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
      if (this.menus.length === 0) this.destroy();
    }
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
  assert.equal(spawned.length, 2);

  applet.on_applet_removed_from_panel();
  applet.on_applet_removed_from_panel();
  statusItem.activate();
  settingsItem.activate();

  assert.equal(spawned.length, 2, "stale activation handlers are disconnected");
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

test("menu cleanup failures retain resources and are retried", () => {
  for (const failure of ["close", "remove", "menu-destroy", "manager-destroy"]) {
    const { main } = loadApplet();
    const applet = main({ uuid: "codex-master@H234598" }, "top", 24, 10);
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

    assert.equal(applet.menu, menu, `${failure}: failed resource remains reachable`);
    assert.equal(applet.menuManager, manager, `${failure}: failed manager remains reachable`);
    assert.equal(manager.grabbed, false, `${failure}: modal grab is released on the first attempt`);

    applet.on_applet_removed_from_panel();

    assert.equal(menu.isOpen, false, `${failure}: retry closes menu`);
    assert.equal(menu.destroyed, true, `${failure}: retry destroys menu`);
    assert.equal(manager.destroyed, true, `${failure}: retry destroys manager`);
    assert.equal(manager.grabbed, false, `${failure}: retry leaves no modal grab`);
    assert.equal(applet.menu, null, `${failure}: successful retry clears menu reference`);
    assert.equal(applet.menuManager, null, `${failure}: successful retry clears manager reference`);
  }
});

test("metadata failure remains safe to click and remove", () => {
  const { main } = loadApplet();
  const applet = main({ uuid: "wrong" }, "top", 24, 2);

  assert.equal(applet.labels.at(-1), "Applet-Fehler");
  assert.doesNotThrow(() => applet.on_applet_clicked());
  assert.doesNotThrow(() => applet.on_applet_removed_from_panel());
  assert.doesNotThrow(() => applet.on_applet_removed_from_panel());
});
