import test from "node:test";
import assert from "node:assert/strict";
import applet from "../cinnamon/applets/codex-master@H234598/applet.js";

const {MAX_AGENTS, MAX_NATIVE_AGENTS, MAX_VISIBLE_ROWS, SeriesMenuModel, normalizeAppletSnapshot} = applet;

test("v3 snapshot is bounded and keeps limited targets non-reactive", () => {
  const snapshot = normalizeAppletSnapshot({
    schema_version: 3,
    generation: 4,
    series: [{prefix: "d", display_name: "D", count: 100, running_count: 0,
      eligible_count: 0, limit_state: "limited", blocked_until_utc: null}],
    dispatch_targets: ["d1", "d2", "invalid", "d3", "d4", "d5", "d6"],
  });
  assert.equal(snapshot.series.length, 1);
  assert.equal(snapshot.dispatch_targets.length, 6);
  const model = new SeriesMenuModel();
  model.setSnapshot(snapshot);
  assert.equal(model.openSeries("d", 0).length, MAX_VISIBLE_ROWS);
  assert.equal(model.openSeries("d", 0)[0].reactive, false);
  assert.equal(model.rows[0].status, "limited");
});

test("generation change invalidates old pages without retaining old rows", () => {
  const model = new SeriesMenuModel();
  model.setSnapshot({schema_version: 3, generation: 1,
    series: [{prefix: "d", count: 100, eligible_count: 100, limit_state: "ready"}],
    dispatch_targets: ["d1"]});
  model.openSeries("d", 3);
  assert.equal(model.rows.length, MAX_VISIBLE_ROWS);
  model.setSnapshot({schema_version: 3, generation: 2, series: [], dispatch_targets: []});
  assert.equal(model.rows.length, 0);
  assert.equal(model.openedSeries, null);
});

test("snapshot and page churn stays globally bounded", () => {
  const model = new SeriesMenuModel();
  const payload = (generation) => ({
    schema_version: 3,
    generation,
    series: Array.from({length: 26}, (_, index) => ({
      prefix: String.fromCharCode(97 + index),
      display_name: `Series ${index}`,
      count: 100,
      running_count: 25,
      eligible_count: 25,
      limit_state: "ready",
    })),
    dispatch_targets: ["d1", "d2", "d3"],
  });

  for (let generation = 1; generation <= 10_000; generation += 1) {
    const snapshot = model.setSnapshot(payload(generation));
    assert.ok(snapshot.series.length <= 26);
    assert.ok(snapshot.series.reduce((total, series) => total + series.count, 0) <= MAX_AGENTS);
    assert.ok(model.rows.length <= MAX_VISIBLE_ROWS);
  }

  model.setSnapshot(payload(10_001));
  for (let page = 0; page < 1_000; page += 1) {
    const rows = model.openSeries("d", page);
    assert.ok(rows.length <= MAX_VISIBLE_ROWS);
    assert.ok(model.rows.length <= MAX_VISIBLE_ROWS);
  }
  model.closeSeries();
  assert.deepEqual(model.rows, []);
  assert.equal(model.openedSeries, null);
});

test("main always returns an adapter owning the bounded model", () => {
  const adapter = applet.main({uuid: "codex-master@H234598"}, 0, 24, 0);
  assert.ok(adapter.model instanceof SeriesMenuModel);
});

test("native agents stay in a separate bounded menu dataset", () => {
  const model = new SeriesMenuModel();
  const snapshot = model.setSnapshot({
    schema_version: 3,
    generation: 7,
    series: [{prefix: "d", display_name: "D", count: 2, eligible_count: 2, limit_state: "ready"}],
    native_agents: [
      {id: "a1", label: "Native A", running: true, limit_state: "ready"},
      {id: "b1", label: "Native B", running: false, limit_state: "limited"},
      {id: "bad", label: "ignored"},
    ],
    dispatch_targets: ["a1", "d1"],
  });
  assert.equal(snapshot.native_agents.length, 2);
  assert.equal(model.seriesRows().length, 1);
  assert.deepEqual(model.nativeRows(), [
    {id: "a1", label: "Native A", running: true, limit_state: "ready", reactive: true},
    {id: "b1", label: "Native B", running: false, limit_state: "limited", reactive: false},
  ]);

  const bounded = model.setSnapshot({
    schema_version: 3,
    generation: 8,
    series: [{prefix: "d", count: MAX_AGENTS, eligible_count: MAX_AGENTS, limit_state: "ready"}],
    native_agents: Array.from({length: MAX_NATIVE_AGENTS}, (_, index) => ({
      id: `${String.fromCharCode(107 + Math.floor(index / 100))}${(index % 100) + 1}`,
    })),
    dispatch_targets: [],
  });
  assert.equal(bounded.series[0].count + bounded.native_agents.length, MAX_AGENTS);
  assert.equal(bounded.native_agents.length, MAX_AGENTS - 100);
});

test("normalization drops duplicate series and native ids", () => {
  const snapshot = normalizeAppletSnapshot({
    schema_version: 3,
    generation: 10,
    series: [
      {prefix: "d", count: 2, eligible_count: 2, limit_state: "ready"},
      {prefix: "d", count: 99, eligible_count: 99, limit_state: "limited"},
    ],
    native_agents: [{id: "a1"}, {id: "a1"}, {id: "b1"}],
    dispatch_targets: [],
  });

  assert.deepEqual(snapshot.series.map((item) => item.prefix), ["d"]);
  assert.deepEqual(snapshot.native_agents.map((item) => item.id), ["a1", "b1"]);
});

test("Cinnamon adapter renders separate series and native submenus", () => {
  class FakeMenu {
    constructor() {
      this.items = [];
      this.isOpen = false;
    }

    addMenuItem(item) {
      this.items.push(item);
    }

    removeMenuItem(item) {
      this.items = this.items.filter((current) => current !== item);
    }

    toggle() {
      this.isOpen = !this.isOpen;
    }

    close() {
      this.isOpen = false;
    }
  }

  class FakeItem {
    constructor(label) {
      this.label = label;
      this.handlers = [];
    }

    connect(_event, handler) {
      this.handlers.push(handler);
    }
  }

  class FakeSubmenu extends FakeItem {
    constructor(label) {
      super(label);
      this.menu = new FakeMenu();
    }
  }

  const fakeImports = {
    ui: {
      applet: {
        TextApplet: {
          prototype: {
            _init() {
              this.set_applet_label = (label) => { this.appletLabel = label; };
              this.set_applet_tooltip = (tooltip) => { this.appletTooltip = tooltip; };
            },
          },
        },
        AppletPopupMenu: FakeMenu,
      },
      popupMenu: {
        PopupMenuManager: class {
          addMenu() {}
          removeMenu() {}
        },
        PopupMenuItem: FakeItem,
        PopupSubMenuMenuItem: FakeSubmenu,
      },
    },
    misc: {util: {spawn() {}}},
  };
  globalThis.imports = fakeImports;
  try {
    const adapter = applet.main({uuid: "codex-master@H234598"}, 0, 24, 0);
    adapter.setSnapshot({
      schema_version: 3,
      generation: 9,
      series: [{prefix: "d", display_name: "D", count: 1, running_count: 0,
        eligible_count: 1, limit_state: "ready"}],
      native_agents: [{id: "a1", label: "Native A", limit_state: "ready"}],
      dispatch_targets: ["d1", "a1"],
    });
    const dynamic = adapter.menu.items.filter((item) => ["Serien", "Native Bienen"].includes(item.label));
    assert.deepEqual(dynamic.map((item) => item.label), ["Serien", "Native Bienen"]);
    assert.equal(dynamic[0].menu.items[0].label.startsWith("D"), true);
    assert.equal(dynamic[1].menu.items[0].label.startsWith("Native A"), true);
  } finally {
    delete globalThis.imports;
  }
});

test("limited native menu items are visibly non-reactive", () => {
  class FakeMenu {
    constructor() { this.items = []; }
    addMenuItem(item) { this.items.push(item); }
    removeMenuItem(item) { this.items = this.items.filter((current) => current !== item); }
  }
  class FakeItem {
    constructor(label) { this.label = label; this.sensitive = true; }
    connect(_event, handler) { this.handler = handler; }
    setSensitive(value) { this.sensitive = value; }
    destroy() {}
  }
  class FakeSubmenu extends FakeItem {
    constructor(label) { super(label); this.menu = new FakeMenu(); }
  }
  const fakeImports = {
    ui: {
      applet: {
        TextApplet: {prototype: {_init() {
          this.set_applet_label = () => {};
          this.set_applet_tooltip = () => {};
        }}},
        AppletPopupMenu: FakeMenu,
      },
      popupMenu: {
        PopupMenuManager: class { addMenu() {} removeMenu() {} },
        PopupMenuItem: FakeItem,
        PopupSubMenuMenuItem: FakeSubmenu,
      },
    },
    misc: {util: {spawn() {}}},
  };
  globalThis.imports = fakeImports;
  try {
    const adapter = applet.main({uuid: "codex-master@H234598"}, 0, 24, 0);
    adapter.setSnapshot({schema_version: 3, generation: 10, series: [],
      native_agents: [{id: "a1", label: "Limited", limit_state: "limited"}], dispatch_targets: []});
    const submenu = adapter.menu.items.find((item) => item.label === "Native Bienen");
    assert.equal(submenu.menu.items[0].sensitive, false);
  } finally {
    delete globalThis.imports;
  }
});

test("dispatch without Cinnamon bindings is a safe no-op", () => {
  const adapter = applet.main({uuid: "codex-master@H234598"}, 0, 24, 0);
  assert.doesNotThrow(() => adapter._dispatchAgent("a1"));
});
