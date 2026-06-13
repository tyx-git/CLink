# Codegraph DataFlow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `.codegraph` as a no-build, no-network, static dark technical console that opens directly to a complete CLink runtime data-flow flowchart with drill-down views and source-level deep understanding.

**Architecture:** The implementation is a plain HTML/CSS/JavaScript app. `graph-data.js` manually curates nodes, edges, views, risk metadata, source reading paths, and deep-understanding content; `app.js` renders SVG flowcharts and detail tabs from that data; `styles.css` owns the dark console theme. A Python stdlib validator provides repeatable integrity checks without becoming a runtime dependency.

**Tech Stack:** Static HTML, CSS, vanilla JavaScript, SVG, Python 3 stdlib validation script, browser manual verification.

---

## File Structure

Create and maintain these files:

```text
.codegraph/
  index.html
  README.md
  assets/
    styles.css
    graph-data.js
    app.js
  tools/
    validate_graph_data.py
```

Responsibilities:

- `.codegraph/index.html`: Static shell only. Defines the top bar, navigation container, SVG viewport, and detail panel containers. Loads `graph-data.js` before `app.js` using classic script tags so it works under `file://`.
- `.codegraph/assets/styles.css`: Dark technical console theme, three-column layout, near-rectangular corners, node and edge visual states, tabs, search, toggles, responsive fallback.
- `.codegraph/assets/graph-data.js`: Manual curated graph data. No DOM code. Exposes `window.CLINK_GRAPH` with `meta`, `views`, `nodes`, `edges`, `groups`, `legends`, and `glossary`.
- `.codegraph/assets/app.js`: Pure rendering and interaction code. Reads `window.CLINK_GRAPH`, validates references defensively, renders navigation, SVG nodes/edges, detail tabs, search results, and toggles.
- `.codegraph/tools/validate_graph_data.py`: Optional development-time validator. Uses Python stdlib only. Loads `graph-data.js`, extracts the object assigned to `window.CLINK_GRAPH`, and checks view/node/edge references, risk tags, address-family tags, required deep content, and banned wording.
- `.codegraph/README.md`: User and maintainer guide: how to open, how to maintain graph data, how to verify after IPv4/IPv6 fixes, and how to run the optional validator.

Do not modify C++ source files for this feature.

## Implementation Rules

- Keep the runtime app dependency-free.
- Do not use `fetch()` for graph data.
- Do not use ES modules; classic scripts are more reliable from `file://`.
- Keep all visible wording neutral and professional.
- Do not add offensive procedure documentation. Risk content must stay defensive and source-understanding oriented.
- Prefer small commits after each task.
- When the plan says to run a browser manual check, open `.codegraph/index.html` directly in a browser. In this CLI environment, the developer may also use `python -m http.server` for convenience, but passing through a local server is not required for acceptance.

---

### Task 1: Add Static Shell, Theme Skeleton, and Runtime Smoke Test

**Files:**
- Create: `.codegraph/index.html`
- Create: `.codegraph/assets/styles.css`
- Create: `.codegraph/assets/graph-data.js`
- Create: `.codegraph/assets/app.js`
- Create: `.codegraph/tools/validate_graph_data.py`

- [ ] **Step 1: Write the validator smoke test file**

Create `.codegraph/tools/validate_graph_data.py` with this exact initial content:

```python
#!/usr/bin/env python3
"""Validate the static CLink codegraph data and shell.

This script uses only Python stdlib. It is a development-time check; the
.codegraph UI itself must still open directly from index.html without Python.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "index.html"
GRAPH_DATA = ROOT / "assets" / "graph-data.js"
APP_JS = ROOT / "assets" / "app.js"
STYLES = ROOT / "assets" / "styles.css"
README = ROOT / "README.md"

ALLOWED_RISK_TAGS = {
    "privilege-boundary",
    "injection-boundary",
    "untrusted-input",
    "local-listener",
    "remote-listener",
    "config-sensitive",
    "credential-sensitive",
    "platform-specific",
    "observability-critical",
}

ALLOWED_ADDRESS_FAMILIES = {"IPv4", "IPv6", "Dual-stack"}
BANNED_TERMS = ["".join(chr(codepoint) for codepoint in [23567, 30333])]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: Path) -> str:
    if not path.exists():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def extract_graph_data() -> dict:
    text = read(GRAPH_DATA)
    match = re.search(
        r"window\.CLINK_GRAPH\s*=\s*(\{.*\})\s*;\s*$",
        text,
        flags=re.DOTALL,
    )
    if not match:
        fail("graph-data.js must assign one object to window.CLINK_GRAPH")
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        fail(f"graph-data.js object must be valid JSON-compatible syntax: {exc}")


def assert_no_banned_terms(path: Path) -> None:
    text = read(path)
    for term in BANNED_TERMS:
        if term in text:
            fail(f"banned term {term!r} appears in {path.relative_to(ROOT)}")


def validate_shell_files() -> None:
    for path in [INDEX, GRAPH_DATA, APP_JS, STYLES]:
        assert_no_banned_terms(path)
    index = read(INDEX)
    if "assets/graph-data.js" not in index:
        fail("index.html must load assets/graph-data.js")
    if "assets/app.js" not in index:
        fail("index.html must load assets/app.js")
    if "assets/styles.css" not in index:
        fail("index.html must load assets/styles.css")


def validate_graph_shape(data: dict) -> None:
    for key in ["meta", "views", "nodes", "edges", "groups", "legends", "glossary"]:
        if key not in data:
            fail(f"CLINK_GRAPH missing top-level key: {key}")
    if not isinstance(data["views"], list):
        fail("views must be a list")
    if not isinstance(data["nodes"], dict):
        fail("nodes must be an object")
    if not isinstance(data["edges"], dict):
        fail("edges must be an object")


def main() -> int:
    validate_shell_files()
    data = extract_graph_data()
    validate_graph_shape(data)
    print("PASS: codegraph shell and data shape are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Run the validator and verify it fails before shell files exist**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected output includes:

```text
FAIL: missing required file: index.html
```

If `.codegraph/index.html` already exists from a previous attempt, remove the partial attempt before continuing or verify the failure references the next missing required file.

- [ ] **Step 3: Create the static HTML shell**

Create `.codegraph/index.html` with this exact content:

```html
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CLink DataFlow CodeGraph</title>
  <link rel="stylesheet" href="assets/styles.css">
</head>
<body>
  <div class="app-shell" data-app-shell>
    <header class="topbar" aria-label="CLink DataFlow toolbar">
      <div class="brand-block">
        <div class="brand-mark" aria-hidden="true">CL</div>
        <div>
          <h1>CLink DataFlow</h1>
          <p id="current-view-label">Home: Global Data Flow</p>
        </div>
      </div>
      <label class="search-box" for="graph-search">
        <span>Search</span>
        <input id="graph-search" type="search" placeholder="SessionManager, IPv6, zero-copy" autocomplete="off">
      </label>
      <div class="toggle-row" aria-label="Display toggles">
        <label><input type="checkbox" data-toggle="control" checked> Control</label>
        <label><input type="checkbox" data-toggle="data" checked> Data</label>
        <label><input type="checkbox" data-toggle="risk" checked> Risk</label>
        <label><input type="checkbox" data-toggle="source" checked> Source</label>
        <label><input type="checkbox" data-toggle="ipv4" checked> IPv4</label>
        <label><input type="checkbox" data-toggle="ipv6" checked> IPv6</label>
      </div>
    </header>

    <aside class="side-nav" aria-label="CodeGraph views">
      <div class="panel-heading">Views</div>
      <nav id="view-nav"></nav>
    </aside>

    <main class="graph-stage" aria-label="Data-flow canvas">
      <div class="stage-header">
        <div>
          <h2 id="view-title">Home: Global Data Flow</h2>
          <p id="view-description">Loading graph data...</p>
        </div>
        <div id="view-badges" class="badge-row"></div>
      </div>
      <div id="search-results" class="search-results" hidden></div>
      <svg id="graph-svg" role="img" aria-label="CLink data-flow graph" viewBox="0 0 1280 760"></svg>
    </main>

    <aside class="detail-panel" aria-label="Selected item details">
      <div class="detail-heading">
        <p class="eyebrow" id="detail-kind">Overview</p>
        <h2 id="detail-title">CLink DataFlow</h2>
      </div>
      <div class="tab-row" role="tablist" aria-label="Detail sections">
        <button class="tab-button is-active" type="button" data-tab="overview">Overview</button>
        <button class="tab-button" type="button" data-tab="deep">Deep Understanding</button>
        <button class="tab-button" type="button" data-tab="source">Source</button>
        <button class="tab-button" type="button" data-tab="risk">Risk</button>
        <button class="tab-button" type="button" data-tab="debug">Debug</button>
      </div>
      <div id="detail-content" class="detail-content"></div>
    </aside>
  </div>

  <script src="assets/graph-data.js"></script>
  <script src="assets/app.js"></script>
</body>
</html>
```

- [ ] **Step 4: Create the initial dark theme skeleton**

Create `.codegraph/assets/styles.css` with this exact content:

```css
:root {
  color-scheme: dark;
  --bg: #080d16;
  --panel: #0f1724;
  --panel-2: #121c2c;
  --panel-3: #172235;
  --text: #dce7f7;
  --muted: #8ea0b8;
  --faint: #53657d;
  --border: #263449;
  --border-strong: #3a4a62;
  --control: #a78bfa;
  --data: #38bdf8;
  --risk: #f97316;
  --observe: #34d399;
  --config: #94a3b8;
  --selected: #facc15;
  --shadow: rgba(0, 0, 0, 0.35);
  --radius: 5px;
  --radius-sm: 3px;
}

* { box-sizing: border-box; }

html, body { margin: 0; min-height: 100%; }

body {
  background: radial-gradient(circle at top left, #111d32 0, var(--bg) 38rem);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

button, input { font: inherit; }

.app-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 240px minmax(520px, 1fr) 360px;
  grid-template-rows: 76px minmax(0, 1fr);
  grid-template-areas:
    "topbar topbar topbar"
    "nav stage detail";
}

.topbar {
  grid-area: topbar;
  display: grid;
  grid-template-columns: minmax(260px, 1fr) 360px auto;
  align-items: center;
  gap: 18px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  background: rgba(10, 16, 27, 0.94);
  backdrop-filter: blur(12px);
}

.brand-block { display: flex; align-items: center; gap: 12px; }
.brand-mark {
  display: grid;
  place-items: center;
  width: 38px;
  height: 38px;
  border: 1px solid #2563eb;
  border-radius: var(--radius);
  color: #bfdbfe;
  background: #102243;
  font-weight: 800;
  letter-spacing: 0.04em;
}

h1, h2, p { margin: 0; }
.topbar h1 { font-size: 18px; line-height: 1.1; }
.topbar p, .eyebrow { color: var(--muted); font-size: 12px; }

.search-box {
  display: grid;
  grid-template-columns: auto 1fr;
  align-items: center;
  gap: 8px;
  color: var(--muted);
  font-size: 12px;
}

.search-box input {
  width: 100%;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: #0a1220;
  color: var(--text);
  padding: 8px 10px;
  outline: none;
}
.search-box input:focus { border-color: var(--data); }

.toggle-row { display: flex; gap: 10px; flex-wrap: wrap; justify-content: flex-end; font-size: 12px; color: var(--muted); }
.toggle-row label { display: flex; align-items: center; gap: 4px; }

.side-nav, .detail-panel, .graph-stage {
  min-height: 0;
  border-color: var(--border);
}

.side-nav {
  grid-area: nav;
  padding: 16px;
  border-right: 1px solid var(--border);
  background: rgba(9, 15, 26, 0.86);
  overflow: auto;
}

.panel-heading {
  margin-bottom: 10px;
  color: var(--faint);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}

.nav-button {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin: 0 0 6px;
  padding: 9px 10px;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--muted);
  text-align: left;
  cursor: pointer;
}
.nav-button:hover { background: #111a2a; color: var(--text); }
.nav-button.is-active { border-color: #315173; background: #132239; color: #e0f2fe; }

.graph-stage {
  grid-area: stage;
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr);
  gap: 12px;
  padding: 16px;
  overflow: hidden;
}

.stage-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: rgba(15, 23, 36, 0.78);
}
.stage-header h2 { font-size: 18px; }
.stage-header p { margin-top: 5px; color: var(--muted); font-size: 13px; line-height: 1.45; }

.badge-row { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
.badge {
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  padding: 3px 6px;
  color: var(--muted);
  font-size: 11px;
}

.search-results {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: #0c1422;
  padding: 10px;
}
.search-result-button {
  display: block;
  width: 100%;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text);
  text-align: left;
  padding: 7px;
  cursor: pointer;
}
.search-result-button:hover { background: #162238; }

#graph-svg {
  width: 100%;
  height: 100%;
  min-height: 520px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background:
    linear-gradient(rgba(148, 163, 184, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148, 163, 184, 0.05) 1px, transparent 1px),
    rgba(8, 13, 22, 0.9);
  background-size: 32px 32px;
  box-shadow: 0 16px 42px var(--shadow);
}

.detail-panel {
  grid-area: detail;
  border-left: 1px solid var(--border);
  background: rgba(9, 15, 26, 0.94);
  overflow: auto;
  padding: 16px;
}
.detail-heading { margin-bottom: 12px; }
.detail-heading h2 { margin-top: 4px; font-size: 20px; }

.tab-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 4px; margin-bottom: 12px; }
.tab-button {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: #0d1626;
  color: var(--muted);
  font-size: 11px;
  padding: 7px 4px;
  cursor: pointer;
}
.tab-button.is-active { border-color: var(--data); color: #dff6ff; background: #10243a; }

.detail-content {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: rgba(15, 23, 36, 0.7);
  padding: 14px;
  color: var(--text);
  font-size: 13px;
  line-height: 1.55;
}
.detail-content h3 { margin: 0 0 8px; font-size: 15px; }
.detail-content h4 { margin: 14px 0 6px; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }
.detail-content ul { margin: 6px 0 0; padding-left: 18px; }
.detail-content code { color: #bfdbfe; }

.graph-node rect { stroke-width: 1.4; rx: 5; ry: 5; cursor: pointer; }
.graph-node text { pointer-events: none; fill: var(--text); font-size: 13px; }
.graph-node .node-subtitle { fill: var(--muted); font-size: 10px; }
.graph-node.is-selected rect { stroke: var(--selected); stroke-width: 2.4; }
.graph-node.is-dimmed { opacity: 0.28; }

.graph-edge path { fill: none; stroke-width: 2; cursor: pointer; }
.graph-edge text { fill: var(--muted); font-size: 11px; pointer-events: none; }
.graph-edge.is-selected path { stroke: var(--selected); stroke-width: 3; }
.graph-edge.is-dimmed { opacity: 0.22; }

.kind-control rect { fill: #201a3a; stroke: var(--control); }
.kind-data rect { fill: #0f283a; stroke: var(--data); }
.kind-risk rect { fill: #2d1d12; stroke: var(--risk); }
.kind-observe rect { fill: #10291f; stroke: var(--observe); }
.kind-config rect { fill: #182232; stroke: var(--config); }

.edge-control path { stroke: var(--control); }
.edge-data path { stroke: var(--data); }
.edge-risk path { stroke: var(--risk); }
.edge-observe path { stroke: var(--observe); }
.edge-config path { stroke: var(--config); }

@media (max-width: 1100px) {
  .app-shell {
    grid-template-columns: 220px minmax(0, 1fr);
    grid-template-rows: auto minmax(480px, 1fr) auto;
    grid-template-areas:
      "topbar topbar"
      "nav stage"
      "detail detail";
  }
  .topbar { grid-template-columns: 1fr; }
  .toggle-row { justify-content: flex-start; }
}
```

- [ ] **Step 5: Create initial graph data with a home view placeholder object**

Create `.codegraph/assets/graph-data.js` with this exact content:

```js
window.CLINK_GRAPH = {
  "meta": {
    "title": "CLink DataFlow",
    "version": "post-dual-stack-target",
    "sourceRepo": "CLink",
    "generatedBy": "manual-curation",
    "defaultViewId": "home"
  },
  "views": [
    {
      "id": "home",
      "title": "Home: Global Data Flow",
      "description": "Complete runtime data transmission flow from local control to daemon data-plane paths and remote daemon forwarding.",
      "type": "flow",
      "nodes": [],
      "edges": [],
      "groups": [],
      "badges": ["Control plane", "Data plane", "Dual-stack target", "Defensive risk view"],
      "deepDive": {
        "purpose": "Show the entire project data path before drilling into focused implementation views.",
        "runtimeFlow": [],
        "moduleComposition": [],
        "sourceReadingPath": [],
        "importantStates": [],
        "edgeCases": [],
        "riskBoundaries": [],
        "debuggingChecklist": [],
        "dualStackReview": [],
        "testsToRead": []
      }
    }
  ],
  "nodes": {},
  "edges": {},
  "groups": {},
  "legends": {
    "colors": [
      {"label": "Control plane", "color": "purple"},
      {"label": "Network data plane", "color": "blue/cyan"},
      {"label": "Sensitive boundary", "color": "orange"},
      {"label": "Observability", "color": "green"},
      {"label": "Configuration or platform dependency", "color": "gray"}
    ]
  },
  "glossary": {
    "control-plane": "Commands and status exchanged between CLI and daemon.",
    "data-plane": "Runtime traffic forwarded through SOCKS, process injection, VIF, sessions, and transport adapters.",
    "dual-stack": "Target architecture where IPv4 and IPv6 are first-class address-family dimensions."
  }
};
```

- [ ] **Step 6: Create initial app bootstrap code**

Create `.codegraph/assets/app.js` with this exact content:

```js
(function () {
  "use strict";

  const graph = window.CLINK_GRAPH;

  function byId(id) {
    return document.getElementById(id);
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function renderList(items) {
    if (!items || items.length === 0) {
      return "<p class=\"muted\">No entries recorded for this section.</p>";
    }
    return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
  }

  function renderBadges(items) {
    const target = byId("view-badges");
    target.innerHTML = (items || []).map((item) => `<span class=\"badge\">${escapeHtml(item)}</span>`).join("");
  }

  function renderNavigation() {
    const nav = byId("view-nav");
    nav.innerHTML = graph.views.map((view) => {
      const active = view.id === graph.meta.defaultViewId ? " is-active" : "";
      return `<button class=\"nav-button${active}\" type=\"button\" data-view-id=\"${escapeHtml(view.id)}\"><span>${escapeHtml(view.title)}</span></button>`;
    }).join("");
  }

  function renderView(viewId) {
    const view = graph.views.find((candidate) => candidate.id === viewId) || graph.views[0];
    byId("current-view-label").textContent = view.title;
    byId("view-title").textContent = view.title;
    byId("view-description").textContent = view.description;
    renderBadges(view.badges);
    renderHomeSummary(view);
    document.querySelectorAll(".nav-button").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.viewId === view.id);
    });
  }

  function renderHomeSummary(view) {
    const svg = byId("graph-svg");
    svg.innerHTML = `
      <text x="44" y="72" fill="#dce7f7" font-size="24" font-weight="700">${escapeHtml(view.title)}</text>
      <text x="44" y="104" fill="#8ea0b8" font-size="14">Graph renderer will draw curated nodes and edges in the next task.</text>
      <rect x="44" y="140" width="360" height="92" rx="5" ry="5" fill="#10243a" stroke="#38bdf8"></rect>
      <text x="64" y="176" fill="#dce7f7" font-size="16">Static shell loaded</text>
      <text x="64" y="204" fill="#8ea0b8" font-size="13">No server, no build step, no network dependency.</text>
    `;
    byId("detail-kind").textContent = "View";
    byId("detail-title").textContent = view.title;
    byId("detail-content").innerHTML = `
      <h3>Overview</h3>
      <p>${escapeHtml(view.description)}</p>
      <h4>Deep Understanding</h4>
      ${renderList([view.deepDive.purpose])}
    `;
  }

  function bindEvents() {
    byId("view-nav").addEventListener("click", (event) => {
      const button = event.target.closest("[data-view-id]");
      if (button) renderView(button.dataset.viewId);
    });
  }

  function init() {
    if (!graph) {
      throw new Error("window.CLINK_GRAPH is not loaded");
    }
    renderNavigation();
    renderView(graph.meta.defaultViewId);
    bindEvents();
  }

  init();
})();
```

- [ ] **Step 7: Run the validator and verify the shell passes**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected output:

```text
PASS: codegraph shell and data shape are valid
```

- [ ] **Step 8: Manually open the shell**

Open:

```text
.codegraph/index.html
```

Expected:

- A dark three-column application loads.
- Left navigation contains `Home: Global Data Flow`.
- Central SVG shows the shell-loaded message.
- Right panel shows an Overview and Deep Understanding section.

- [ ] **Step 9: Commit Task 1**

Run:

```bash
git add .codegraph/index.html .codegraph/assets/styles.css .codegraph/assets/graph-data.js .codegraph/assets/app.js .codegraph/tools/validate_graph_data.py
git commit -m "feat: scaffold static codegraph shell"
```

Expected:

```text
[branch <hash>] feat: scaffold static codegraph shell
```

---

### Task 2: Add Complete Home Data Flow Graph Data and Stronger Validation

**Files:**
- Modify: `.codegraph/assets/graph-data.js`
- Modify: `.codegraph/tools/validate_graph_data.py`

- [ ] **Step 1: Extend the validator to check references, tags, and deep content**

Replace `.codegraph/tools/validate_graph_data.py` with this complete content:

```python
#!/usr/bin/env python3
"""Validate the static CLink codegraph data and shell."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "index.html"
GRAPH_DATA = ROOT / "assets" / "graph-data.js"
APP_JS = ROOT / "assets" / "app.js"
STYLES = ROOT / "assets" / "styles.css"
README = ROOT / "README.md"

ALLOWED_RISK_TAGS = {
    "privilege-boundary",
    "injection-boundary",
    "untrusted-input",
    "local-listener",
    "remote-listener",
    "config-sensitive",
    "credential-sensitive",
    "platform-specific",
    "observability-critical",
}
ALLOWED_ADDRESS_FAMILIES = {"IPv4", "IPv6", "Dual-stack"}
ALLOWED_KINDS = {"control", "data", "risk", "observe", "config"}
BANNED_TERMS = ["".join(chr(codepoint) for codepoint in [23567, 30333])]
REQUIRED_NODE_DETAIL_KEYS = {
    "runtimeResponsibilities",
    "lifecycle",
    "dataStructures",
    "threadingModel",
    "collaborations",
    "stateTransitions",
    "errorPaths",
    "platformNotes",
    "dualStackNotes",
    "securityBoundaries",
    "performanceNotes",
    "sourceReadingOrder",
    "relatedTests",
    "currentImplementationNotes",
    "postFixReviewPoints",
}
REQUIRED_VIEW_DEEP_KEYS = {
    "purpose",
    "runtimeFlow",
    "moduleComposition",
    "sourceReadingPath",
    "importantStates",
    "edgeCases",
    "riskBoundaries",
    "debuggingChecklist",
    "dualStackReview",
    "testsToRead",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def warn(message: str) -> None:
    print(f"WARN: {message}", file=sys.stderr)


def read(path: Path) -> str:
    if not path.exists():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def extract_graph_data() -> dict:
    text = read(GRAPH_DATA)
    match = re.search(
        r"window\.CLINK_GRAPH\s*=\s*(\{.*\})\s*;\s*$",
        text,
        flags=re.DOTALL,
    )
    if not match:
        fail("graph-data.js must assign one object to window.CLINK_GRAPH")
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        fail(f"graph-data.js object must be valid JSON-compatible syntax: {exc}")


def assert_no_banned_terms(path: Path) -> None:
    text = read(path)
    for term in BANNED_TERMS:
        if term in text:
            fail(f"banned term {term!r} appears in {path.relative_to(ROOT)}")


def validate_shell_files() -> None:
    for path in [INDEX, GRAPH_DATA, APP_JS, STYLES]:
        assert_no_banned_terms(path)
    index = read(INDEX)
    for expected in ["assets/graph-data.js", "assets/app.js", "assets/styles.css"]:
        if expected not in index:
            fail(f"index.html must load {expected}")


def require_keys(obj: dict, keys: set[str], context: str) -> None:
    missing = sorted(keys - set(obj))
    if missing:
        fail(f"{context} missing keys: {', '.join(missing)}")


def validate_risk(risk: dict | None, context: str) -> None:
    if not risk:
        return
    for tag in risk.get("tags", []):
        if tag not in ALLOWED_RISK_TAGS:
            fail(f"{context} has invalid risk tag: {tag}")


def validate_address_families(values: list[str], context: str) -> None:
    for value in values:
        if value not in ALLOWED_ADDRESS_FAMILIES:
            fail(f"{context} has invalid address family: {value}")


def validate_graph_shape(data: dict) -> None:
    for key in ["meta", "views", "nodes", "edges", "groups", "legends", "glossary"]:
        if key not in data:
            fail(f"CLINK_GRAPH missing top-level key: {key}")
    if not isinstance(data["views"], list):
        fail("views must be a list")
    if not isinstance(data["nodes"], dict):
        fail("nodes must be an object")
    if not isinstance(data["edges"], dict):
        fail("edges must be an object")


def validate_views(data: dict) -> None:
    view_ids = {view.get("id") for view in data["views"]}
    default_view_id = data["meta"].get("defaultViewId")
    if default_view_id not in view_ids:
        fail("meta.defaultViewId must reference an existing view")
    if default_view_id != "home":
        fail("home must be the default view")

    node_ids = set(data["nodes"])
    edge_ids = set(data["edges"])
    for view in data["views"]:
        context = f"view {view.get('id')}"
        require_keys(view, {"id", "title", "description", "nodes", "edges", "groups", "deepDive"}, context)
        require_keys(view["deepDive"], REQUIRED_VIEW_DEEP_KEYS, f"{context}.deepDive")
        for node_id in view.get("nodes", []):
            if node_id not in node_ids:
                fail(f"{context} references missing node {node_id}")
        for edge_id in view.get("edges", []):
            if edge_id not in edge_ids:
                fail(f"{context} references missing edge {edge_id}")


def validate_nodes(data: dict) -> None:
    for node_id, node in data["nodes"].items():
        context = f"node {node_id}"
        require_keys(
            node,
            {"id", "label", "kind", "layer", "position", "summary", "inputs", "outputs", "sourceFiles", "tests", "addressFamilies", "risk", "implementationStatus", "details"},
            context,
        )
        if node["id"] != node_id:
            fail(f"{context} id field must equal object key")
        if node["kind"] not in ALLOWED_KINDS:
            fail(f"{context} has invalid kind: {node['kind']}")
        require_keys(node["position"], {"x", "y"}, f"{context}.position")
        require_keys(node["details"], {"basic", "deep"}, f"{context}.details")
        require_keys(node["details"]["basic"], {"role", "receives", "emits", "whyItExists"}, f"{context}.details.basic")
        require_keys(node["details"]["deep"], REQUIRED_NODE_DETAIL_KEYS, f"{context}.details.deep")
        validate_risk(node.get("risk"), context)
        validate_address_families(node.get("addressFamilies", []), context)


def validate_edges(data: dict) -> None:
    node_ids = set(data["nodes"])
    for edge_id, edge in data["edges"].items():
        context = f"edge {edge_id}"
        require_keys(
            edge,
            {"id", "from", "to", "label", "kind", "dataType", "addressFamilies", "sourceFiles", "notes", "risk", "implementationStatus"},
            context,
        )
        if edge["id"] != edge_id:
            fail(f"{context} id field must equal object key")
        if edge["from"] not in node_ids:
            fail(f"{context}.from references missing node {edge['from']}")
        if edge["to"] not in node_ids:
            fail(f"{context}.to references missing node {edge['to']}")
        if edge["kind"] not in ALLOWED_KINDS:
            fail(f"{context} has invalid kind: {edge['kind']}")
        validate_risk(edge.get("risk"), context)
        validate_address_families(edge.get("addressFamilies", []), context)


def validate_home(data: dict) -> None:
    home = next((view for view in data["views"] if view.get("id") == "home"), None)
    if home is None:
        fail("home view is required")
    if len(home.get("nodes", [])) < 12:
        fail("home view must include at least 12 nodes for the full project flow")
    required_edges = {
        "cli-to-ipc",
        "ipc-to-local-daemon",
        "local-session-to-transport",
        "transport-to-remote-listener",
        "socks-to-process-manager",
        "hook-to-process-manager",
        "vif-to-session-manager",
        "tls-to-buffer-pool",
    }
    missing = sorted(required_edges - set(home.get("edges", [])))
    if missing:
        fail(f"home view missing required edges: {', '.join(missing)}")


def main() -> int:
    validate_shell_files()
    data = extract_graph_data()
    validate_graph_shape(data)
    validate_views(data)
    validate_nodes(data)
    validate_edges(data)
    validate_home(data)
    print("PASS: codegraph shell and data are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Run the validator and verify it fails against the placeholder data**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected output includes:

```text
FAIL: home view must include at least 12 nodes for the full project flow
```

- [ ] **Step 3: Replace `graph-data.js` with complete home graph data**

Replace `.codegraph/assets/graph-data.js` with the complete home graph object below. This task intentionally seeds the home view first; later tasks add the focused detail views while preserving these node and edge IDs.

```js
window.CLINK_GRAPH = {
  "meta": {
    "title": "CLink DataFlow",
    "version": "post-dual-stack-target",
    "sourceRepo": "CLink",
    "generatedBy": "manual-curation",
    "defaultViewId": "home"
  },
  "views": [
    {
      "id": "home",
      "title": "Home: Global Data Flow",
      "description": "Complete runtime data transmission flow from local control to daemon data-plane paths and remote daemon forwarding.",
      "type": "flow",
      "nodes": [
        "user-script",
        "clink-cli",
        "ipc-client",
        "ipc-server",
        "local-daemon",
        "local-application",
        "socks-server",
        "target-process",
        "hook-dll",
        "process-manager",
        "os-network-stack",
        "virtual-interface",
        "session-manager-local",
        "tls-transport",
        "buffer-pool",
        "remote-listener",
        "remote-auth-policy",
        "session-manager-remote",
        "remote-forwarding",
        "observability"
      ],
      "edges": [
        "user-to-cli",
        "cli-to-ipc",
        "ipc-client-to-server",
        "ipc-to-local-daemon",
        "local-app-to-socks",
        "socks-to-process-manager",
        "target-process-to-hook",
        "hook-to-process-manager",
        "os-to-vif",
        "vif-to-session-manager",
        "process-manager-to-session",
        "local-session-to-transport",
        "tls-to-buffer-pool",
        "transport-to-remote-listener",
        "remote-listener-to-auth",
        "auth-to-remote-session",
        "remote-session-to-forwarding",
        "daemon-to-observability"
      ],
      "groups": ["local-side", "transport-side", "remote-side", "observability-side"],
      "badges": ["Control plane", "Data plane", "Dual-stack target", "Defensive risk view"],
      "deepDive": {
        "purpose": "Show the entire project data path before drilling into focused implementation views.",
        "runtimeFlow": [
          "Control commands originate from a user or script and travel through clink CLI into the local daemon over IPC.",
          "Data-plane traffic can enter through SOCKS, Windows process hook IPC, or the virtual interface path.",
          "Local data-plane entries converge at ProcessManager or SessionManager before moving through TCP/TLS transport.",
          "The remote daemon receives the transport session, evaluates authentication and policy, then forwards or observes the session path."
        ],
        "moduleComposition": [
          "Local control: clink CLI, IPC client, IPC server, local daemon Application.",
          "Local data entries: SOCKS server, ProcessManager, process injection, VirtualInterface.",
          "Transport and buffering: SessionManager, TLS transport, BufferPool.",
          "Remote path: Transport listener, Auth/ACL/Policy, remote SessionManager, forwarding, observability."
        ],
        "sourceReadingPath": [
          "src/client/main.cpp",
          "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md",
          "src/server/core/application/application.cpp",
          "src/server/core/network/session_manager.hpp",
          "src/server/core/network/tls_adapter.hpp",
          "src/server/modules/process_manager/process_manager.hpp",
          "src/server/modules/socks_server/socks_server.hpp",
          "src/server/core/network/virtual_interface.hpp"
        ],
        "importantStates": [
          "Disconnected, connecting, connected, disconnecting session states.",
          "Process manager enabled or disabled by runtime configuration.",
          "Virtual interface enabled or disabled by environment and platform privileges.",
          "Post-fix dual-stack transport should preserve address-family context."
        ],
        "edgeCases": [
          "Local daemon not running when CLI sends IPC command.",
          "Transport connection starts but TLS handshake fails.",
          "SOCKS listener is reachable from an unintended local interface.",
          "IPv4 and IPv6 candidates resolve differently after dual-stack fixes."
        ],
        "riskBoundaries": [
          "IPC command boundary between CLI and daemon.",
          "Local listener boundary for SOCKS.",
          "Windows process injection and hook IPC boundary.",
          "VIF privilege and packet boundary.",
          "Remote listener and authentication boundary."
        ],
        "debuggingChecklist": [
          "Check CLI status output for structured status and reason fields.",
          "Check daemon logs for transport and session state transitions.",
          "Check process manager state when SOCKS or injection paths are unavailable.",
          "Check telemetry sampling when data-plane spans appear missing."
        ],
        "dualStackReview": [
          "Recheck TCP listen/connect address resolution after IPv4/IPv6 fixes.",
          "Recheck SOCKS listener address-family behavior.",
          "Recheck VIF packet labeling for IPv4 and IPv6.",
          "Recheck logs and status payloads for address-family visibility."
        ],
        "testsToRead": [
          "tests/network/tcp_framing_test.cpp",
          "tests/network/tls_adapter_test.cpp",
          "tests/network/zero_copy_test.cpp",
          "tests/server/socks_server_test.cpp",
          "tests/server/ipc_proxy_test.cpp"
        ]
      }
    }
  ],
  "nodes": {
    "user-script": {
      "id": "user-script",
      "label": "User / Script",
      "kind": "control",
      "layer": "control-plane",
      "position": {"x": 60, "y": 80},
      "summary": "Human operator or automation that invokes clink commands.",
      "inputs": ["operator intent", "shell command", "configuration path"],
      "outputs": ["clink command line"],
      "sourceFiles": ["README.md"],
      "tests": [],
      "addressFamilies": [],
      "risk": {"level": "low", "tags": [], "explanation": "Command input must map to structured daemon control requests."},
      "implementationStatus": {"current": "stable-current", "target": "stable-current", "confidence": "high", "note": "Documented usage flow."},
      "details": {
        "basic": {"role": "Starts control actions such as connect, status, and disconnect.", "receives": ["User intent"], "emits": ["Command line invocation"], "whyItExists": "CLink exposes local control through a CLI rather than direct remote session handling."},
        "deep": {"runtimeResponsibilities": ["Provides command arguments and environment context."], "lifecycle": ["Invoke command", "wait for CLI result", "inspect exit code and rendered status"], "dataStructures": ["Shell arguments", "environment variables"], "threadingModel": ["Outside process runtime."], "collaborations": ["clink CLI"], "stateTransitions": ["No internal project state."], "errorPaths": ["Invalid command", "daemon unavailable", "configuration path invalid"], "platformNotes": ["Windows and Linux shells differ, but control-plane contract is shared."], "dualStackNotes": ["IPv4 and IPv6 target values enter through CLI/config parameters."], "securityBoundaries": ["Shell input boundary"], "performanceNotes": ["No data-plane payload work occurs here."], "sourceReadingOrder": ["README.md", "src/client/main.cpp"], "relatedTests": [], "currentImplementationNotes": ["README documents CLI controlling local daemon."], "postFixReviewPoints": ["Confirm dual-stack CLI examples after bug fixes land."]}
      }
    },
    "clink-cli": {
      "id": "clink-cli",
      "label": "clink CLI",
      "kind": "control",
      "layer": "control-plane",
      "position": {"x": 230, "y": 80},
      "summary": "Local command-line controller that sends structured IPC requests to the daemon.",
      "inputs": ["command line", "config/env", "IPC address"],
      "outputs": ["IPC command envelope", "rendered status", "exit code"],
      "sourceFiles": ["src/client/main.cpp", "src/client/core/application/application.cpp"],
      "tests": ["tests/application_connect_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "low", "tags": ["config-sensitive"], "explanation": "CLI parameters influence daemon transport target and control behavior."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Dual-stack argument behavior should be reviewed after transport fixes."},
      "details": {
        "basic": {"role": "Parses user commands and sends them to the local daemon.", "receives": ["connect/status/disconnect command", "config path", "transport target"], "emits": ["framed IPC request", "human-readable output", "exit code"], "whyItExists": "It keeps control interaction separate from the long-running daemon and data-plane work."},
        "deep": {"runtimeResponsibilities": ["Resolve IPC address", "Parse commands", "Send command payload", "Render structured responses"], "lifecycle": ["process start", "argument parse", "IPC request", "response render", "exit"], "dataStructures": ["control-plane JSON envelope", "status payload", "exit-code contract"], "threadingModel": ["Short-lived command process."], "collaborations": ["IPC client", "control-plane schema", "local daemon IPC server"], "stateTransitions": ["CLI process state only; daemon owns session state."], "errorPaths": ["service_not_running", "unknown command", "IPC connection failure"], "platformNotes": ["Default IPC pipe path differs across Windows and Linux."], "dualStackNotes": ["Target IP/host values should preserve IPv4 or IPv6 intent into daemon connect handling."], "securityBoundaries": ["Local control boundary", "configuration input boundary"], "performanceNotes": ["Not on the data-plane hot path."], "sourceReadingOrder": ["src/client/main.cpp", "src/client/core/application/application.cpp", "src/share/include/clink/protocol/control_plane.hpp"], "relatedTests": ["tests/application_connect_test.cpp"], "currentImplementationNotes": ["CLI consumes structured control-plane responses."], "postFixReviewPoints": ["Confirm IPv6 literal formatting and status rendering after dual-stack fixes."]}
      }
    },
    "ipc-client": {
      "id": "ipc-client",
      "label": "IPC Client",
      "kind": "control",
      "layer": "control-plane",
      "position": {"x": 420, "y": 80},
      "summary": "Client-side local IPC endpoint for framed command messages.",
      "inputs": ["command payload"],
      "outputs": ["framed IPC bytes"],
      "sourceFiles": ["src/share/core/ipc/ipc.hpp", "src/share/core/ipc/ipc_linux.cpp", "src/share/core/ipc/ipc_win.cpp", "src/share/include/clink/protocol/ipc_wire.hpp"],
      "tests": ["tests/ipc_linux_test.cpp"],
      "addressFamilies": [],
      "risk": {"level": "medium", "tags": ["local-listener"], "explanation": "IPC is local but controls daemon session state."},
      "implementationStatus": {"current": "current-source-observed", "target": "stable-current", "confidence": "medium", "note": "IPC contract is shared and should remain stable."},
      "details": {
        "basic": {"role": "Frames and sends command messages to the daemon IPC server.", "receives": ["control command"], "emits": ["IPC frame"], "whyItExists": "It decouples CLI process lifetime from daemon runtime state."},
        "deep": {"runtimeResponsibilities": ["Connect to IPC endpoint", "Serialize command", "Read response"], "lifecycle": ["create client", "connect", "send", "receive", "disconnect"], "dataStructures": ["ipc::Message", "IPC wire frame", "JSON envelope"], "threadingModel": ["Synchronous CLI-facing request/response path."], "collaborations": ["IPC server", "control-plane schema"], "stateTransitions": ["Disconnected", "connected", "response received"], "errorPaths": ["endpoint missing", "framing error", "response parse error"], "platformNotes": ["Unix socket on Linux; named pipe path on Windows."], "dualStackNotes": ["No network address family here; commands may carry transport targets."], "securityBoundaries": ["Local IPC boundary"], "performanceNotes": ["Low-volume control path."], "sourceReadingOrder": ["src/share/core/ipc/ipc.hpp", "src/share/include/clink/protocol/ipc_wire.hpp", "src/share/core/ipc/ipc_linux.cpp", "src/share/core/ipc/ipc_win.cpp"], "relatedTests": ["tests/ipc_linux_test.cpp"], "currentImplementationNotes": ["IPC helpers are shared across roles."], "postFixReviewPoints": ["Confirm status payload can represent dual-stack diagnostics."]}
      }
    },
    "ipc-server": {
      "id": "ipc-server",
      "label": "Daemon IPC Server",
      "kind": "control",
      "layer": "control-plane",
      "position": {"x": 610, "y": 80},
      "summary": "Daemon-side IPC listener that dispatches control commands.",
      "inputs": ["framed IPC request"],
      "outputs": ["Application command dispatch", "structured IPC response"],
      "sourceFiles": ["src/server/core/application/application.cpp", "src/share/core/ipc/ipc_message_utils.hpp"],
      "tests": ["tests/ipc_linux_test.cpp"],
      "addressFamilies": [],
      "risk": {"level": "medium", "tags": ["local-listener", "observability-critical"], "explanation": "Local command input changes daemon session state and should be observable."},
      "implementationStatus": {"current": "current-source-observed", "target": "stable-current", "confidence": "medium", "note": "Control dispatch belongs to daemon Application."},
      "details": {
        "basic": {"role": "Receives local control requests and routes them to the daemon application state machine.", "receives": ["IPC command envelope"], "emits": ["structured response", "daemon action"], "whyItExists": "It provides a stable local control surface for the long-running daemon."},
        "deep": {"runtimeResponsibilities": ["Listen on configured IPC endpoint", "Parse message", "Dispatch command", "Build structured response"], "lifecycle": ["start with daemon", "serve requests", "stop during shutdown"], "dataStructures": ["ipc::Message", "control-plane envelope", "status data"], "threadingModel": ["Daemon-owned server callback path."], "collaborations": ["Application", "configuration", "logger"], "stateTransitions": ["idle", "request handling", "response sent"], "errorPaths": ["unknown command", "invalid payload", "handler exception"], "platformNotes": ["IPC backend differs by platform."], "dualStackNotes": ["Status response should expose enough diagnostics for dual-stack transport."], "securityBoundaries": ["Local control boundary"], "performanceNotes": ["Low throughput relative to data plane."], "sourceReadingOrder": ["src/server/core/application/application.cpp", "src/share/core/ipc/ipc_message_utils.hpp"], "relatedTests": ["tests/ipc_linux_test.cpp"], "currentImplementationNotes": ["Structured envelope is the control-plane contract."], "postFixReviewPoints": ["Confirm dual-stack status fields after fixes."]}
      }
    },
    "local-daemon": {
      "id": "local-daemon",
      "label": "Local clinkd daemon",
      "kind": "control",
      "layer": "daemon-runtime",
      "position": {"x": 610, "y": 220},
      "summary": "Long-running local service that owns control state, modules, and data-plane forwarding.",
      "inputs": ["IPC commands", "configuration", "module data"],
      "outputs": ["session actions", "module lifecycle", "logs/metrics"],
      "sourceFiles": ["src/server/main.cpp", "src/server/core/application/application.cpp", "src/server/core/registry.cpp"],
      "tests": ["tests/application_connect_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6", "Dual-stack"],
      "risk": {"level": "medium", "tags": ["config-sensitive", "observability-critical"], "explanation": "Daemon configuration controls local listeners, remote transport, and enabled modules."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Daemon should become dual-stack aware through transport and module paths."},
      "details": {
        "basic": {"role": "Owns session lifecycle and data-plane modules.", "receives": ["control commands", "local data streams", "configuration"], "emits": ["transport sessions", "status", "logs"], "whyItExists": "CLink separates long-running session work from short-lived CLI control."},
        "deep": {"runtimeResponsibilities": ["Load configuration", "Start IPC", "Register modules", "Start transport/session components", "Stop components cleanly"], "lifecycle": ["process start", "configuration load", "module start", "run", "shutdown"], "dataStructures": ["Configuration", "module registry", "session status", "control payloads"], "threadingModel": ["Long-running daemon with module-owned asynchronous work."], "collaborations": ["Registry", "SessionManager", "SOCKS server", "ProcessManager", "VirtualInterface", "Telemetry"], "stateTransitions": ["starting", "running", "connecting", "connected", "stopping"], "errorPaths": ["config load failure", "module start failure", "transport start failure", "shutdown during connect"], "platformNotes": ["Windows-specific VIF and injection paths are gated by platform and build settings."], "dualStackNotes": ["Transport, listeners, status, and logs should carry address-family context."], "securityBoundaries": ["Local daemon privilege boundary", "configuration boundary"], "performanceNotes": ["Coordinates hot-path modules but should avoid unnecessary payload copying."], "sourceReadingOrder": ["src/server/main.cpp", "src/server/core/application/application.cpp", "src/server/core/registry.cpp"], "relatedTests": ["tests/application_connect_test.cpp"], "currentImplementationNotes": ["Runtime knobs can disable VIF and process manager."], "postFixReviewPoints": ["Confirm daemon-level status exposes dual-stack details."]}
      }
    },
    "local-application": {
      "id": "local-application",
      "label": "Local application",
      "kind": "data",
      "layer": "data-plane",
      "position": {"x": 60, "y": 360},
      "summary": "Application that explicitly sends traffic to the local SOCKS server.",
      "inputs": ["application network intent"],
      "outputs": ["SOCKS5 TCP stream"],
      "sourceFiles": ["README.md"],
      "tests": ["tests/server/socks_server_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "medium", "tags": ["local-listener"], "explanation": "Traffic enters CLink through a local proxy listener."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "SOCKS listener address family should be reviewed after dual-stack work."},
      "details": {
        "basic": {"role": "Uses CLink through an explicit SOCKS proxy path.", "receives": ["network request"], "emits": ["SOCKS5 stream"], "whyItExists": "SOCKS provides a clear local data entry point without injecting into the process."},
        "deep": {"runtimeResponsibilities": ["Connect to SOCKS listener", "Perform SOCKS negotiation", "Send application stream"], "lifecycle": ["open connection", "negotiate", "stream", "close"], "dataStructures": ["SOCKS5 request", "TCP stream"], "threadingModel": ["Application-owned; CLink observes at listener boundary."], "collaborations": ["SOCKS server"], "stateTransitions": ["disconnected", "negotiating", "streaming", "closed"], "errorPaths": ["listener unavailable", "negotiation failure", "remote connect failure"], "platformNotes": ["Cross-platform concept; listener implementation is daemon-side."], "dualStackNotes": ["Destination may be IPv4 or IPv6; listener binding also needs review."], "securityBoundaries": ["Local listener boundary"], "performanceNotes": ["Stream enters daemon data path."], "sourceReadingOrder": ["src/server/modules/socks_server/socks_server.hpp", "src/server/modules/socks_server/socks_server.cpp"], "relatedTests": ["tests/server/socks_server_test.cpp"], "currentImplementationNotes": ["SOCKS path is distinct from injection path."], "postFixReviewPoints": ["Verify IPv6 SOCKS destination handling and listener binding."]}
      }
    },
    "socks-server": {
      "id": "socks-server",
      "label": "SOCKS Server",
      "kind": "data",
      "layer": "data-plane",
      "position": {"x": 250, "y": 360},
      "summary": "Local daemon module that accepts explicit SOCKS5 traffic.",
      "inputs": ["SOCKS5 TCP stream"],
      "outputs": ["proxy session stream"],
      "sourceFiles": ["src/server/modules/socks_server/socks_server.cpp", "src/server/modules/socks_server/socks_server.hpp"],
      "tests": ["tests/server/socks_server_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "medium", "tags": ["local-listener", "untrusted-input"], "explanation": "Accepts local network input and should clearly define listen scope."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Dual-stack listener behavior needs post-fix verification."},
      "details": {
        "basic": {"role": "Accepts SOCKS5 connections and passes normalized stream data toward the tunnel path.", "receives": ["SOCKS5 negotiation", "TCP stream"], "emits": ["proxy session data"], "whyItExists": "It offers an explicit proxy data-plane entry separate from process injection and VIF."},
        "deep": {"runtimeResponsibilities": ["Listen on configured port", "Parse SOCKS negotiation", "Create proxy session", "Hand stream to process/session path"], "lifecycle": ["module start", "listen", "accept", "session active", "session close", "module stop"], "dataStructures": ["SOCKS request", "proxy session state"], "threadingModel": ["Asynchronous network listener path."], "collaborations": ["ProcessManager", "ipc_proxy_session", "SessionManager"], "stateTransitions": ["listening", "negotiating", "forwarding", "closed"], "errorPaths": ["bind failure", "unsupported command", "session close", "transport unavailable"], "platformNotes": ["Daemon module; local backend behavior may vary by platform."], "dualStackNotes": ["Listen address and destination parsing must preserve IPv4/IPv6 semantics."], "securityBoundaries": ["Local listener", "untrusted stream input"], "performanceNotes": ["Forwarding path should avoid avoidable buffer copies."], "sourceReadingOrder": ["src/server/modules/socks_server/socks_server.hpp", "src/server/modules/socks_server/socks_server.cpp", "src/server/modules/process_manager/ipc_proxy_session.hpp"], "relatedTests": ["tests/server/socks_server_test.cpp"], "currentImplementationNotes": ["Process manager can be disabled by environment variable."], "postFixReviewPoints": ["Confirm IPv6 bind and destination handling."]}
      }
    },
    "target-process": {
      "id": "target-process",
      "label": "Target process",
      "kind": "risk",
      "layer": "process-injection",
      "position": {"x": 60, "y": 520},
      "summary": "Windows process whose network API calls can be observed by the hook path when that build option is enabled.",
      "inputs": ["process network API calls"],
      "outputs": ["socket/connect/send/recv boundary"],
      "sourceFiles": ["src/server/modules/process_inject/include/process_injector.hpp"],
      "tests": ["tests/server/dll_integration_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "high", "tags": ["injection-boundary", "privilege-boundary", "platform-specific"], "explanation": "Process injection crosses a process and privilege boundary and must be described only for defensive source understanding."},
      "implementationStatus": {"current": "windows-only", "target": "windows-only", "confidence": "medium", "note": "Enabled only when injection build/runtime path exists."},
      "details": {
        "basic": {"role": "Source process for the Windows hook-based data path.", "receives": ["application network calls"], "emits": ["hook-observed payload metadata"], "whyItExists": "This path captures network activity from a process without requiring explicit SOCKS configuration."},
        "deep": {"runtimeResponsibilities": ["Own original network API calls", "Provide process boundary crossed by hook DLL"], "lifecycle": ["process running", "hook active", "network call observed", "process exits"], "dataStructures": ["socket parameters", "payload bytes", "address metadata"], "threadingModel": ["Target process threads call hooked APIs."], "collaborations": ["Hook DLL", "HookManager", "Process IPC protocol"], "stateTransitions": ["unhooked", "hooked", "call intercepted", "payload sent"], "errorPaths": ["hook install failure", "IPC unavailable", "process exit"], "platformNotes": ["Windows-only."], "dualStackNotes": ["Hook metadata should preserve IPv4/IPv6 address information."], "securityBoundaries": ["Process boundary", "privilege boundary", "injection boundary"], "performanceNotes": ["Hook path is sensitive to per-call overhead."], "sourceReadingOrder": ["src/server/modules/process_inject/include/process_injector.hpp", "src/server/modules/process_inject/src/process_injector.cpp", "src/server/modules/process_inject/src/hook_manager.cpp"], "relatedTests": ["tests/server/dll_integration_test.cpp"], "currentImplementationNotes": ["Build gated by process injection configuration."], "postFixReviewPoints": ["Confirm IPv6 sockaddr metadata is represented in hook IPC."]}
      }
    },
    "hook-dll": {
      "id": "hook-dll",
      "label": "Hook DLL / MinHook",
      "kind": "risk",
      "layer": "process-injection",
      "position": {"x": 250, "y": 520},
      "summary": "Windows hook component that observes selected network API boundaries.",
      "inputs": ["network API call boundary"],
      "outputs": ["Hook IPC payload"],
      "sourceFiles": ["src/server/modules/process_inject/src/dll_main.cpp", "src/server/modules/process_inject/src/hook_manager.cpp", "external/minhook/README.md"],
      "tests": ["tests/server/dll_integration_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "high", "tags": ["injection-boundary", "platform-specific", "observability-critical"], "explanation": "Hooked API boundaries should be auditable and fail safely."},
      "implementationStatus": {"current": "windows-only", "target": "windows-only", "confidence": "medium", "note": "Hook internals are Windows-specific."},
      "details": {
        "basic": {"role": "Observes network API calls and forwards structured metadata through hook IPC.", "receives": ["socket API call", "payload bytes"], "emits": ["Hook IPC protocol message"], "whyItExists": "It supports the process-injection data path for applications that are not explicitly configured for SOCKS."},
        "deep": {"runtimeResponsibilities": ["Initialize DLL entry", "Install hooks", "Capture parameters", "Forward metadata to daemon IPC path"], "lifecycle": ["DLL load", "hook install", "API call observed", "hook cleanup", "DLL unload"], "dataStructures": ["hook IPC message", "captured payload", "address metadata"], "threadingModel": ["Runs inside target process call context."], "collaborations": ["HookManager", "Process IPC server", "ProcessManager"], "stateTransitions": ["loaded", "hooks installed", "observing", "unloaded"], "errorPaths": ["hook install failure", "IPC send failure", "unexpected process unload"], "platformNotes": ["Windows-only and MinHook-backed."], "dualStackNotes": ["IPv4/IPv6 metadata should survive conversion into hook IPC payloads."], "securityBoundaries": ["Injected code boundary", "IPC boundary"], "performanceNotes": ["Hot API path must avoid excessive allocation and logging."], "sourceReadingOrder": ["src/server/modules/process_inject/src/dll_main.cpp", "src/server/modules/process_inject/include/hook_manager.hpp", "src/server/modules/process_inject/src/hook_manager.cpp", "src/share/core/ipc/hook_ipc_protocol.hpp"], "relatedTests": ["tests/server/dll_integration_test.cpp"], "currentImplementationNotes": ["Hook behavior is build-gated."], "postFixReviewPoints": ["Review sockaddr handling for IPv6 in intercepted calls."]}
      }
    },
    "process-manager": {
      "id": "process-manager",
      "label": "ProcessManager",
      "kind": "data",
      "layer": "data-plane",
      "position": {"x": 450, "y": 440},
      "summary": "Daemon module that normalizes SOCKS and process-injection streams before forwarding.",
      "inputs": ["proxy session stream", "Hook IPC payload"],
      "outputs": ["session forwarding input"],
      "sourceFiles": ["src/server/modules/process_manager/process_manager.cpp", "src/server/modules/process_manager/process_manager.hpp", "src/server/modules/process_manager/ipc_proxy_session.hpp"],
      "tests": ["tests/server/ipc_proxy_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "high", "tags": ["injection-boundary", "local-listener", "observability-critical"], "explanation": "This module joins explicit proxy and hook-based data entry paths."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Input address-family metadata should be verified after dual-stack fixes."},
      "details": {
        "basic": {"role": "Collects local data-plane entries and passes normalized traffic toward SessionManager.", "receives": ["SOCKS proxy stream", "Hook IPC payload"], "emits": ["session forwarding input"], "whyItExists": "It gives multiple local data sources one routing and lifecycle boundary."},
        "deep": {"runtimeResponsibilities": ["Start or disable process manager runtime", "Coordinate SOCKS availability", "Handle IPC proxy sessions", "Forward normalized data"], "lifecycle": ["module configure", "start", "accept data source", "forward", "stop"], "dataStructures": ["process manager state", "proxy session", "hook IPC payload"], "threadingModel": ["Module-owned asynchronous sessions."], "collaborations": ["SOCKS server", "Process IPC server", "SessionManager"], "stateTransitions": ["disabled", "starting", "ready", "degraded", "stopped"], "errorPaths": ["disabled by CLINK_DISABLE_PROCESS_MANAGER", "SOCKS unavailable", "IPC proxy failure"], "platformNotes": ["Injection input is Windows-specific; SOCKS path is general daemon behavior."], "dualStackNotes": ["Should preserve source/destination address family from SOCKS and hook inputs."], "securityBoundaries": ["Local listener", "hook IPC", "module routing boundary"], "performanceNotes": ["Converges data streams before session forwarding."], "sourceReadingOrder": ["src/server/modules/process_manager/process_manager.hpp", "src/server/modules/process_manager/process_manager.cpp", "src/server/modules/process_manager/ipc_proxy_session.hpp"], "relatedTests": ["tests/server/ipc_proxy_test.cpp"], "currentImplementationNotes": ["Runtime can be disabled through environment."], "postFixReviewPoints": ["Confirm dual-stack metadata across both SOCKS and hook inputs."]}
      }
    },
    "os-network-stack": {
      "id": "os-network-stack",
      "label": "OS network stack",
      "kind": "data",
      "layer": "virtual-interface",
      "position": {"x": 60, "y": 660},
      "summary": "Operating system routing path that can send selected packets through the virtual interface.",
      "inputs": ["route-selected traffic"],
      "outputs": ["virtual NIC packet"],
      "sourceFiles": ["README.md"],
      "tests": [],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "medium", "tags": ["privilege-boundary", "platform-specific"], "explanation": "Routing selected OS traffic through VIF changes packet path and often requires elevated privileges."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Packet address-family handling should be reviewed after fixes."},
      "details": {
        "basic": {"role": "Supplies packet-level traffic to the virtual interface route.", "receives": ["system network traffic"], "emits": ["IP packet"], "whyItExists": "VIF gives CLink a packet-level data entry path beyond SOCKS and hook flows."},
        "deep": {"runtimeResponsibilities": ["Route selected traffic", "Deliver packets to virtual adapter"], "lifecycle": ["route configured", "packet emitted", "route removed"], "dataStructures": ["IPv4 packet", "IPv6 packet"], "threadingModel": ["OS network stack outside CLink process."], "collaborations": ["Wintun", "VirtualInterface"], "stateTransitions": ["route inactive", "route active", "packet delivered"], "errorPaths": ["route missing", "driver unavailable", "privilege denied"], "platformNotes": ["Windows VIF path depends on Wintun."], "dualStackNotes": ["Both IPv4 and IPv6 packet families should be represented distinctly in packet labels."], "securityBoundaries": ["Privilege boundary", "packet routing boundary"], "performanceNotes": ["Packet-level path can be higher volume than control plane."], "sourceReadingOrder": ["src/server/core/network/virtual_interface.hpp", "src/share/core/network/packet.hpp"], "relatedTests": [], "currentImplementationNotes": ["CLINK_DISABLE_VIF disables VIF path."], "postFixReviewPoints": ["Verify IPv6 packet handling and route diagnostics."]}
      }
    },
    "virtual-interface": {
      "id": "virtual-interface",
      "label": "VirtualInterface / Wintun",
      "kind": "data",
      "layer": "virtual-interface",
      "position": {"x": 250, "y": 660},
      "summary": "Virtual NIC path that reads and writes packet data for tunnel forwarding.",
      "inputs": ["virtual NIC packet"],
      "outputs": ["packet codec input"],
      "sourceFiles": ["src/server/core/network/virtual_interface.cpp", "src/server/core/network/virtual_interface.hpp", "src/share/core/network/packet.cpp", "src/share/core/network/packet.hpp"],
      "tests": [],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "high", "tags": ["privilege-boundary", "platform-specific", "observability-critical"], "explanation": "Virtual NIC setup requires privilege and should expose clear diagnostics."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Dual-stack packet path needs post-fix review."},
      "details": {
        "basic": {"role": "Moves packet-level traffic between the OS network stack and CLink session path.", "receives": ["IP packet"], "emits": ["packet frame for session forwarding"], "whyItExists": "It enables tunnel behavior at virtual network interface level."},
        "deep": {"runtimeResponsibilities": ["Initialize virtual adapter", "Read packets", "Write packets", "Coordinate packet codec"], "lifecycle": ["adapter setup", "read/write loop", "adapter teardown"], "dataStructures": ["Packet", "virtual NIC frame"], "threadingModel": ["Long-running read/write loop."], "collaborations": ["Packet codec", "SessionManager", "Telemetry"], "stateTransitions": ["disabled", "initializing", "running", "stopped"], "errorPaths": ["driver missing", "permission failure", "read/write failure"], "platformNotes": ["Windows path depends on Wintun."], "dualStackNotes": ["Packet codec should distinguish IPv4 and IPv6 packet metadata."], "securityBoundaries": ["Driver boundary", "privilege boundary", "packet trust boundary"], "performanceNotes": ["Packet loop should minimize copies and excessive per-packet logging."], "sourceReadingOrder": ["src/server/core/network/virtual_interface.hpp", "src/server/core/network/virtual_interface.cpp", "src/share/core/network/packet.hpp", "src/share/core/network/packet.cpp"], "relatedTests": [], "currentImplementationNotes": ["Environment can disable VIF."], "postFixReviewPoints": ["Confirm IPv6 packet path and diagnostics."]}
      }
    },
    "session-manager-local": {
      "id": "session-manager-local",
      "label": "Local SessionManager",
      "kind": "data",
      "layer": "data-plane",
      "position": {"x": 660, "y": 440},
      "summary": "Local session coordinator that connects data entries to the transport tunnel.",
      "inputs": ["forwarding input", "packet input", "control session state"],
      "outputs": ["tunnel session frames"],
      "sourceFiles": ["src/server/core/network/session_manager.cpp", "src/server/core/network/session_manager.hpp", "src/server/core/network/session_manager_impl.hpp"],
      "tests": ["tests/network/session_manager_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6", "Dual-stack"],
      "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Session state changes should be visible in status and logs."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Session metadata should be checked for address-family visibility."},
      "details": {
        "basic": {"role": "Coordinates tunnel session forwarding between local modules and transport.", "receives": ["SOCKS/process manager traffic", "VIF packet frames", "connect state"], "emits": ["tunnel frames"], "whyItExists": "It centralizes session lifecycle and forwarding coordination."},
        "deep": {"runtimeResponsibilities": ["Manage sessions", "Coordinate transport adapter", "Handle forwarding callbacks", "Expose session metrics"], "lifecycle": ["create", "connect", "active forwarding", "disconnect", "cleanup"], "dataStructures": ["Session", "Packet", "transport frame"], "threadingModel": ["Asynchronous network/session callbacks."], "collaborations": ["TLS adapter", "ReliabilityEngine", "ProcessManager", "VirtualInterface"], "stateTransitions": ["disconnected", "connecting", "connected", "disconnecting"], "errorPaths": ["handshake timeout", "connection lost", "transport failure"], "platformNotes": ["Core logic should be platform-neutral."], "dualStackNotes": ["Address family should be known at connect/listen boundary and reflected in diagnostics."], "securityBoundaries": ["Session boundary", "remote trust boundary"], "performanceNotes": ["Central forwarding path should limit copies and coordinate zero-copy callbacks."], "sourceReadingOrder": ["src/server/core/network/session_manager.hpp", "src/server/core/network/session_manager.cpp", "src/server/core/network/session_manager_impl.hpp", "src/server/core/network/reliability_engine.hpp"], "relatedTests": ["tests/network/session_manager_test.cpp"], "currentImplementationNotes": ["Session state appears in control status."], "postFixReviewPoints": ["Confirm dual-stack session metadata and tests."]}
      }
    },
    "tls-transport": {
      "id": "tls-transport",
      "label": "TCP/TLS Transport",
      "kind": "data",
      "layer": "transport",
      "position": {"x": 870, "y": 360},
      "summary": "Network transport path for secured daemon-to-daemon session frames.",
      "inputs": ["tunnel frames", "endpoint host/port", "cert/PSK config"],
      "outputs": ["TCP/TLS session frames"],
      "sourceFiles": ["src/server/core/network/tcp_adapter.cpp", "src/server/core/network/tls_adapter.cpp", "src/share/core/network/tls_helpers.cpp"],
      "tests": ["tests/network/tcp_framing_test.cpp", "tests/network/tls_adapter_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6", "Dual-stack"],
      "risk": {"level": "medium", "tags": ["remote-listener", "credential-sensitive", "observability-critical"], "explanation": "Transport crosses machine boundary and relies on TLS/auth configuration."},
      "implementationStatus": {"current": "partial-current", "target": "post-fix-target", "confidence": "needs-recheck", "note": "Target design is dual-stack; current behavior must be reviewed after bug fixes."},
      "details": {
        "basic": {"role": "Carries secured session frames between local and remote daemons.", "receives": ["tunnel frames", "endpoint config"], "emits": ["TCP/TLS frames"], "whyItExists": "It protects and transports daemon session data across hosts."},
        "deep": {"runtimeResponsibilities": ["Resolve/connect/listen", "Perform TLS handshake", "Read/write framed data", "Surface connection errors"], "lifecycle": ["endpoint resolution", "TCP connect/listen", "TLS handshake", "active IO", "shutdown"], "dataStructures": ["transport frame", "TLS context", "resolved endpoint"], "threadingModel": ["Asynchronous socket and TLS IO."], "collaborations": ["SessionManager", "tls_helpers", "auth/PSK provider"], "stateTransitions": ["resolving", "connecting", "handshaking", "connected", "closed"], "errorPaths": ["resolution failure", "connect failure", "handshake timeout", "certificate/PSK failure"], "platformNotes": ["Cross-platform transport abstractions."], "dualStackNotes": ["Address resolution and listener setup should support IPv4 and IPv6 candidates."], "securityBoundaries": ["Remote listener boundary", "credential boundary", "network trust boundary"], "performanceNotes": ["Receive path can use BufferPool zero-copy callbacks."], "sourceReadingOrder": ["src/server/core/network/tcp_adapter.hpp", "src/server/core/network/tcp_adapter.cpp", "src/server/core/network/tls_adapter.hpp", "src/server/core/network/tls_adapter.cpp", "src/share/core/network/tls_helpers.hpp"], "relatedTests": ["tests/network/tcp_framing_test.cpp", "tests/network/tls_adapter_test.cpp"], "currentImplementationNotes": ["Dual-stack fixes are in progress outside this graph work."], "postFixReviewPoints": ["Verify IPv4/IPv6 candidate selection, logging, and test coverage."]}
      }
    },
    "buffer-pool": {
      "id": "buffer-pool",
      "label": "BufferPool / Zero-copy",
      "kind": "data",
      "layer": "performance",
      "position": {"x": 870, "y": 540},
      "summary": "Shared buffer block path used to reduce copies on receive and forwarding paths.",
      "inputs": ["TLS receive bytes"],
      "outputs": ["BufferPool block", "zero-copy callback"],
      "sourceFiles": ["src/server/core/memory/buffer_pool.hpp", "src/server/core/network/tls_adapter.cpp", "src/client/core/network/tls_adapter.cpp"],
      "tests": ["tests/network/zero_copy_test.cpp"],
      "addressFamilies": [],
      "risk": {"level": "low", "tags": [], "explanation": "Performance path; correctness depends on buffer lifetime and callback ownership."},
      "implementationStatus": {"current": "test-covered", "target": "stable-current", "confidence": "medium", "note": "Zero-copy tests exist and should remain green."},
      "details": {
        "basic": {"role": "Carries received bytes through shared blocks instead of repeatedly copying payloads.", "receives": ["transport receive bytes"], "emits": ["shared buffer block"], "whyItExists": "It improves forwarding efficiency on hot data paths."},
        "deep": {"runtimeResponsibilities": ["Allocate/reuse buffer blocks", "Hold receive payload", "Invoke zero-copy receive callback"], "lifecycle": ["block acquired", "filled", "callback invoked", "block released/reused"], "dataStructures": ["BufferPool::Block", "ZeroCopyReceiveCallback"], "threadingModel": ["Callback-driven receive path."], "collaborations": ["TLS adapter", "SessionManager", "forwarding target"], "stateTransitions": ["available", "in-use", "released"], "errorPaths": ["allocation pressure", "callback misuse", "lifetime mismatch"], "platformNotes": ["Shared concept across client/server adapters."], "dualStackNotes": ["Address family does not affect buffer ownership, but transport metadata may accompany payload."], "securityBoundaries": ["Payload memory ownership boundary"], "performanceNotes": ["Primary optimization is reducing payload copies."], "sourceReadingOrder": ["src/server/core/memory/buffer_pool.hpp", "src/server/core/network/tls_adapter.cpp", "src/client/core/network/tls_adapter.cpp"], "relatedTests": ["tests/network/zero_copy_test.cpp"], "currentImplementationNotes": ["Receive code references BufferPool for zero-copy support."], "postFixReviewPoints": ["Confirm dual-stack transport changes do not break zero-copy callback paths."]}
      }
    },
    "remote-listener": {
      "id": "remote-listener",
      "label": "Remote Transport Listener",
      "kind": "data",
      "layer": "remote-daemon",
      "position": {"x": 1080, "y": 300},
      "summary": "Remote daemon listener that accepts incoming TCP/TLS sessions.",
      "inputs": ["TCP/TLS session frames"],
      "outputs": ["accepted transport session"],
      "sourceFiles": ["src/server/core/network/transport_listener.hpp", "src/server/core/network/tcp_adapter.cpp", "src/server/core/network/tls_adapter.cpp"],
      "tests": ["tests/network/tls_adapter_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6", "Dual-stack"],
      "risk": {"level": "high", "tags": ["remote-listener", "credential-sensitive", "observability-critical"], "explanation": "Externally reachable listener must be authenticated and observable."},
      "implementationStatus": {"current": "partial-current", "target": "post-fix-target", "confidence": "needs-recheck", "note": "Dual-stack listen behavior requires post-fix verification."},
      "details": {
        "basic": {"role": "Accepts secured daemon-to-daemon connections on the remote side.", "receives": ["TCP/TLS frames"], "emits": ["accepted session"], "whyItExists": "Remote daemon must receive tunnel sessions initiated by local daemon."},
        "deep": {"runtimeResponsibilities": ["Listen on configured endpoint", "Accept connections", "Start TLS handling", "Pass session to auth/policy"], "lifecycle": ["bind", "listen", "accept", "handshake", "close"], "dataStructures": ["listener endpoint", "transport session"], "threadingModel": ["Asynchronous accept loop."], "collaborations": ["TLS adapter", "Auth", "Policy", "SessionManager"], "stateTransitions": ["not listening", "listening", "accepted", "closed"], "errorPaths": ["bind failure", "TLS failure", "auth failure"], "platformNotes": ["Server role can run on Linux or Windows."], "dualStackNotes": ["Listener should bind according to dual-stack policy and log chosen address family."], "securityBoundaries": ["Remote network boundary", "credential boundary"], "performanceNotes": ["Accept path should remain lightweight."], "sourceReadingOrder": ["src/server/core/network/transport_listener.hpp", "src/server/core/network/tcp_adapter.cpp", "src/server/core/network/tls_adapter.cpp"], "relatedTests": ["tests/network/tls_adapter_test.cpp"], "currentImplementationNotes": ["Transport listener is a core server boundary."], "postFixReviewPoints": ["Verify IPv4 and IPv6 listener tests and logs."]}
      }
    },
    "remote-auth-policy": {
      "id": "remote-auth-policy",
      "label": "Auth / ACL / Policy",
      "kind": "risk",
      "layer": "remote-daemon",
      "position": {"x": 1080, "y": 420},
      "summary": "Remote-side authentication, access control, and policy evaluation boundary.",
      "inputs": ["accepted transport session", "credentials/config"],
      "outputs": ["authorized session", "rejected session"],
      "sourceFiles": ["src/server/core/security/auth.hpp", "src/server/core/network/acl.cpp", "src/server/core/policy/engine.hpp"],
      "tests": [],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "high", "tags": ["remote-listener", "credential-sensitive", "config-sensitive"], "explanation": "Remote trust decision controls whether a session may continue."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Policy and ACL should understand address family where relevant."},
      "details": {
        "basic": {"role": "Decides whether an incoming remote session is allowed.", "receives": ["transport session", "credentials", "ACL/policy config"], "emits": ["allow or reject decision"], "whyItExists": "Remote listener must protect tunnel access."},
        "deep": {"runtimeResponsibilities": ["Authenticate session", "Evaluate ACL", "Apply policy"], "lifecycle": ["session accepted", "credentials checked", "policy evaluated", "session allowed/rejected"], "dataStructures": ["auth context", "ACL rule", "policy decision"], "threadingModel": ["Called during connection/session establishment."], "collaborations": ["Transport listener", "SessionManager", "configuration"], "stateTransitions": ["pending", "authorized", "rejected"], "errorPaths": ["credential failure", "policy deny", "config missing"], "platformNotes": ["Core security concept is platform-neutral."], "dualStackNotes": ["Address-family and remote endpoint metadata should be available for policy/log review."], "securityBoundaries": ["Authentication boundary", "policy boundary"], "performanceNotes": ["Decision path should be fast but auditable."], "sourceReadingOrder": ["src/server/core/security/auth.hpp", "src/server/core/network/acl.hpp", "src/server/core/network/acl.cpp", "src/server/core/policy/engine.hpp"], "relatedTests": [], "currentImplementationNotes": ["Security components exist as core server modules."], "postFixReviewPoints": ["Review address-family metadata in policy decisions."]}
      }
    },
    "session-manager-remote": {
      "id": "session-manager-remote",
      "label": "Remote SessionManager",
      "kind": "data",
      "layer": "remote-daemon",
      "position": {"x": 1080, "y": 540},
      "summary": "Remote-side session coordinator for accepted tunnel traffic.",
      "inputs": ["authorized session"],
      "outputs": ["forwarding operations", "session metrics"],
      "sourceFiles": ["src/server/core/network/session_manager.cpp", "src/server/core/network/session_manager.hpp", "src/server/core/network/reliability_engine.cpp"],
      "tests": ["tests/network/session_manager_test.cpp", "tests/network/reliability_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6", "Dual-stack"],
      "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Remote session state must remain observable for tunnel debugging."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Remote session metadata should be reviewed after dual-stack fixes."},
      "details": {
        "basic": {"role": "Coordinates the accepted remote side of a tunnel session.", "receives": ["authorized transport session"], "emits": ["forwarding operations", "telemetry"], "whyItExists": "It mirrors session coordination on the remote daemon side."},
        "deep": {"runtimeResponsibilities": ["Track remote session", "Coordinate forwarding", "Interact with reliability engine", "Emit status/telemetry"], "lifecycle": ["authorized", "active", "forwarding", "closed"], "dataStructures": ["Session", "reliability state", "forwarding frame"], "threadingModel": ["Asynchronous session callbacks."], "collaborations": ["ReliabilityEngine", "Forwarding", "Telemetry"], "stateTransitions": ["pending", "active", "closing", "closed"], "errorPaths": ["transport close", "forwarding failure", "reliability failure"], "platformNotes": ["Core server component."], "dualStackNotes": ["Remote endpoint address family should be reflected in logs/metrics."], "securityBoundaries": ["Post-auth session boundary"], "performanceNotes": ["Forwarding and reliability decisions occur in active data path."], "sourceReadingOrder": ["src/server/core/network/session_manager.hpp", "src/server/core/network/session_manager.cpp", "src/server/core/network/reliability_engine.hpp", "src/server/core/network/reliability_engine.cpp"], "relatedTests": ["tests/network/session_manager_test.cpp", "tests/network/reliability_test.cpp"], "currentImplementationNotes": ["Reliability engine is part of network core."], "postFixReviewPoints": ["Verify IPv6 endpoint metadata in remote telemetry."]}
      }
    },
    "remote-forwarding": {
      "id": "remote-forwarding",
      "label": "Remote Forwarding",
      "kind": "data",
      "layer": "remote-daemon",
      "position": {"x": 1080, "y": 660},
      "summary": "Remote egress or peer forwarding operation after session acceptance.",
      "inputs": ["session payload"],
      "outputs": ["network forwarding result"],
      "sourceFiles": ["src/server/core/network/session_manager.cpp", "src/share/core/network/packet.cpp"],
      "tests": ["tests/network/session_manager_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "medium", "tags": ["remote-listener", "observability-critical"], "explanation": "Remote forwarding is where tunnel payload leaves the remote daemon path."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Address-family context should be visible for forwarding debug."},
      "details": {
        "basic": {"role": "Represents the remote-side output of accepted session payloads.", "receives": ["session payload"], "emits": ["forwarded network data"], "whyItExists": "It completes the tunnel path beyond session management."},
        "deep": {"runtimeResponsibilities": ["Forward payload", "Report errors", "Update observability"], "lifecycle": ["payload received", "forward attempt", "success/failure", "close"], "dataStructures": ["packet", "stream frame"], "threadingModel": ["Data-plane callback path."], "collaborations": ["SessionManager", "Packet codec", "Telemetry"], "stateTransitions": ["ready", "forwarding", "blocked", "closed"], "errorPaths": ["destination unavailable", "packet format error", "session closed"], "platformNotes": ["Forwarding behavior depends on enabled module/path."], "dualStackNotes": ["Remote output may be IPv4 or IPv6 after dual-stack fixes."], "securityBoundaries": ["Remote egress boundary"], "performanceNotes": ["Payload hot path."], "sourceReadingOrder": ["src/server/core/network/session_manager.cpp", "src/share/core/network/packet.cpp"], "relatedTests": ["tests/network/session_manager_test.cpp"], "currentImplementationNotes": ["Represented as a conceptual remote egress node in the graph."], "postFixReviewPoints": ["Confirm IPv6 forwarding visibility in logs/tests."]}
      }
    },
    "observability": {
      "id": "observability",
      "label": "Logs / Metrics / Telemetry",
      "kind": "observe",
      "layer": "observability",
      "position": {"x": 780, "y": 700},
      "summary": "Runtime visibility path for status, logs, metrics, heartbeat, and telemetry events.",
      "inputs": ["daemon state", "session events", "module events"],
      "outputs": ["structured logs", "metrics", "heartbeat", "CLI status"],
      "sourceFiles": ["src/server/modules/metrics/metrics.cpp", "src/server/modules/heartbeat/heartbeat.cpp", "src/server/core/observability/telemetry.cpp", "src/share/core/logging/logger.cpp"],
      "tests": ["tests/logging/logger_test.cpp", "tests/logging/config_test.cpp"],
      "addressFamilies": ["IPv4", "IPv6"],
      "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Sensitive and failure-prone paths need enough diagnostics to be safely reviewed."},
      "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Dual-stack diagnostics should be added or verified after fixes."},
      "details": {
        "basic": {"role": "Makes runtime state and failures visible through status, logs, metrics, heartbeat, and telemetry.", "receives": ["daemon events", "session events", "module events"], "emits": ["structured logs", "metrics", "status payload"], "whyItExists": "Complex network paths require inspectable state for operation and debugging."},
        "deep": {"runtimeResponsibilities": ["Record structured log entries", "Emit telemetry spans", "Publish metrics", "Expose heartbeat"], "lifecycle": ["configured", "events emitted", "logs/metrics consumed", "shutdown"], "dataStructures": ["log record", "telemetry span", "metrics payload", "status JSON"], "threadingModel": ["Called from daemon modules and network callbacks."], "collaborations": ["Application", "SessionManager", "metrics module", "heartbeat module"], "stateTransitions": ["normal", "degraded", "failed", "stopped"], "errorPaths": ["log sink unavailable", "status missing reason", "telemetry sampling disabled"], "platformNotes": ["Log paths and defaults differ by platform."], "dualStackNotes": ["Logs/status should include address family where it helps connection diagnosis."], "securityBoundaries": ["Diagnostics may reveal sensitive config or endpoint information and should be scoped appropriately."], "performanceNotes": ["Telemetry sampling controls data-plane span volume."], "sourceReadingOrder": ["src/share/core/logging/logger.hpp", "src/share/core/logging/logger.cpp", "src/server/core/observability/telemetry.hpp", "src/server/core/observability/telemetry.cpp", "src/server/modules/metrics/metrics.cpp", "src/server/modules/heartbeat/heartbeat.cpp"], "relatedTests": ["tests/logging/logger_test.cpp", "tests/logging/config_test.cpp"], "currentImplementationNotes": ["README documents CLINK_TELEMETRY_SAMPLE."], "postFixReviewPoints": ["Confirm IPv4/IPv6 fields in transport and session diagnostics."]}
      }
    }
  },
  "edges": {
    "user-to-cli": {"id": "user-to-cli", "from": "user-script", "to": "clink-cli", "label": "command line", "kind": "control", "dataType": "shell arguments", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["README.md", "src/client/main.cpp"], "notes": ["User intent enters the control plane here."], "risk": {"level": "low", "tags": ["config-sensitive"], "explanation": "Command arguments influence control behavior."}, "implementationStatus": {"current": "stable-current", "target": "stable-current", "confidence": "high", "note": "CLI entry is documented."}},
    "cli-to-ipc": {"id": "cli-to-ipc", "from": "clink-cli", "to": "ipc-client", "label": "IPC command envelope", "kind": "control", "dataType": "JSON envelope plus command payload", "addressFamilies": [], "sourceFiles": ["src/client/main.cpp", "src/share/include/clink/protocol/control_plane.hpp"], "notes": ["Commands include connect, status, and disconnect."], "risk": {"level": "low", "tags": [], "explanation": "Structured local control payload."}, "implementationStatus": {"current": "current-source-observed", "target": "stable-current", "confidence": "medium", "note": "Control-plane constants are canonical."}},
    "ipc-client-to-server": {"id": "ipc-client-to-server", "from": "ipc-client", "to": "ipc-server", "label": "framed IPC bytes", "kind": "control", "dataType": "IPC wire frame", "addressFamilies": [], "sourceFiles": ["src/share/include/clink/protocol/ipc_wire.hpp", "src/share/core/ipc/ipc.hpp"], "notes": ["Local platform transport differs between Windows and Linux."], "risk": {"level": "medium", "tags": ["local-listener"], "explanation": "Local IPC can control daemon state."}, "implementationStatus": {"current": "current-source-observed", "target": "stable-current", "confidence": "medium", "note": "IPC is shared infrastructure."}},
    "ipc-to-local-daemon": {"id": "ipc-to-local-daemon", "from": "ipc-server", "to": "local-daemon", "label": "command dispatch", "kind": "control", "dataType": "Application command", "addressFamilies": [], "sourceFiles": ["src/server/core/application/application.cpp"], "notes": ["Daemon owns session state changes."], "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Control actions should be visible through status/logs."}, "implementationStatus": {"current": "current-source-observed", "target": "stable-current", "confidence": "medium", "note": "Application command dispatch is daemon-side."}},
    "local-app-to-socks": {"id": "local-app-to-socks", "from": "local-application", "to": "socks-server", "label": "SOCKS5 TCP stream", "kind": "data", "dataType": "SOCKS5 negotiation and TCP stream", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/modules/socks_server/socks_server.cpp"], "notes": ["Explicit proxy entry point."], "risk": {"level": "medium", "tags": ["local-listener", "untrusted-input"], "explanation": "Listener should have clear binding and access expectations."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Review IPv6 listener/destination behavior."}},
    "socks-to-process-manager": {"id": "socks-to-process-manager", "from": "socks-server", "to": "process-manager", "label": "proxy session stream", "kind": "data", "dataType": "normalized proxy stream", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/modules/process_manager/ipc_proxy_session.hpp"], "notes": ["SOCKS traffic joins the process manager/session path."], "risk": {"level": "medium", "tags": ["local-listener"], "explanation": "Proxy streams enter daemon forwarding."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Address-family metadata should remain visible."}},
    "target-process-to-hook": {"id": "target-process-to-hook", "from": "target-process", "to": "hook-dll", "label": "socket API boundary", "kind": "risk", "dataType": "hooked socket/connect/send/recv call", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/modules/process_inject/src/hook_manager.cpp"], "notes": ["Defensive source-understanding view only."], "risk": {"level": "high", "tags": ["injection-boundary", "privilege-boundary", "platform-specific"], "explanation": "Crosses process and hook boundary."}, "implementationStatus": {"current": "windows-only", "target": "windows-only", "confidence": "medium", "note": "Windows-only injection path."}},
    "hook-to-process-manager": {"id": "hook-to-process-manager", "from": "hook-dll", "to": "process-manager", "label": "hooked socket payload", "kind": "risk", "dataType": "Hook IPC protocol payload", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/share/core/ipc/hook_ipc_protocol.hpp", "src/server/modules/process_inject/src/process_ipc_server.cpp"], "notes": ["Hook IPC carries captured metadata into daemon-managed path."], "risk": {"level": "high", "tags": ["injection-boundary", "untrusted-input", "observability-critical"], "explanation": "Hook IPC input should be bounded and logged for audit."}, "implementationStatus": {"current": "windows-only", "target": "windows-only", "confidence": "medium", "note": "Review IPv6 metadata after fixes."}},
    "os-to-vif": {"id": "os-to-vif", "from": "os-network-stack", "to": "virtual-interface", "label": "virtual NIC packet", "kind": "data", "dataType": "IPv4 or IPv6 packet", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/core/network/virtual_interface.cpp", "src/share/core/network/packet.cpp"], "notes": ["Packet path can be disabled through CLINK_DISABLE_VIF."], "risk": {"level": "high", "tags": ["privilege-boundary", "platform-specific"], "explanation": "Virtual NIC path needs privilege and clear diagnostics."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Review IPv6 packet handling."}},
    "vif-to-session-manager": {"id": "vif-to-session-manager", "from": "virtual-interface", "to": "session-manager-local", "label": "packet frame", "kind": "data", "dataType": "Packet codec output", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/share/core/network/packet.cpp", "src/server/core/network/session_manager.cpp"], "notes": ["Packet-level data joins the session path."], "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Packet forwarding failures need clear logs."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Dual-stack packet labels should be verified."}},
    "process-manager-to-session": {"id": "process-manager-to-session", "from": "process-manager", "to": "session-manager-local", "label": "forwarding input", "kind": "data", "dataType": "stream payload for tunnel session", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/modules/process_manager/process_manager.cpp", "src/server/core/network/session_manager.cpp"], "notes": ["SOCKS and hook paths converge before transport."], "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Converged data path should preserve source context."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Review address-family context."}},
    "local-session-to-transport": {"id": "local-session-to-transport", "from": "session-manager-local", "to": "tls-transport", "label": "TCP/TLS session frames", "kind": "data", "dataType": "tunnel transport frames", "addressFamilies": ["IPv4", "IPv6", "Dual-stack"], "sourceFiles": ["src/server/core/network/session_manager.cpp", "src/server/core/network/tls_adapter.cpp"], "notes": ["Core daemon-to-daemon data path."], "risk": {"level": "medium", "tags": ["credential-sensitive", "observability-critical"], "explanation": "Session frames cross machine boundary under TLS."}, "implementationStatus": {"current": "partial-current", "target": "post-fix-target", "confidence": "needs-recheck", "note": "Dual-stack transport target."}},
    "tls-to-buffer-pool": {"id": "tls-to-buffer-pool", "from": "tls-transport", "to": "buffer-pool", "label": "BufferPool block", "kind": "data", "dataType": "zero-copy receive buffer", "addressFamilies": [], "sourceFiles": ["src/server/core/memory/buffer_pool.hpp", "src/server/core/network/tls_adapter.cpp"], "notes": ["Receive path can invoke zero-copy callback with a shared block."], "risk": {"level": "low", "tags": [], "explanation": "Memory ownership and callback lifetime should remain clear."}, "implementationStatus": {"current": "test-covered", "target": "stable-current", "confidence": "medium", "note": "Covered by zero-copy test."}},
    "transport-to-remote-listener": {"id": "transport-to-remote-listener", "from": "tls-transport", "to": "remote-listener", "label": "TCP/TLS session frames", "kind": "data", "dataType": "secured network transport", "addressFamilies": ["IPv4", "IPv6", "Dual-stack"], "sourceFiles": ["src/server/core/network/tcp_adapter.cpp", "src/server/core/network/tls_adapter.cpp"], "notes": ["Remote daemon accepts session frames."], "risk": {"level": "high", "tags": ["remote-listener", "credential-sensitive"], "explanation": "Remote network boundary requires authentication."}, "implementationStatus": {"current": "partial-current", "target": "post-fix-target", "confidence": "needs-recheck", "note": "Review dual-stack listener/connect behavior."}},
    "remote-listener-to-auth": {"id": "remote-listener-to-auth", "from": "remote-listener", "to": "remote-auth-policy", "label": "accepted session", "kind": "risk", "dataType": "transport session context", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/core/security/auth.hpp", "src/server/core/network/acl.cpp"], "notes": ["Session must pass auth/policy boundary."], "risk": {"level": "high", "tags": ["credential-sensitive", "remote-listener"], "explanation": "Remote trust decision boundary."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Review address-family policy visibility."}},
    "auth-to-remote-session": {"id": "auth-to-remote-session", "from": "remote-auth-policy", "to": "session-manager-remote", "label": "authorized session", "kind": "data", "dataType": "authorized session context", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/core/network/session_manager.cpp"], "notes": ["Authorized session enters remote session manager."], "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Authorized state should be observable."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Review diagnostics."}},
    "remote-session-to-forwarding": {"id": "remote-session-to-forwarding", "from": "session-manager-remote", "to": "remote-forwarding", "label": "session payload", "kind": "data", "dataType": "forwarded tunnel payload", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/server/core/network/session_manager.cpp", "src/share/core/network/packet.cpp"], "notes": ["Remote session sends payload to final forwarding behavior."], "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Forwarding errors must be diagnosable."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Review IPv6 egress diagnostics."}},
    "daemon-to-observability": {"id": "daemon-to-observability", "from": "local-daemon", "to": "observability", "label": "telemetry event / structured log", "kind": "observe", "dataType": "status, log, metrics, heartbeat, telemetry", "addressFamilies": ["IPv4", "IPv6"], "sourceFiles": ["src/share/core/logging/logger.cpp", "src/server/core/observability/telemetry.cpp"], "notes": ["Observability spans control and data paths."], "risk": {"level": "medium", "tags": ["observability-critical"], "explanation": "Complex paths need structured diagnostics."}, "implementationStatus": {"current": "current-source-observed", "target": "post-fix-target", "confidence": "medium", "note": "Review dual-stack log/status fields."}}
  },
  "groups": {
    "local-side": {"id": "local-side", "label": "Local side", "bounds": {"x": 30, "y": 40, "width": 760, "height": 670}},
    "transport-side": {"id": "transport-side", "label": "Transport", "bounds": {"x": 830, "y": 250, "width": 170, "height": 380}},
    "remote-side": {"id": "remote-side", "label": "Remote daemon", "bounds": {"x": 1030, "y": 250, "width": 210, "height": 470}},
    "observability-side": {"id": "observability-side", "label": "Observability", "bounds": {"x": 740, "y": 650, "width": 260, "height": 80}}
  },
  "legends": {
    "colors": [
      {"label": "Control plane", "color": "purple"},
      {"label": "Network data plane", "color": "blue/cyan"},
      {"label": "Sensitive boundary", "color": "orange"},
      {"label": "Observability", "color": "green"},
      {"label": "Configuration or platform dependency", "color": "gray"}
    ]
  },
  "glossary": {
    "control-plane": "Commands and status exchanged between CLI and daemon.",
    "data-plane": "Runtime traffic forwarded through SOCKS, process injection, VIF, sessions, and transport adapters.",
    "dual-stack": "Target architecture where IPv4 and IPv6 are first-class address-family dimensions.",
    "zero-copy": "Receive path that forwards shared buffer blocks instead of repeatedly copying payload bytes."
  }
};
```

- [ ] **Step 4: Run the validator and verify home data passes**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected output:

```text
PASS: codegraph shell and data are valid
```

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add .codegraph/assets/graph-data.js .codegraph/tools/validate_graph_data.py
git commit -m "feat: add codegraph home data model"
```

Expected:

```text
[branch <hash>] feat: add codegraph home data model
```

---

### Task 3: Implement SVG Flowchart Rendering and Selection

**Files:**
- Modify: `.codegraph/assets/app.js`
- Modify: `.codegraph/assets/styles.css`

- [ ] **Step 1: Run the current page and observe the missing graph renderer**

Open `.codegraph/index.html`.

Expected current behavior:

- The app loads.
- The central SVG still shows `Graph renderer will draw curated nodes and edges in the next task.`
- Clicking nodes is not possible yet.

- [ ] **Step 2: Replace `app.js` with the renderer implementation**

Replace `.codegraph/assets/app.js` with this complete content:

```js
(function () {
  "use strict";

  const graph = window.CLINK_GRAPH;
  const state = {
    currentViewId: graph.meta.defaultViewId,
    selectedType: "view",
    selectedId: graph.meta.defaultViewId,
    activeTab: "overview",
    toggles: {
      control: true,
      data: true,
      risk: true,
      source: true,
      ipv4: true,
      ipv6: true
    }
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function svgEl(tag, attributes) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attributes || {}).forEach(([key, value]) => element.setAttribute(key, String(value)));
    return element;
  }

  function getView(viewId) {
    return graph.views.find((view) => view.id === viewId) || graph.views[0];
  }

  function getNode(nodeId) {
    return graph.nodes[nodeId];
  }

  function getEdge(edgeId) {
    return graph.edges[edgeId];
  }

  function list(items) {
    if (!items || items.length === 0) return "<p class=\"muted\">No entries recorded for this section.</p>";
    return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
  }

  function paragraph(value) {
    if (!value) return "<p class=\"muted\">No description recorded.</p>";
    return `<p>${escapeHtml(value)}</p>`;
  }

  function renderBadges(items) {
    byId("view-badges").innerHTML = (items || [])
      .map((item) => `<span class=\"badge\">${escapeHtml(item)}</span>`)
      .join("");
  }

  function renderNavigation() {
    byId("view-nav").innerHTML = graph.views.map((view) => {
      const active = view.id === state.currentViewId ? " is-active" : "";
      return `<button class=\"nav-button${active}\" type=\"button\" data-view-id=\"${escapeHtml(view.id)}\"><span>${escapeHtml(view.title)}</span></button>`;
    }).join("");
  }

  function ensureMarkers(svg) {
    const defs = svgEl("defs");
    [
      ["arrow-control", "#a78bfa"],
      ["arrow-data", "#38bdf8"],
      ["arrow-risk", "#f97316"],
      ["arrow-observe", "#34d399"],
      ["arrow-config", "#94a3b8"]
    ].forEach(([id, color]) => {
      const marker = svgEl("marker", { id, viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
      marker.appendChild(svgEl("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: color }));
      defs.appendChild(marker);
    });
    svg.appendChild(defs);
  }

  function shouldDimItem(kind, addressFamilies) {
    if (!state.toggles.control && kind === "control") return true;
    if (!state.toggles.data && kind === "data") return true;
    if (!state.toggles.risk && kind === "risk") return true;
    const families = addressFamilies || [];
    if (!state.toggles.ipv4 && families.includes("IPv4") && !families.includes("IPv6")) return true;
    if (!state.toggles.ipv6 && families.includes("IPv6") && !families.includes("IPv4")) return true;
    return false;
  }

  function edgePath(fromNode, toNode) {
    const x1 = fromNode.position.x + 70;
    const y1 = fromNode.position.y + 26;
    const x2 = toNode.position.x;
    const y2 = toNode.position.y + 26;
    const dx = Math.max(80, Math.abs(x2 - x1) / 2);
    return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
  }

  function renderGroups(svg, view) {
    (view.groups || []).forEach((groupId) => {
      const group = graph.groups[groupId];
      if (!group) return;
      const g = svgEl("g", { class: "graph-group" });
      const b = group.bounds;
      g.appendChild(svgEl("rect", { x: b.x, y: b.y, width: b.width, height: b.height, rx: 5, ry: 5 }));
      const label = svgEl("text", { x: b.x + 12, y: b.y + 22 });
      label.textContent = group.label;
      g.appendChild(label);
      svg.appendChild(g);
    });
  }

  function renderEdges(svg, view) {
    (view.edges || []).forEach((edgeId) => {
      const edge = getEdge(edgeId);
      if (!edge) {
        console.warn(`Missing edge ${edgeId}`);
        return;
      }
      const from = getNode(edge.from);
      const to = getNode(edge.to);
      if (!from || !to) {
        console.warn(`Invalid edge endpoints for ${edgeId}`);
        return;
      }
      const g = svgEl("g", {
        class: `graph-edge edge-${edge.kind}${state.selectedType === "edge" && state.selectedId === edgeId ? " is-selected" : ""}${shouldDimItem(edge.kind, edge.addressFamilies) ? " is-dimmed" : ""}`,
        "data-edge-id": edgeId,
        tabindex: "0"
      });
      const path = svgEl("path", { d: edgePath(from, to), "marker-end": `url(#arrow-${edge.kind})` });
      g.appendChild(path);
      const midX = (from.position.x + to.position.x) / 2 + 34;
      const midY = (from.position.y + to.position.y) / 2 + 12;
      const label = svgEl("text", { x: midX, y: midY });
      label.textContent = edge.label;
      g.appendChild(label);
      g.addEventListener("click", () => selectEdge(edgeId));
      svg.appendChild(g);
    });
  }

  function renderNodes(svg, view) {
    (view.nodes || []).forEach((nodeId) => {
      const node = getNode(nodeId);
      if (!node) {
        console.warn(`Missing node ${nodeId}`);
        return;
      }
      const g = svgEl("g", {
        class: `graph-node kind-${node.kind}${state.selectedType === "node" && state.selectedId === nodeId ? " is-selected" : ""}${shouldDimItem(node.kind, node.addressFamilies) ? " is-dimmed" : ""}`,
        transform: `translate(${node.position.x}, ${node.position.y})`,
        "data-node-id": nodeId,
        tabindex: "0"
      });
      g.appendChild(svgEl("rect", { width: 142, height: 56, rx: 5, ry: 5 }));
      const title = svgEl("text", { x: 12, y: 22 });
      title.textContent = node.label;
      g.appendChild(title);
      const subtitle = svgEl("text", { x: 12, y: 42, class: "node-subtitle" });
      subtitle.textContent = node.layer;
      g.appendChild(subtitle);
      g.addEventListener("click", () => selectNode(nodeId));
      svg.appendChild(g);
    });
  }

  function renderGraph() {
    const svg = byId("graph-svg");
    const view = getView(state.currentViewId);
    svg.innerHTML = "";
    ensureMarkers(svg);
    renderGroups(svg, view);
    renderEdges(svg, view);
    renderNodes(svg, view);
  }

  function renderView(viewId) {
    state.currentViewId = viewId;
    const view = getView(viewId);
    byId("current-view-label").textContent = view.title;
    byId("view-title").textContent = view.title;
    byId("view-description").textContent = view.description;
    renderBadges(view.badges);
    renderNavigation();
    renderGraph();
    if (state.selectedType === "view" || !view.nodes.includes(state.selectedId)) {
      selectView(view.id);
    } else {
      renderDetails();
    }
  }

  function selectView(viewId) {
    state.selectedType = "view";
    state.selectedId = viewId;
    state.activeTab = "overview";
    renderDetails();
    renderGraph();
  }

  function selectNode(nodeId) {
    state.selectedType = "node";
    state.selectedId = nodeId;
    state.activeTab = "overview";
    renderDetails();
    renderGraph();
  }

  function selectEdge(edgeId) {
    state.selectedType = "edge";
    state.selectedId = edgeId;
    state.activeTab = "overview";
    renderDetails();
    renderGraph();
  }

  function selectedItem() {
    if (state.selectedType === "node") return getNode(state.selectedId);
    if (state.selectedType === "edge") return getEdge(state.selectedId);
    return getView(state.selectedId);
  }

  function renderDetails() {
    const item = selectedItem();
    if (!item) return;
    byId("detail-kind").textContent = state.selectedType;
    byId("detail-title").textContent = item.label || item.title;
    document.querySelectorAll(".tab-button").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.tab === state.activeTab);
    });
    byId("detail-content").innerHTML = renderDetailTab(item);
  }

  function renderDetailTab(item) {
    if (state.selectedType === "view") return renderViewTab(item);
    if (state.selectedType === "edge") return renderEdgeTab(item);
    return renderNodeTab(item);
  }

  function renderViewTab(view) {
    const deep = view.deepDive || {};
    if (state.activeTab === "deep") {
      return `<h3>Deep Understanding</h3><h4>Runtime Flow</h4>${list(deep.runtimeFlow)}<h4>Module Composition</h4>${list(deep.moduleComposition)}<h4>Important States</h4>${list(deep.importantStates)}<h4>Edge Cases</h4>${list(deep.edgeCases)}`;
    }
    if (state.activeTab === "source") {
      return `<h3>Source Reading Path</h3>${list(deep.sourceReadingPath)}<h4>Tests to Read</h4>${list(deep.testsToRead)}`;
    }
    if (state.activeTab === "risk") {
      return `<h3>Risk Boundaries</h3>${list(deep.riskBoundaries)}`;
    }
    if (state.activeTab === "debug") {
      return `<h3>Debugging Checklist</h3>${list(deep.debuggingChecklist)}<h4>Dual-stack Review</h4>${list(deep.dualStackReview)}`;
    }
    return `<h3>Overview</h3>${paragraph(view.description)}<h4>Purpose</h4>${paragraph(deep.purpose)}`;
  }

  function renderNodeTab(node) {
    const basic = node.details.basic;
    const deep = node.details.deep;
    if (state.activeTab === "deep") {
      return `<h3>Deep Understanding</h3><h4>Runtime Responsibilities</h4>${list(deep.runtimeResponsibilities)}<h4>Lifecycle</h4>${list(deep.lifecycle)}<h4>Data Structures</h4>${list(deep.dataStructures)}<h4>Collaborations</h4>${list(deep.collaborations)}<h4>Error Paths</h4>${list(deep.errorPaths)}<h4>Platform Notes</h4>${list(deep.platformNotes)}<h4>Dual-stack Notes</h4>${list(deep.dualStackNotes)}`;
    }
    if (state.activeTab === "source") {
      return `<h3>Source</h3>${list(node.sourceFiles)}<h4>Reading Order</h4>${list(deep.sourceReadingOrder)}<h4>Related Tests</h4>${list(deep.relatedTests)}`;
    }
    if (state.activeTab === "risk") {
      return `<h3>Risk</h3>${paragraph(node.risk.explanation)}<h4>Tags</h4>${list(node.risk.tags)}<h4>Security Boundaries</h4>${list(deep.securityBoundaries)}`;
    }
    if (state.activeTab === "debug") {
      return `<h3>Debug</h3><h4>Current Implementation Notes</h4>${list(deep.currentImplementationNotes)}<h4>Post-fix Review Points</h4>${list(deep.postFixReviewPoints)}<h4>Implementation Status</h4>${paragraph(node.implementationStatus.note)}`;
    }
    return `<h3>Overview</h3>${paragraph(basic.role)}<h4>Receives</h4>${list(basic.receives)}<h4>Emits</h4>${list(basic.emits)}<h4>Why it exists</h4>${paragraph(basic.whyItExists)}`;
  }

  function renderEdgeTab(edge) {
    if (state.activeTab === "source") {
      return `<h3>Source</h3>${list(edge.sourceFiles)}`;
    }
    if (state.activeTab === "risk") {
      return `<h3>Risk</h3>${paragraph(edge.risk.explanation)}<h4>Tags</h4>${list(edge.risk.tags)}`;
    }
    if (state.activeTab === "debug") {
      return `<h3>Debug</h3><h4>Implementation Status</h4>${paragraph(edge.implementationStatus.note)}<h4>Notes</h4>${list(edge.notes)}`;
    }
    if (state.activeTab === "deep") {
      return `<h3>Deep Understanding</h3><h4>Data Type</h4>${paragraph(edge.dataType)}<h4>Address Families</h4>${list(edge.addressFamilies)}<h4>Notes</h4>${list(edge.notes)}`;
    }
    return `<h3>Overview</h3><p><strong>${escapeHtml(edge.from)}</strong> → <strong>${escapeHtml(edge.to)}</strong></p><h4>Label</h4>${paragraph(edge.label)}<h4>Data Type</h4>${paragraph(edge.dataType)}`;
  }

  function bindEvents() {
    byId("view-nav").addEventListener("click", (event) => {
      const button = event.target.closest("[data-view-id]");
      if (button) renderView(button.dataset.viewId);
    });
    document.querySelectorAll(".tab-button").forEach((button) => {
      button.addEventListener("click", () => {
        state.activeTab = button.dataset.tab;
        renderDetails();
      });
    });
    document.querySelectorAll("[data-toggle]").forEach((input) => {
      input.addEventListener("change", () => {
        state.toggles[input.dataset.toggle] = input.checked;
        renderGraph();
      });
    });
  }

  function init() {
    if (!graph) throw new Error("window.CLINK_GRAPH is not loaded");
    renderNavigation();
    bindEvents();
    renderView(graph.meta.defaultViewId);
  }

  init();
})();
```

- [ ] **Step 3: Add group styling and muted text styling**

Append this CSS to `.codegraph/assets/styles.css`:

```css
.muted { color: var(--muted); }
.graph-group rect {
  fill: rgba(15, 23, 36, 0.42);
  stroke: rgba(148, 163, 184, 0.22);
  stroke-dasharray: 6 6;
}
.graph-group text {
  fill: var(--faint);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
```

- [ ] **Step 4: Run the validator**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected:

```text
PASS: codegraph shell and data are valid
```

- [ ] **Step 5: Manually verify home graph rendering**

Open `.codegraph/index.html`.

Expected:

- Home graph renders multiple grouped SVG nodes and curved arrows.
- Clicking `clink CLI` updates the right panel.
- Clicking `TCP/TLS session frames` edge updates the right panel.
- Switching tabs changes content without page reload.
- Toggling `Risk` dims risk-kind nodes and edges.

- [ ] **Step 6: Commit Task 3**

Run:

```bash
git add .codegraph/assets/app.js .codegraph/assets/styles.css
git commit -m "feat: render codegraph flowchart"
```

Expected:

```text
[branch <hash>] feat: render codegraph flowchart
```

---

### Task 4: Add Focused Navigation Views

**Files:**
- Modify: `.codegraph/assets/graph-data.js`

- [ ] **Step 1: Run the validator to establish the current passing baseline**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected:

```text
PASS: codegraph shell and data are valid
```

- [ ] **Step 2: Add the 11 focused views after the home view**

In `.codegraph/assets/graph-data.js`, add these objects to the `views` array immediately after the existing `home` view object. Keep valid JSON syntax by placing a comma between view objects.

```js
{
  "id": "cli-control",
  "title": "CLI Control Endpoint",
  "description": "How clink parses local commands and sends structured control requests to the daemon.",
  "type": "flow",
  "nodes": ["user-script", "clink-cli", "ipc-client", "ipc-server", "local-daemon"],
  "edges": ["user-to-cli", "cli-to-ipc", "ipc-client-to-server", "ipc-to-local-daemon"],
  "groups": ["local-side"],
  "badges": ["Control plane", "IPC", "Status rendering"],
  "deepDive": {
    "purpose": "Explain why the CLI is a controller and not the long-running tunnel worker.",
    "runtimeFlow": ["User command enters clink CLI.", "CLI resolves config and IPC address.", "CLI sends a structured IPC command envelope.", "Daemon IPC server dispatches to Application state."],
    "moduleComposition": ["src/client/main.cpp", "IPC client", "control-plane constants", "daemon IPC server"],
    "sourceReadingPath": ["src/client/main.cpp", "src/client/core/application/application.cpp", "src/share/include/clink/protocol/control_plane.hpp", "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md"],
    "importantStates": ["CLI process is short-lived.", "Daemon owns persistent session state."],
    "edgeCases": ["Daemon not running", "Unknown command", "IPC address mismatch", "Structured error response"],
    "riskBoundaries": ["Local command boundary", "Local IPC boundary", "Configuration-sensitive target fields"],
    "debuggingChecklist": ["Run clink status", "Check service_not_running reason", "Compare configured and effective IPC address"],
    "dualStackReview": ["Verify IPv6 literal input and rendering", "Verify target host/port survives into daemon connect state"],
    "testsToRead": ["tests/application_connect_test.cpp", "tests/ipc_linux_test.cpp"]
  }
},
{
  "id": "ipc-control-plane",
  "title": "IPC Control Plane",
  "description": "Framed local IPC request/response path and structured control-plane schema.",
  "type": "flow",
  "nodes": ["clink-cli", "ipc-client", "ipc-server", "local-daemon"],
  "edges": ["cli-to-ipc", "ipc-client-to-server", "ipc-to-local-daemon"],
  "groups": ["local-side"],
  "badges": ["IPC", "JSON envelope", "Structured errors"],
  "deepDive": {
    "purpose": "Show the contract between short-lived CLI commands and daemon-owned state.",
    "runtimeFlow": ["CLI builds a control command.", "IPC client frames the message.", "Daemon IPC server parses and dispatches.", "Daemon returns structured status or error data."],
    "moduleComposition": ["ipc_wire.hpp", "ipc_message_utils.hpp", "control_plane.hpp", "Application command handler"],
    "sourceReadingPath": ["src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md", "src/share/include/clink/protocol/ipc_wire.hpp", "src/share/core/ipc/ipc_message_utils.hpp", "src/server/core/application/application.cpp"],
    "importantStates": ["ok true response", "ok false response", "accepted false command result"],
    "edgeCases": ["Malformed envelope", "Unknown command", "Daemon shutting down during request"],
    "riskBoundaries": ["Local IPC control boundary"],
    "debuggingChecklist": ["Branch on data.status and data.reason", "Check IPC endpoint path", "Inspect daemon logs for command handling"],
    "dualStackReview": ["Confirm status payload exposes transport address-family diagnostics after fixes"],
    "testsToRead": ["tests/ipc_linux_test.cpp"]
  }
},
{
  "id": "daemon-lifecycle",
  "title": "daemon Lifecycle",
  "description": "How clinkd starts, configures modules, exposes IPC, and stops runtime components.",
  "type": "flow",
  "nodes": ["local-daemon", "ipc-server", "socks-server", "process-manager", "virtual-interface", "session-manager-local", "observability"],
  "edges": ["ipc-to-local-daemon", "socks-to-process-manager", "process-manager-to-session", "vif-to-session-manager", "daemon-to-observability"],
  "groups": ["local-side", "observability-side"],
  "badges": ["Application", "Modules", "Runtime flags"],
  "deepDive": {
    "purpose": "Explain daemon startup, module boundaries, runtime toggles, and shutdown responsibilities.",
    "runtimeFlow": ["main loads configuration.", "Application constructs daemon runtime.", "Registry/module components are configured and started.", "Stop path closes IPC, sessions, and modules."],
    "moduleComposition": ["Application", "Registry", "IPC server", "SOCKS server", "ProcessManager", "VirtualInterface", "Telemetry"],
    "sourceReadingPath": ["src/server/main.cpp", "src/server/core/application/application.cpp", "src/server/core/registry.hpp", "src/server/core/module.hpp"],
    "importantStates": ["running", "connecting", "connected", "disconnecting", "stopped"],
    "edgeCases": ["Config missing", "module disabled", "transport start failure", "shutdown during active session"],
    "riskBoundaries": ["Daemon privilege boundary", "configuration boundary", "module enable/disable boundary"],
    "debuggingChecklist": ["Check CLINK_DISABLE_VIF", "Check CLINK_DISABLE_PROCESS_MANAGER", "Inspect daemon logs", "Check status restart_required fields"],
    "dualStackReview": ["Confirm daemon status contains useful address-family diagnostics"],
    "testsToRead": ["tests/application_connect_test.cpp"]
  }
},
{
  "id": "tcp-tls-dual-stack",
  "title": "TCP/TLS and IPv4/IPv6",
  "description": "Transport setup, TLS session behavior, and post-fix dual-stack review points.",
  "type": "flow",
  "nodes": ["local-daemon", "session-manager-local", "tls-transport", "remote-listener", "remote-auth-policy", "session-manager-remote"],
  "edges": ["local-session-to-transport", "transport-to-remote-listener", "remote-listener-to-auth", "auth-to-remote-session"],
  "groups": ["local-side", "transport-side", "remote-side"],
  "badges": ["Transport", "TLS", "IPv4", "IPv6", "Dual-stack target"],
  "deepDive": {
    "purpose": "Show address resolution and secured daemon-to-daemon transport as one unified dual-stack target design.",
    "runtimeFlow": ["Connect request provides host, port, and transport mode.", "Transport resolves IPv4 and IPv6 candidates according to policy.", "TCP connect or listen succeeds for one address family.", "TLS handshake secures the session.", "SessionManager receives active transport."],
    "moduleComposition": ["TCP adapter", "TLS adapter", "tls_helpers", "PSK/cert configuration", "SessionManager"],
    "sourceReadingPath": ["src/server/core/network/tcp_adapter.hpp", "src/server/core/network/tcp_adapter.cpp", "src/server/core/network/tls_adapter.hpp", "src/server/core/network/tls_adapter.cpp", "src/share/core/network/tls_helpers.hpp"],
    "importantStates": ["resolving", "connecting", "handshaking", "connected", "closed"],
    "edgeCases": ["IPv6 literal formatting", "IPv4 fallback", "handshake timeout", "certificate or PSK failure"],
    "riskBoundaries": ["Remote listener", "credential-sensitive TLS config", "network trust boundary"],
    "debuggingChecklist": ["Check resolved endpoint", "Check handshake status", "Check logs for address family", "Run TCP/TLS tests"],
    "dualStackReview": ["Verify listen/connect for IPv4", "Verify listen/connect for IPv6", "Verify logs and status expose chosen family", "Verify tests cover both families"],
    "testsToRead": ["tests/network/tcp_framing_test.cpp", "tests/network/tls_adapter_test.cpp"]
  }
},
{
  "id": "socks-forwarding",
  "title": "SOCKS Forwarding",
  "description": "Explicit proxy data entry path from local applications into the tunnel session.",
  "type": "flow",
  "nodes": ["local-application", "socks-server", "process-manager", "session-manager-local", "tls-transport"],
  "edges": ["local-app-to-socks", "socks-to-process-manager", "process-manager-to-session", "local-session-to-transport"],
  "groups": ["local-side", "transport-side"],
  "badges": ["SOCKS5", "Local listener", "Data plane"],
  "deepDive": {
    "purpose": "Explain the explicit proxy path and how it differs from process injection and VIF packet routing.",
    "runtimeFlow": ["Local app connects to SOCKS listener.", "SOCKS server negotiates request.", "Proxy session enters ProcessManager.", "ProcessManager forwards normalized stream to SessionManager.", "SessionManager emits tunnel frames."],
    "moduleComposition": ["SOCKS server", "ipc_proxy_session", "ProcessManager", "SessionManager"],
    "sourceReadingPath": ["src/server/modules/socks_server/socks_server.hpp", "src/server/modules/socks_server/socks_server.cpp", "src/server/modules/process_manager/ipc_proxy_session.hpp", "src/server/modules/process_manager/process_manager.cpp"],
    "importantStates": ["listening", "negotiating", "forwarding", "closed"],
    "edgeCases": ["Bind failure", "Unsupported SOCKS command", "Listener exposed on unintended interface", "IPv6 destination parsing"],
    "riskBoundaries": ["Local listener", "untrusted local stream", "process manager convergence boundary"],
    "debuggingChecklist": ["Check process_manager state", "Check socks_available status", "Run socks_server tests"],
    "dualStackReview": ["Verify SOCKS listener bind behavior", "Verify IPv6 destination handling", "Verify status/log visibility"],
    "testsToRead": ["tests/server/socks_server_test.cpp", "tests/server/ipc_proxy_test.cpp"]
  }
},
{
  "id": "process-injection",
  "title": "Process Injection Path",
  "description": "Windows-only hook and IPC data path explained for defensive source understanding.",
  "type": "flow",
  "nodes": ["target-process", "hook-dll", "process-manager", "session-manager-local", "tls-transport"],
  "edges": ["target-process-to-hook", "hook-to-process-manager", "process-manager-to-session", "local-session-to-transport"],
  "groups": ["local-side", "transport-side"],
  "badges": ["Windows-only", "Hook IPC", "Sensitive boundary"],
  "deepDive": {
    "purpose": "Describe the internal hook data path, process boundary, and daemon normalization point without operational misuse instructions.",
    "runtimeFlow": ["Target process reaches a network API boundary.", "Hook component observes selected call metadata.", "Hook IPC carries payload metadata into daemon-controlled path.", "ProcessManager normalizes input.", "SessionManager forwards through transport."],
    "moduleComposition": ["DLL entry", "HookManager", "ProcessInjector", "ProcessIpcServer", "Hook IPC protocol", "ProcessManager"],
    "sourceReadingPath": ["src/server/modules/process_inject/include/process_injector.hpp", "src/server/modules/process_inject/include/hook_manager.hpp", "src/server/modules/process_inject/src/hook_manager.cpp", "src/server/modules/process_inject/src/process_ipc_server.cpp", "src/share/core/ipc/hook_ipc_protocol.hpp"],
    "importantStates": ["unhooked", "hook installed", "payload observed", "IPC delivered", "forwarding active"],
    "edgeCases": ["Hook install failure", "IPC unavailable", "target process exits", "IPv6 sockaddr metadata missing"],
    "riskBoundaries": ["Process boundary", "privilege boundary", "injection boundary", "IPC boundary", "build-option boundary"],
    "debuggingChecklist": ["Check CLINK_BUILD_CLIENT_HOOK", "Check process manager state", "Check hook IPC logs", "Read dll integration test"],
    "dualStackReview": ["Verify hook protocol carries IPv6 metadata", "Verify ProcessManager preserves address family"],
    "testsToRead": ["tests/server/dll_integration_test.cpp", "tests/server/ipc_proxy_test.cpp"]
  }
},
{
  "id": "virtual-interface-vif",
  "title": "Virtual Interface / VIF",
  "description": "Packet-level data path through OS routing, Wintun/VIF, packet codec, and SessionManager.",
  "type": "flow",
  "nodes": ["os-network-stack", "virtual-interface", "session-manager-local", "tls-transport"],
  "edges": ["os-to-vif", "vif-to-session-manager", "local-session-to-transport"],
  "groups": ["local-side", "transport-side"],
  "badges": ["VIF", "Wintun", "Packet path", "Privilege boundary"],
  "deepDive": {
    "purpose": "Show how selected OS traffic becomes packet-level tunnel input.",
    "runtimeFlow": ["OS routing selects traffic.", "Virtual adapter receives packet.", "VirtualInterface read/write loop handles packet.", "Packet codec frames data.", "SessionManager forwards through transport."],
    "moduleComposition": ["Wintun/VIF", "VirtualInterface", "Packet codec", "SessionManager"],
    "sourceReadingPath": ["src/server/core/network/virtual_interface.hpp", "src/server/core/network/virtual_interface.cpp", "src/share/core/network/packet.hpp", "src/share/core/network/packet.cpp"],
    "importantStates": ["disabled", "initializing", "running", "stopped"],
    "edgeCases": ["Driver missing", "privilege denied", "packet parse error", "IPv6 packet handling"],
    "riskBoundaries": ["Driver boundary", "privilege boundary", "packet trust boundary"],
    "debuggingChecklist": ["Check CLINK_DISABLE_VIF", "Check elevation behavior", "Check Wintun availability", "Inspect packet/log telemetry"],
    "dualStackReview": ["Verify IPv4 packet labels", "Verify IPv6 packet labels", "Verify logs distinguish families"],
    "testsToRead": []
  }
},
{
  "id": "zero-copy-forwarding",
  "title": "Zero-copy Forwarding",
  "description": "Receive-buffer ownership path through BufferPool blocks and forwarding callbacks.",
  "type": "flow",
  "nodes": ["tls-transport", "buffer-pool", "session-manager-local"],
  "edges": ["tls-to-buffer-pool"],
  "groups": ["transport-side"],
  "badges": ["BufferPool", "Performance", "Receive callback"],
  "deepDive": {
    "purpose": "Explain what zero-copy means in this project and where buffer ownership matters.",
    "runtimeFlow": ["TLS adapter receives bytes.", "BufferPool block stores receive data.", "ZeroCopyReceiveCallback receives shared block.", "Forwarding path consumes block without repeated payload copying."],
    "moduleComposition": ["BufferPool::Block", "TLS adapter", "ZeroCopyReceiveCallback", "SessionManager"],
    "sourceReadingPath": ["src/server/core/memory/buffer_pool.hpp", "src/server/core/network/tls_adapter.cpp", "src/client/core/network/tls_adapter.cpp", "tests/network/zero_copy_test.cpp"],
    "importantStates": ["block available", "block in use", "callback invoked", "block released"],
    "edgeCases": ["callback lifetime mismatch", "allocation pressure", "transport closed during receive"],
    "riskBoundaries": ["Payload memory ownership boundary"],
    "debuggingChecklist": ["Run zero_copy_test", "Inspect TLS receive path", "Review callback ownership"],
    "dualStackReview": ["Confirm transport dual-stack changes do not change buffer lifetime assumptions"],
    "testsToRead": ["tests/network/zero_copy_test.cpp"]
  }
},
{
  "id": "observability-debugging",
  "title": "Observability and Debugging",
  "description": "How daemon state, failures, logs, metrics, heartbeat, telemetry, and CLI status relate.",
  "type": "flow",
  "nodes": ["local-daemon", "session-manager-local", "tls-transport", "process-manager", "observability"],
  "edges": ["daemon-to-observability", "local-session-to-transport", "process-manager-to-session"],
  "groups": ["local-side", "observability-side"],
  "badges": ["Logs", "Metrics", "Heartbeat", "Telemetry"],
  "deepDive": {
    "purpose": "Provide a practical reading path for runtime state and failure diagnosis.",
    "runtimeFlow": ["Daemon modules emit structured logs.", "Session and transport paths update status and telemetry.", "Metrics and heartbeat expose runtime health.", "CLI status renders structured daemon response."],
    "moduleComposition": ["logger", "logging config", "telemetry", "metrics module", "heartbeat module", "control status payload"],
    "sourceReadingPath": ["src/share/core/logging/logger.hpp", "src/share/core/logging/logger.cpp", "src/share/core/logging/config.cpp", "src/server/core/observability/telemetry.cpp", "src/server/modules/metrics/metrics.cpp", "src/server/modules/heartbeat/heartbeat.cpp"],
    "importantStates": ["connecting", "connected", "failed", "rejected", "stopped"],
    "edgeCases": ["log sink unavailable", "telemetry sampling disabled", "status lacks enough transport detail"],
    "riskBoundaries": ["observability-critical sensitive paths", "credential/log redaction boundary"],
    "debuggingChecklist": ["Check CLI status", "Check daemon log path", "Check process_manager.state", "Check connect_reason", "Check telemetry sampling"],
    "dualStackReview": ["Verify address family appears in transport logs", "Verify IPv6 failures are distinguishable from IPv4 failures"],
    "testsToRead": ["tests/logging/logger_test.cpp", "tests/logging/config_test.cpp"]
  }
},
{
  "id": "risk-boundary-overview",
  "title": "Risk Boundary Overview",
  "description": "Defensive audit map of sensitive local, remote, privilege, injection, and configuration boundaries.",
  "type": "flow",
  "nodes": ["ipc-server", "socks-server", "target-process", "hook-dll", "virtual-interface", "tls-transport", "remote-listener", "remote-auth-policy", "observability"],
  "edges": ["ipc-to-local-daemon", "local-app-to-socks", "target-process-to-hook", "hook-to-process-manager", "os-to-vif", "transport-to-remote-listener", "remote-listener-to-auth", "daemon-to-observability"],
  "groups": ["local-side", "transport-side", "remote-side", "observability-side"],
  "badges": ["Defensive audit", "Sensitive boundaries", "Trust transitions"],
  "deepDive": {
    "purpose": "Collect sensitive boundaries in one view for source review and hardening discussion.",
    "runtimeFlow": ["Control enters through local IPC.", "Data enters through SOCKS, hook IPC, or VIF.", "Transport crosses the network boundary.", "Remote auth/policy decides session trust.", "Observability supports review and diagnosis."],
    "moduleComposition": ["IPC server", "SOCKS server", "Process injection", "VirtualInterface", "TLS transport", "Auth/ACL/Policy", "Observability"],
    "sourceReadingPath": ["src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md", "src/server/modules/socks_server/socks_server.cpp", "src/server/modules/process_inject/src/hook_manager.cpp", "src/server/core/network/virtual_interface.cpp", "src/server/core/security/auth.hpp", "src/server/core/network/acl.cpp"],
    "importantStates": ["listener enabled", "module disabled", "authorized", "rejected", "failed"],
    "edgeCases": ["unexpected listener exposure", "missing auth diagnostics", "hook IPC malformed data", "VIF privilege failure"],
    "riskBoundaries": ["privilege-boundary", "injection-boundary", "untrusted-input", "local-listener", "remote-listener", "credential-sensitive", "observability-critical"],
    "debuggingChecklist": ["Review enabled modules", "Review bind addresses", "Review status reason fields", "Review logs around sensitive boundaries"],
    "dualStackReview": ["Ensure risk review covers IPv4 and IPv6 listener exposure", "Ensure logs distinguish address family"],
    "testsToRead": ["tests/server/socks_server_test.cpp", "tests/server/ipc_proxy_test.cpp", "tests/server/dll_integration_test.cpp"]
  }
},
{
  "id": "source-index",
  "title": "Source Index",
  "description": "Source reading order grouped by runtime concept rather than by directory listing.",
  "type": "flow",
  "nodes": ["clink-cli", "ipc-server", "local-daemon", "session-manager-local", "tls-transport", "socks-server", "process-manager", "hook-dll", "virtual-interface", "buffer-pool", "observability"],
  "edges": ["cli-to-ipc", "ipc-to-local-daemon", "process-manager-to-session", "local-session-to-transport", "tls-to-buffer-pool", "daemon-to-observability"],
  "groups": ["local-side", "transport-side", "observability-side"],
  "badges": ["Reading path", "Source anchors", "Tests"],
  "deepDive": {
    "purpose": "Give maintainers a directed reading path through the CLink source for this graph.",
    "runtimeFlow": ["Start with README and control-plane schema.", "Read CLI and daemon Application boundaries.", "Read SessionManager and transport.", "Read data entry modules.", "Read observability and tests."],
    "moduleComposition": ["Documentation", "Control plane", "Daemon runtime", "Network core", "Modules", "Tests"],
    "sourceReadingPath": ["README.md", "src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md", "src/client/main.cpp", "src/server/core/application/application.cpp", "src/server/core/network/session_manager.hpp", "src/server/core/network/tls_adapter.hpp", "src/server/modules/socks_server/socks_server.hpp", "src/server/modules/process_manager/process_manager.hpp", "src/server/core/network/virtual_interface.hpp", "src/server/core/memory/buffer_pool.hpp"],
    "importantStates": ["control command", "daemon session state", "data entry active", "transport connected", "forwarding active"],
    "edgeCases": ["source behavior changes during dual-stack bug fixes", "tests lag behind target design"],
    "riskBoundaries": ["Use risk overview for sensitive boundary review."],
    "debuggingChecklist": ["After source changes, update graph-data source files and implementation notes", "Run validator", "Run manual acceptance"],
    "dualStackReview": ["Re-read TCP/TLS and SOCKS/VIF sources after dual-stack fixes"],
    "testsToRead": ["tests/network/session_manager_test.cpp", "tests/network/tls_adapter_test.cpp", "tests/network/zero_copy_test.cpp", "tests/server/socks_server_test.cpp", "tests/server/ipc_proxy_test.cpp", "tests/server/dll_integration_test.cpp"]
  }
}
```

- [ ] **Step 3: Run the validator**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected:

```text
PASS: codegraph shell and data are valid
```

- [ ] **Step 4: Manually verify navigation views**

Open `.codegraph/index.html`.

Expected:

- Left navigation contains 12 views total.
- Clicking each view updates the title, description, badges, and flowchart.
- Each focused view shows fewer nodes than Home and keeps relevant context.
- The detail panel for each view has meaningful Overview and Deep Understanding content.

- [ ] **Step 5: Commit Task 4**

Run:

```bash
git add .codegraph/assets/graph-data.js
git commit -m "feat: add codegraph detail views"
```

Expected:

```text
[branch <hash>] feat: add codegraph detail views
```

---

### Task 5: Add Search, Source Labels Toggle, and Address-family Emphasis

**Files:**
- Modify: `.codegraph/assets/app.js`
- Modify: `.codegraph/assets/styles.css`

- [ ] **Step 1: Manually confirm search is not implemented yet**

Open `.codegraph/index.html`, type `SessionManager` in the search box.

Expected current behavior:

- Nothing happens or no results are displayed.

- [ ] **Step 2: Insert search helper functions into `app.js`**

In `.codegraph/assets/app.js`, insert these functions immediately before `function bindEvents()`:

```js
  function searchableTextForNode(node) {
    return [
      node.id,
      node.label,
      node.summary,
      node.layer,
      ...(node.inputs || []),
      ...(node.outputs || []),
      ...(node.sourceFiles || []),
      ...(node.tests || []),
      ...(node.addressFamilies || []),
      ...(node.risk?.tags || []),
      node.details?.basic?.role,
      ...(node.details?.deep?.sourceReadingOrder || [])
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function searchableTextForEdge(edge) {
    return [
      edge.id,
      edge.label,
      edge.dataType,
      edge.from,
      edge.to,
      ...(edge.sourceFiles || []),
      ...(edge.notes || []),
      ...(edge.addressFamilies || []),
      ...(edge.risk?.tags || [])
    ].filter(Boolean).join(" ").toLowerCase();
  }

  function runSearch(query) {
    const normalized = query.trim().toLowerCase();
    const panel = byId("search-results");
    if (!normalized) {
      panel.hidden = true;
      panel.innerHTML = "";
      return;
    }

    const nodeResults = Object.values(graph.nodes)
      .filter((node) => searchableTextForNode(node).includes(normalized))
      .slice(0, 8)
      .map((node) => ({ type: "node", id: node.id, title: node.label, meta: node.layer }));

    const edgeResults = Object.values(graph.edges)
      .filter((edge) => searchableTextForEdge(edge).includes(normalized))
      .slice(0, 8)
      .map((edge) => ({ type: "edge", id: edge.id, title: edge.label, meta: edge.dataType }));

    const results = [...nodeResults, ...edgeResults].slice(0, 10);
    panel.hidden = false;
    if (results.length === 0) {
      panel.innerHTML = `<p class="muted">No matches. Try a module, file name, risk tag, or address-family term.</p>`;
      return;
    }
    panel.innerHTML = results.map((result) => `
      <button class="search-result-button" type="button" data-result-type="${escapeHtml(result.type)}" data-result-id="${escapeHtml(result.id)}">
        <strong>${escapeHtml(result.title)}</strong><br>
        <span>${escapeHtml(result.type)} · ${escapeHtml(result.meta)}</span>
      </button>
    `).join("");
  }

  function viewContainingItem(type, id) {
    return graph.views.find((view) => {
      if (type === "node") return (view.nodes || []).includes(id);
      if (type === "edge") return (view.edges || []).includes(id);
      return false;
    }) || getView(graph.meta.defaultViewId);
  }
```

- [ ] **Step 3: Update `renderNodes` to optionally show source labels and address badges**

In `renderNodes`, after appending the subtitle and before adding the click listener, insert:

```js
      if (state.toggles.source && node.sourceFiles && node.sourceFiles.length > 0) {
        const source = svgEl("text", { x: 12, y: 68, class: "node-source" });
        source.textContent = node.sourceFiles[0].replace(/^src\//, "src/");
        g.appendChild(source);
      }
      if (node.addressFamilies && node.addressFamilies.length > 0) {
        const family = svgEl("text", { x: 12, y: 84, class: "node-family" });
        family.textContent = node.addressFamilies.join(" / ");
        g.appendChild(family);
      }
```

Then change the rectangle height in that same function from:

```js
      g.appendChild(svgEl("rect", { width: 142, height: 56, rx: 5, ry: 5 }));
```

to:

```js
      g.appendChild(svgEl("rect", { width: 156, height: 96, rx: 5, ry: 5 }));
```

- [ ] **Step 4: Update edge path geometry for wider nodes**

In `edgePath`, change:

```js
    const x1 = fromNode.position.x + 70;
```

to:

```js
    const x1 = fromNode.position.x + 156;
```

- [ ] **Step 5: Add search event handlers**

Inside `bindEvents()`, after the toggle listeners, add:

```js
    byId("graph-search").addEventListener("input", (event) => {
      runSearch(event.target.value);
    });
    byId("search-results").addEventListener("click", (event) => {
      const button = event.target.closest("[data-result-type]");
      if (!button) return;
      const type = button.dataset.resultType;
      const id = button.dataset.resultId;
      const view = viewContainingItem(type, id);
      renderView(view.id);
      if (type === "node") selectNode(id);
      if (type === "edge") selectEdge(id);
    });
```

- [ ] **Step 6: Add CSS for source and address labels**

Append to `.codegraph/assets/styles.css`:

```css
.graph-node .node-source {
  fill: #93c5fd;
  font-size: 9px;
}
.graph-node .node-family {
  fill: #facc15;
  font-size: 9px;
}
.search-result-button span {
  color: var(--muted);
  font-size: 12px;
}
```

- [ ] **Step 7: Run validation**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected:

```text
PASS: codegraph shell and data are valid
```

- [ ] **Step 8: Manually verify search and toggles**

Open `.codegraph/index.html`.

Expected:

- Searching `SessionManager` displays node results.
- Clicking a result selects the node and updates the detail panel.
- Searching `IPv6` displays multiple nodes or edges.
- Turning off `Source` hides source labels on graph nodes.
- Turning off `IPv4` or `IPv6` dims single-family-only elements while preserving the graph.

- [ ] **Step 9: Commit Task 5**

Run:

```bash
git add .codegraph/assets/app.js .codegraph/assets/styles.css
git commit -m "feat: add codegraph search and display toggles"
```

Expected:

```text
[branch <hash>] feat: add codegraph search and display toggles
```

---

### Task 6: Add README and Final Manual Acceptance Guide

**Files:**
- Create: `.codegraph/README.md`

- [ ] **Step 1: Create `.codegraph/README.md`**

Create `.codegraph/README.md` with this exact content:

```markdown
# CLink DataFlow CodeGraph

`index.html` is a static, no-build data-flow guide for CLink.

## Open

Open directly in a modern browser:

```text
.codegraph/index.html
```

No npm install, build step, local server, CDN, or network access is required.

## What this shows

The default Home view is the complete runtime data transmission flowchart:

```text
User / script → clink CLI → IPC → local clinkd daemon
  ├─ SOCKS data path
  ├─ Windows process hook path
  ├─ VirtualInterface / VIF packet path
  ├─ BufferPool / zero-copy receive path
  └─ TCP/TLS transport → remote clinkd daemon → forwarding / observability
```

Focused views break that flow into:

- CLI control endpoint
- IPC control plane
- daemon lifecycle
- TCP/TLS and IPv4/IPv6
- SOCKS forwarding
- Process injection path
- Virtual interface / VIF
- Zero-copy forwarding
- Observability and debugging
- Risk boundary overview
- Source index

## Interaction

- Click a view in the left navigation to switch diagrams.
- Click a node to inspect role, inputs, outputs, source files, risk notes, and debug guidance.
- Click an edge to inspect data type, direction, source anchors, and implementation notes.
- Use `Overview`, `Deep Understanding`, `Source`, `Risk`, and `Debug` tabs in the right panel.
- Search for module names, files, concepts, risk tags, or address-family terms.
- Use top-bar toggles to emphasize control plane, data plane, risk, source labels, IPv4, and IPv6.

## Maintenance

All curated content lives in:

```text
.codegraph/assets/graph-data.js
```

The object assigned to `window.CLINK_GRAPH` must remain JSON-compatible because the validator parses it as JSON after stripping the assignment.

When adding a node:

1. Add an entry under `nodes`.
2. Include `details.basic` and `details.deep`.
3. Add source files and related tests where known.
4. Add risk tags only from the allowed list.
5. Add address families only as `IPv4`, `IPv6`, or `Dual-stack`.
6. Reference the node from one or more views.

When adding an edge:

1. Add an entry under `edges`.
2. Ensure `from` and `to` reference existing node IDs.
3. Set `dataType` to the real transmitted data shape.
4. Add source files and implementation status.
5. Reference the edge from one or more views.

## Optional validation

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected:

```text
PASS: codegraph shell and data are valid
```

The validator checks:

- Required shell files exist.
- `index.html` loads CSS, graph data, and app script.
- Graph data has required top-level keys.
- Views reference existing nodes and edges.
- Edges reference existing endpoints.
- Risk tags and address-family tags use allowed values.
- Core nodes have basic and deep details.
- Home is the default view.
- Banned beginner-label wording is absent.

## IPv4/IPv6 review after transport fixes

This graph represents the intended post-fix dual-stack design. After IPv4/IPv6 fixes land, re-check:

- TCP listen/connect address resolution.
- TLS adapter address-family context.
- SOCKS listener bind and destination handling.
- VIF packet handling for IPv4 and IPv6.
- Logs, metrics, and status payloads for address-family visibility.
- Tests covering IPv4 and IPv6 behavior.

Update `implementationStatus`, `dualStackNotes`, and `postFixReviewPoints` in `graph-data.js` after the source behavior is confirmed.

## Defensive risk wording

Risk content is for defensive source understanding and audit context. Keep it focused on boundaries, data flow, observability, and review points. Do not add operational misuse instructions.
```

- [ ] **Step 2: Run validation**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected:

```text
PASS: codegraph shell and data are valid
```

- [ ] **Step 3: Run a text scan for banned wording and placeholders**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
terms = [''.join(chr(c) for c in [84, 66, 68]), ''.join(chr(c) for c in [84, 79, 68, 79]), ''.join(chr(codepoint) for codepoint in [23567, 30333])]
for path in [*Path('.codegraph').rglob('*'), Path('docs/superpowers/plans/2026-06-12-codegraph-dataflow-implementation.md')]:
    if path.is_file():
        text = path.read_text(encoding='utf-8', errors='ignore')
        for line_number, line in enumerate(text.splitlines(), 1):
            if any(term in line for term in terms):
                print(f'{path}:{line_number}:{line}')
PY
```

Expected:

```text
```

No output.

- [ ] **Step 4: Manual acceptance pass**

Open `.codegraph/index.html` and verify:

- Home is selected by default.
- Home shows the complete project data transmission flowchart.
- Left navigation switches all 12 views.
- Node click opens right-panel details.
- Edge click opens data-path details.
- `Overview` and `Deep Understanding` content exist for core nodes.
- Each major topic has a deep-dive section.
- Search for `SessionManager` works.
- Search for `IPv6` finds dual-stack-related nodes or edges.
- Risk layer toggle works.
- Source label toggle works.
- IPv4 and IPv6 toggles work as emphasis controls.
- No network access is required.
- No npm install or build is required.
- The selected dark technical console style is clear and readable.
- Corners are subtly rounded, not pill-shaped.

- [ ] **Step 5: Commit Task 6**

Run:

```bash
git add .codegraph/README.md
git commit -m "docs: add codegraph maintenance guide"
```

Expected:

```text
[branch <hash>] docs: add codegraph maintenance guide
```

---

### Task 7: Final Verification and Review Prep

**Files:**
- No new files expected.
- Verify: `.codegraph/index.html`, `.codegraph/assets/*.js`, `.codegraph/assets/styles.css`, `.codegraph/README.md`, `.codegraph/tools/validate_graph_data.py`

- [ ] **Step 1: Run graph validator**

Run:

```bash
python3 .codegraph/tools/validate_graph_data.py
```

Expected:

```text
PASS: codegraph shell and data are valid
```

- [ ] **Step 2: Run whitespace check on changed files**

Run:

```bash
git diff --check
```

Expected:

```text
```

No output.

- [ ] **Step 3: Inspect final changed files**

Run:

```bash
git status --short
```

Expected:

```text
```

No uncommitted changes after Task 6 commit. If there are uncommitted edits, review them, validate them, and commit them with a focused message.

- [ ] **Step 4: Review browser acceptance one more time**

Open `.codegraph/index.html`.

Expected:

- The page opens directly under `file://`.
- No visible JavaScript error blocks the page.
- Home graph renders.
- Search and tabs work.
- Focused views render.

- [ ] **Step 5: Prepare final summary**

Report:

```text
Implemented .codegraph static DataFlow UI.
Verified:
- python3 .codegraph/tools/validate_graph_data.py → PASS
- git diff --check → PASS
- Manual browser check of .codegraph/index.html → PASS

Commits:
- feat: scaffold static codegraph shell
- feat: add codegraph home data model
- feat: render codegraph flowchart
- feat: add codegraph detail views
- feat: add codegraph search and display toggles
- docs: add codegraph maintenance guide
```

If manual browser verification was not possible in the environment, report that explicitly instead of claiming it passed.

---

## Self-Review

### Spec coverage

- Static no-build product shape: Tasks 1 and 6.
- Dark technical console style: Task 1 styles, Task 3/5 styling additions.
- Default Home full data-flow flowchart: Tasks 2 and 3.
- Left navigation views: Task 4.
- Right panel tabs: Tasks 1 and 3.
- Manual curated `graph-data.js`: Tasks 2 and 4.
- CLI, IPC, daemon, TCP/TLS, SOCKS, process injection, VIF, zero-copy, observability, risk, source index coverage: Tasks 2 and 4.
- IPv4/IPv6 dual-stack metadata and review points: Tasks 2 and 4.
- Defensive risk expression: Tasks 2 and 4.
- Search and toggles: Task 5.
- README and maintenance guide: Task 6.
- Validation and acceptance: Tasks 1, 2, 6, and 7.

### Placeholder scan

This plan avoids placeholder instructions. Each code-changing step provides exact content or exact insertion snippets with locations.

### Type and naming consistency

- View IDs match navigation and validator references.
- Required home edge IDs match graph data IDs.
- Allowed risk tags and address-family values match spec terminology.
- Detail tab IDs in HTML match `app.js`: `overview`, `deep`, `source`, `risk`, `debug`.
- Toggle IDs in HTML match `app.js`: `control`, `data`, `risk`, `source`, `ipv4`, `ipv6`.
