(() => {
  "use strict";

  const graph = window.CLINK_GRAPH || {};
  const NODE_WIDTH = 154;
  const NODE_HEIGHT = 82;
  const GROUP_PADDING = 24;
  const VIEW_PADDING = 44;
  const VIEWPORT_SCALE_MIN = 0.55;
  const VIEWPORT_SCALE_MAX = 2.6;
  const KIND_ORDER = ["control", "data", "risk", "observe", "config"];
  const TAB_TITLES = {
    overview: "概览",
    deep: "深度理解",
    source: "源码",
    risk: "风险",
    debug: "调试"
  };

  const state = {
    activeViewId: graph.meta?.defaultViewId || graph.views?.[0]?.id || "home",
    activeTab: "overview",
    selected: { type: "view", id: graph.meta?.defaultViewId || graph.views?.[0]?.id || "home" },
    searchQuery: "",
    searchResults: [],
    viewport: { scale: 1, x: 0, y: 0 },
    drag: {
      active: false,
      moved: false,
      startX: 0,
      startY: 0,
      viewportX: 0,
      viewportY: 0
    },
    toggles: {
      control: true,
      data: true,
      risk: true,
      source: true,
      ipv4: true,
      ipv6: true
    }
  };

  const elements = {
    nav: document.querySelector("#view-nav"),
    currentViewLabel: document.querySelector("#current-view-label"),
    title: document.querySelector("#graph-title"),
    description: document.querySelector("#graph-description"),
    badges: document.querySelector("#graph-badges"),
    svg: document.querySelector("#graph-svg"),
    detail: document.querySelector("#detail-content"),
    search: document.querySelector("#graph-search"),
    searchResults: ensureSearchResultsElement(),
    viewportReset: ensureViewportResetElement(),
    tabs: document.querySelectorAll("[data-tab]"),
    toggles: document.querySelectorAll("[data-toggle]")
  };

  function ensureViewportResetElement() {
    const existing = document.querySelector("#reset-graph-view");
    if (existing) {
      return existing;
    }
    const summary = document.querySelector(".graph-summary");
    if (!summary) {
      return null;
    }
    const button = document.createElement("button");
    button.id = "reset-graph-view";
    button.className = "graph-reset-view";
    button.type = "button";
    button.textContent = "重置视图";
    button.setAttribute("aria-label", "重置图谱视图");
    summary.appendChild(button);
    return button;
  }

  function ensureSearchResultsElement() {
    const existing = document.querySelector("#search-results");
    if (existing) {
      return existing;
    }
    const container = document.querySelector(".search-box");
    if (!container) {
      return null;
    }
    const panel = document.createElement("div");
    panel.id = "search-results";
    panel.className = "search-results";
    panel.setAttribute("role", "listbox");
    panel.setAttribute("aria-label", "搜索结果");
    panel.hidden = true;
    container.appendChild(panel);
    return panel;
  }

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      "\"": "&quot;"
    })[character]);
  }

  function attr(value) {
    return escapeHtml(value);
  }

  function getViews() {
    return asArray(graph.views);
  }

  function getNodeMap() {
    return graph.nodes && typeof graph.nodes === "object" && !Array.isArray(graph.nodes) ? graph.nodes : {};
  }

  function getEdgeMap() {
    return graph.edges && typeof graph.edges === "object" && !Array.isArray(graph.edges) ? graph.edges : {};
  }

  function getGroupMap() {
    return graph.groups && typeof graph.groups === "object" && !Array.isArray(graph.groups) ? graph.groups : {};
  }

  function getActiveView() {
    return getViews().find((view) => view.id === state.activeViewId) || getViews()[0] || {
      id: "empty",
      title: "暂无视图",
      description: "当前没有可显示的图谱视图。",
      badges: [],
      nodes: [],
      edges: [],
      groups: [],
      deepDive: { summary: "暂无记录", sections: [] }
    };
  }

  function getViewNodes(view) {
    const nodes = getNodeMap();
    return asArray(view.nodes).map((nodeId) => nodes[nodeId]).filter(Boolean);
  }

  function getViewEdges(view) {
    const edges = getEdgeMap();
    return asArray(view.edges).map((edgeId) => edges[edgeId]).filter(Boolean);
  }

  function getViewGroups(view) {
    const groups = getGroupMap();
    return asArray(view.groups).map((groupId) => groups[groupId]).filter(Boolean);
  }

  function getSelectedItem(view) {
    if (state.selected.type === "node") {
      const node = getNodeMap()[state.selected.id];
      if (node && asArray(view.nodes).includes(node.id)) {
        return { type: "node", item: node };
      }
    }
    if (state.selected.type === "edge") {
      const edge = getEdgeMap()[state.selected.id];
      if (edge && asArray(view.edges).includes(edge.id)) {
        return { type: "edge", item: edge };
      }
    }
    if (state.selected.type === "group") {
      const group = getGroupMap()[state.selected.id];
      if (group && asArray(view.groups).includes(group.id)) {
        return { type: "group", item: group };
      }
    }
    return { type: "view", item: view };
  }

  function kindClass(kind) {
    return `kind-${String(kind || "observe").replace(/[^a-z0-9_-]/gi, "-")}`;
  }

  function markerId(kind) {
    const normalized = KIND_ORDER.includes(kind) ? kind : "observe";
    return `arrow-${normalized}`;
  }

  function truncateText(value, maxUnits) {
    const text = String(value ?? "").trim();
    let usedUnits = 0;
    let output = "";
    for (const character of text) {
      const nextUnits = character.charCodeAt(0) > 127 ? 2 : 1;
      if (usedUnits + nextUnits > Math.max(0, maxUnits - 1)) {
        return `${output}…`;
      }
      usedUnits += nextUnits;
      output += character;
    }
    return output;
  }

  const ADDRESS_FAMILY_LABELS = {
    ipv4: { full: "IPv4", compact: "IPv4" },
    ipv6: { full: "IPv6", compact: "IPv6" },
    "dual-stack": { full: "Dual-stack", compact: "Dual" },
    loopback: { full: "本机回环", compact: "本机" },
    "unix-domain-socket": { full: "Unix Socket", compact: "Unix" },
    "windows-named-pipe": { full: "Windows Named Pipe", compact: "管道" },
    "virtual-adapter": { full: "虚拟网卡", compact: "虚拟" },
    process: { full: "进程边界", compact: "进程" },
    memory: { full: "内存缓冲", compact: "内存" },
    "not-applicable": { full: "不适用", compact: "N/A" }
  };

  function canonicalAddressFamily(entry) {
    const normalized = String(entry || "").trim().toLowerCase().replace(/[\s_]+/g, "-");
    if (!normalized) {
      return "";
    }
    if (normalized === "dual" || normalized === "dualstack") {
      return "dual-stack";
    }
    return normalized;
  }

  function normalizeAddressFamilies(item) {
    const families = [];
    const seen = new Set();
    asArray(item.addressFamilies).forEach((entry) => {
      const family = canonicalAddressFamily(entry);
      if (!family || seen.has(family)) {
        return;
      }
      seen.add(family);
      families.push(family);
    });
    return families;
  }

  function formatAddressFamily(family, mode = "full") {
    const labels = ADDRESS_FAMILY_LABELS[family];
    if (labels && labels[mode]) {
      return labels[mode];
    }
    return String(family || "");
  }

  function networkAddressFamilies(item) {
    const families = new Set();
    normalizeAddressFamilies(item).forEach((family) => {
      if (family === "dual-stack") {
        families.add("ipv4");
        families.add("ipv6");
      } else if (family === "ipv4" || family === "ipv6") {
        families.add(family);
      }
    });
    return [...families];
  }

  function isAddressFamilyDimmed(item) {
    const families = networkAddressFamilies(item);
    if (families.length === 0) {
      return false;
    }
    return families.every((family) => state.toggles[family] === false);
  }

  function safeSvgId(prefix, value, index) {
    const normalized = String(value || "item").replace(/[^A-Za-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
    return `${prefix}-${index}-${normalized || "item"}`;
  }

  function truncateNodeField(field, value) {
    const limits = {
      kind: 13,
      title: 16,
      subtitle: 18,
      source: 13,
      family: 18
    };
    return truncateText(value, limits[field] || 18);
  }

  function sourceLabel(item) {
    const first = asArray(item.sourceFiles).find((entry) => String(entry || "").trim());
    if (!first) {
      return "";
    }
    const parts = String(first).replace(/\\/g, "/").split("/").filter(Boolean);
    return parts[parts.length - 1] || String(first);
  }

  function formatAddressFamilies(item) {
    const families = normalizeAddressFamilies(item);
    if (families.length === 0) {
      return "未标注";
    }
    return families.map((family) => formatAddressFamily(family, "full")).filter(Boolean).join("、");
  }

  function compactAddressFamilies(item) {
    const families = normalizeAddressFamilies(item);
    if (families.length === 0) {
      return "";
    }
    return families.map((family) => formatAddressFamily(family, "compact")).filter(Boolean).join("/");
  }

  function isDimmed(item) {
    const kind = item.kind;
    if ((kind === "control" || kind === "data" || kind === "risk") && state.toggles[kind] === false) {
      return true;
    }
    return isAddressFamilyDimmed(item);
  }

  function classNames(...parts) {
    return parts.filter(Boolean).join(" ");
  }

  function cssAttributeValue(value) {
    return String(value ?? "").replace(/[\\"]/g, "\\$&");
  }

  function collectSearchText(value) {
    const parts = [];
    const visit = (entry) => {
      if (entry === null || entry === undefined) {
        return;
      }
      if (Array.isArray(entry)) {
        entry.forEach(visit);
        return;
      }
      if (typeof entry === "object") {
        Object.keys(entry).forEach((key) => visit(entry[key]));
        return;
      }
      parts.push(String(entry));
    };
    visit(value);
    return parts;
  }

  function firstViewFor(type, id) {
    const key = type === "node" ? "nodes" : type === "edge" ? "edges" : "groups";
    return getViews().find((view) => asArray(view[key]).includes(id)) || getActiveView();
  }

  function searchHaystack(...values) {
    return values.flatMap((value) => collectSearchText(value)).join(" ").toLowerCase();
  }

  function makeSearchEntry(type, item, view) {
    const titles = {
      node: "节点",
      edge: "边",
      view: "视图",
      group: "分组"
    };
    const title = item.label || item.title || item.id;
    const summary = item.summary || item.description || item.dataType || item.implementationStatus || "";
    const familyText = type === "node" || type === "edge" ? formatAddressFamilies(item) : "";
    const haystack = searchHaystack(
      item.id,
      item.label,
      item.title,
      item.description,
      item.summary,
      item.sourceFiles,
      item.tests,
      item.addressFamilies,
      item.risk,
      item.deepDive,
      item.details,
      item.notes,
      item.dataType,
      item.implementationStatus,
      item.badges
    );
    return {
      type,
      id: item.id,
      title: title || item.id,
      typeLabel: titles[type] || type,
      summary,
      familyText,
      viewId: view?.id || item.id,
      viewTitle: view?.title || item.title || item.id,
      haystack
    };
  }

  function buildSearchIndex() {
    const nodes = Object.values(getNodeMap());
    const edges = Object.values(getEdgeMap());
    const groups = Object.values(getGroupMap());
    return [
      ...getViews().map((view) => makeSearchEntry("view", view, view)),
      ...nodes.map((node) => makeSearchEntry("node", node, firstViewFor("node", node.id))),
      ...edges.map((edge) => makeSearchEntry("edge", edge, firstViewFor("edge", edge.id))),
      ...groups.map((group) => makeSearchEntry("group", group, firstViewFor("group", group.id)))
    ];
  }

  function searchGraph(query) {
    const terms = String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length === 0) {
      return [];
    }
    return buildSearchIndex()
      .filter((entry) => terms.every((term) => entry.haystack.includes(term)))
      .slice(0, 30);
  }

  function resetViewport() {
    state.viewport = { scale: 1, x: 0, y: 0 };
  }

  function clampViewportScale(scale) {
    return Math.min(VIEWPORT_SCALE_MAX, Math.max(VIEWPORT_SCALE_MIN, scale));
  }

  function viewportTransform() {
    const { scale, x, y } = state.viewport;
    return `translate(${x} ${y}) scale(${scale})`;
  }

  function applyViewportTransform() {
    if (!elements.svg) {
      return;
    }
    const layer = elements.svg.querySelector(".viewport-layer");
    if (layer) {
      layer.setAttribute("transform", viewportTransform());
    }
  }

  function getSvgPoint(event) {
    if (!elements.svg) {
      return { x: 0, y: 0 };
    }
    const rect = elements.svg.getBoundingClientRect();
    const viewBox = elements.svg.viewBox.baseVal;
    const width = rect.width || 1;
    const height = rect.height || 1;
    return {
      x: viewBox.x + ((event.clientX - rect.left) / width) * viewBox.width,
      y: viewBox.y + ((event.clientY - rect.top) / height) * viewBox.height
    };
  }

  function handleGraphWheel(event) {
    event.preventDefault();
    const point = getSvgPoint(event);
    const previousScale = state.viewport.scale;
    const nextScale = clampViewportScale(previousScale * Math.exp(-event.deltaY * 0.001));
    if (nextScale === previousScale) {
      return;
    }
    const worldX = (point.x - state.viewport.x) / previousScale;
    const worldY = (point.y - state.viewport.y) / previousScale;
    state.viewport.scale = nextScale;
    state.viewport.x = point.x - worldX * nextScale;
    state.viewport.y = point.y - worldY * nextScale;
    applyViewportTransform();
  }

  function renderSearchResults() {
    if (!elements.searchResults) {
      return;
    }
    const query = state.searchQuery.trim();
    if (!query) {
      state.searchResults = [];
      elements.searchResults.hidden = true;
      elements.searchResults.innerHTML = "";
      return;
    }
    state.searchResults = searchGraph(query);
    elements.searchResults.hidden = false;
    if (state.searchResults.length === 0) {
      elements.searchResults.innerHTML = `<div class="search-results__empty">没有找到匹配项。请尝试节点、边、源码路径、测试、风险标签或地址族。</div>`;
      return;
    }
    elements.searchResults.innerHTML = `
      <div class="search-results__status">找到 ${state.searchResults.length} 项</div>
      ${state.searchResults.map((result, index) => `
        <button type="button" class="search-result" data-search-index="${index}" role="option" title="${attr(result.title)}">
          <span class="search-result__type">${escapeHtml(result.typeLabel)}</span>
          <span class="search-result__title">${escapeHtml(result.title)}</span>
          <span class="search-result__meta">${escapeHtml(result.viewTitle)}${result.familyText ? ` · ${escapeHtml(result.familyText)}` : ""}</span>
          ${result.summary ? `<span class="search-result__summary">${escapeHtml(result.summary)}</span>` : ""}
        </button>
      `).join("")}
    `;
  }

  function focusSelectedGraphItem(type, id) {
    if (!elements.svg) {
      return;
    }
    const escapedId = cssAttributeValue(id);
    const selector = type === "node"
      ? `[data-node-id="${escapedId}"]`
      : type === "edge"
        ? `[data-edge-id="${escapedId}"]`
        : type === "group"
          ? `[data-group-id="${escapedId}"]`
          : "";
    const target = selector ? elements.svg.querySelector(selector) : null;
    target?.focus?.({ preventScroll: true });
  }

  function openSearchResult(result) {
    if (!result) {
      return;
    }
    const nextViewId = result.viewId || result.id;
    const viewChanged = state.activeViewId !== nextViewId;
    state.activeViewId = nextViewId;
    state.selected = result.type === "view"
      ? { type: "view", id: result.id }
      : { type: result.type, id: result.id };
    state.activeTab = "overview";
    if (viewChanged) {
      resetViewport();
    }
    render();
    focusSelectedGraphItem(result.type, result.id);
  }


  function renderNavigation() {
    if (!elements.nav) {
      return;
    }

    elements.nav.innerHTML = getViews().map((view) => {
      const isActive = view.id === state.activeViewId ? " is-active" : "";
      const isSelected = state.selected.type === "view" && state.selected.id === view.id ? " is-selected" : "";
      const nodeCount = asArray(view.nodes).length;
      const edgeCount = asArray(view.edges).length;
      return `
        <button type="button" class="${(isActive + isSelected).trim()}" data-view-id="${attr(view.id)}" title="${attr(view.title || view.id)}">
          <span class="view-name">${escapeHtml(view.title || view.id)}</span>
          <span class="view-meta">${nodeCount} 节点 / ${edgeCount} 边</span>
        </button>
      `;
    }).join("");
  }

  function renderViewHeader(view) {
    if (elements.currentViewLabel) {
      elements.currentViewLabel.textContent = view.title || view.id;
    }
    if (elements.title) {
      elements.title.textContent = view.title || "未命名视图";
    }
    if (elements.description) {
      elements.description.textContent = view.description || "";
    }
    if (elements.badges) {
      elements.badges.innerHTML = asArray(view.badges).map((badge) => (
        `<span class="badge" title="${attr(badge)}">${escapeHtml(badge)}</span>`
      )).join("");
    }
  }

  function calculateViewBox(nodes, groups) {
    const boxes = [];
    nodes.forEach((node) => {
      const position = node.position || {};
      boxes.push({
        x: Number(position.x) || 0,
        y: Number(position.y) || 0,
        width: NODE_WIDTH,
        height: NODE_HEIGHT
      });
    });
    groups.forEach((group) => {
      const bounds = group.bounds || {};
      boxes.push({
        x: Number(bounds.x) || 0,
        y: Number(bounds.y) || 0,
        width: Number(bounds.width) || 0,
        height: Number(bounds.height) || 0
      });
    });

    if (boxes.length === 0) {
      return "0 0 900 520";
    }

    const minX = Math.min(...boxes.map((box) => box.x)) - VIEW_PADDING;
    const minY = Math.min(...boxes.map((box) => box.y)) - VIEW_PADDING;
    const maxX = Math.max(...boxes.map((box) => box.x + box.width)) + VIEW_PADDING;
    const maxY = Math.max(...boxes.map((box) => box.y + box.height)) + VIEW_PADDING;
    return `${minX} ${minY} ${Math.max(900, maxX - minX)} ${Math.max(520, maxY - minY)}`;
  }

  function centerOf(node) {
    const position = node.position || {};
    return {
      x: (Number(position.x) || 0) + NODE_WIDTH / 2,
      y: (Number(position.y) || 0) + NODE_HEIGHT / 2
    };
  }

  function edgePath(fromNode, toNode) {
    const from = centerOf(fromNode);
    const to = centerOf(toNode);
    const dx = Math.max(48, Math.abs(to.x - from.x) * 0.45);
    const fromControlX = from.x + (to.x >= from.x ? dx : -dx);
    const toControlX = to.x - (to.x >= from.x ? dx : -dx);
    return `M ${from.x} ${from.y} C ${fromControlX} ${from.y}, ${toControlX} ${to.y}, ${to.x} ${to.y}`;
  }

  function renderMarkers() {
    const colors = {
      control: "var(--control)",
      data: "var(--data)",
      risk: "var(--risk)",
      observe: "var(--observe)",
      config: "var(--config)"
    };
    return `
      <defs>
        ${KIND_ORDER.map((kind) => `
          <marker id="${markerId(kind)}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="${colors[kind]}"></path>
          </marker>
        `).join("")}
      </defs>
    `;
  }

  function renderGroups(groups) {
    return groups.map((group) => {
      const bounds = group.bounds || {};
      const x = Number(bounds.x) || 0;
      const y = Number(bounds.y) || 0;
      const width = Number(bounds.width) || 0;
      const height = Number(bounds.height) || 0;
      const selected = state.selected.type === "group" && state.selected.id === group.id;
      return `
        <g class="${classNames("graph-group", selected && "is-selected")}" data-group-id="${attr(group.id)}" tabindex="0" role="button" aria-label="${attr(group.label || group.id)}">
          <rect x="${x}" y="${y}" width="${width}" height="${height}" rx="8"></rect>
          <text x="${x + GROUP_PADDING}" y="${y + 26}">${escapeHtml(truncateText(group.label || group.id, 34))}</text>
          <title>${escapeHtml(group.summary || group.label || group.id)}</title>
        </g>
      `;
    }).join("");
  }

  function renderEdges(edges, nodesById) {
    return edges.map((edge) => {
      const fromNode = nodesById.get(edge.from);
      const toNode = nodesById.get(edge.to);
      if (!fromNode || !toNode) {
        return "";
      }
      const path = edgePath(fromNode, toNode);
      const from = centerOf(fromNode);
      const to = centerOf(toNode);
      const labelX = (from.x + to.x) / 2;
      const labelY = (from.y + to.y) / 2 - 8;
      const selected = state.selected.type === "edge" && state.selected.id === edge.id;
      const classes = classNames("graph-edge-link", kindClass(edge.kind), isDimmed(edge) && "muted", selected && "is-selected");
      return `
        <g class="${classes}" data-edge-id="${attr(edge.id)}" tabindex="0" role="button" aria-label="${attr(edge.label || edge.id)}">
          <path class="graph-edge-hit" d="${path}"></path>
          <path class="graph-edge" d="${path}" marker-end="url(#${markerId(edge.kind)})"></path>
          <text class="edge-label" x="${labelX}" y="${labelY}" text-anchor="middle">${escapeHtml(truncateText(edge.label || edge.id, 30))}</text>
          <title>${escapeHtml(edge.label || edge.id)}</title>
        </g>
      `;
    }).join("");
  }

  function renderNodes(nodes) {
    return nodes.map((node, index) => {
      const position = node.position || {};
      const x = Number(position.x) || 0;
      const y = Number(position.y) || 0;
      const selected = state.selected.type === "node" && state.selected.id === node.id;
      const classes = classNames("graph-node", kindClass(node.kind), isDimmed(node) && "muted", selected && "is-selected");
      const families = compactAddressFamilies(node);
      const source = state.toggles.source === false ? "" : sourceLabel(node);
      const summary = node.summary || node.implementationStatus || "";
      const clipId = safeSvgId("node-text", node.id, index);
      return `
        <g class="${classes}" transform="translate(${x} ${y})" data-node-id="${attr(node.id)}" tabindex="0" role="button" aria-label="${attr(node.label || node.id)}">
          <defs>
            <clipPath id="${attr(clipId)}">
              <rect x="10" y="7" width="${NODE_WIDTH - 20}" height="${NODE_HEIGHT - 13}" rx="3"></rect>
            </clipPath>
          </defs>
          <rect class="node-card" width="${NODE_WIDTH}" height="${NODE_HEIGHT}" rx="7"></rect>
          <g class="node-text-area" clip-path="url(#${attr(clipId)})">
            <text class="node-kind" x="12" y="18">${escapeHtml(truncateNodeField("kind", node.kind || node.layer || "node"))}</text>
            <text class="node-title" x="12" y="38">${escapeHtml(truncateNodeField("title", node.label || node.id))}</text>
            <text class="node-subtitle" x="12" y="56">${escapeHtml(truncateNodeField("subtitle", summary))}</text>
            ${source ? `<text class="node-source" x="12" y="73">${escapeHtml(truncateNodeField("source", source))}</text>` : ""}
            ${families ? `<text class="node-family-badge" x="${NODE_WIDTH - 12}" y="73" text-anchor="end">${escapeHtml(truncateNodeField("family", families))}</text>` : ""}
          </g>
          <title>${escapeHtml(`${node.label || node.id}
${node.summary || ""}
地址族: ${formatAddressFamilies(node)}${source ? `
源码: ${source}` : ""}`)}</title>
        </g>
      `;
    }).join("");
  }

  function renderSvg(view) {
    if (!elements.svg) {
      return;
    }

    const nodes = getViewNodes(view);
    const edges = getViewEdges(view);
    const groups = getViewGroups(view);
    const nodesById = new Map(nodes.map((node) => [node.id, node]));

    elements.svg.setAttribute("viewBox", calculateViewBox(nodes, groups));
    elements.svg.innerHTML = `
      ${renderMarkers()}
      <g class="viewport-layer" transform="${viewportTransform()}">
        <g class="graph-layer graph-layer-groups">${renderGroups(groups)}</g>
        <g class="graph-layer graph-layer-edges">${renderEdges(edges, nodesById)}</g>
        <g class="graph-layer graph-layer-nodes">${renderNodes(nodes)}</g>
      </g>
    `;
    applyViewportTransform();
  }

  function renderEmptyState() {
    return `<p class="muted">暂无记录。</p>`;
  }

  function renderTextBlock(title, body) {
    const content = asArray(body).length > 0 ? asArray(body).join("、") : body;
    if (!content) {
      return "";
    }
    return `
      <li>
        <strong>${escapeHtml(title)}</strong>
        <span>${escapeHtml(content)}</span>
      </li>
    `;
  }

  function renderEntries(entries) {
    const rows = asArray(entries).filter((entry) => entry && (entry.title || entry.body));
    if (rows.length === 0) {
      return renderEmptyState();
    }

    return `
      <ul class="detail-list">
        ${rows.map((entry) => renderTextBlock(entry.title, entry.body)).join("")}
      </ul>
    `;
  }

  function uniqueEntries(entries) {
    const seen = new Set();
    return asArray(entries).filter((entry) => {
      const key = `${entry.title}\n${entry.body}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  function renderCountList(view) {
    const deepDive = view.deepDive || {};
    const glossaryTermCount = graph.glossary && typeof graph.glossary === "object" && !Array.isArray(graph.glossary)
      ? Object.keys(graph.glossary).length
      : 0;
    return renderEntries([
      { title: "节点", body: `${asArray(view.nodes).length} 个` },
      { title: "边", body: `${asArray(view.edges).length} 条` },
      { title: "分组", body: `${asArray(view.groups).length} 个` },
      { title: "深度说明", body: `${asArray(deepDive.sections).length} 段` },
      { title: "术语", body: `${glossaryTermCount} 项` }
    ]);
  }

  function renderViewOverview(view) {
    return `
      <h2>${escapeHtml(view.title || view.id)}</h2>
      <p>${escapeHtml(view.description || "暂无记录。")}</p>
      ${renderCountList(view)}
      <p>${escapeHtml(view.deepDive?.summary || "暂无记录。")}</p>
    `;
  }

  function renderNodeOverview(node) {
    return `
      <h2>${escapeHtml(node.label || node.id)}</h2>
      <p>${escapeHtml(node.summary || "暂无记录。")}</p>
      ${renderEntries([
        { title: "类型", body: node.kind },
        { title: "层级", body: node.layer },
        { title: "状态", body: node.implementationStatus },
        { title: "输入", body: asArray(node.inputs).join("、") },
        { title: "输出", body: asArray(node.outputs).join("、") },
        { title: "地址族", body: formatAddressFamilies(node) }
      ])}
    `;
  }

  function renderGroupOverview(group) {
    const groupNodes = asArray(group.nodes).map((nodeId) => getNodeMap()[nodeId]).filter(Boolean);
    return `
      <h2>${escapeHtml(group.label || group.id)}</h2>
      <p>${escapeHtml(group.summary || "暂无记录。")}</p>
      ${renderEntries([
        { title: "分组 ID", body: group.id },
        { title: "节点数量", body: `${groupNodes.length} 个` },
        { title: "包含节点", body: groupNodes.map((node) => node.label || node.id).join("、") }
      ])}
    `;
  }

  function renderEdgeOverview(edge) {
    const fromLabel = getNodeMap()[edge.from]?.label || edge.from;
    const toLabel = getNodeMap()[edge.to]?.label || edge.to;
    return `
      <h2>${escapeHtml(edge.label || edge.id)}</h2>
      ${renderEntries([
        { title: "路径", body: `${fromLabel} → ${toLabel}` },
        { title: "类型", body: edge.kind },
        { title: "数据", body: edge.dataType },
        { title: "状态", body: edge.implementationStatus },
        { title: "地址族", body: formatAddressFamilies(edge) },
        { title: "说明", body: asArray(edge.notes).join("、") }
      ])}
    `;
  }

  function renderOverview(selected) {
    if (selected.type === "node") {
      return renderNodeOverview(selected.item);
    }
    if (selected.type === "edge") {
      return renderEdgeOverview(selected.item);
    }
    if (selected.type === "group") {
      return renderGroupOverview(selected.item);
    }
    return renderViewOverview(selected.item);
  }

  function renderDeep(selected) {
    if (selected.type === "view") {
      const deepDive = selected.item.deepDive || {};
      const sectionEntries = asArray(deepDive.sections).map((section) => ({
        title: section.title,
        body: section.body
      }));
      return renderEntries(sectionEntries);
    }

    if (selected.type === "group") {
      return renderEntries([
        { title: "分组说明", body: selected.item.summary },
        { title: "节点", body: asArray(selected.item.nodes).join("、") }
      ]);
    }

    if (selected.type === "node") {
      const basic = selected.item.details?.basic || {};
      const deep = selected.item.details?.deep || {};
      return renderEntries([
        { title: "职责", body: basic.role },
        { title: "接收", body: basic.receives },
        { title: "发出", body: basic.emits },
        { title: "存在原因", body: basic.whyItExists },
        { title: "数据流", body: deep.dataFlow },
        { title: "运行行为", body: deep.runtimeBehavior },
        { title: "IPv4 / IPv6 说明", body: deep.ipv4Ipv6Notes }
      ]);
    }

    return renderEntries([
      { title: "数据", body: selected.item.dataType },
      { title: "说明", body: asArray(selected.item.notes).join("、") },
      { title: "状态", body: selected.item.implementationStatus }
    ]);
  }

  function renderSource(selected, view) {
    if (selected.type === "view") {
      return renderEntries(uniqueEntries(getViewNodes(view).map((node) => ({
        title: node.label || node.id,
        body: asArray(node.sourceFiles).join("、")
      }))));
    }
    if (selected.type === "group") {
      const groupNodes = asArray(selected.item.nodes).map((nodeId) => getNodeMap()[nodeId]).filter(Boolean);
      return renderEntries(uniqueEntries(groupNodes.map((node) => ({
        title: node.label || node.id,
        body: asArray(node.sourceFiles).join("、")
      }))));
    }
    return renderEntries([
      { title: selected.item.label || selected.item.id, body: asArray(selected.item.sourceFiles).join("、") },
      { title: "代码路径", body: selected.item.details?.deep?.codePath }
    ]);
  }

  function renderRisk(selected, view) {
    if (selected.type === "view") {
      const nodeRisks = getViewNodes(view).map((node) => ({
        title: node.label || node.id,
        body: asArray(node.risk).join("、")
      }));
      const edgeRisks = getViewEdges(view).map((edge) => ({
        title: edge.label || edge.id,
        body: asArray(edge.risk).join("、")
      }));
      return renderEntries(uniqueEntries([...nodeRisks, ...edgeRisks]));
    }

    if (selected.type === "group") {
      const groupNodes = asArray(selected.item.nodes).map((nodeId) => getNodeMap()[nodeId]).filter(Boolean);
      return renderEntries(uniqueEntries(groupNodes.map((node) => ({
        title: node.label || node.id,
        body: asArray(node.risk).join("、")
      }))));
    }

    return renderEntries([
      { title: "风险标签", body: asArray(selected.item.risk).join("、") },
      { title: "失败模式", body: selected.item.details?.deep?.failureModes }
    ]);
  }

  function renderDebug(selected, view) {
    if (selected.type === "view") {
      return renderEntries(uniqueEntries(getViewNodes(view).map((node) => ({
        title: node.label || node.id,
        body: asArray(node.tests).join("、") || node.details?.deep?.debugSignals
      }))));
    }
    if (selected.type === "group") {
      const groupNodes = asArray(selected.item.nodes).map((nodeId) => getNodeMap()[nodeId]).filter(Boolean);
      return renderEntries(uniqueEntries(groupNodes.map((node) => ({
        title: node.label || node.id,
        body: asArray(node.tests).join("、") || node.details?.deep?.debugSignals
      }))));
    }

    return renderEntries([
      { title: "测试", body: asArray(selected.item.tests).join("、") },
      { title: "诊断信号", body: selected.item.details?.deep?.debugSignals },
      { title: "说明", body: asArray(selected.item.notes).join("、") }
    ]);
  }

  function renderTabContent(selected, view) {
    if (state.activeTab === "deep") {
      return renderDeep(selected, view);
    }
    if (state.activeTab === "source") {
      return renderSource(selected, view);
    }
    if (state.activeTab === "risk") {
      return renderRisk(selected, view);
    }
    if (state.activeTab === "debug") {
      return renderDebug(selected, view);
    }
    return renderOverview(selected);
  }

  function renderDetail(view) {
    if (!elements.detail) {
      return;
    }

    const selected = getSelectedItem(view);
    const heading = state.activeTab === "overview" ? "" : `<h2>${escapeHtml(TAB_TITLES[state.activeTab] || state.activeTab)}</h2>`;
    elements.detail.innerHTML = `${heading}${renderTabContent(selected, view)}`;
  }

  function renderTabs() {
    elements.tabs.forEach((tab) => {
      const isActive = tab.dataset.tab === state.activeTab;
      tab.classList.toggle("is-active", isActive);
      tab.setAttribute("aria-selected", String(isActive));
      if (TAB_TITLES[tab.dataset.tab]) {
        tab.textContent = TAB_TITLES[tab.dataset.tab];
      }
    });
  }

  function renderToggles() {
    elements.toggles.forEach((toggle) => {
      const key = toggle.dataset.toggle;
      const active = state.toggles[key] !== false;
      toggle.setAttribute("aria-pressed", String(active));
    });
  }

  function render() {
    const view = getActiveView();
    state.activeViewId = view.id;
    if (!state.selected.id || (state.selected.type === "view" && state.selected.id !== view.id)) {
      state.selected = { type: "view", id: view.id };
    }
    renderNavigation();
    renderViewHeader(view);
    renderSvg(view);
    renderTabs();
    renderToggles();
    renderDetail(view);
    renderSearchResults();
  }

  function selectView(viewId) {
    const viewChanged = state.activeViewId !== viewId;
    state.activeViewId = viewId;
    state.selected = { type: "view", id: viewId };
    state.activeTab = "overview";
    if (viewChanged) {
      resetViewport();
    }
    render();
  }

  function bindEvents() {
    elements.nav?.addEventListener("click", (event) => {
      const button = event.target.closest("[data-view-id]");
      if (!button) {
        return;
      }
      selectView(button.dataset.viewId);
    });

    elements.svg?.addEventListener("click", (event) => {
      if (state.drag.moved) {
        state.drag.moved = false;
        return;
      }
      const nodeTarget = event.target.closest("[data-node-id]");
      const edgeTarget = event.target.closest("[data-edge-id]");
      const groupTarget = event.target.closest("[data-group-id]");
      if (nodeTarget) {
        state.selected = { type: "node", id: nodeTarget.dataset.nodeId };
      } else if (edgeTarget) {
        state.selected = { type: "edge", id: edgeTarget.dataset.edgeId };
      } else if (groupTarget) {
        state.selected = { type: "group", id: groupTarget.dataset.groupId };
      } else {
        state.selected = { type: "view", id: state.activeViewId };
      }
      render();
    });

    elements.svg?.addEventListener("wheel", handleGraphWheel, { passive: false });

    elements.svg?.addEventListener("pointerdown", (event) => {
      if (event.button !== 0 || event.target !== elements.svg) {
        return;
      }
      const point = getSvgPoint(event);
      state.drag = {
        active: true,
        moved: false,
        startX: point.x,
        startY: point.y,
        viewportX: state.viewport.x,
        viewportY: state.viewport.y
      };
      elements.svg.classList.add("is-panning");
      elements.svg.setPointerCapture?.(event.pointerId);
      event.preventDefault();
    });

    elements.svg?.addEventListener("pointermove", (event) => {
      if (!state.drag.active) {
        return;
      }
      const point = getSvgPoint(event);
      const dx = point.x - state.drag.startX;
      const dy = point.y - state.drag.startY;
      if (Math.abs(dx) > 1 || Math.abs(dy) > 1) {
        state.drag.moved = true;
      }
      state.viewport.x = state.drag.viewportX + dx;
      state.viewport.y = state.drag.viewportY + dy;
      applyViewportTransform();
      event.preventDefault();
    });

    const stopPanning = (event) => {
      if (!state.drag.active) {
        return;
      }
      state.drag.active = false;
      elements.svg?.classList.remove("is-panning");
      if (event?.pointerId !== undefined && elements.svg?.hasPointerCapture?.(event.pointerId)) {
        elements.svg.releasePointerCapture(event.pointerId);
      }
      if (state.drag.moved) {
        window.setTimeout(() => {
          state.drag.moved = false;
        }, 0);
      }
    };

    elements.svg?.addEventListener("pointerup", stopPanning);
    elements.svg?.addEventListener("pointercancel", stopPanning);
    elements.svg?.addEventListener("pointerleave", stopPanning);

    elements.svg?.addEventListener("dblclick", (event) => {
      if (event.target !== elements.svg) {
        return;
      }
      resetViewport();
      applyViewportTransform();
    });

    elements.viewportReset?.addEventListener("click", () => {
      resetViewport();
      applyViewportTransform();
    });

    elements.svg?.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") {
        return;
      }
      const nodeTarget = event.target.closest("[data-node-id]");
      const edgeTarget = event.target.closest("[data-edge-id]");
      const groupTarget = event.target.closest("[data-group-id]");
      if (!nodeTarget && !edgeTarget && !groupTarget) {
        return;
      }
      event.preventDefault();
      state.selected = nodeTarget
        ? { type: "node", id: nodeTarget.dataset.nodeId }
        : edgeTarget
          ? { type: "edge", id: edgeTarget.dataset.edgeId }
          : { type: "group", id: groupTarget.dataset.groupId };
      render();
    });

    elements.search?.addEventListener("input", () => {
      state.searchQuery = elements.search.value;
      renderSearchResults();
    });

    elements.search?.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        elements.search.value = "";
        state.searchQuery = "";
        renderSearchResults();
      }
    });

    elements.searchResults?.addEventListener("click", (event) => {
      const button = event.target.closest("[data-search-index]");
      if (!button) {
        return;
      }
      openSearchResult(state.searchResults[Number(button.dataset.searchIndex)]);
    });

    elements.tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        state.activeTab = tab.dataset.tab;
        render();
      });
    });

    elements.toggles.forEach((toggle) => {
      toggle.addEventListener("click", () => {
        const key = toggle.dataset.toggle;
        state.toggles[key] = state.toggles[key] === false;
        render();
      });
    });
  }

  bindEvents();
  render();
})();
