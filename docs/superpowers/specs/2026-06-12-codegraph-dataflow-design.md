# CLink `.codegraph` DataFlow Design

Date: 2026-06-12

## 1. Purpose

`.codegraph` is a static, interactive data-flow and source-understanding interface for CLink. It is intended to help a first-time reader quickly build a correct mental model of the project, then progressively drill down into source-level runtime behavior.

The page must explain:

- The relationship between `clink` and `clinkd`.
- The separation between the control plane and data plane.
- The full runtime data paths for CLI control, IPC, daemon lifecycle, TCP/TLS sessions, SOCKS forwarding, process injection, virtual interface forwarding, zero-copy buffers, and observability.
- The intended post-fix IPv4/IPv6 dual-stack architecture.
- Security-sensitive boundaries from a defensive understanding and audit perspective.
- Source entry points and reading paths for deeper study.

This is not an automatically generated file dependency graph. It is a manually curated runtime data-flow guide based on source-code analysis.

## 2. Product Shape

The deliverable lives under `.codegraph` and is opened directly in a browser:

```text
.codegraph/
  index.html
  README.md
  assets/
    styles.css
    app.js
    graph-data.js
```

Constraints:

- No npm dependency.
- No build step.
- No local server requirement.
- No CDN dependency.
- No integration with the C++ build.
- Works from `file://` by opening `.codegraph/index.html`.
- Uses plain HTML, CSS, JavaScript, and SVG.
- Loads graph data through a normal script tag, not through `fetch()`.

`graph-data.js` exposes:

```js
window.CLINK_GRAPH = {
  meta: {},
  views: [],
  nodes: {},
  edges: {},
  groups: {},
  legends: {},
  glossary: {}
};
```

## 3. Visual Direction

The selected visual direction is a dark technical console style.

Design traits:

- Dark professional background.
- Network/security analysis dashboard feel.
- Restrained, near-rectangular corners with only subtle rounding.
- Minimal decoration.
- High information clarity.
- Strong visual hierarchy.
- No oversized rounded cards, playful UI, or excessive gradients.

Color semantics:

| Color family | Meaning |
|---|---|
| Purple | Control plane |
| Blue / cyan | Network data plane |
| Orange | Sensitive, privilege, injection, or trust boundary |
| Green | Observability, logs, metrics, heartbeat |
| Gray | Configuration, platform dependency, external dependency |

The UI and documentation must avoid condescending beginner-label wording. Use neutral wording such as “入门视角”, “基础解释”, “快速理解”, “首次阅读者”, or “学习路径” when needed.

## 4. Page Layout

The page uses a three-column application layout:

```text
┌────────────────────────────────────────────────────────────────────┐
│ Top bar: CLink DataFlow / current view / search / display toggles   │
├───────────────┬──────────────────────────────────────┬─────────────┤
│ Navigation     │ Central SVG flow canvas              │ Detail panel │
│ - Home         │ Global flow or selected detail view   │ Overview     │
│ - CLI          │                                      │ Deep dive    │
│ - IPC          │                                      │ Source       │
│ - daemon       │                                      │ Risk         │
│ - TCP/TLS      │                                      │ Debug        │
│ - SOCKS        │                                      │              │
│ - Injection    │                                      │              │
│ - VIF          │                                      │              │
│ - Zero-copy    │                                      │              │
│ - Observability│                                      │              │
│ - Risk         │                                      │              │
│ - Source index │                                      │              │
└───────────────┴──────────────────────────────────────┴─────────────┘
```

The detail panel uses tabs:

```text
Overview | Deep Understanding | Source | Risk | Debug
```

Tab roles:

- **Overview**: concise role, input, output, and why the module exists.
- **Deep Understanding**: source-level runtime behavior and module collaboration.
- **Source**: files, functions or classes where known, reading order, and tests.
- **Risk**: defensive audit notes and sensitive boundaries.
- **Debug**: status, logs, metrics, environment flags, and review checklist.

## 5. Default Home View

Opening `.codegraph/index.html` must show the default view:

```text
Home: Global Data Flow
```

Home is not a welcome page. It is the complete project-wide data transmission flowchart.

The home flowchart must show the full runtime path:

```text
User / script
  │
  ▼
clink CLI
  │ IPC command envelope
  ▼
Local clinkd daemon
  ├─ Application state machine
  ├─ IPC server
  ├─ Configuration / logging / metrics
  ├─ SOCKS server
  ├─ ProcessManager
  ├─ Process inject / Hook IPC
  ├─ VirtualInterface / Wintun
  ├─ BufferPool / zero-copy
  └─ SessionManager
        │ TCP/TLS session frames
        │ IPv4 / IPv6 / Dual-stack
        ▼
Remote clinkd daemon
  ├─ Transport listener
  ├─ Auth / ACL / policy
  ├─ SessionManager
  ├─ Forwarding
  ├─ Reliability engine
  └─ Telemetry / logs / metrics
```

The central drawing should use flowchart-style arrows, not a force-directed graph. Layout is manually curated with SVG coordinates so the full path remains readable and stable.

Home edge labels must include concrete data types, including:

- `IPC command envelope`
- `TCP/TLS session frames`
- `SOCKS5 TCP stream`
- `hooked socket payload`
- `virtual NIC packet`
- `BufferPool block`
- `telemetry event`
- `structured log`

Home must support clicking any major node to show details and an “enter detail view” action for the related topic.

## 6. Navigation Views

The first version includes these left-navigation views:

1. Home: global data flow
2. CLI control endpoint
3. IPC control plane
4. daemon lifecycle
5. TCP/TLS and IPv4/IPv6
6. SOCKS forwarding
7. Process injection path
8. Virtual interface / VIF
9. Zero-copy forwarding
10. Observability and debugging
11. Risk boundary overview
12. Source index

Each view contains:

- A focused SVG flowchart.
- A topic summary.
- Key nodes.
- Key edges.
- Source entry points.
- Current implementation notes.
- Post-fix target behavior.
- Deep-understanding content.

## 7. Topic Coverage

### 7.1 CLI Control Endpoint

Flow:

```text
User command
  ▼
clink main.cpp
  ▼
argument / config / IPC address resolution
  ▼
IPC client
  ▼
framed JSON envelope
  ▼
clinkd IPC server
```

Must explain:

- Why `clink` controls the local daemon rather than directly carrying the remote data session.
- How commands such as `connect`, `status`, and `disconnect` map to IPC payloads.
- How status rendering and exit-code behavior relate to control-plane responses.
- How IPv4/IPv6 command or config values eventually affect transport setup.

Key source anchors:

- `src/client/main.cpp`
- `src/client/core/application/application.cpp`
- `src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md`
- `src/share/include/clink/protocol/control_plane.hpp`
- `src/share/include/clink/protocol/ipc_wire.hpp`

### 7.2 IPC Control Plane

Flow:

```text
CLI request
  ▼
IPC framing
  ▼
JSON envelope
  ▼
daemon command dispatch
  ▼
structured response
```

Must explain:

- The shared control-plane contract.
- Envelope shape and structured error behavior.
- Why automation should branch on `data.status` and `data.reason` rather than free-form text.
- IPC producer and consumer roles.

### 7.3 daemon Lifecycle

Flow:

```text
main.cpp
  ▼
load configuration
  ▼
Application
  ▼
module registry
  ├─ heartbeat
  ├─ metrics
  ├─ SOCKS server
  ├─ ProcessManager
  └─ transport listener
```

Must explain:

- Startup sequence.
- Configuration loading.
- Module registration.
- Shutdown sequence.
- Runtime flags such as `CLINK_DISABLE_VIF` and `CLINK_DISABLE_PROCESS_MANAGER`.

### 7.4 TCP/TLS and IPv4/IPv6

Target post-fix flow:

```text
connect request
  │ host + port + transport
  ▼
address resolution
  ├─ IPv4 candidate
  ├─ IPv6 candidate
  └─ dual-stack policy
  ▼
TCP connect/listen
  ▼
TLS handshake
  ▼
SessionManager
```

Must explain:

- Address family is a transport dimension, not a separate business module.
- The home view remains unified and marks transport edges with IPv4/IPv6/Dual-stack metadata.
- Current-source observations that differ from the intended dual-stack target must be explicitly marked as current implementation notes.
- Post-fix verification should revisit TCP adapter, TLS adapter, SOCKS listener, virtual interface, logging, and status payloads.

Key source anchors:

- `src/server/core/network/tcp_adapter.*`
- `src/server/core/network/tls_adapter.*`
- `src/client/core/network/tls_adapter.*`
- `src/share/core/network/tls_helpers.*`

### 7.5 SOCKS Forwarding

Flow:

```text
Local application
  ▼
SOCKS5 TCP stream
  ▼
SOCKS server
  ▼
Proxy session / ProcessManager
  ▼
SessionManager
  ▼
TLS transport
```

Must explain:

- SOCKS as an explicit local proxy entry point.
- Difference between SOCKS and process injection.
- Listener boundary and address-family implications.
- Access-control and local exposure considerations.

Key source anchors:

- `src/server/modules/socks_server/socks_server.*`
- `src/server/modules/process_manager/process_manager.*`
- `src/server/modules/process_manager/ipc_proxy_session.hpp`
- `tests/server/socks_server_test.cpp`

### 7.6 Process Injection Path

This view must use defensive and source-understanding wording. It should explain internal data flow and boundaries without giving reusable offensive procedure.

Flow:

```text
Target process
  ▼
socket/connect/send/recv API boundary
  ▼
Hook DLL / MinHook
  ▼
Hook IPC protocol
  ▼
Process IPC server
  ▼
ProcessManager
  ▼
SessionManager
```

Must explain:

- Windows-only nature.
- `CLINK_BUILD_CLIENT_HOOK` build gating.
- DLL entry, hook manager, process injector, process IPC server, and protocol roles.
- Process boundary, privilege boundary, IPC boundary, platform boundary, and build-option boundary.
- Which data enters the daemon from injected-process paths.

Key source anchors:

- `src/server/modules/process_inject/include/*`
- `src/server/modules/process_inject/src/*`
- `src/client/modules/process_inject/include/*`
- `src/client/modules/process_inject/src/*`
- `src/share/core/ipc/hook_ipc_protocol.hpp`
- `tests/server/dll_integration_test.cpp`

### 7.7 Virtual Interface / VIF

Flow:

```text
OS network stack
  ▼
route-selected traffic
  ▼
Wintun / VIF
  ▼
VirtualInterface read/write loop
  ▼
Packet codec
  ▼
SessionManager
  ▼
TLS transport
```

Must explain:

- Why VIF requires elevated privileges.
- Windows Wintun dependency.
- Effect of `CLINK_DISABLE_VIF=1`.
- IPv4 and IPv6 packet handling as data labels and metadata, not duplicated home graphs.

Key source anchors:

- `src/server/core/network/virtual_interface.*`
- `src/share/core/network/packet.*`
- `external/wintun/README.md`

### 7.8 Zero-copy Forwarding

Flow:

```text
TLS adapter receive
  ▼
BufferPool::Block
  ▼
ZeroCopyReceiveCallback
  ▼
SessionManager / forwarding target
```

Must explain:

- What zero-copy means in this project context.
- How `BufferPool::Block` reduces copying.
- Which paths are currently supported and which are target behavior.
- Performance implications and tests.

Key source anchors:

- `src/server/core/memory/buffer_pool.hpp`
- `src/server/core/network/tls_adapter.*`
- `src/client/core/network/tls_adapter.*`
- `tests/network/zero_copy_test.cpp`

### 7.9 Observability and Debugging

Flow:

```text
daemon modules
  ├─ structured logs
  ├─ telemetry spans
  ├─ heartbeat
  └─ metrics
       ▼
logs / CLI monitor / status payload
```

Must explain:

- Where runtime state is surfaced.
- How connection failures flow back to CLI status.
- How logs, metrics, heartbeat, and telemetry relate to data-plane paths.
- Which environment variables change observability behavior.

Key source anchors:

- `src/server/modules/metrics/*`
- `src/server/modules/heartbeat/*`
- `src/server/core/observability/telemetry.*`
- `src/share/core/logging/*`

## 8. Two-level Understanding Model

Each core node and each major topic must support two levels of explanation:

```text
Overview: quick mental model
Deep Understanding: source-level runtime expansion
```

### 8.1 Node Details

Nodes include:

```js
details: {
  basic: {
    role: "",
    receives: [],
    emits: [],
    whyItExists: ""
  },
  deep: {
    runtimeResponsibilities: [],
    lifecycle: [],
    dataStructures: [],
    threadingModel: [],
    collaborations: [],
    stateTransitions: [],
    errorPaths: [],
    platformNotes: [],
    dualStackNotes: [],
    securityBoundaries: [],
    performanceNotes: [],
    sourceReadingOrder: [],
    relatedTests: [],
    currentImplementationNotes: [],
    postFixReviewPoints: []
  }
}
```

### 8.2 View Deep Dive

Views include:

```js
deepDive: {
  purpose: "",
  runtimeFlow: [],
  moduleComposition: [],
  sourceReadingPath: [],
  importantStates: [],
  edgeCases: [],
  riskBoundaries: [],
  debuggingChecklist: [],
  dualStackReview: [],
  testsToRead: []
}
```

The deep-understanding layer is a core acceptance requirement, not a later optional enhancement.

Deep-understanding content must include, where applicable:

- Runtime responsibilities.
- Lifecycle.
- Input and output data structures.
- Threading or asynchronous model.
- Collaborating modules.
- State transitions.
- Error paths.
- Platform differences.
- IPv4/IPv6 impact.
- Security and trust boundaries.
- Performance considerations.
- Source reading order.
- Related tests.
- Current implementation notes.
- Post-fix review points.

## 9. Interaction Design

### 9.1 View Switching

Clicking a navigation item changes the central flowchart and updates the right detail panel.

### 9.2 Node Selection

Clicking a node:

- Selects and highlights the node.
- Highlights directly related edges.
- Opens details in the right panel.
- Preserves current view context.

### 9.3 Edge Selection

Clicking an edge shows:

- Data type.
- Direction.
- Protocol or format.
- Related source files.
- Address-family metadata.
- Risk notes.
- Current and target behavior notes.

### 9.4 Path Highlighting

Selecting a topic highlights related nodes and edges while dimming unrelated elements. The graph must preserve enough context to keep the selected path understandable.

### 9.5 Search

Search supports:

- Module names, such as `SessionManager`.
- File names, such as `tls_adapter.cpp`.
- Concepts, such as `zero-copy`.
- Risk tags, such as `injection-boundary`.
- Address-family terms, such as `IPv6`.

### 9.6 Display Toggles

Top-bar toggles:

- Control plane.
- Data plane.
- Risk layer.
- Source labels.
- IPv4.
- IPv6.

Toggles control visibility or emphasis. They must not mutate underlying graph data.

## 10. Data Model

### 10.1 Node Fields

```js
{
  id,
  label,
  kind,
  layer,
  position,
  summary,
  inputs,
  outputs,
  sourceFiles,
  tests,
  addressFamilies,
  risk,
  implementationStatus,
  details
}
```

### 10.2 Edge Fields

```js
{
  id,
  from,
  to,
  label,
  kind,
  dataType,
  addressFamilies,
  sourceFiles,
  notes,
  risk,
  implementationStatus
}
```

### 10.3 Implementation Status

Use implementation status to distinguish current source observations from the intended post-fix target.

Recommended values:

```text
stable-current
current-source-observed
partial-current
post-fix-target
needs-recheck
windows-only
linux-only
test-covered
```

Example:

```js
implementationStatus: {
  current: "partial-current",
  target: "post-fix-target",
  confidence: "needs-recheck",
  note: "Recheck after IPv4/IPv6 dual-stack fixes are complete."
}
```

## 11. IPv4/IPv6 Dual-stack Handling

The graph targets the intended post-bugfix dual-stack design.

Rules:

- Do not duplicate the home flow into separate IPv4 and IPv6 graphs.
- Treat address family as node and edge metadata.
- Mark transport edges with IPv4 / IPv6 / Dual-stack badges.
- Detail views may compare IPv4 and IPv6 behavior where it clarifies implementation.
- Current-source discrepancies must be marked as implementation notes, not treated as final architecture.

Dual-stack review areas:

- TCP listen/connect address resolution.
- TLS adapter address-family context.
- SOCKS listener address-family behavior.
- VIF packet handling.
- Logs and metrics address-family visibility.
- Control-plane status payloads.
- IPv4 and IPv6 test coverage.

## 12. Risk Expression

Risk expression is limited to defensive understanding and source audit context.

Risk tags:

```text
privilege-boundary
injection-boundary
untrusted-input
local-listener
remote-listener
config-sensitive
credential-sensitive
platform-specific
observability-critical
```

Risk details should explain:

- Why the node or edge is sensitive.
- What data crosses the boundary.
- What permissions or trust assumptions exist.
- Which logs, metrics, config, or tests help review it.

Risk details must not include operational steps that would enable misuse outside authorized defensive analysis.

## 13. Error Handling

Because `.codegraph` is static, error handling covers graph-data quality and UI interactions.

Expected behavior:

- Missing node or edge references do not crash the page.
- Missing data renders an explicit “data pending” state.
- The browser console logs warnings for invalid references.
- Empty views render a clear empty state.
- Search with no result shows a clear message.
- The page does not rely on `fetch()` so it works from `file://`.

## 14. Validation and Acceptance

### 14.1 Manual Acceptance

Acceptance checklist:

- `.codegraph/index.html` opens directly in a modern browser.
- Home is selected by default.
- Home shows the complete project data transmission flowchart.
- Left navigation switches all views.
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
- The UI and docs avoid condescending beginner-label wording.

### 14.2 Data Integrity Checks

A future optional validator may live at `.codegraph/tools/validate-graph-data.mjs`. The first implementation should not require it to open the page.

Potential checks:

- All view references point to existing nodes and edges.
- All `edge.from` and `edge.to` values reference existing nodes.
- All risk tags are from the allowed list.
- All address-family tags are from `IPv4`, `IPv6`, or `Dual-stack`.
- Home view exists and is the default.
- Core nodes have `details.basic` and `details.deep`.
- Major views have `deepDive` content.

## 15. Source Analysis Scope Before Implementation

Before filling `graph-data.js`, perform source analysis across at least:

```text
src/client/main.cpp
src/client/core/application/application.cpp
src/server/main.cpp
src/server/core/application/application.cpp
src/server/core/network/session_manager.*
src/server/core/network/tcp_adapter.*
src/server/core/network/tls_adapter.*
src/client/core/network/tls_adapter.*
src/server/core/network/virtual_interface.*
src/server/core/memory/buffer_pool.hpp
src/server/modules/socks_server/*
src/server/modules/process_manager/*
src/server/modules/process_inject/*
src/client/modules/process_inject/*
src/share/include/clink/protocol/*
src/share/core/ipc/*
src/share/core/network/packet.*
tests/network/zero_copy_test.cpp
tests/server/socks_server_test.cpp
tests/server/ipc_proxy_test.cpp
tests/server/dll_integration_test.cpp
```

The source pass must separate:

- Observed current implementation.
- Intended post-fix dual-stack target.
- Windows-only behavior.
- Linux-only behavior.
- Test-covered behavior.
- Behavior that needs review after bug fixes land.

## 16. Out of Scope for First Version

The first version does not include:

- Automatic C++ parsing.
- Live runtime tracing.
- npm-based build tooling.
- Remote dashboard hosting.
- Mutation of project source code outside `.codegraph` and the design/spec docs.
- Offensive procedure documentation.

## 17. Open Implementation Notes

Implementation should proceed incrementally:

1. Build static shell and theme.
2. Render the default home flowchart from curated graph data.
3. Add node and edge selection.
4. Add detail panel tabs.
5. Add navigation views.
6. Add search and toggles.
7. Fill deep-understanding content from source analysis.
8. Validate against acceptance checklist.

The implementation plan should be written only after this spec is reviewed and approved.
