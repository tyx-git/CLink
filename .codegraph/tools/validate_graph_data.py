#!/usr/bin/env python3
"""Validate the static .codegraph shell and graph data contract."""

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = [
    ROOT / "index.html",
    ROOT / "assets" / "styles.css",
    ROOT / "assets" / "graph-data.js",
    ROOT / "assets" / "app.js",
]
REQUIRED_ASSETS = [
    "assets/graph-data.js",
    "assets/app.js",
    "assets/styles.css",
]
REQUIRED_GRAPH_KEYS = {
    "meta",
    "views",
    "nodes",
    "edges",
    "groups",
    "legends",
    "glossary",
}
REQUIRED_NODE_FIELDS = {
    "id",
    "label",
    "kind",
    "layer",
    "position",
    "summary",
    "inputs",
    "outputs",
    "sourceFiles",
    "tests",
    "addressFamilies",
    "risk",
    "implementationStatus",
    "details",
}
REQUIRED_EDGE_FIELDS = {
    "id",
    "from",
    "to",
    "label",
    "kind",
    "dataType",
    "addressFamilies",
    "sourceFiles",
    "notes",
    "risk",
    "implementationStatus",
}
REQUIRED_GROUP_FIELDS = {
    "id",
    "label",
    "summary",
    "nodes",
    "bounds",
}
REQUIRED_BASIC_DETAIL_FIELDS = {
    "role",
    "receives",
    "emits",
    "whyItExists",
}
REQUIRED_DEEP_DETAIL_FIELDS = {
    "codePath",
    "dataFlow",
    "runtimeBehavior",
    "failureModes",
    "debugSignals",
    "ipv4Ipv6Notes",
}
ALLOWED_NODE_KINDS = {
    "control",
    "data",
    "risk",
    "observe",
    "config",
}
ALLOWED_RISK_TAGS = {
    "none",
    "low",
    "medium",
    "high",
    "auth",
    "config",
    "daemon-lifecycle",
    "data-leak",
    "dual-stack",
    "injection",
    "ipc",
    "memory-pressure",
    "observability",
    "privilege",
    "process-boundary",
    "remote-access",
    "routing",
    "tls",
}
ALLOWED_ADDRESS_FAMILIES = {
    "ipv4",
    "ipv6",
    "loopback",
    "unix-domain-socket",
    "windows-named-pipe",
    "virtual-adapter",
    "process",
    "memory",
    "not-applicable",
}
REQUIRED_HOME_EDGES = {
    "cli-to-ipc",
    "ipc-to-local-daemon",
    "local-session-to-transport",
    "transport-to-remote-listener",
    "socks-to-process-manager",
    "hook-to-process-manager",
    "vif-to-session-manager",
    "tls-to-buffer-pool",
}
BANNED_TERMS = ["".join(chr(codepoint) for codepoint in [23567, 30333])]
DISALLOWED_GRAPH_TEXT = [
    "".join(chr(codepoint) for codepoint in codepoints)
    for codepoints in (
        [84, 79, 68, 79],
        [84, 66, 68],
        [112, 108, 97, 99, 101, 104, 111, 108, 100, 101, 114],
        [102, 117, 116, 117, 114, 101],
        [108, 97, 116, 101, 114],
    )
]


class ValidationError(ValueError):
    """Raised when graph data violates the static graph contract."""


def fail(message: str) -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_graph_data(source: str) -> object:
    match = re.match(r"\A\s*window\.CLINK_GRAPH\s*=\s*", source)
    if not match:
        raise ValidationError("assets/graph-data.js must start with a window.CLINK_GRAPH assignment")

    object_source = source[match.end():]
    try:
        graph, end_index = json.JSONDecoder().raw_decode(object_source)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"window.CLINK_GRAPH must be a JSON-compatible object "
            f"(line {exc.lineno}, column {exc.colno}: {exc.msg})"
        ) from exc

    if not isinstance(graph, dict):
        raise ValidationError("window.CLINK_GRAPH must be a JSON-compatible object")

    suffix = object_source[end_index:].strip()
    if suffix not in ("", ";"):
        raise ValidationError(
            "assets/graph-data.js must contain only one window.CLINK_GRAPH assignment "
            "with an optional trailing semicolon"
        )

    return graph


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def require_object(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be a list")
    return value


def require_string(value: Any, label: str) -> None:
    require(isinstance(value, str) and value.strip() != "", f"{label} must be a non-empty string")


def require_number(value: Any, label: str) -> None:
    require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{label} must be a JSON number (not a boolean)",
    )


def require_string_list(value: Any, label: str) -> list[str]:
    items = require_list(value, label)
    for index, item in enumerate(items):
        require_string(item, f"{label}[{index}]")
    return items


def validate_tags(values: Any, allowed: set[str], label: str) -> None:
    tags = require_string_list(values, label)
    unknown = sorted(set(tags).difference(allowed))
    require(not unknown, f"{label} has unknown tags: {', '.join(unknown)}")


def validate_graph_text(value: Any, label: str) -> None:
    if isinstance(value, str):
        normalized = value.lower()
        for term in DISALLOWED_GRAPH_TEXT:
            require(term.lower() not in normalized, f"{label} contains disallowed display wording")
        return

    if isinstance(value, dict):
        for key, item in value.items():
            validate_graph_text(item, f"{label}.{key}")
        return

    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_graph_text(item, f"{label}[{index}]")


def validate_shell_files() -> None:
    for path in REQUIRED_FILES:
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

    index_html = read_text(ROOT / "index.html")
    for asset in REQUIRED_ASSETS:
        require(asset in index_html, f"index.html must load {asset}")

    app_js = read_text(ROOT / "assets" / "app.js")
    require("window.CLINK_GRAPH" in app_js, "assets/app.js must read window.CLINK_GRAPH")

    for path in REQUIRED_FILES:
        contents = read_text(path)
        for term in BANNED_TERMS:
            require(term not in contents, f"banned term found in {path.relative_to(ROOT)}")


def validate_node(node_id: str, node: Any) -> None:
    node = require_object(node, f"nodes.{node_id}")
    missing = sorted(REQUIRED_NODE_FIELDS.difference(node))
    require(not missing, f"node {node_id} missing fields: {', '.join(missing)}")
    require(node.get("id") == node_id, f"node {node_id} id must equal object key")
    require(node.get("kind") in ALLOWED_NODE_KINDS, f"node {node_id} has invalid kind")

    require_string(node.get("label"), f"node {node_id}.label")
    require_string(node.get("layer"), f"node {node_id}.layer")
    require_string(node.get("summary"), f"node {node_id}.summary")
    require_string(node.get("implementationStatus"), f"node {node_id}.implementationStatus")
    require_string_list(node.get("inputs"), f"node {node_id}.inputs")
    require_string_list(node.get("outputs"), f"node {node_id}.outputs")
    require_string_list(node.get("sourceFiles"), f"node {node_id}.sourceFiles")
    require_string_list(node.get("tests"), f"node {node_id}.tests")
    validate_tags(node.get("addressFamilies"), ALLOWED_ADDRESS_FAMILIES, f"node {node_id}.addressFamilies")
    validate_tags(node.get("risk"), ALLOWED_RISK_TAGS, f"node {node_id}.risk")

    position = require_object(node.get("position"), f"node {node_id}.position")
    require("x" in position and "y" in position, f"node {node_id}.position must include x and y")
    require_number(position.get("x"), f"node {node_id}.position.x")
    require_number(position.get("y"), f"node {node_id}.position.y")

    details = require_object(node.get("details"), f"node {node_id}.details")
    basic = require_object(details.get("basic"), f"node {node_id}.details.basic")
    deep = require_object(details.get("deep"), f"node {node_id}.details.deep")

    basic_missing = sorted(REQUIRED_BASIC_DETAIL_FIELDS.difference(basic))
    require(not basic_missing, f"node {node_id}.details.basic missing fields: {', '.join(basic_missing)}")
    for field in REQUIRED_BASIC_DETAIL_FIELDS:
        require_string(basic.get(field), f"node {node_id}.details.basic.{field}")

    deep_missing = sorted(REQUIRED_DEEP_DETAIL_FIELDS.difference(deep))
    require(not deep_missing, f"node {node_id}.details.deep missing fields: {', '.join(deep_missing)}")
    for field in REQUIRED_DEEP_DETAIL_FIELDS:
        require_string(deep.get(field), f"node {node_id}.details.deep.{field}")


def validate_edge(edge_id: str, edge: Any, node_ids: set[str]) -> None:
    edge = require_object(edge, f"edges.{edge_id}")
    missing = sorted(REQUIRED_EDGE_FIELDS.difference(edge))
    require(not missing, f"edge {edge_id} missing fields: {', '.join(missing)}")
    require(edge.get("id") == edge_id, f"edge {edge_id} id must equal object key")
    require(edge.get("from") in node_ids, f"edge {edge_id} from endpoint does not exist")
    require(edge.get("to") in node_ids, f"edge {edge_id} to endpoint does not exist")
    require(edge.get("kind") in ALLOWED_NODE_KINDS, f"edge {edge_id} has invalid kind")

    require_string(edge.get("label"), f"edge {edge_id}.label")
    require_string(edge.get("dataType"), f"edge {edge_id}.dataType")
    require_string(edge.get("implementationStatus"), f"edge {edge_id}.implementationStatus")
    require_string_list(edge.get("sourceFiles"), f"edge {edge_id}.sourceFiles")
    require_string_list(edge.get("notes"), f"edge {edge_id}.notes")
    validate_tags(edge.get("addressFamilies"), ALLOWED_ADDRESS_FAMILIES, f"edge {edge_id}.addressFamilies")
    validate_tags(edge.get("risk"), ALLOWED_RISK_TAGS, f"edge {edge_id}.risk")


def validate_group(group_id: str, group: Any, node_ids: set[str]) -> None:
    group = require_object(group, f"groups.{group_id}")
    missing = sorted(REQUIRED_GROUP_FIELDS.difference(group))
    require(not missing, f"group {group_id} missing fields: {', '.join(missing)}")
    require(group.get("id") == group_id, f"group {group_id} id must equal object key")
    require_string(group.get("label"), f"group {group_id}.label")
    require_string(group.get("summary"), f"group {group_id}.summary")

    group_nodes = require_string_list(group.get("nodes"), f"group {group_id}.nodes")
    require(group_nodes, f"group {group_id}.nodes must not be empty")
    missing_nodes = sorted(set(group_nodes).difference(node_ids))
    require(not missing_nodes, f"group {group_id} references missing nodes: {', '.join(missing_nodes)}")

    bounds = require_object(group.get("bounds"), f"group {group_id}.bounds")
    for field in ("x", "y", "width", "height"):
        require(field in bounds, f"group {group_id}.bounds must include {field}")
        require_number(bounds.get(field), f"group {group_id}.bounds.{field}")


def require_string_map(value: Any, label: str) -> dict[str, Any]:
    entries = require_object(value, label)
    require(entries, f"{label} must not be empty")
    for key, entry_value in entries.items():
        require_string(key, f"{label} key")
        require_string(entry_value, f"{label}.{key}")
    return entries


def validate_legends(legends: Any) -> None:
    legends = require_object(legends, "legends")

    colors = require_list(legends.get("colors"), "legends.colors")
    require(colors, "legends.colors must not be empty")
    for index, entry in enumerate(colors):
        entry = require_object(entry, f"legends.colors[{index}]")
        require_string(entry.get("label"), f"legends.colors[{index}].label")
        require_string(entry.get("color"), f"legends.colors[{index}].color")

    require_string_map(legends.get("risk"), "legends.risk")
    require_string_map(legends.get("addressFamilies"), "legends.addressFamilies")


def validate_glossary(glossary: Any) -> None:
    require_string_map(glossary, "glossary")


def validate_view(view: Any, index: int, node_ids: set[str], edge_ids: set[str], group_ids: set[str]) -> None:
    view = require_object(view, f"views[{index}]")
    require_string(view.get("id"), f"views[{index}].id")
    require_string(view.get("title"), f"view {view.get('id')}.title")
    require_string(view.get("description"), f"view {view.get('id')}.description")

    view_nodes = require_string_list(view.get("nodes"), f"view {view.get('id')}.nodes")
    view_edges = require_string_list(view.get("edges"), f"view {view.get('id')}.edges")
    view_groups = require_string_list(view.get("groups"), f"view {view.get('id')}.groups")
    missing_nodes = sorted(set(view_nodes).difference(node_ids))
    missing_edges = sorted(set(view_edges).difference(edge_ids))
    missing_groups = sorted(set(view_groups).difference(group_ids))
    require(not missing_nodes, f"view {view.get('id')} references missing nodes: {', '.join(missing_nodes)}")
    require(not missing_edges, f"view {view.get('id')} references missing edges: {', '.join(missing_edges)}")
    require(not missing_groups, f"view {view.get('id')} references missing groups: {', '.join(missing_groups)}")


def validate_graph(graph: Any) -> None:
    graph = require_object(graph, "window.CLINK_GRAPH")
    validate_graph_text(graph, "window.CLINK_GRAPH")
    missing_keys = sorted(REQUIRED_GRAPH_KEYS.difference(graph))
    require(not missing_keys, f"window.CLINK_GRAPH missing top-level keys: {', '.join(missing_keys)}")

    meta = require_object(graph.get("meta"), "meta")
    views = require_list(graph.get("views"), "views")
    require(views, "views must not be empty")

    view_ids = {view.get("id") for view in views if isinstance(view, dict)}
    require(meta.get("defaultViewId") == "home", "meta.defaultViewId must equal home")
    require(meta.get("defaultViewId") in view_ids, "meta.defaultViewId must reference an existing view")

    home_view = next((view for view in views if isinstance(view, dict) and view.get("id") == "home"), None)
    require(home_view is not None, "home view must exist")
    home_nodes = require_string_list(home_view.get("nodes"), "home.nodes")
    require(len(home_nodes) >= 12, "home view must include at least 12 nodes")

    nodes = require_object(graph.get("nodes"), "nodes")
    edges = require_object(graph.get("edges"), "edges")
    groups = require_object(graph.get("groups"), "groups")
    require(nodes, "nodes must not be empty")
    require(edges, "edges must not be empty")
    require(groups, "groups must not be empty")

    node_ids = set(nodes.keys())
    edge_ids = set(edges.keys())
    group_ids = set(groups.keys())
    for node_id, node in nodes.items():
        validate_node(node_id, node)
    for edge_id, edge in edges.items():
        validate_edge(edge_id, edge, node_ids)
    for group_id, group in groups.items():
        validate_group(group_id, group, node_ids)
    validate_legends(graph.get("legends"))
    validate_glossary(graph.get("glossary"))
    for index, view in enumerate(views):
        validate_view(view, index, node_ids, edge_ids, group_ids)

    home_edges = require_string_list(home_view.get("edges"), "home.edges")
    missing_home_edges = sorted(REQUIRED_HOME_EDGES.difference(home_edges))
    require(not missing_home_edges, f"home view missing required edges: {', '.join(missing_home_edges)}")


def main() -> int:
    try:
        validate_shell_files()
        graph = parse_graph_data(read_text(ROOT / "assets" / "graph-data.js"))
        validate_graph(graph)
    except ValidationError as exc:
        return fail(str(exc))

    print("PASS: codegraph shell and data are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
