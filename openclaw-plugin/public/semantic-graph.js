/**
 * semantic-graph.js
 * SemanticGraph：基于本地 vendored Cytoscape.js + dagre 的语义动作图渲染器。
 *
 * 职责：
 *   ① 渲染 GraphAdapter 产出的 { nodes, edges }。
 *   ② Attack-path highlighting：攻击因果链加粗、发红、发光；其余路径降低透明度。
 *   ③ 点击节点/边 → 回调 Inspector（右侧显示「为什么」）。
 *   ④ 暴露 setReveal(step) 供时间轴回放。
 *
 * 依赖（均为本地 vendor，非 CDN）：
 *   /vendor/cytoscape.min.js  /vendor/dagre.min.js  /vendor/cytoscape-dagre.js
 *   /graph-adapter.js（NODE_KINDS / DECISION_META）
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && typeof module.exports === "object") {
    module.exports = api;
  }
  if (root) root.SemanticGraph = api;
})(typeof self !== "undefined" ? self : typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  "use strict";

  const KIND_COLORS = {
    intent: "#40e6ff",
    capability: "#35f29b",
    agent: "#7ee0ff",
    action: "#58bfff",
    data: "#f8b84e",
    tainted: "#ff8a4d",
    secret: "#ff6b81",
    sink: "#ff4d5e",
    guard: "#24e6b6",
    judge: "#b48cff",
    decision: "#35f29b",
    collapsed: "#7e8c97",
  };

  const VERDICT_COLORS = { allow: "#35f29b", ask: "#f8b84e", deny: "#ff4d5e" };

  function hexToRgba(hex, alpha) {
    const value = hex.replace("#", "");
    const r = parseInt(value.slice(0, 2), 16);
    const g = parseInt(value.slice(2, 4), 16);
    const b = parseInt(value.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  function nodeColor(node) {
    if (node.kind === "decision" && VERDICT_COLORS[node.decision]) return VERDICT_COLORS[node.decision];
    if (node.confidential) return "#ff4d5e";
    if (node.tainted) return "#ff8a4d";
    return KIND_COLORS[node.kind] || "#7e8c97";
  }

  class SemanticGraph {
    constructor(container, options = {}) {
      this.container = typeof container === "string" ? document.querySelector(container) : container;
      this.onSelect = options.onSelect || (() => {});
      this.cy = null;
      this.model = null;
      this.revealStep = Infinity;
      this.timeline = [];
      this._init();
    }

    _init() {
      const cytoscape = root && root.cytoscape;
      if (!this.container || !cytoscape) return;
      if (root.cytoscapeDagre && typeof cytoscape.use === "function") {
        try { cytoscape.use(root.cytoscapeDagre); } catch { /* already registered */ }
      }
      this.cy = cytoscape({
        container: this.container,
        elements: [],
        wheelSensitivity: 0.18,
        minZoom: 0.35,
        maxZoom: 2.4,
        style: this._style(),
      });
      this.cy.on("tap", "node", (event) => this._emitSelect(event.target));
      this.cy.on("tap", "edge", (event) => this._emitSelect(event.target));
      this.cy.on("tap", (event) => {
        if (event.target === this.cy) this.onSelect({ kind: "background" });
      });
    }

    _style() {
      return [
        {
          selector: "node",
          style: {
            "background-color": (ele) => hexToRgba(nodeColor(ele.data("node")) || "#7e8c97", 0.16),
            "border-color": (ele) => nodeColor(ele.data("node")) || "#7e8c97",
            "border-width": 2,
            "label": "data(label)",
            color: "#d7e3ee",
            "font-size": 11,
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 7,
            "text-wrap": "wrap",
            "text-max-width": 128,
            "font-family": "'Microsoft YaHei UI', 'Microsoft YaHei', Inter, sans-serif",
            width: 44,
            height: 44,
            shape: "round-rectangle",
            "overlay-padding": 6,
          },
        },
        {
          selector: "node[kind='intent'], node[kind='capability'], node[kind='agent'], node[kind='judge']",
          style: { shape: "ellipse" },
        },
        {
          selector: "node[kind='decision']",
          style: { shape: "tag", "border-width": 2.5 },
        },
        {
          selector: "node[kind='collapsed']",
          style: { shape: "round-diamond", "border-style": "dashed" },
        },
        {
          selector: "edge",
          style: {
            "curve-style": "bezier",
            width: 1.6,
            "line-color": (ele) => (ele.data("edge").onPath ? "rgba(255,77,94,0.9)" : "rgba(126,140,151,0.5)"),
            "target-arrow-color": (ele) => (ele.data("edge").onPath ? "rgba(255,77,94,0.9)" : "rgba(126,140,151,0.6)"),
            "target-arrow-shape": "triangle",
            "arrow-scale": 1.1,
            label: "data(label)",
            "font-size": 9.5,
            color: "#8fa3b2",
            "text-background-color": "#061018",
            "text-background-opacity": 0.75,
            "text-background-padding": 2,
            "text-rotation": "autorotate",
          },
        },
        // Attack path：加粗、发红、发光。
        {
          selector: "node.onPath",
          style: {
            "border-width": 3,
            "border-color": "#ff4d5e",
            "background-color": "rgba(255,77,94,0.20)",
            "overlay-color": "rgba(255,77,94,0.35)",
            "overlay-opacity": 0.5,
            "z-index": 20,
          },
        },
        {
          selector: "edge.onPath",
          style: {
            width: 3.2,
            "line-color": "#ff4d5e",
            "target-arrow-color": "#ff4d5e",
            color: "#ffb3ba",
            "font-weight": "bold",
            "font-size": 10,
            "z-index": 20,
          },
        },
        // 其余路径自动降低透明度。
        {
          selector: "node.dimmed",
          style: { opacity: 0.32 },
        },
        {
          selector: "edge.dimmed",
          style: { opacity: 0.22 },
        },
        {
          selector: ".selected",
          style: {
            "border-color": "#40e6ff",
            "border-width": 4,
            "overlay-color": "rgba(64,230,255,0.3)",
            "overlay-opacity": 0.7,
            "z-index": 40,
          },
        },
        {
          selector: "node.replay-hidden, edge.replay-hidden",
          style: { opacity: 0, "overlay-opacity": 0 },
        },
      ];
    }

    render(model, timeline = []) {
      if (!this.cy) return;
      this.model = model;
      this.timeline = timeline;
      this.revealStep = Infinity;

      const hasPath = model.nodes.some((node) => node.onPath) || model.edges.some((edge) => edge.onPath);
      const nodes = model.nodes.map((node) => ({
        data: {
          id: node.id,
          label: `${node.icon || ""} ${node.label}`.trim(),
          kind: node.kind,
          node,
        },
        classes: [node.cls, node.onPath ? "onPath" : hasPath ? "dimmed" : ""].filter(Boolean),
      }));
      const edges = model.edges.map((edge, index) => ({
        data: {
          id: edge.id || `edge-${index}`,
          source: edge.source,
          target: edge.target,
          label: edge.label,
          edge,
        },
        classes: [edge.onPath ? "onPath" : hasPath ? "dimmed" : ""].filter(Boolean),
      }));

      this.cy.elements().remove();
      this.cy.add([...nodes, ...edges]);
      this._layout();
    }

    _layout() {
      const layout = this.cy.layout({
        name: "dagre",
        rankDir: "LR",
        nodeSep: 34,
        rankSep: 92,
        edgeSep: 18,
        ranker: "network-simplex",
        animate: false,
        padding: 42,
      });
      layout.on("layoutstop", () => this.cy.fit(undefined, 48));
      layout.run();
    }

    _emitSelect(element) {
      const data = element.data();
      if (data.node) {
        this._markSelected(element);
        this.onSelect({ kind: "node", node: data.node, element });
      } else if (data.edge) {
        this._markSelected(element);
        this.onSelect({ kind: "edge", edge: data.edge, element });
      }
    }

    _markSelected(element) {
      this.cy.elements(".selected").removeClass("selected");
      element.addClass("selected");
    }

    clearSelection() {
      if (!this.cy) return;
      this.cy.elements(".selected").removeClass("selected");
    }

    // 时间轴回放：step 表示已推进到第几个时间轴事件。
    // 通过逐步揭示「动作/裁决」类节点实现。
    setReveal(step) {
      if (!this.cy || !this.model) return;
      this.revealStep = step;
      const total = Math.max(1, this.timeline.length);
      const progress = step >= total ? 1 : Math.max(0, step) / total;
      const pathNodes = this.model.nodes.filter((n) => n.onPath && n.kind !== "collapsed");
      const visibleCount = Math.round(progress * pathNodes.length);
      const visibleIds = new Set(pathNodes.slice(0, visibleCount).map((n) => n.id));

      this.cy.nodes().forEach((node) => {
        const data = node.data("node");
        const revealed = !data || !data.onPath || visibleIds.has(data.id) || step >= total;
        node.toggleClass("replay-hidden", !revealed);
      });
      this.cy.edges().forEach((edge) => {
        const data = edge.data("edge");
        const sourceHidden = this.cy.getElementById(data.source).hasClass("replay-hidden");
        const targetHidden = this.cy.getElementById(data.target).hasClass("replay-hidden");
        const revealed = !data || !data.onPath || (!sourceHidden && !targetHidden) || step >= total;
        edge.toggleClass("replay-hidden", !revealed);
      });
    }

    fit() {
      if (this.cy) this.cy.fit(undefined, 48);
    }
  }

  return { SemanticGraph, KIND_COLORS, VERDICT_COLORS, nodeColor };
});
