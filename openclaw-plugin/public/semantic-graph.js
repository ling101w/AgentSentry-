const SVG_NS = "http://www.w3.org/2000/svg";

export class SemanticGraph {
  constructor({ viewport, world, svg, nodes, empty, onSelect }) {
    this.viewport = viewport;
    this.world = world;
    this.svg = svg;
    this.nodesLayer = nodes;
    this.empty = empty;
    this.onSelect = onSelect;
    this.graph = null;
    this.renderSignature = "";
    this.layout = null;
    this.nodeElements = new Map();
    this.edgeElements = new Map();
    this.transform = { scale: 1, x: 0, y: 0 };
    this.pathFocus = true;
    this.revealRatio = 1;
    this.revealSequence = Number.POSITIVE_INFINITY;
    this.selectedNodeId = "";
    this.selectedEdgeId = "";
    this.drag = null;
    this.nodeDrag = null;
    this.suppressNodeClick = { id: "", until: 0 };
    this.edgeFrame = null;
    this.manualLayout = new Map();
    this.resizeTimer = null;
    this.bindViewport();
  }

  setGraph(graph, { selectedNodeId = "", selectedEdgeId = "", preserveTransform = false } = {}) {
    const previousKey = this.graphKey();
    const previousSignature = this.renderSignature;
    this.graph = graph || null;
    const nextKey = this.graphKey();
    const nextSignature = graphRenderSignature(graph);
    this.selectedEdgeId = graph?.edges?.some((edge) => edge.id === selectedEdgeId) ? selectedEdgeId : "";
    this.selectedNodeId = !this.selectedEdgeId && graph?.nodes?.some((node) => node.id === selectedNodeId)
      ? selectedNodeId
      : !this.selectedEdgeId && graph?.nodes?.some((node) => node.id === graph?.selectedNodeId)
        ? graph.selectedNodeId
        : "";

    if (!graph || !Array.isArray(graph.nodes) || graph.nodes.length < 2) {
      this.renderSignature = "";
      this.nodeElements.clear();
      this.edgeElements.clear();
      this.nodesLayer.replaceChildren();
      this.svg.replaceChildren();
      this.empty.hidden = false;
      this.world.style.width = "100%";
      this.world.style.height = "100%";
      return;
    }

    const canReuse = previousKey === nextKey
      && previousSignature === nextSignature
      && this.nodeElements.size === graph.nodes.length
      && this.edgeElements.size === graph.edges.length;
    if (canReuse) {
      this.renderSignature = nextSignature;
      this.applyVisibility();
      this.applyFocus();
      if (!preserveTransform) this.fit();
      else this.applyTransform();
      return;
    }

    this.renderSignature = nextSignature;
    this.nodeElements.clear();
    this.edgeElements.clear();

    this.empty.hidden = true;
    this.layout = layoutGraph(graph, this.viewport.clientWidth, this.viewport.clientHeight);
    this.manualLayout = this.loadManualLayout(nextKey);
    this.applyManualLayout();
    this.world.dataset.traceKind = String(graph.traceKind || "attack");
    this.world.dataset.verdict = String(graph.verdict || "info");
    this.world.style.width = `${this.layout.worldWidth}px`;
    this.world.style.height = `${this.layout.worldHeight}px`;
    this.svg.setAttribute("viewBox", `0 0 ${this.layout.worldWidth} ${this.layout.worldHeight}`);
    this.svg.setAttribute("width", String(this.layout.worldWidth));
    this.svg.setAttribute("height", String(this.layout.worldHeight));
    this.renderNodes();
    this.drawEdges();
    this.applyVisibility();

    if (!preserveTransform || previousKey !== nextKey) this.fit();
    else this.applyTransform();
  }

  graphKey() {
    if (!this.graph) return "";
    const nodes = this.graph.nodes?.map((node) => node.id).join("|") || "";
    const edges = this.graph.edges?.map((edge) => `${edge.from}>${edge.to}`).join("|") || "";
    return `${this.graph.sessionId || "session"}:${this.graph.traceKind || ""}:${this.graph.risk || ""}:${nodes}:${edges}`;
  }

  setPathFocus(enabled) {
    this.pathFocus = Boolean(enabled);
    this.applyFocus();
  }

  setRevealRatio(ratio) {
    this.revealRatio = Math.max(0, Math.min(1, Number(ratio) || 0));
    this.revealSequence = Number.POSITIVE_INFINITY;
    this.applyVisibility();
  }

  setRevealSequence(sequence) {
    const value = Number(sequence);
    this.revealSequence = Number.isFinite(value) ? Math.max(0, value) : Number.POSITIVE_INFINITY;
    this.applyVisibility();
  }

  zoom(factor, anchor = null) {
    if (!this.graph || !this.layout) return;
    const current = this.transform;
    const box = this.viewport.getBoundingClientRect();
    const point = anchor || { x: box.width / 2, y: box.height / 2 };
    const scale = Math.max(0.32, Math.min(1.85, current.scale * factor));
    const ratio = scale / current.scale;
    this.transform = {
      scale,
      x: point.x - (point.x - current.x) * ratio,
      y: point.y - (point.y - current.y) * ratio,
    };
    this.applyTransform();
  }

  fit() {
    if (!this.graph || !this.layout) return;
    const width = this.viewport.clientWidth;
    const height = this.viewport.clientHeight;
    const scale = Math.min(
      1,
      Math.max(0.32, (width - 38) / this.layout.worldWidth),
      Math.max(0.32, (height - 38) / this.layout.worldHeight),
    );
    this.transform = {
      scale,
      x: (width - this.layout.worldWidth * scale) / 2,
      y: (height - this.layout.worldHeight * scale) / 2,
    };
    this.applyTransform();
  }

  resize() {
    clearTimeout(this.resizeTimer);
    this.resizeTimer = setTimeout(() => {
      if (!this.graph) return;
      this.layout = layoutGraph(this.graph, this.viewport.clientWidth, this.viewport.clientHeight);
      this.applyManualLayout();
      this.world.style.width = `${this.layout.worldWidth}px`;
      this.world.style.height = `${this.layout.worldHeight}px`;
      this.svg.setAttribute("viewBox", `0 0 ${this.layout.worldWidth} ${this.layout.worldHeight}`);
      this.svg.setAttribute("width", String(this.layout.worldWidth));
      this.svg.setAttribute("height", String(this.layout.worldHeight));
      this.positionNodes();
      this.drawEdges();
      this.applyVisibility();
      this.fit();
    }, 80);
  }

  clearSelection({ notify = true } = {}) {
    this.selectedNodeId = "";
    this.selectedEdgeId = "";
    this.applyFocus();
    if (notify) this.onSelect?.(null);
  }

  selectNode(id, { notify = true } = {}) {
    if (!this.graph?.nodes.some((node) => node.id === id)) return;
    this.selectedNodeId = id;
    this.selectedEdgeId = "";
    this.applyFocus();
    if (notify) this.onSelect?.({ type: "node", value: this.graph.nodes.find((node) => node.id === id) });
  }

  selectEdge(id, { notify = true } = {}) {
    if (!this.graph?.edges.some((edge) => edge.id === id)) return;
    this.selectedNodeId = "";
    this.selectedEdgeId = id;
    this.applyFocus();
    if (notify) this.onSelect?.({ type: "edge", value: this.graph.edges.find((edge) => edge.id === id) });
  }

  renderNodes() {
    this.nodesLayer.innerHTML = this.graph.nodes.map((node) => {
      const point = this.layout.positions.get(node.id) || { x: 80, y: 80 };
      const display = nodeDisplay(node);
      const tone = nodeTone(node, this.graph);
      return `<button class="semantic-node kind-${escapeHtml(node.kind)} tone-${escapeHtml(tone)} ${node.onPath ? "on-path" : "support"} ${node.displayOnly ? "display-only" : ""}"
        type="button"
        data-node-id="${escapeHtml(node.id)}"
        data-kind="${escapeHtml(node.kind)}"
        data-state="${escapeHtml(node.state)}"
        style="left:${point.x}px;top:${point.y}px"
        aria-pressed="false"
        title="${escapeHtml(`${node.kindLabel} · ${node.title} · ${node.meta}`)}">
        <span class="node-icon" aria-hidden="true"><i data-lucide="${escapeHtml(display.icon)}"></i></span>
        <span class="node-copy">
          <strong>${escapeHtml(display.title)}</strong>
          <small>${escapeHtml(display.subtitle)}</small>
        </span>
        <span class="node-info-icon" aria-hidden="true"><i data-lucide="info"></i></span>
      </button>`;
    }).join("");

    for (const element of this.nodesLayer.querySelectorAll(".semantic-node")) {
      const id = String(element.dataset.nodeId || "");
      this.nodeElements.set(id, element);
      element.addEventListener("click", (event) => {
        event.stopPropagation();
        if (this.suppressNodeClick.id === id && Date.now() < this.suppressNodeClick.until) {
          event.preventDefault();
          return;
        }
        this.selectNode(id);
      });
      this.bindNodeDrag(element, id);
    }
    window.lucide?.createIcons({ attrs: { "stroke-width": 1.8 } });
  }

  positionNodes() {
    for (const [id, element] of this.nodeElements) {
      const point = this.layout.positions.get(id);
      if (!point) continue;
      element.style.left = `${point.x}px`;
      element.style.top = `${point.y}px`;
    }
  }

  drawEdges() {
    if (!this.graph || !this.layout) return;
    this.svg.replaceChildren(createDefinitions(this.graph.traceKind, this.graph.verdict));
    this.edgeElements.clear();
    const nodeBoxes = new Map(this.graph.nodes
      .map((node) => [node.id, nodeBox(node.id, this.layout.positions, this.nodeElements)])
      .filter(([, box]) => Boolean(box)));
    const labelBoxes = [];

    for (const edge of this.graph.edges) {
      const from = nodeBoxes.get(edge.from);
      const to = nodeBoxes.get(edge.to);
      if (!from || !to) continue;
      const geometry = edgeGeometry(from, to);
      const labelPosition = placeEdgeLabel(geometry, [...nodeBoxes.values()], labelBoxes);
      const tone = edgeTone(edge, this.graph);
      const group = document.createElementNS(SVG_NS, "g");
      group.dataset.edgeId = edge.id;
      group.setAttribute("class", `semantic-edge-group tone-${tone} ${edge.onPath ? "on-path" : "support"} ${edge.displayOnly ? "display-only" : ""}`);

      const hit = document.createElementNS(SVG_NS, "path");
      hit.setAttribute("d", geometry.path);
      hit.setAttribute("class", "semantic-edge-hit");
      hit.setAttribute("tabindex", "0");
      hit.setAttribute("role", "button");
      hit.setAttribute("aria-label", `${edge.label}，置信度 ${Math.round(edge.confidence * 100)}%`);
      const activateEdge = (event) => {
        event.stopPropagation();
        this.selectEdge(edge.id);
      };
      const reserveEdgePointer = (event) => event.stopPropagation();
      const activateEdgeByKeyboard = (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          this.selectEdge(edge.id);
        }
      };
      hit.addEventListener("pointerdown", reserveEdgePointer);
      hit.addEventListener("click", activateEdge);
      hit.addEventListener("keydown", activateEdgeByKeyboard);

      const path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("d", geometry.path);
      path.setAttribute("class", "semantic-edge");
      path.setAttribute("marker-end", `url(#arrow-${tone})`);

      const labelHit = document.createElementNS(SVG_NS, "rect");
      labelHit.setAttribute("x", String(labelPosition.x - 48));
      labelHit.setAttribute("y", String(labelPosition.y - 14));
      labelHit.setAttribute("width", "96");
      labelHit.setAttribute("height", "22");
      labelHit.setAttribute("rx", "3");
      labelHit.setAttribute("class", "semantic-edge-label-hit");
      labelHit.setAttribute("tabindex", "0");
      labelHit.setAttribute("role", "button");
      labelHit.setAttribute("aria-label", `关系 ${edge.label}：${edge.from} 到 ${edge.to}`);
      labelHit.addEventListener("pointerdown", reserveEdgePointer);
      labelHit.addEventListener("click", activateEdge);
      labelHit.addEventListener("keydown", activateEdgeByKeyboard);

      const label = document.createElementNS(SVG_NS, "text");
      label.setAttribute("x", String(labelPosition.x));
      label.setAttribute("y", String(labelPosition.y));
      label.setAttribute("class", "semantic-edge-label");
      label.setAttribute("text-anchor", "middle");
      label.textContent = edge.label;

      const title = document.createElementNS(SVG_NS, "title");
      title.textContent = `${edge.label} · ${edge.basis} · confidence ${Math.round(edge.confidence * 100)}%`;
      path.appendChild(title);
      group.append(hit, path, labelHit, label);
      this.svg.appendChild(group);
      this.edgeElements.set(edge.id, group);
    }
    this.applyFocus();
  }

  applyVisibility() {
    if (!this.graph) return;
    const ordered = this.graph.nodes.slice().sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id));
    const visible = Number.isFinite(this.revealSequence)
      ? new Set(ordered.filter((node, index) => node.sequence <= this.revealSequence || (this.revealSequence === 0 && index === 0)).map((node) => node.id))
      : new Set(ordered.slice(0, this.revealRatio >= 1 ? ordered.length : Math.max(1, Math.ceil(ordered.length * this.revealRatio))).map((node) => node.id));
    for (const [id, element] of this.nodeElements) element.classList.toggle("future", !visible.has(id));
    for (const edge of this.graph.edges) {
      const element = this.edgeElements.get(edge.id);
      if (element) element.classList.toggle("future", !visible.has(edge.from) || !visible.has(edge.to));
    }
    this.applyFocus();
  }

  applyFocus() {
    if (!this.graph) return;
    const focus = this.focusSets();
    for (const [id, element] of this.nodeElements) {
      const selected = id === this.selectedNodeId;
      element.classList.toggle("selected", selected);
      element.classList.toggle("dimmed", focus.active && !focus.nodes.has(id));
      element.setAttribute("aria-pressed", String(selected));
    }
    for (const [id, element] of this.edgeElements) {
      element.classList.toggle("selected", id === this.selectedEdgeId);
      element.classList.toggle("dimmed", focus.active && !focus.edges.has(id));
    }
  }

  focusSets() {
    const allNodes = new Set(this.graph.nodes.map((node) => node.id));
    const allEdges = new Set(this.graph.edges.map((edge) => edge.id));
    if (!this.selectedNodeId && !this.selectedEdgeId) {
      if (!this.pathFocus) return { active: false, nodes: allNodes, edges: allEdges };
      return { active: true, nodes: new Set(this.graph.pathNodeIds), edges: new Set(this.graph.pathEdgeIds) };
    }

    const selectedEdge = this.graph.edges.find((edge) => edge.id === this.selectedEdgeId);
    const seeds = this.selectedNodeId ? [this.selectedNodeId] : selectedEdge ? [selectedEdge.from, selectedEdge.to] : [];
    const incoming = new Map();
    const outgoing = new Map();
    for (const edge of this.graph.edges) {
      incoming.set(edge.to, [...(incoming.get(edge.to) || []), edge.from]);
      outgoing.set(edge.from, [...(outgoing.get(edge.from) || []), edge.to]);
    }
    const nodes = new Set(seeds);
    const walk = (seed, adjacency) => {
      const pending = [seed];
      while (pending.length) {
        const current = pending.pop();
        for (const next of adjacency.get(current) || []) {
          if (nodes.has(next)) continue;
          nodes.add(next);
          pending.push(next);
        }
      }
    };
    for (const seed of seeds) {
      walk(seed, incoming);
      walk(seed, outgoing);
    }
    const edges = new Set(this.graph.edges
      .filter((edge) => nodes.has(edge.from) && nodes.has(edge.to))
      .map((edge) => edge.id));
    if (this.selectedEdgeId) edges.add(this.selectedEdgeId);
    return { active: true, nodes, edges };
  }

  applyTransform() {
    if (!this.layout) return;
    const box = this.viewport.getBoundingClientRect();
    const scale = Math.max(0.32, Math.min(1.85, this.transform.scale));
    const scaledWidth = this.layout.worldWidth * scale;
    const scaledHeight = this.layout.worldHeight * scale;
    const margin = 28;
    const minX = Math.min(margin, box.width - scaledWidth - margin);
    const maxX = Math.max(box.width - scaledWidth - margin, margin);
    const minY = Math.min(margin, box.height - scaledHeight - margin);
    const maxY = Math.max(box.height - scaledHeight - margin, margin);
    const x = scaledWidth <= box.width ? (box.width - scaledWidth) / 2 : clamp(this.transform.x, minX, maxX);
    const y = scaledHeight <= box.height ? (box.height - scaledHeight) / 2 : clamp(this.transform.y, minY, maxY);
    this.transform = { scale, x, y };
    this.world.style.transform = `translate(${x}px, ${y}px) scale(${scale})`;
  }

  bindViewport() {
    this.viewport.addEventListener("click", (event) => {
      if (event.target === this.viewport || event.target.classList.contains("graph-grid")) this.clearSelection();
    });
    this.viewport.addEventListener("wheel", (event) => {
      if (!this.graph) return;
      event.preventDefault();
      const box = this.viewport.getBoundingClientRect();
      this.zoom(event.deltaY < 0 ? 1.1 : 0.9, { x: event.clientX - box.left, y: event.clientY - box.top });
    }, { passive: false });
    this.viewport.addEventListener("pointerdown", (event) => {
      if (!this.graph || event.button !== 0 || event.target.closest("button") || event.target.closest(".semantic-edge-group")) return;
      this.drag = { pointerId: event.pointerId, x: event.clientX, y: event.clientY, startX: this.transform.x, startY: this.transform.y };
      this.viewport.setPointerCapture(event.pointerId);
      this.viewport.classList.add("dragging");
    });
    this.viewport.addEventListener("pointermove", (event) => {
      if (!this.drag || event.pointerId !== this.drag.pointerId) return;
      this.transform.x = this.drag.startX + event.clientX - this.drag.x;
      this.transform.y = this.drag.startY + event.clientY - this.drag.y;
      this.applyTransform();
    });
    const endDrag = (event) => {
      if (!this.drag || event.pointerId !== this.drag.pointerId) return;
      this.drag = null;
      this.viewport.classList.remove("dragging");
    };
    this.viewport.addEventListener("pointerup", endDrag);
    this.viewport.addEventListener("pointercancel", endDrag);
  }

  bindNodeDrag(element, id) {
    element.addEventListener("pointerdown", (event) => {
      if (!this.graph || !this.layout || event.button !== 0 || this.nodeDrag) return;
      event.stopPropagation();
      const point = this.layout.positions.get(id);
      if (!point) return;
      this.nodeDrag = {
        id,
        pointerId: event.pointerId,
        startClientX: event.clientX,
        startClientY: event.clientY,
        startX: point.x,
        startY: point.y,
        moved: false,
        element,
      };
      element.setPointerCapture(event.pointerId);
      element.classList.add("dragging");
    });
    element.addEventListener("pointermove", (event) => {
      const drag = this.nodeDrag;
      if (!drag || drag.id !== id || event.pointerId !== drag.pointerId || !this.layout) return;
      const deltaX = (event.clientX - drag.startClientX) / Math.max(0.32, this.transform.scale || 1);
      const deltaY = (event.clientY - drag.startClientY) / Math.max(0.32, this.transform.scale || 1);
      if (!drag.moved && Math.hypot(deltaX, deltaY) < 3) return;
      drag.moved = true;
      event.preventDefault();
      const halfWidth = (element.offsetWidth || 164) / 2;
      const halfHeight = (element.offsetHeight || 62) / 2;
      const point = {
        x: clamp(drag.startX + deltaX, halfWidth + 8, this.layout.worldWidth - halfWidth - 8),
        y: clamp(drag.startY + deltaY, halfHeight + 8, this.layout.worldHeight - halfHeight - 8),
      };
      this.layout.positions.set(id, point);
      element.style.left = `${point.x}px`;
      element.style.top = `${point.y}px`;
      this.scheduleEdgeRedraw();
    });
    const finish = (event) => {
      const drag = this.nodeDrag;
      if (!drag || drag.id !== id || event.pointerId !== drag.pointerId) return;
      if (drag.moved) {
        this.suppressNodeClick = { id, until: Date.now() + 300 };
        this.saveManualPosition(id);
        this.drawEdges();
      }
      element.classList.remove("dragging");
      if (element.hasPointerCapture(event.pointerId)) element.releasePointerCapture(event.pointerId);
      this.nodeDrag = null;
    };
    element.addEventListener("pointerup", finish);
    element.addEventListener("pointercancel", finish);
  }

  scheduleEdgeRedraw() {
    if (this.edgeFrame !== null) return;
    this.edgeFrame = window.requestAnimationFrame(() => {
      this.edgeFrame = null;
      this.drawEdges();
    });
  }

  applyManualLayout() {
    if (!this.layout || !this.manualLayout.size) return;
    for (const [id, ratio] of this.manualLayout) {
      if (!this.layout.positions.has(id)) continue;
      const element = this.nodeElements.get(id);
      const halfWidth = (element?.offsetWidth || 164) / 2;
      const halfHeight = (element?.offsetHeight || 62) / 2;
      this.layout.positions.set(id, {
        x: clamp(ratio.x * this.layout.worldWidth, halfWidth + 8, this.layout.worldWidth - halfWidth - 8),
        y: clamp(ratio.y * this.layout.worldHeight, halfHeight + 8, this.layout.worldHeight - halfHeight - 8),
      });
    }
  }

  saveManualPosition(id) {
    if (!this.layout) return;
    const point = this.layout.positions.get(id);
    if (!point) return;
    this.manualLayout.set(id, {
      x: point.x / Math.max(1, this.layout.worldWidth),
      y: point.y / Math.max(1, this.layout.worldHeight),
    });
    const key = this.graphKey();
    try {
      window.localStorage.setItem(manualLayoutStorageKey(key), JSON.stringify({
        graphKey: key,
        positions: Object.fromEntries(this.manualLayout),
      }));
    } catch {
      // The graph remains draggable when browser storage is unavailable.
    }
  }

  loadManualLayout(key) {
    if (!key) return new Map();
    try {
      const parsed = JSON.parse(window.localStorage.getItem(manualLayoutStorageKey(key)) || "null");
      if (parsed?.graphKey !== key || !parsed.positions || typeof parsed.positions !== "object") return new Map();
      return new Map(Object.entries(parsed.positions).filter(([, point]) => Number.isFinite(point?.x) && Number.isFinite(point?.y)));
    } catch {
      return new Map();
    }
  }
}

function layoutGraph(graph, viewportWidth, viewportHeight) {
  if (graph.primaryView) return layoutPrimaryPathGraph(graph, viewportWidth, viewportHeight);
  if (graph.nodes.length <= 12) return layoutNarrativeGraph(graph, viewportWidth, viewportHeight);

  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const validEdges = graph.edges.filter((edge) => nodeById.has(edge.from) && nodeById.has(edge.to));
  const incoming = new Map(graph.nodes.map((node) => [node.id, []]));
  const outgoing = new Map(graph.nodes.map((node) => [node.id, []]));
  const indegree = new Map(graph.nodes.map((node) => [node.id, 0]));
  for (const edge of validEdges) {
    outgoing.get(edge.from).push(edge.to);
    incoming.get(edge.to).push(edge.from);
    indegree.set(edge.to, (indegree.get(edge.to) || 0) + 1);
  }

  const pathOrder = new Map(graph.pathNodeIds.map((id, index) => [id, index]));
  const compare = (left, right) => {
    const leftPath = pathOrder.has(left) ? pathOrder.get(left) : Number.MAX_SAFE_INTEGER;
    const rightPath = pathOrder.has(right) ? pathOrder.get(right) : Number.MAX_SAFE_INTEGER;
    if (leftPath !== rightPath) return leftPath - rightPath;
    return (nodeById.get(left)?.sequence || 0) - (nodeById.get(right)?.sequence || 0) || left.localeCompare(right);
  };

  const queue = [...indegree.entries()].filter(([, value]) => value === 0).map(([id]) => id).sort(compare);
  const rank = new Map(graph.nodes.map((node) => [node.id, 0]));
  const ordered = [];
  while (queue.length) {
    const current = queue.shift();
    ordered.push(current);
    for (const next of outgoing.get(current).slice().sort(compare)) {
      rank.set(next, Math.max(rank.get(next) || 0, (rank.get(current) || 0) + 1));
      indegree.set(next, (indegree.get(next) || 0) - 1);
      if (indegree.get(next) === 0) {
        queue.push(next);
        queue.sort(compare);
      }
    }
  }
  for (const node of graph.nodes.map((item) => item.id).filter((id) => !ordered.includes(id)).sort(compare)) {
    rank.set(node, Math.max(0, ...(incoming.get(node).map((parent) => (rank.get(parent) || 0) + 1))));
    ordered.push(node);
  }

  const layers = new Map();
  for (const id of ordered) {
    const level = rank.get(id) || 0;
    layers.set(level, [...(layers.get(level) || []), id]);
  }
  const priorOrder = new Map();
  for (const level of [...layers.keys()].sort((left, right) => left - right)) {
    const layer = layers.get(level);
    layer.sort((left, right) => {
      const center = (id) => {
        const values = incoming.get(id).map((parent) => priorOrder.get(parent)).filter(Number.isFinite);
        return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
      };
      const leftCenter = center(left);
      const rightCenter = center(right);
      if (leftCenter !== null && rightCenter !== null && leftCenter !== rightCenter) return leftCenter - rightCenter;
      if (leftCenter !== null) return -1;
      if (rightCenter !== null) return 1;
      return compare(left, right);
    });
    layer.forEach((id, index) => priorOrder.set(id, index));
  }

  const maxRank = Math.max(0, ...rank.values());
  const maxLayerSize = Math.max(1, ...[...layers.values()].map((layer) => layer.length));
  const gapX = 212;
  const gapY = 126;
  const paddingX = 118;
  const paddingY = 78;
  const worldWidth = Math.max(Math.round(viewportWidth || 720), paddingX * 2 + maxRank * gapX);
  const worldHeight = Math.max(Math.round(viewportHeight || 420), paddingY * 2 + (maxLayerSize - 1) * gapY);
  const positions = new Map();
  for (const [level, layer] of layers) {
    const layerHeight = (layer.length - 1) * gapY;
    const startY = (worldHeight - layerHeight) / 2;
    layer.forEach((id, index) => positions.set(id, {
      x: maxRank === 0 ? worldWidth / 2 : paddingX + level * ((worldWidth - paddingX * 2) / maxRank),
      y: startY + index * gapY,
    }));
  }
  return { positions, worldWidth, worldHeight };
}

function layoutPrimaryPathGraph(graph, viewportWidth, viewportHeight) {
  const worldWidth = Math.max(610, Math.round(viewportWidth || 650));
  const nodeCount = graph.nodes.length;
  const columns = Math.min(3, Math.max(1, nodeCount));
  const rows = Math.max(1, Math.ceil(nodeCount / columns));
  const paddingX = Math.max(92, Math.min(128, worldWidth / (columns + 1)));
  const worldHeight = Math.max(420, Math.round(viewportHeight || 470), 132 + (rows - 1) * 132);
  const usableWidth = Math.max(0, worldWidth - paddingX * 2);
  const gapX = columns > 1 ? usableWidth / (columns - 1) : 0;
  const gapY = rows > 1 ? (worldHeight - 132) / (rows - 1) : 0;
  const ordered = graph.nodes.slice().sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id));
  const positions = new Map();

  // Snake through the rows so a causal sequence reads continuously without
  // forcing all nodes into one narrow horizontal line.
  ordered.forEach((node, index) => {
    const row = Math.floor(index / columns);
    const columnInRow = index % columns;
    const rowSize = Math.min(columns, nodeCount - row * columns);
    const reverse = row % 2 === 1;
    const column = reverse ? rowSize - 1 - columnInRow : columnInRow;
    const rowOffset = rowSize < columns ? (columns - rowSize) * gapX * 0.5 : 0;
    positions.set(node.id, {
      x: paddingX + column * gapX + rowOffset,
      y: 66 + row * gapY,
    });
  });
  return { positions, worldWidth, worldHeight };
}

function layoutNarrativeGraph(graph, viewportWidth, viewportHeight) {
  const worldWidth = Math.max(610, Math.round(viewportWidth || 650));
  const worldHeight = Math.max(420, Math.round(viewportHeight || 470));
  const rows = [47, 164, 286, worldHeight - 73];
  const occupied = new Set();
  const positions = new Map();
  const nodes = graph.nodes.slice().sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id));

  const openSlots = [
    [80, 0], [worldWidth * 0.445, 0], [worldWidth - 144, 0],
    [worldWidth * 0.35, 1], [worldWidth * 0.67, 1], [80, 1],
    [80, 2], [worldWidth * 0.445, 2], [worldWidth - 144, 2],
    [121, 3], [worldWidth * 0.445, 3], [worldWidth - 144, 3],
  ];

  const preferences = (node) => {
    const state = String(node.state || "").toUpperCase();
    if (node.kind === "intent") return [[80, 0]];
    if (node.kind === "capability" && node.authorized !== false) return [[worldWidth * 0.445, 0], [worldWidth * 0.35, 1]];
    if (node.kind === "capability") return [[worldWidth * 0.445, 2], [80, 2]];
    if (node.kind === "taint") return [[worldWidth - 144, 0], [worldWidth * 0.67, 1]];
    if (node.kind === "action" && !/BLOCK|DENY|UNSCOPED|REJECT/.test(state) && node.authorized !== false) return [[worldWidth * 0.35, 1], [80, 1]];
    if (node.kind === "action") return [[worldWidth * 0.67, 1], [worldWidth - 144, 2]];
    if (node.kind === "secret") return [[worldWidth - 144, 2], [worldWidth * 0.445, 2]];
    if (node.kind === "data") return [[80, 2], [worldWidth * 0.445, 2]];
    if (node.kind === "sink") return [[worldWidth - 144, 3]];
    if (node.kind === "guard") return [[121, 3], [worldWidth * 0.445, 3]];
    if (node.kind === "decision") return [[worldWidth * 0.445, 3], [80, 2]];
    if (node.kind === "judge") return [[worldWidth * 0.445, 2]];
    if (node.kind === "agent") return [[worldWidth * 0.35, 1]];
    return [[80, 2], [worldWidth * 0.445, 2], [worldWidth - 144, 2]];
  };

  for (const node of nodes) {
    const candidates = [...preferences(node), ...openSlots];
    const slot = candidates.find(([x, row]) => !occupied.has(`${Math.round(x)}:${row}`)) || openSlots.at(-1);
    occupied.add(`${Math.round(slot[0])}:${slot[1]}`);
    positions.set(node.id, { x: slot[0], y: rows[slot[1]] });
  }

  return { positions, worldWidth, worldHeight };
}

function nodeBox(id, positions, elements) {
  const point = positions.get(id);
  const element = elements.get(id);
  if (!point || !element) return null;
  const width = element.offsetWidth || 174;
  const height = element.offsetHeight || 84;
  return {
    x: point.x,
    y: point.y,
    left: point.x - width / 2,
    right: point.x + width / 2,
    top: point.y - height / 2,
    bottom: point.y + height / 2,
  };
}

function edgeGeometry(from, to) {
  const horizontal = Math.abs(to.x - from.x) >= Math.abs(to.y - from.y) * 0.65;
  if (horizontal) {
    const forward = to.x >= from.x;
    const start = { x: forward ? from.right : from.left, y: from.y };
    const end = { x: forward ? to.left : to.right, y: to.y };
    const dx = end.x - start.x;
    const control1 = { x: start.x + dx * 0.46, y: start.y };
    const control2 = { x: end.x - dx * 0.46, y: end.y };
    return {
      path: `M${start.x},${start.y} C${control1.x},${control1.y} ${control2.x},${control2.y} ${end.x},${end.y}`,
      start,
      control1,
      control2,
      end,
      horizontal,
      labelX: (start.x + end.x) / 2,
      labelY: (start.y + end.y) / 2 - 8,
    };
  }
  const downward = to.y >= from.y;
  const start = { x: from.x, y: downward ? from.bottom : from.top };
  const end = { x: to.x, y: downward ? to.top : to.bottom };
  const dy = end.y - start.y;
  const control1 = { x: start.x, y: start.y + dy * 0.48 };
  const control2 = { x: end.x, y: end.y - dy * 0.48 };
  return {
    path: `M${start.x},${start.y} C${control1.x},${control1.y} ${control2.x},${control2.y} ${end.x},${end.y}`,
    start,
    control1,
    control2,
    end,
    horizontal,
    labelX: (start.x + end.x) / 2 + 8,
    labelY: (start.y + end.y) / 2 - 4,
  };
}

function placeEdgeLabel(geometry, nodeBoxes, occupiedBoxes) {
  const candidates = [0.5, 0.35, 0.65, 0.24, 0.76, 0.18, 0.82, 0.12, 0.88].map((ratio) => {
    const point = cubicPoint(geometry, ratio);
    return { x: point.x, y: point.y - (geometry.horizontal ? 8 : 4) };
  });
  const midpoint = candidates[0];
  for (const offset of [-24, 24, -48, 48, -72, 72, -96, 96]) {
    candidates.push(geometry.horizontal
      ? { x: midpoint.x, y: midpoint.y + offset }
      : { x: midpoint.x + offset, y: midpoint.y });
  }

  for (const candidate of candidates) {
    const box = edgeLabelBox(candidate);
    const collidesWithNode = nodeBoxes.some((node) => boxesOverlap(box, {
      left: node.left - 4,
      right: node.right + 4,
      top: node.top - 4,
      bottom: node.bottom + 4,
    }));
    if (collidesWithNode || occupiedBoxes.some((occupied) => boxesOverlap(box, occupied))) continue;
    occupiedBoxes.push(box);
    return candidate;
  }

  const fallback = { x: geometry.labelX, y: geometry.labelY };
  occupiedBoxes.push(edgeLabelBox(fallback));
  return fallback;
}

function cubicPoint(geometry, ratio) {
  const t = Math.max(0, Math.min(1, ratio));
  const inverse = 1 - t;
  return {
    x: inverse ** 3 * geometry.start.x
      + 3 * inverse ** 2 * t * geometry.control1.x
      + 3 * inverse * t ** 2 * geometry.control2.x
      + t ** 3 * geometry.end.x,
    y: inverse ** 3 * geometry.start.y
      + 3 * inverse ** 2 * t * geometry.control1.y
      + 3 * inverse * t ** 2 * geometry.control2.y
      + t ** 3 * geometry.end.y,
  };
}

function edgeLabelBox(point) {
  return { left: point.x - 48, right: point.x + 48, top: point.y - 14, bottom: point.y + 8 };
}

function boxesOverlap(left, right) {
  return left.left < right.right && left.right > right.left && left.top < right.bottom && left.bottom > right.top;
}

function createDefinitions(traceKind, verdict) {
  const defs = document.createElementNS(SVG_NS, "defs");
  const colors = {
    attack: "#ff5d6c",
    authorized: "#4bd39b",
    review: "#f3b95f",
    evidence: "#84929b",
    projection: "#7e8990",
  };
  if (traceKind === "authorized" || verdict === "allow") colors.attack = colors.authorized;
  if (verdict === "ask") colors.attack = colors.review;
  for (const [name, color] of Object.entries(colors)) {
    const marker = document.createElementNS(SVG_NS, "marker");
    marker.setAttribute("id", `arrow-${name}`);
    marker.setAttribute("markerWidth", "8");
    marker.setAttribute("markerHeight", "8");
    marker.setAttribute("refX", "7");
    marker.setAttribute("refY", "4");
    marker.setAttribute("orient", "auto");
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", "M0,0 L8,4 L0,8 Z");
    path.setAttribute("fill", color);
    marker.appendChild(path);
    defs.appendChild(marker);
  }
  return defs;
}

function edgeTone(edge, graph) {
  const kind = String(edge.kind || "").toLowerCase();
  const from = graph.nodes.find((node) => node.id === edge.from);
  const to = graph.nodes.find((node) => node.id === edge.to);
  if (["blocked_by", "approved_by", "decides"].includes(kind)) return graph.verdict === "ask" ? "review" : "authorized";
  if (kind === "reviewed_by" || graph.verdict === "ask" && edge.onPath) return "review";
  if (kind === "taints" && graph.verdict !== "allow") return "attack";
  if (kind === "consumes" && graph.verdict !== "allow" && ["taint", "secret"].includes(from?.kind)) return "attack";
  if (kind === "targets" && graph.verdict !== "allow" && (to?.kind === "sink" || to?.effect === "external")) return "attack";
  if (edge.displayOnly) return "projection";
  if (edge.onPath && (graph.traceKind === "authorized" || graph.verdict === "allow")) return "authorized";
  return "evidence";
}

function nodeTone(node, graph) {
  const state = String(node.state || "").toUpperCase();
  if (node.kind === "guard" || node.kind === "decision") {
    if (state === "ASK" || graph.verdict === "ask") return "suspicious";
    return "control";
  }
  if (node.kind === "taint") return "attack";
  if (node.kind === "secret") return "suspicious";
  if (node.kind === "sink" && graph.verdict !== "allow") return "attack";
  if (node.kind === "action" && (/BLOCK|DENY|UNSCOPED|REJECT/.test(state) || node.authorized === false)) return "attack";
  if (node.authorized === false) return "suspicious";
  if (["intent", "capability", "agent", "data", "action"].includes(node.kind)) return "normal";
  return "neutral";
}

function nodeDisplay(node) {
  const rawTitle = String(node.title || node.kindLabel || "语义节点");
  const state = String(node.state || "").toUpperCase();
  const iconByKind = {
    intent: "user-round",
    capability: node.authorized === false ? "shield-alert" : "badge-check",
    agent: "bot",
    action: "wrench",
    data: "database",
    taint: "skull",
    secret: "lock-keyhole",
    sink: "send",
    guard: "shield-check",
    judge: "scale",
    decision: "gavel",
    collapsed: "ellipsis",
  };

  if (node.kind === "intent") return { title: "用户输入", subtitle: rawTitle, icon: iconByKind.intent };
  if (node.kind === "capability" && node.authorized !== false) {
    return { title: "意图解析", subtitle: `理解用户意图 · ${rawTitle}`, icon: iconByKind.capability };
  }
  if (node.kind === "capability") {
    return { title: "系统/配置访问", subtitle: `越权能力请求 · ${rawTitle}`, icon: iconByKind.capability };
  }
  if (node.kind === "taint") return { title: "Prompt 注入", subtitle: "指令操纵 / 越权", icon: iconByKind.taint };
  if (node.kind === "secret") return { title: "敏感数据", subtitle: rawTitle, icon: iconByKind.secret };
  if (node.kind === "sink") return { title: "外发/执行", subtitle: rawTitle, icon: iconByKind.sink };
  if (node.kind === "guard") return { title: "玄鉴执行边界", subtitle: `${rawTitle} · ${node.state || "EVALUATING"}`, icon: iconByKind.guard };
  if (node.kind === "decision") return { title: "安全裁决", subtitle: rawTitle, icon: iconByKind.decision };
  if (node.kind === "action") {
    const unsafe = node.authorized === false || /BLOCK|DENY|UNSCOPED|REJECT/.test(state);
    return { title: unsafe ? "工具调用" : "工具选择", subtitle: `${unsafe ? "调用" : "选择可用工具"} · ${rawTitle}`, icon: iconByKind.action };
  }
  if (node.kind === "data") return { title: "知识检索", subtitle: rawTitle, icon: iconByKind.data };
  if (node.kind === "judge") return { title: "语义裁判", subtitle: rawTitle, icon: iconByKind.judge };
  if (node.kind === "agent") return { title: "Agent 计划", subtitle: rawTitle, icon: iconByKind.agent };
  return { title: rawTitle, subtitle: node.meta || node.state || "运行时证据", icon: iconByKind[node.kind] || node.icon || "circle" };
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]);
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

function manualLayoutStorageKey(graphKey) {
  let hash = 2166136261;
  for (let index = 0; index < graphKey.length; index += 1) {
    hash ^= graphKey.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `xuanjian:semantic-layout:${(hash >>> 0).toString(36)}`;
}

function graphRenderSignature(graph) {
  if (!graph) return "";
  const nodes = (graph.nodes || []).map((node) => [
    node.id,
    node.kind,
    node.title,
    node.state,
    node.onPath,
    node.displayOnly,
    node.authorized,
  ].join(":"));
  const edges = (graph.edges || []).map((edge) => [
    edge.id,
    edge.from,
    edge.to,
    edge.label,
    edge.onPath,
    edge.displayOnly,
  ].join(":"));
  return `${graph.verdict || ""}|${nodes.join("|")}|${edges.join("|")}`;
}
