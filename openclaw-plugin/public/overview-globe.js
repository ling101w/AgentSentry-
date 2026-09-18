import { LAND_DOTS_B64 } from "/land-dots.js?v=20260820-2";

const CORE = { lat: 31.23, lon: 121.47 };
const SURFACE_ORIGINS = {
  injection: [
    { lat: 37.77, lon: -122.42 },
    { lat: 51.51, lon: -0.13 },
    { lat: 35.68, lon: 139.69 },
    { lat: 40.71, lon: -74.01 },
    { lat: 48.86, lon: 2.35 },
  ],
  hijack: [
    { lat: 47.61, lon: -122.33 },
    { lat: 52.52, lon: 13.40 },
    { lat: 1.35, lon: 103.82 },
    { lat: 37.57, lon: 126.98 },
    { lat: 50.11, lon: 8.68 },
  ],
  memory: [
    { lat: 55.76, lon: 37.62 },
    { lat: -33.87, lon: 151.21 },
    { lat: 19.43, lon: -99.13 },
    { lat: 28.61, lon: 77.21 },
    { lat: 59.33, lon: 18.07 },
  ],
};
const SURFACE_RGB = {
  injection: [26, 165, 143],
  hijack: [214, 154, 63],
  memory: [141, 99, 196],
  allow: [120, 148, 142],
};
const LAND_DOTS = decodeLand(LAND_DOTS_B64);

let canvas;
let ctx;
let raf = 0;
let rotY = 0.85;
let rotX = -0.28;
let dragging = false;
let lastX = 0;
let autoRotate = true;
let arcs = [];
let dpr = 1;

function decodeLand(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  const view = new DataView(bytes.buffer);
  const n = bytes.length / 4;
  const dots = new Float32Array(n * 2);
  for (let i = 0; i < n; i += 1) {
    dots[i * 2] = view.getInt16(i * 4, true) / 100;
    dots[i * 2 + 1] = view.getInt16(i * 4 + 2, true) / 100;
  }
  return dots;
}

function lonLatToVec(lat, lon) {
  const phi = (90 - lat) * Math.PI / 180;
  const theta = (lon + 180) * Math.PI / 180;
  return {
    x: -Math.sin(phi) * Math.cos(theta),
    y: Math.cos(phi),
    z: Math.sin(phi) * Math.sin(theta),
  };
}

function rotate(v) {
  const cy = Math.cos(rotY);
  const sy = Math.sin(rotY);
  const cx = Math.cos(rotX);
  const sx = Math.sin(rotX);
  const xz = { x: v.x * cy - v.z * sy, y: v.y, z: v.x * sy + v.z * cy };
  return { x: xz.x, y: xz.y * cx - xz.z * sx, z: xz.y * sx + xz.z * cx };
}

function isDarkTheme() {
  const theme = document.documentElement.getAttribute("data-theme");
  return theme === "midnight" || theme === "graphite";
}

function palette() {
  if (isDarkTheme()) {
    return {
      land: [96, 232, 214],
      landBack: [28, 78, 88],
      ocean: [8, 28, 38, 0.92],
      rim: [64, 230, 255, 0.22],
      glow: [64, 230, 255, 0.16],
      allow: [64, 214, 186],
      deny: [255, 107, 92],
    };
  }
  return {
    land: [46, 186, 168],
    landBack: [186, 226, 220],
    ocean: [246, 252, 250, 0.96],
    rim: [46, 186, 168, 0.16],
    glow: [46, 201, 176, 0.12],
    allow: [32, 168, 148],
    deny: [220, 92, 78],
  };
}

function resize() {
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.max(1, Math.round(rect.width * dpr));
  canvas.height = Math.max(1, Math.round(rect.height * dpr));
}

function project(v, cx, cy, radius) {
  const perspective = 1.35 / (1.35 - v.z * 0.42);
  return {
    x: cx + v.x * radius * perspective,
    y: cy - v.y * radius * perspective,
    z: v.z,
    scale: perspective,
  };
}

function greatCircle(from, to, steps = 28) {
  const a = lonLatToVec(from.lat, from.lon);
  const b = lonLatToVec(to.lat, to.lon);
  const dot = Math.max(-1, Math.min(1, a.x * b.x + a.y * b.y + a.z * b.z));
  const omega = Math.acos(dot);
  if (omega < 0.001) return [a, b];
  const pts = [];
  for (let i = 0; i <= steps; i += 1) {
    const t = i / steps;
    const s0 = Math.sin((1 - t) * omega) / Math.sin(omega);
    const s1 = Math.sin(t * omega) / Math.sin(omega);
    const lift = Math.sin(t * Math.PI) * 0.18;
    const x = a.x * s0 + b.x * s1;
    const y = a.y * s0 + b.y * s1;
    const z = a.z * s0 + b.z * s1;
    const len = Math.hypot(x, y, z) || 1;
    pts.push({ x: (x / len) * (1 + lift), y: (y / len) * (1 + lift), z: (z / len) * (1 + lift) });
  }
  return pts;
}

function drawGlobe() {
  if (!canvas || !ctx) return;
  const dark = isDarkTheme();
  const pal = palette();
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const cx = w * 0.5;
  const cy = h * 0.5;
  const radius = Math.min(w, h) * 0.38;

  const halo = ctx.createRadialGradient(cx, cy, radius * 0.82, cx, cy, radius * 1.28);
  halo.addColorStop(0, `rgba(${pal.glow.slice(0, 3).join(",")},0)`);
  halo.addColorStop(0.55, `rgba(${pal.glow.join(",")})`);
  halo.addColorStop(1, `rgba(${pal.glow.slice(0, 3).join(",")},0)`);
  ctx.beginPath();
  ctx.arc(cx, cy, radius * 1.28, 0, Math.PI * 2);
  ctx.fillStyle = halo;
  ctx.fill();

  const ocean = ctx.createRadialGradient(cx - radius * 0.28, cy - radius * 0.32, radius * 0.1, cx, cy, radius * 1.08);
  ocean.addColorStop(0, dark ? "rgba(18, 64, 78, 0.95)" : "rgba(255, 255, 255, 0.98)");
  ocean.addColorStop(0.55, dark ? "rgba(10, 40, 52, 0.96)" : "rgba(236, 250, 246, 0.96)");
  ocean.addColorStop(1, dark ? "rgba(6, 22, 32, 0.88)" : "rgba(210, 236, 230, 0.9)");
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.fillStyle = ocean;
  ctx.fill();

  const light = { x: -0.45, y: 0.35, z: 0.82 };
  for (let i = 0; i < LAND_DOTS.length; i += 2) {
    const v = rotate(lonLatToVec(LAND_DOTS[i], LAND_DOTS[i + 1]));
    const p = project(v, cx, cy, radius);
    const lit = Math.max(0, v.x * light.x + v.y * light.y + v.z * light.z);
    const size = (v.z > 0 ? 1.35 : 0.7) * dpr * p.scale;
    const alpha = v.z > 0 ? 0.38 + lit * 0.62 : 0.08 + lit * 0.08;
    const color = v.z > 0 ? pal.land : pal.landBack;
    ctx.fillStyle = `rgba(${color.join(",")},${alpha.toFixed(3)})`;
    ctx.beginPath();
    ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
    ctx.fill();
  }

  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.clip();
  for (const arc of arcs) {
    const color = SURFACE_RGB[arc.surface] || (arc.kind === "allow" ? SURFACE_RGB.allow : pal.deny);
    const pts = greatCircle(arc.from, CORE).map((v) => project(rotate(v), cx, cy, radius));
    const visible = pts.filter((p) => p.z > -0.05);
    if (visible.length < 2) continue;
    ctx.beginPath();
    ctx.moveTo(visible[0].x, visible[0].y);
    for (let i = 1; i < visible.length; i += 1) ctx.lineTo(visible[i].x, visible[i].y);
    ctx.strokeStyle = `rgba(${color.join(",")},${arc.kind === "allow" ? 0.38 : 0.62})`;
    ctx.lineWidth = (arc.kind === "deny" || arc.surface ? 1.7 : 1.15) * dpr;
    ctx.stroke();
    const tip = visible[visible.length - 1];
    ctx.fillStyle = `rgb(${color.join(",")})`;
    ctx.beginPath();
    ctx.arc(tip.x, tip.y, 2.2 * dpr, 0, Math.PI * 2);
    ctx.fill();
    const origin = visible[0];
    ctx.beginPath();
    ctx.arc(origin.x, origin.y, 2.6 * dpr, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${color.join(",")},0.9)`;
    ctx.fill();
  }
  ctx.restore();

  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.strokeStyle = dark ? "rgba(64,230,255,0.28)" : "rgba(46,186,168,0.28)";
  ctx.lineWidth = 1.2 * dpr;
  ctx.stroke();
}

function tick() {
  if (!canvas?.isConnected) {
    raf = 0;
    return;
  }
  if (autoRotate && !dragging && document.visibilityState !== "hidden") rotY += 0.0032;
  drawGlobe();
  raf = requestAnimationFrame(tick);
}

function originFor(surface, seed) {
  const pool = SURFACE_ORIGINS[surface] || SURFACE_ORIGINS.injection;
  let h = 2166136261;
  const value = String(seed || surface);
  for (let i = 0; i < value.length; i += 1) h = Math.imul(h ^ value.charCodeAt(i), 16777619);
  return pool[Math.abs(h) % pool.length];
}

export function initOverviewGlobe() {
  canvas = document.getElementById("overviewGlobe");
  if (!canvas) return;
  ctx = canvas.getContext("2d");
  resize();
  if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => resize()).observe(canvas.parentElement || canvas);
  }
  requestAnimationFrame(resize);
  canvas.addEventListener("pointerdown", (event) => {
    dragging = true;
    autoRotate = false;
    lastX = event.clientX;
    canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    rotY += (event.clientX - lastX) * 0.006;
    lastX = event.clientX;
  });
  const stopDrag = () => {
    dragging = false;
    autoRotate = true;
  };
  canvas.addEventListener("pointerup", stopDrag);
  canvas.addEventListener("pointercancel", stopDrag);
  window.addEventListener("resize", resize);
  if (!raf) raf = requestAnimationFrame(tick);
}

export function updateOverviewGlobe(payload = {}) {
  const items = Array.isArray(payload.arcs) ? payload.arcs : [];
  const filter = payload.filterSurface || "all";
  arcs = items
    .filter((item) => filter === "all" || item.surface === filter)
    .slice(0, 16)
    .map((item) => ({
      from: item.from || originFor(item.surface, item.id || item.label),
      surface: item.surface || (item.kind === "allow" ? "" : "injection"),
      kind: item.kind === "allow" ? "allow" : "deny",
    }));
}
