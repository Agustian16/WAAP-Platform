"use client";
// Dynamic Attack Graph (FR-6.5..6.9): WebGL rendering via sigma, force layout in a Web Worker (FA2), static
// hierarchical/radial layouts, drag-to-pin, double-click expand, path highlighting, live edge flashing.
import * as React from "react";
import Graph from "graphology";
import Sigma from "sigma";
import { NodeCircleProgram, EdgeArrowProgram, EdgeRectangleProgram, createNodeCompoundProgram } from "sigma/rendering";
import { animateNodes } from "sigma/utils";
import { createNodeImageProgram } from "@sigma/node-image";
import FA2Layout from "graphology-layout-forceatlas2/worker";
import forceAtlas2 from "graphology-layout-forceatlas2";
import { downloadAsPNG } from "@sigma/export-image";
import type { GEdge, GNode, GNodeType } from "@/lib/attack-graph";
import { PICTO, type GraphApi, type GraphColors } from "./picto";
import { staticLayout } from "@/lib/attack-graph";
import { stageIndex } from "@/lib/killchain";
import { download } from "@/lib/utils";

const rgb = (ch: string) => (ch.startsWith("#") ? ch : `rgb(${ch.split(" ").join(",")})`);
function luminance(hex: string) {
  const m = hex.replace("#", "").match(/.{2}/g);
  if (!m) return 0;
  const [r, g, b] = m.map((x) => { const c = parseInt(x, 16) / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

interface Props {
  nodes: GNode[];
  edges: GEdge[];
  layout: "force" | "hierarchical" | "radial";
  colors: GraphColors;
  selectedId: string | null;
  highlightCampaign: string | null;
  flash: boolean;
  onSelectNode: (id: string | null) => void;
  onSelectEdge: (id: string) => void;
  onExpand: (id: string) => void;
  onPinChange?: (id: string, pinned: boolean) => void;
  pinned: Set<string>;
  apiRef: React.MutableRefObject<GraphApi | null>;
}

export default function AttackGraph(p: Props) {
  const container = React.useRef<HTMLDivElement>(null);
  const sigmaRef = React.useRef<Sigma | null>(null);
  const graphRef = React.useRef(new Graph({ type: "directed", multi: false }));
  const fa2 = React.useRef<FA2Layout | null>(null);
  const props = React.useRef(p);
  props.current = p;

  const stageColor = React.useCallback((s: string | null) => {
    const c = props.current.colors;
    if (!s) return rgb(c["--muted"]);
    const i = stageIndex(s as never);
    return c[`--stage-${i === 1 ? 0 : i === 0 ? 1 : i}` as keyof GraphColors];
  }, []);

  // ---- mount sigma once ----
  React.useEffect(() => {
    const graph = graphRef.current;
    const NodeProgram = createNodeCompoundProgram([
      NodeCircleProgram,
      createNodeImageProgram({ padding: 0.28, size: { mode: "force", value: 128 }, drawingMode: "color", colorAttribute: "pictoColor", imageAttribute: "image" }),
    ]);
    const c = props.current.colors;
    const renderer = new Sigma(graph, container.current!, {
      defaultNodeType: "picto",
      nodeProgramClasses: { picto: NodeProgram },
      edgeProgramClasses: { arrow: EdgeArrowProgram, line: EdgeRectangleProgram },
      defaultEdgeType: "arrow",
      renderEdgeLabels: false,
      enableEdgeEvents: true,
      labelFont: getComputedStyle(document.body).fontFamily, // canvas cannot resolve CSS vars
      labelSize: 12,
      labelWeight: "500",
      labelColor: { color: rgb(c["--fg"]) },
      labelRenderedSizeThreshold: 9,
      zIndex: true,
      allowInvalidContainer: true,
      minCameraRatio: 0.08,
      maxCameraRatio: 6,
      defaultDrawNodeHover: (ctx, data, settings) => {
        const col = props.current.colors;
        const size = settings.labelSize;
        ctx.font = `500 ${size}px ${settings.labelFont}`;
        const label = data.label ?? "";
        const w = ctx.measureText(label).width + 12;
        const x = data.x + data.size + 4, y = data.y - size / 2 - 5;
        ctx.fillStyle = rgb(col["--surface"]);
        ctx.strokeStyle = rgb(col["--border-strong"]);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect(x, y, w, size + 10, 3);
        ctx.fill(); ctx.stroke();
        ctx.beginPath(); ctx.arc(data.x, data.y, data.size + 3, 0, Math.PI * 2);
        ctx.strokeStyle = rgb(col["--accent"]); ctx.lineWidth = 2; ctx.stroke();
        ctx.fillStyle = rgb(col["--fg"]);
        ctx.fillText(label, x + 6, data.y + size / 3);
      },
      nodeReducer: (id, d) => {
        const st = props.current;
        const res = { ...d };
        const hl = pathSet.current;
        if (hl && !hl.has(id)) { res.color = rgb(st.colors["--surface-3"]); res.pictoColor = rgb(st.colors["--muted"]); res.label = ""; res.zIndex = 0; }
        else if (hl) res.zIndex = 2;
        if (id === st.selectedId) { res.highlighted = true; res.zIndex = 3; }
        if (st.pinned.has(id) && res.label) res.label = `${res.label}  [pinned]`;
        return res;
      },
      edgeReducer: (id, d) => {
        const st = props.current;
        const res = { ...d };
        const hl = pathEdges.current;
        if (hl && !hl.has(id)) { res.color = rgb(st.colors["--surface-3"]); res.zIndex = 0; }
        else if (st.flash && d.kind === "attack" && Date.now() - (d.lastTs as number) < 3000) { res.size = (d.size as number) + 2.5; res.color = rgb(st.colors["--accent"]); res.zIndex = 2; }
        return res;
      },
    });
    sigmaRef.current = renderer;
    // Let the page scroll over the graph; zoom needs Ctrl/Cmd + wheel (or the zoom buttons).
    const onWheel = (e: WheelEvent) => { if (!e.ctrlKey && !e.metaKey) e.stopPropagation(); };
    container.current!.addEventListener("wheel", onWheel, { capture: true });

    renderer.on("clickNode", ({ node }) => props.current.onSelectNode(node));
    renderer.on("clickStage", () => props.current.onSelectNode(null));
    renderer.on("clickEdge", ({ edge }) => props.current.onSelectEdge(edge));
    renderer.on("doubleClickNode", (e) => { e.preventSigmaDefault(); props.current.onExpand(e.node); });
    renderer.on("enterNode", () => { if (container.current) container.current.style.cursor = "pointer"; });
    renderer.on("leaveNode", () => { if (container.current) container.current.style.cursor = ""; });
    renderer.on("enterEdge", () => { if (container.current) container.current.style.cursor = "pointer"; });
    renderer.on("leaveEdge", () => { if (container.current) container.current.style.cursor = ""; });

    // Drag a node to reposition; it stays pinned (FR-6.7 drag + pin).
    let dragged: string | null = null;
    let moved = false;
    renderer.on("downNode", (e) => { dragged = e.node; moved = false; if (!renderer.getCustomBBox()) renderer.setCustomBBox(renderer.getBBox()); });
    const captor = renderer.getMouseCaptor();
    captor.on("mousemovebody", (e) => {
      if (!dragged) return;
      moved = true;
      const pos = renderer.viewportToGraph(e);
      graph.setNodeAttribute(dragged, "x", pos.x);
      graph.setNodeAttribute(dragged, "y", pos.y);
      e.preventSigmaDefault(); e.original.preventDefault(); e.original.stopPropagation();
    });
    captor.on("mouseup", () => {
      if (dragged && moved) { graph.setNodeAttribute(dragged, "fixed", true); props.current.onPinChange?.(dragged, true); }
      dragged = null;
    });

    props.current.apiRef.current = {
      zoomIn: () => renderer.getCamera().animatedZoom({ duration: 200 }),
      zoomOut: () => renderer.getCamera().animatedUnzoom({ duration: 200 }),
      reset: () => { renderer.setCustomBBox(null); renderer.getCamera().animatedReset({ duration: 250 }); },
      focus: (id) => {
        if (!graph.hasNode(id)) return;
        const d = renderer.getNodeDisplayData(id);
        if (d) renderer.getCamera().animate({ x: d.x, y: d.y, ratio: 0.5 }, { duration: 400 });
      },
      png: (name) => downloadAsPNG(renderer, { fileName: name, backgroundColor: rgb(props.current.colors["--surface"]) }),
      svg: (name) => {
        const { width, height } = renderer.getDimensions();
        const col = props.current.colors;
        const parts: string[] = [`<rect width="100%" height="100%" fill="${rgb(col["--surface"])}"/>`];
        graph.forEachEdge((e, a, s, t) => {
          const ps = renderer.graphToViewport(graph.getNodeAttributes(s) as { x: number; y: number });
          const pt = renderer.graphToViewport(graph.getNodeAttributes(t) as { x: number; y: number });
          parts.push(`<line x1="${ps.x.toFixed(1)}" y1="${ps.y.toFixed(1)}" x2="${pt.x.toFixed(1)}" y2="${pt.y.toFixed(1)}" stroke="${a.color}" stroke-width="${a.size}"/>`);
        });
        graph.forEachNode((n, a) => {
          const v = renderer.graphToViewport(a as { x: number; y: number });
          const dd = renderer.getNodeDisplayData(n);
          const r = dd ? renderer.scaleSize(dd.size) : a.size;
          parts.push(`<circle cx="${v.x.toFixed(1)}" cy="${v.y.toFixed(1)}" r="${r.toFixed(1)}" fill="${a.color}"/>`);
          if (a.forceLabel) parts.push(`<text x="${(v.x + r + 4).toFixed(1)}" y="${(v.y + 4).toFixed(1)}" font-family="IBM Plex Sans, sans-serif" font-size="12" fill="${rgb(col["--fg"])}">${String(a.label).replace(/&/g, "&amp;").replace(/</g, "&lt;")}</text>`);
        });
        download(`${name}.svg`, `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${parts.join("")}</svg>`, "image/svg+xml");
      },
    };
    const el = container.current!;
    return () => { el.removeEventListener("wheel", onWheel, { capture: true }); fa2.current?.kill(); fa2.current = null; renderer.kill(); sigmaRef.current = null; };
  }, []);

  // ---- path highlighting (FR-6.7): ancestors + descendants of the selection, or a campaign's footprint ----
  const pathSet = React.useRef<Set<string> | null>(null);
  const pathEdges = React.useRef<Set<string> | null>(null);
  React.useEffect(() => {
    const { selectedId, highlightCampaign, nodes, edges } = p;
    if (!selectedId && !highlightCampaign) { pathSet.current = null; pathEdges.current = null; }
    else if (selectedId && selectedId.includes("->")) {
      const e = edges.find((x) => x.id === selectedId);
      pathSet.current = new Set(e ? [e.source, e.target] : []);
      pathEdges.current = new Set([selectedId]);
    } else if (selectedId) {
      const out = new Map<string, GEdge[]>(); const inn = new Map<string, GEdge[]>();
      edges.forEach((e) => { out.set(e.source, [...(out.get(e.source) ?? []), e]); inn.set(e.target, [...(inn.get(e.target) ?? []), e]); });
      const ns = new Set([selectedId]); const es = new Set<string>();
      const walk = (id: string, m: Map<string, GEdge[]>, key: "source" | "target") => (m.get(id) ?? []).forEach((e) => { es.add(e.id); const nx = e[key]; if (!ns.has(nx)) { ns.add(nx); walk(nx, m, key); } });
      walk(selectedId, out, "target");
      walk(selectedId, inn, "source");
      pathSet.current = ns; pathEdges.current = es;
    } else {
      const ns = new Set(nodes.filter((n) => n.campaignIds.includes(highlightCampaign!)).map((n) => n.id));
      pathSet.current = ns;
      pathEdges.current = new Set(edges.filter((e) => ns.has(e.source) && ns.has(e.target) && (e.kind === "structure" || nodes.find((n) => n.id === e.source)?.campaignIds.includes(highlightCampaign!))).map((e) => e.id));
    }
    sigmaRef.current?.refresh({ skipIndexation: true });
  }, [p.selectedId, p.highlightCampaign, p.nodes, p.edges]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---- theme ----
  React.useEffect(() => {
    const r = sigmaRef.current;
    if (!r) return;
    r.setSetting("labelColor", { color: rgb(p.colors["--fg"]) });
    applyColors();
    r.refresh();
  }, [p.colors]); // eslint-disable-line react-hooks/exhaustive-deps

  const applyColors = React.useCallback(() => {
    const g = graphRef.current;
    const c = props.current.colors;
    g.forEachNode((id, a) => {
      const t = a.ntype as GNodeType;
      const color = t === "site" ? rgb(c["--fg-2"]) : t === "category" || t === "edgenode" ? rgb(c["--border-strong"]) : stageColor(a.stage);
      g.mergeNodeAttributes(id, { color, pictoColor: luminance(color) > 0.35 ? "#111214" : "#ffffff" });
    });
    g.forEachEdge((id, a) => g.setEdgeAttribute(id, "color", a.kind === "attack" ? stageColor(a.stage) : rgb(c["--border-strong"])));
  }, [stageColor]);

  // ---- sync model -> graphology ----
  React.useEffect(() => {
    const g = graphRef.current;
    const want = new Set(p.nodes.map((n) => n.id));
    g.forEachNode((id) => { if (!want.has(id)) g.dropNode(id); });
    const statics = p.layout === "force" ? null : staticLayout(p.nodes, p.layout);
    const maxCount = Math.max(1, ...p.nodes.map((n) => n.count));
    let added = 0;
    for (const n of p.nodes) {
      const size = n.type === "site" ? 14 : n.type === "category" || n.type === "edgenode" ? 9 : 6 + Math.sqrt(n.count / maxCount) * 14;
      const attrs = {
        label: n.label, ntype: n.type, stage: n.stage, size, image: PICTO[n.type], lastTs: n.lastTs,
        forceLabel: n.type === "site" || n.type === "cluster" || (n.type === "attacker" && n.count / maxCount > 0.05),
      };
      if (g.hasNode(n.id)) g.mergeNodeAttributes(n.id, attrs);
      else {
        added++;
        const nb = p.edges.find((e) => e.target === n.id || e.source === n.id);
        const other = nb && (nb.source === n.id ? nb.target : nb.source);
        const base = statics?.[n.id] ?? (other && g.hasNode(other) ? g.getNodeAttributes(other) : { x: Math.random() * 100, y: Math.random() * 100 });
        g.addNode(n.id, { ...attrs, x: (base.x as number) + (Math.random() - 0.5) * 30, y: (base.y as number) + (Math.random() - 0.5) * 30, fixed: p.pinned.has(n.id) });
      }
    }
    const wantE = new Set(p.edges.map((e) => e.id));
    g.forEachEdge((id) => { if (!wantE.has(id)) g.dropEdge(id); });
    for (const e of p.edges) {
      const attrs = { kind: e.kind, stage: e.stage, lastTs: e.lastTs, size: e.kind === "attack" ? Math.min(1.5 + Math.log2(e.count), 8) : 1, type: e.kind === "attack" ? "arrow" : "line", label: `${e.count}` };
      if (g.hasEdge(e.id)) g.mergeEdgeAttributes(e.id, attrs);
      else if (g.hasNode(e.source) && g.hasNode(e.target)) g.addEdgeWithKey(e.id, e.source, e.target, attrs);
    }
    applyColors();
    if (statics) {
      fa2.current?.stop();
      const target: Record<string, { x: number; y: number }> = {};
      g.forEachNode((id, a) => { if (!a.fixed && statics[id]) target[id] = statics[id]; });
      animateNodes(g, target, { duration: 450 });
    } else if (added > 0 || !fa2.current) {
      if (!fa2.current) fa2.current = new FA2Layout(g, { settings: { ...forceAtlas2.inferSettings(g), gravity: 1.2, scalingRatio: 8, slowDown: 3, barnesHutOptimize: g.order > 300 } });
      fa2.current.start();
      const t = setTimeout(() => fa2.current?.stop(), added > 20 || g.order < 2 ? 2200 : 900);
      return () => clearTimeout(t);
    }
  }, [p.nodes, p.edges, p.layout]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(() => {
    const g = graphRef.current;
    g.forEachNode((id) => g.setNodeAttribute(id, "fixed", p.pinned.has(id)));
    sigmaRef.current?.refresh({ skipIndexation: true });
  }, [p.pinned]);

  // Live flashing: repaint so recently-hit edges pulse back to normal.
  React.useEffect(() => {
    if (!p.flash) return;
    const t = setInterval(() => sigmaRef.current?.refresh({ skipIndexation: true }), 600);
    return () => clearInterval(t);
  }, [p.flash]);

  React.useEffect(() => { sigmaRef.current?.refresh({ skipIndexation: true }); }, [p.selectedId, p.pinned]);

  return <div ref={container} className="absolute inset-0" role="img" aria-label="Attack graph: attackers on the left connect to the endpoints they targeted, then to sites and rule categories. Use the node search or the Campaign List tab for a keyboard-accessible view." />;
}
