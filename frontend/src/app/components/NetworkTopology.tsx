"use client";

import { useRef, useEffect, useMemo, useState, useCallback } from "react";
import { Network, ZoomIn, ZoomOut, RotateCcw } from "lucide-react";
import type { Alert } from "../lib/types";
import { IPDrilldownModal } from "./IPDrilldownModal";

interface Node {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  severity: "high" | "medium" | "low";
  connectionCount: number;
}

interface Edge {
  source: string;
  target: string;
  weight: number;
  severity: "high" | "medium" | "low";
}

const SEVERITY_COLOR: Record<string, string> = {
  high: "#f43f5e",
  medium: "#f59e0b",
  low: "#3b82f6",
};

const SEVERITY_GLOW: Record<string, string> = {
  high: "rgba(244, 63, 94, 0.3)",
  medium: "rgba(245, 158, 11, 0.2)",
  low: "rgba(59, 130, 246, 0.15)",
};

function buildGraph(alerts: Alert[]) {
  const nodeMap: Record<
    string,
    { count: number; high: number; medium: number; low: number }
  > = {};
  const edgeMap: Record<string, { weight: number; high: number; medium: number; low: number }> =
    {};

  for (const a of alerts) {
    if (!nodeMap[a._src_ip])
      nodeMap[a._src_ip] = { count: 0, high: 0, medium: 0, low: 0 };
    if (!nodeMap[a._dst_ip])
      nodeMap[a._dst_ip] = { count: 0, high: 0, medium: 0, low: 0 };
    nodeMap[a._src_ip].count++;
    nodeMap[a._src_ip][a.severity]++;

    const edgeKey = `${a._src_ip}->${a._dst_ip}`;
    if (!edgeMap[edgeKey])
      edgeMap[edgeKey] = { weight: 0, high: 0, medium: 0, low: 0 };
    edgeMap[edgeKey].weight++;
    edgeMap[edgeKey][a.severity]++;
  }

  const nodes: Node[] = Object.entries(nodeMap).map(([id, data]) => {
    const dominant =
      data.high >= data.medium && data.high >= data.low
        ? "high"
        : data.medium >= data.low
        ? "medium"
        : "low";
    return {
      id,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
      radius: Math.min(4 + Math.sqrt(data.count) * 3, 24),
      severity: dominant,
      connectionCount: data.count,
    };
  });

  const edges: Edge[] = Object.entries(edgeMap).map(([key, data]) => {
    const [source, target] = key.split("->");
    const dominant =
      data.high >= data.medium && data.high >= data.low
        ? "high"
        : data.medium >= data.low
        ? "medium"
        : "low";
    return { source, target, weight: data.weight, severity: dominant };
  });

  return { nodes, edges };
}

function simulate(nodes: Node[], edges: Edge[], width: number, height: number, iterations = 200) {
  const cx = width / 2;
  const cy = height / 2;
  const repulsion = 8000;
  const attraction = 0.005;
  const damping = 0.9;
  const centerGravity = 0.01;

  // Init positions in a circle
  nodes.forEach((n, i) => {
    const angle = (i / nodes.length) * Math.PI * 2;
    const r = Math.min(width, height) * 0.3;
    n.x = cx + Math.cos(angle) * r;
    n.y = cy + Math.sin(angle) * r;
  });

  const nodeIdx: Record<string, number> = {};
  nodes.forEach((n, i) => (nodeIdx[n.id] = i));

  for (let iter = 0; iter < iterations; iter++) {
    const alpha = 1 - iter / iterations;

    // Repulsion between all pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (repulsion * alpha) / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        nodes[i].vx -= fx;
        nodes[i].vy -= fy;
        nodes[j].vx += fx;
        nodes[j].vy += fy;
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const si = nodeIdx[edge.source];
      const ti = nodeIdx[edge.target];
      if (si === undefined || ti === undefined) continue;
      const dx = nodes[ti].x - nodes[si].x;
      const dy = nodes[ti].y - nodes[si].y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = dist * attraction * alpha * Math.log(edge.weight + 1);
      nodes[si].vx += (dx / dist) * force;
      nodes[si].vy += (dy / dist) * force;
      nodes[ti].vx -= (dx / dist) * force;
      nodes[ti].vy -= (dy / dist) * force;
    }

    // Center gravity + damping
    for (const n of nodes) {
      n.vx += (cx - n.x) * centerGravity * alpha;
      n.vy += (cy - n.y) * centerGravity * alpha;
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
      // Bounds
      n.x = Math.max(n.radius + 10, Math.min(width - n.radius - 10, n.x));
      n.y = Math.max(n.radius + 10, Math.min(height - n.radius - 10, n.y));
    }
  }
}

export function NetworkTopology({
  alerts,
}: {
  alerts: Alert[];
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [drilldownIP, setDrilldownIP] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<{
    x: number;
    y: number;
    node: Node;
  } | null>(null);
  const [zoom, setZoom] = useState(1);
  const nodesRef = useRef<Node[]>([]);
  const edgesRef = useRef<Edge[]>([]);
  const animFrameRef = useRef<number>(0);

  const { nodes, edges } = useMemo(() => {
    if (alerts.length === 0) return { nodes: [], edges: [] };
    const graph = buildGraph(alerts);
    return graph;
  }, [alerts]);

  nodesRef.current = nodes;
  edgesRef.current = edges;

  const draw = useCallback(
    (ctx: CanvasRenderingContext2D, width: number, height: number) => {
      ctx.clearRect(0, 0, width, height);
      ctx.save();
      ctx.scale(zoom, zoom);

      const ns = nodesRef.current;
      const es = edgesRef.current;
      const nodeIdx: Record<string, number> = {};
      ns.forEach((n, i) => (nodeIdx[n.id] = i));

      // Draw edges
      for (const edge of es) {
        const si = nodeIdx[edge.source];
        const ti = nodeIdx[edge.target];
        if (si === undefined || ti === undefined) continue;
        const s = ns[si];
        const t = ns[ti];

        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        ctx.strokeStyle = SEVERITY_COLOR[edge.severity] + "30";
        ctx.lineWidth = Math.min(0.5 + Math.log(edge.weight + 1) * 1.5, 6);
        ctx.stroke();
      }

      // Draw nodes
      for (const node of ns) {
        // Glow
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
        ctx.fillStyle = SEVERITY_GLOW[node.severity];
        ctx.fill();

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = SEVERITY_COLOR[node.severity];
        ctx.fill();

        // Inner highlight
        ctx.beginPath();
        ctx.arc(
          node.x - node.radius * 0.2,
          node.y - node.radius * 0.2,
          node.radius * 0.4,
          0,
          Math.PI * 2
        );
        ctx.fillStyle = "rgba(255,255,255,0.15)";
        ctx.fill();

        // Label
        if (node.radius > 8) {
          ctx.font = "10px monospace";
          ctx.fillStyle = "#e2e8f0";
          ctx.textAlign = "center";
          ctx.textBaseline = "top";
          const label =
            node.id.length > 18 ? node.id.slice(0, 16) + ".." : node.id;
          ctx.fillText(label, node.x, node.y + node.radius + 4);
        }
      }

      ctx.restore();
    },
    [zoom]
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const rect = container.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.scale(dpr, dpr);

    if (nodes.length > 0) {
      simulate(nodes, edges, rect.width, rect.height);
    }

    draw(ctx, rect.width, rect.height);
  }, [nodes, edges, zoom, draw]);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx = (e.clientX - rect.left) / zoom;
      const my = (e.clientY - rect.top) / zoom;

      let found: Node | null = null;
      for (const node of nodesRef.current) {
        const dx = mx - node.x;
        const dy = my - node.y;
        if (dx * dx + dy * dy < (node.radius + 4) * (node.radius + 4)) {
          found = node;
          break;
        }
      }

      if (found) {
        canvas.style.cursor = "pointer";
        setTooltip({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
          node: found,
        });
      } else {
        canvas.style.cursor = "default";
        setTooltip(null);
      }
    },
    [zoom]
  );

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx = (e.clientX - rect.left) / zoom;
      const my = (e.clientY - rect.top) / zoom;

      for (const node of nodesRef.current) {
        const dx = mx - node.x;
        const dy = my - node.y;
        if (dx * dx + dy * dy < (node.radius + 4) * (node.radius + 4)) {
          setDrilldownIP(node.id);
          break;
        }
      }
    },
    [zoom]
  );

  const handleZoomIn = () => setZoom((z) => Math.min(z * 1.3, 4));
  const handleZoomOut = () => setZoom((z) => Math.max(z / 1.3, 0.3));
  const handleReset = () => setZoom(1);

  if (alerts.length === 0) {
    return (
      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-[600px] flex flex-col items-center justify-center text-slate-500">
        <Network className="w-10 h-10 text-slate-600 mb-2" />
        <p className="text-sm">No network data available.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            Network Topology
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            {nodes.length} nodes / {edges.length} edges
          </span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={handleZoomIn}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-white/5 transition"
            aria-label="Zoom in"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-white/5 transition"
            aria-label="Zoom out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleReset}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-white/5 transition"
            aria-label="Reset zoom"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs">
        {Object.entries(SEVERITY_COLOR).map(([sev, color]) => (
          <div key={sev} className="flex items-center gap-1.5">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: color }}
            />
            <span className="text-slate-400 capitalize">{sev}</span>
          </div>
        ))}
        <span className="text-slate-600">|</span>
        <span className="text-slate-500">Node size = alert count</span>
        <span className="text-slate-600">|</span>
        <span className="text-slate-500">Click node for details</span>
      </div>

      {/* Canvas */}
      <div
        ref={containerRef}
        className="bg-slate-900 border border-white/5 rounded-2xl overflow-hidden relative"
        style={{ height: 560 }}
      >
        <canvas
          ref={canvasRef}
          onMouseMove={handleMouseMove}
          onClick={handleClick}
          onMouseLeave={() => setTooltip(null)}
        />

        {/* Tooltip */}
        {tooltip && (
          <div
            className="absolute pointer-events-none z-20 bg-slate-950 border border-white/10 rounded-lg p-3 shadow-xl text-xs"
            style={{
              left: tooltip.x + 12,
              top: tooltip.y - 8,
              transform:
                tooltip.x > 400 ? "translateX(-110%)" : undefined,
            }}
          >
            <p className="font-mono text-cyan-400 font-bold mb-1">
              {tooltip.node.id}
            </p>
            <p className="text-slate-300">
              Alerts:{" "}
              <span className="text-white font-semibold">
                {tooltip.node.connectionCount}
              </span>
            </p>
            <p className="text-slate-300">
              Severity:{" "}
              <span
                className="font-bold capitalize"
                style={{ color: SEVERITY_COLOR[tooltip.node.severity] }}
              >
                {tooltip.node.severity}
              </span>
            </p>
            <p className="text-slate-500 mt-1 text-[10px]">Click for full drilldown</p>
          </div>
        )}
      </div>

      {/* IP Drilldown */}
      {drilldownIP && (
        <IPDrilldownModal
          ip={drilldownIP}
          alerts={alerts}
          onClose={() => setDrilldownIP(null)}
        />
      )}
    </div>
  );
}
