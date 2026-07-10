"use client";

import { useRef, useEffect, useMemo, useState, useCallback } from "react";
import { Clock, ZoomIn, ZoomOut, RotateCcw } from "lucide-react";
import type { Alert } from "../lib/types";
import { IPDrilldownModal } from "./IPDrilldownModal";

const SEVERITY_COLOR: Record<string, string> = {
  high: "#f43f5e",
  medium: "#f59e0b",
  low: "#3b82f6",
};

interface TimelineAlert {
  ts: number;
  severity: "high" | "medium" | "low";
  score: number;
  srcIP: string;
  dstIP: string;
}

export function AlertTimeline({ alerts }: { alerts: Alert[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [drilldownIP, setDrilldownIP] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<{
    x: number;
    y: number;
    alert: TimelineAlert;
  } | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [panOffset, setPanOffset] = useState(0);
  const isDragging = useRef(false);
  const lastMouseX = useRef(0);

  const timelineData: TimelineAlert[] = useMemo(
    () =>
      alerts
        .map((a) => ({
          ts: a._alerted_at,
          severity: a.severity,
          score: a.score,
          srcIP: a._src_ip,
          dstIP: a._dst_ip,
        }))
        .sort((a, b) => a.ts - b.ts),
    [alerts]
  );

  const timeRange = useMemo(() => {
    if (timelineData.length === 0)
      return { min: Date.now() / 1000, max: Date.now() / 1000 };
    return {
      min: timelineData[0].ts,
      max: timelineData[timelineData.length - 1].ts,
    };
  }, [timelineData]);

  const draw = useCallback(() => {
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

    const W = rect.width;
    const H = rect.height;
    const pad = { top: 30, bottom: 40, left: 60, right: 20 };
    const plotW = W - pad.left - pad.right;
    const plotH = H - pad.top - pad.bottom;

    ctx.clearRect(0, 0, W, H);

    if (timelineData.length === 0) {
      ctx.fillStyle = "#64748b";
      ctx.font = "13px system-ui";
      ctx.textAlign = "center";
      ctx.fillText("No alert data for timeline", W / 2, H / 2);
      return;
    }

    // Visible time window
    const totalDuration = timeRange.max - timeRange.min || 1;
    const visibleDuration = totalDuration / zoomLevel;
    const viewMin = timeRange.min + panOffset * totalDuration;
    const viewMax = viewMin + visibleDuration;

    // Time axis
    const tsToX = (ts: number) =>
      pad.left + ((ts - viewMin) / (viewMax - viewMin)) * plotW;

    // Background grid
    ctx.strokeStyle = "rgba(255,255,255,0.03)";
    ctx.lineWidth = 1;
    const gridLines = 8;
    for (let i = 0; i <= gridLines; i++) {
      const x = pad.left + (i / gridLines) * plotW;
      ctx.beginPath();
      ctx.moveTo(x, pad.top);
      ctx.lineTo(x, pad.top + plotH);
      ctx.stroke();

      // Time labels
      const t = viewMin + (i / gridLines) * (viewMax - viewMin);
      const date = new Date(t * 1000);
      ctx.fillStyle = "#475569";
      ctx.font = "10px monospace";
      ctx.textAlign = "center";
      ctx.fillText(
        date.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        x,
        H - pad.bottom + 18
      );
    }

    // Severity lanes
    const lanes = ["high", "medium", "low"];
    const laneH = plotH / 3;
    lanes.forEach((sev, i) => {
      const y = pad.top + i * laneH + laneH / 2;
      // Lane label
      ctx.fillStyle = SEVERITY_COLOR[sev] + "80";
      ctx.font = "bold 9px system-ui";
      ctx.textAlign = "right";
      ctx.fillText(sev.toUpperCase(), pad.left - 8, y + 3);
      // Lane line
      ctx.strokeStyle = "rgba(255,255,255,0.02)";
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + plotW, y);
      ctx.stroke();
    });

    // Draw alerts
    for (const a of timelineData) {
      const x = tsToX(a.ts);
      if (x < pad.left - 10 || x > pad.left + plotW + 10) continue;

      const laneIdx = lanes.indexOf(a.severity);
      const baseY = pad.top + laneIdx * laneH + laneH / 2;
      const jitter = ((a.ts * 7 + a.srcIP.length * 13) % 100) / 100;
      const y = baseY + (jitter - 0.5) * (laneH * 0.6);

      // Glow
      ctx.beginPath();
      ctx.arc(x, y, 6, 0, Math.PI * 2);
      ctx.fillStyle = SEVERITY_COLOR[a.severity] + "20";
      ctx.fill();

      // Dot
      ctx.beginPath();
      ctx.arc(x, y, 2.5 + a.score * 2, 0, Math.PI * 2);
      ctx.fillStyle = SEVERITY_COLOR[a.severity];
      ctx.fill();
    }

    // Visible count
    const visible = timelineData.filter(
      (a) => a.ts >= viewMin && a.ts <= viewMax
    );
    ctx.fillStyle = "#64748b";
    ctx.font = "10px monospace";
    ctx.textAlign = "left";
    ctx.fillText(
      `${visible.length} alerts visible`,
      pad.left,
      pad.top - 10
    );
  }, [timelineData, timeRange, zoomLevel, panOffset]);

  useEffect(() => {
    draw();
  }, [draw]);

  // Zoom with wheel
  const handleWheel = useCallback(
    (e: React.WheelEvent) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.8 : 1.25;
      setZoomLevel((z) => Math.max(1, Math.min(z * delta, 50)));
    },
    []
  );

  // Pan with drag
  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      isDragging.current = true;
      lastMouseX.current = e.clientX;
    },
    []
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();

      if (isDragging.current) {
        const dx = e.clientX - lastMouseX.current;
        lastMouseX.current = e.clientX;
        const panDelta = -dx / (rect.width * zoomLevel);
        setPanOffset((p) => Math.max(0, Math.min(1 - 1 / zoomLevel, p + panDelta)));
        return;
      }

      // Tooltip
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const pad = { top: 30, bottom: 40, left: 60, right: 20 };
      const plotW = rect.width - pad.left - pad.right;
      const totalDuration = timeRange.max - timeRange.min || 1;
      const visibleDuration = totalDuration / zoomLevel;
      const viewMin = timeRange.min + panOffset * totalDuration;
      const viewMax = viewMin + visibleDuration;
      const laneH = (rect.height - pad.top - pad.bottom) / 3;

      let found: TimelineAlert | null = null;
      for (const a of timelineData) {
        const x =
          pad.left + ((a.ts - viewMin) / (viewMax - viewMin)) * plotW;
        const lanes = ["high", "medium", "low"];
        const laneIdx = lanes.indexOf(a.severity);
        const baseY = pad.top + laneIdx * laneH + laneH / 2;
        const jitter = ((a.ts * 7 + a.srcIP.length * 13) % 100) / 100;
        const y = baseY + (jitter - 0.5) * (laneH * 0.6);
        const dx = mx - x;
        const dy = my - y;
        if (dx * dx + dy * dy < 100) {
          found = a;
          break;
        }
      }

      if (found) {
        canvas.style.cursor = "pointer";
        setTooltip({ x: e.clientX - rect.left, y: e.clientY - rect.top, alert: found });
      } else {
        canvas.style.cursor = isDragging.current ? "grabbing" : "grab";
        setTooltip(null);
      }
    },
    [timelineData, timeRange, zoomLevel, panOffset]
  );

  const handleMouseUp = useCallback(() => {
    isDragging.current = false;
  }, []);

  const handleMouseLeave = useCallback(() => {
    isDragging.current = false;
    setTooltip(null);
  }, []);

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      if (tooltip) {
        setDrilldownIP(tooltip.alert.srcIP);
      }
    },
    [tooltip]
  );

  const handleZoomIn = () => setZoomLevel((z) => Math.min(z * 1.5, 50));
  const handleZoomOut = () => {
    setZoomLevel((z) => Math.max(1, z / 1.5));
    if (zoomLevel <= 1.5) setPanOffset(0);
  };
  const handleReset = () => {
    setZoomLevel(1);
    setPanOffset(0);
  };

  if (alerts.length === 0) {
    return (
      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-64 flex flex-col items-center justify-center text-slate-500">
        <Clock className="w-8 h-8 text-slate-600 mb-2" />
        <p className="text-sm">No alerts for timeline.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-slate-300 font-medium flex items-center gap-2">
          <Clock className="w-4 h-4 text-emerald-400" />
          Alert Event Timeline
          <span className="text-xs text-slate-500 font-mono">
            {alerts.length} events
          </span>
        </h3>
        <div className="flex items-center gap-1">
          <button
            onClick={handleZoomIn}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-white/5 transition"
            aria-label="Zoom in"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-white/5 transition"
            aria-label="Zoom out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleReset}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-white/5 transition"
            aria-label="Reset"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div
        ref={containerRef}
        className="bg-slate-900 border border-white/5 rounded-2xl overflow-hidden"
        style={{ height: 180 }}
      >
        <canvas
          ref={canvasRef}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseLeave}
          onClick={handleClick}
          style={{ cursor: "grab" }}
        />

        {tooltip && (
          <div
            className="absolute pointer-events-none z-20 bg-slate-950 border border-white/10 rounded-lg p-2.5 shadow-xl text-xs"
            style={{
              left: tooltip.x + 12,
              top: tooltip.y - 40,
              transform: tooltip.x > 500 ? "translateX(-110%)" : undefined,
            }}
          >
            <p className="text-slate-300">
              {new Date(tooltip.alert.ts * 1000).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}
            </p>
            <p className="font-mono text-cyan-400">{tooltip.alert.srcIP}</p>
            <p className="text-slate-500">&rarr; {tooltip.alert.dstIP}</p>
            <p
              className="font-bold capitalize"
              style={{ color: SEVERITY_COLOR[tooltip.alert.severity] }}
            >
              {tooltip.alert.severity} ({(tooltip.alert.score * 100).toFixed(0)}%)
            </p>
          </div>
        )}
      </div>

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
