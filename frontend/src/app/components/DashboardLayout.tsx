"use client";

import { useState, useCallback } from "react";
import {
  DndContext,
  closestCenter,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  useSortable,
  rectSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { GripVertical } from "lucide-react";
import type { KPIs } from "../lib/types";

interface Props {
  kpis: KPIs | undefined;
  children: React.ReactNode;
}

interface WidgetConfig {
  id: string;
  label: string;
  visible: boolean;
}

const DEFAULT_WIDGETS: WidgetConfig[] = [
  { id: "kpis", label: "KPI Cards", visible: true },
  { id: "alerts-table", label: "Recent Alerts", visible: true },
  { id: "topology-mini", label: "Topology Preview", visible: true },
  { id: "timeline", label: "Event Timeline", visible: true },
];

function SortableWidget({
  id,
  label,
  children,
  onToggle,
  visible,
}: {
  id: string;
  label: string;
  children: React.ReactNode;
  onToggle: (id: string) => void;
  visible: boolean;
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    zIndex: isDragging ? 50 : undefined,
    opacity: isDragging ? 0.8 : 1,
  };

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={`group relative bg-slate-900 border border-white/5 rounded-2xl overflow-hidden transition ${
        isDragging ? "ring-2 ring-emerald-500/30 shadow-lg shadow-emerald-500/10" : ""
      }`}
    >
      {/* Drag handle + visibility toggle */}
      <div className="absolute top-3 right-3 flex items-center gap-1 z-10 opacity-0 group-hover:opacity-100 transition">
        <button
          onClick={() => onToggle(id)}
          className="p-1 rounded bg-slate-800/80 text-slate-400 hover:text-white text-[10px] transition"
          aria-label={`Toggle ${label}`}
        >
          {visible ? "✓" : "–"}
        </button>
        <div
          {...attributes}
          {...listeners}
          className="p-1 rounded bg-slate-800/80 text-slate-400 hover:text-white cursor-grab active:cursor-grabbing transition"
          aria-label={`Drag ${label}`}
        >
          <GripVertical className="w-3 h-3" />
        </div>
      </div>
      {visible && children}
    </div>
  );
}

export function DashboardLayout({ kpis, children }: Props) {
  const [widgets, setWidgets] = useState<WidgetConfig[]>(DEFAULT_WIDGETS);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } })
  );

  const toggleWidget = useCallback((id: string) => {
    setWidgets((prev) =>
      prev.map((w) => (w.id === id ? { ...w, visible: !w.visible } : w))
    );
  }, []);

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    setWidgets((prev) => {
      const oldIdx = prev.findIndex((w) => w.id === active.id);
      const newIdx = prev.findIndex((w) => w.id === over.id);
      return arrayMove(prev, oldIdx, newIdx);
    });
  }, []);

  const visibleWidgets = widgets.filter((w) => w.visible);

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragEnd={handleDragEnd}
    >
      <SortableContext
        items={widgets.map((w) => w.id)}
        strategy={rectSortingStrategy}
      >
        <div className="space-y-6">
          {widgets.map((widget) => (
            <SortableWidget
              key={widget.id}
              id={widget.id}
              label={widget.label}
              visible={widget.visible}
              onToggle={toggleWidget}
            >
              {widget.id === "kpis" && (
                <div className="p-6">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">Key Metrics</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {kpis && [
                      { label: "Total Traffic", value: (kpis.comparison_stats?.flows?.[0] || 0).toLocaleString(), color: "text-sky-400" },
                      { label: "Alerts", value: (kpis.recent_alerts || 0).toLocaleString(), color: "text-rose-400" },
                      { label: "Critical Hits", value: (kpis.high_severity_count || 0).toLocaleString(), color: "text-amber-400" },
                      { label: "Uptime", value: `${Math.floor(kpis.uptime_seconds / 60)}m`, color: "text-emerald-400" },
                    ].map((kpi) => (
                      <div key={kpi.label} className="bg-slate-950/40 rounded-xl p-3 border border-white/5">
                        <div className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">{kpi.label}</div>
                        <div className={`text-xl font-bold mt-1 ${kpi.color}`}>{kpi.value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {widget.id === "alerts-table" && <div className="p-6">{children}</div>}
              {widget.id === "topology-mini" && (
                <div className="p-6">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Network View</h3>
                  <p className="text-slate-600 text-xs">Switch to the Topology tab for the full interactive map.</p>
                </div>
              )}
              {widget.id === "timeline" && (
                <div className="p-6">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-2">Timeline</h3>
                  <p className="text-slate-600 text-xs">Switch to the Alerts tab for the full event timeline.</p>
                </div>
              )}
            </SortableWidget>
          ))}
        </div>
      </SortableContext>
    </DndContext>
  );
}
