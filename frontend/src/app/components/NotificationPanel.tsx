"use client";

import useSWR from "swr";
import { useEffect, useState, useCallback } from "react";
import { AlertTriangle, Bell, X, ChevronDown, ChevronUp } from "lucide-react";
import { apiUrl, fetcher } from "../lib/api";
import type { Alert } from "../lib/types";

interface NotificationEntry {
  id: string;
  timestamp: number;
  title: string;
  message: string;
  severity: "high" | "medium" | "low";
  dismissed: boolean;
}

const SEVERITY_STYLES: Record<string, string> = {
  high: "border-rose-500/30 bg-rose-500/5",
  medium: "border-amber-500/30 bg-amber-500/5",
  low: "border-sky-500/30 bg-sky-500/5",
};

const SEVERITY_DOT: Record<string, string> = {
  high: "bg-rose-400",
  medium: "bg-amber-400",
  low: "bg-sky-400",
};

export function NotificationPanel() {
  const [expanded, setExpanded] = useState(false);
  const [items, setItems] = useState<NotificationEntry[]>([]);
  const [lastSeen, setLastSeen] = useState<number>(0);

  const { data } = useSWR<Alert[]>(
    apiUrl("/api/alerts?limit=20"),
    fetcher,
    { refreshInterval: 5000 }
  );

  useEffect(() => {
    if (!data) return;
    const now = Date.now() / 1000;
    const newAlerts = data.filter(
      (a: Alert) => a._alerted_at > lastSeen && a._alerted_at > now - 300
    );

    if (newAlerts.length > 0) {
      const entries: NotificationEntry[] = newAlerts.map((a: Alert) => ({
        id: `${a._alerted_at}-${a._src_ip}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: a._alerted_at,
        title: "Alert",
        message: `${a._src_ip} → ${a._dst_port}`,
        severity: a.severity as "high" | "medium" | "low",
        dismissed: false,
      }));

      setItems((prev) => [...entries, ...prev].slice(0, 50));
      setLastSeen(Math.max(...data.map((a: Alert) => a._alerted_at)));
    }
  }, [data, lastSeen]);

  const dismiss = useCallback((id: string) => {
    setItems((prev) => prev.map((i) => (i.id === id ? { ...i, dismissed: true } : i)));
  }, []);

  const active = items.filter((i) => !i.dismissed);
  const recent = active.slice(0, 5);

  return (
    <div className="relative">
      {/* Bell icon with count badge */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="relative p-2 rounded-lg hover:bg-slate-800 transition"
        aria-label={`${active.length} notifications`}
      >
        <Bell className="w-4 h-4 text-slate-400" />
        {active.length > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 flex items-center justify-center rounded-full bg-rose-500 text-white text-[9px] font-bold px-1">
            {active.length > 99 ? "99+" : active.length}
          </span>
        )}
      </button>

      {/* Dropdown panel */}
      {expanded && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-slate-900 border border-white/10 rounded-2xl shadow-2xl z-50 overflow-hidden">
          {/* Header */}
          <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between">
            <span className="text-xs font-bold text-white">Notifications</span>
            {active.length > 0 && (
              <button
                onClick={() => setItems([])}
                className="text-[10px] text-slate-500 hover:text-rose-400 transition"
              >
                Clear all
              </button>
            )}
          </div>

          {/* List */}
          <div className="max-h-80 overflow-y-auto divide-y divide-white/5">
            {active.length === 0 ? (
              <div className="px-4 py-8 text-center text-slate-600 text-xs">
                No recent notifications
              </div>
            ) : (
              recent.map((item) => (
                <div
                  key={item.id}
                  className={`px-4 py-3 border-l-2 ${SEVERITY_STYLES[item.severity]} flex gap-3 transition`}
                >
                  <div className="pt-1">
                    <span className={`block w-2 h-2 rounded-full ${SEVERITY_DOT[item.severity]}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-semibold text-white truncate">{item.title}</div>
                    <div className="text-[10px] text-slate-400 mt-0.5 truncate">{item.message}</div>
                    <div className="text-[9px] text-slate-600 mt-1">
                      {new Date(item.timestamp * 1000).toLocaleTimeString()}
                    </div>
                  </div>
                  <button
                    onClick={() => dismiss(item.id)}
                    className="self-start p-1 rounded text-slate-600 hover:text-rose-400 transition"
                    aria-label="Dismiss notification"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))
            )}
          </div>

          {/* Footer count */}
          {active.length > 5 && (
            <div className="px-4 py-2 border-t border-white/5 text-center text-[10px] text-slate-600">
              +{active.length - 5} more notifications
            </div>
          )}
        </div>
      )}
    </div>
  );
}
