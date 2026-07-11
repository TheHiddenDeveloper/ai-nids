"use client";
import { useState, useEffect } from "react";
import useSWR from "swr";
import { X, RotateCcw, Brain, Trash2, Loader2 } from "lucide-react";
import { apiUrl, fetcher } from "../lib/api";
import { LogsViewer } from "./LogsViewer";
import { SettingsSkeleton } from "./Skeleton";

export function SettingsTab() {
  const { data: health, mutate: mutateHealth } = useSWR<{ redis_connected: boolean; models: { random_forest: boolean } }>(apiUrl("/api/settings/health"), fetcher);
  const { data: ips, mutate: mutateIps } = useSWR<string[]>(apiUrl("/api/settings/blocked_ips"), fetcher);
  const [notification, setNotification] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);

  useEffect(() => {
    if (notification) {
      const t = setTimeout(() => setNotification(null), 5000);
      return () => clearTimeout(t);
    }
  }, [notification]);

  const notify = (message: string, type: "success" | "error") => setNotification({ message, type });

  const fireWallAction = async (ip: string, action: "block" | "unblock") => {
    try {
      const res = await fetch(apiUrl("/api/settings/firewall"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ip })
      });
      if (res.ok) {
        mutateIps();
        mutateHealth();
        notify(`${ip} ${action === "unblock" ? "unblocked" : "blocked"} successfully.`, "success");
      } else {
        const err = await res.json().catch(() => ({ detail: "Unknown error" }));
        notify(`Failed to ${action} ${ip}: ${err.detail || res.statusText}`, "error");
      }
    } catch {
      notify(`Network error during firewall action.`, "error");
    }
  };

  const wipeSystem = async () => {
    if (!confirm("Are you sure? This deletes ALL alerts, flows, and incidents!")) return;
    setLoadingAction("wipe");
    try {
      const res = await fetch(apiUrl("/api/settings/wipe"), { method: "POST" });
      if (res.ok) {
        notify("System data wiped successfully.", "success");
      } else {
        const err = await res.json().catch(() => ({ detail: "Unknown error" }));
        notify(`Failed to wipe: ${err.detail}`, "error");
      }
    } catch {
      notify("Network error during wipe.", "error");
    } finally {
      setLoadingAction(null);
    }
  };

  const restartMonitor = async () => {
    if (!confirm("Restart the monitor service? This will briefly interrupt traffic analysis.")) return;
    setLoadingAction("restart");
    try {
      const res = await fetch(apiUrl("/api/system/monitor/restart"), { method: "POST" });
      if (res.ok) {
        notify("Monitor restarted successfully.", "success");
      } else {
        const err = await res.json().catch(() => ({ detail: "Unknown error" }));
        notify(`Failed to restart: ${err.detail}`, "error");
      }
    } catch {
      notify("Network error during restart.", "error");
    } finally {
      setLoadingAction(null);
    }
  };

  const retrainModels = async () => {
    setLoadingAction("retrain");
    try {
      const res = await fetch(apiUrl("/api/models/retrain"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ precision: "high" })
      });
      if (res.ok) {
        notify("Retraining job started. Check Tasks Widget.", "success");
      } else {
        const err = await res.json().catch(() => ({ detail: "Unknown error" }));
        notify(`Failed to start retraining: ${err.detail}`, "error");
      }
    } catch {
      notify("Network error during retrain request.", "error");
    } finally {
      setLoadingAction(null);
    }
  };

  if (!health && !ips) return <SettingsSkeleton />;

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {notification && (
        <div className={`flex items-center justify-between px-4 py-3 rounded-xl text-sm border ${
          notification.type === "success"
            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"
            : "bg-rose-500/10 border-rose-500/20 text-rose-300"
        }`}>
          <span>{notification.message}</span>
          <button onClick={() => setNotification(null)} className="p-0.5 hover:opacity-70 transition-opacity" aria-label="Dismiss notification">
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>
      )}

      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-bold text-white mb-4">Engine Health</h2>
        <div className="grid grid-cols-2 gap-4">
           <div className="bg-slate-800/50 p-4 rounded-xl border border-white/5">
              <p className="text-sm text-slate-400">Redis Cache</p>
              <p className="text-lg font-bold text-emerald-400">{health?.redis_connected ? "Connected" : "Disconnected"}</p>
           </div>
           <div className="bg-slate-800/50 p-4 rounded-xl border border-white/5">
              <p className="text-sm text-slate-400">AI Models</p>
              <p className="text-lg font-bold text-cyan-400">
                {health?.models?.random_forest ? "RF Active" : "Waiting"}
              </p>
           </div>
        </div>
        <div className="mt-4 flex gap-3">
          <button
            onClick={restartMonitor}
            disabled={loadingAction === "restart"}
            className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-2 rounded-xl transition"
          >
            {loadingAction === "restart" ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
            Restart Monitor Service
          </button>
          <button
            onClick={retrainModels}
            disabled={loadingAction === "retrain"}
            className="flex items-center gap-2 bg-cyan-500/20 hover:bg-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed text-cyan-400 border border-cyan-500/30 text-sm font-medium px-4 py-2 rounded-xl transition"
          >
            {loadingAction === "retrain" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Brain className="w-4 h-4" />}
            Retrain AI Models
          </button>
        </div>
      </div>

      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-bold text-white mb-4">Managed Blocked IPs</h2>
        {ips && ips.length > 0 ? (
          <div className="space-y-2">
              {ips.map((ip: string) => (
                  <div key={ip} className="flex justify-between items-center bg-slate-800/50 p-3 rounded-xl border border-white/5">
                     <code className="text-rose-400">{ip}</code>
                     <button onClick={() => fireWallAction(ip, "unblock")} className="text-sm bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded-lg text-white transition">
                       Unblock
                     </button>
                  </div>
                ))}
          </div>
        ) : (
          <p className="text-slate-400 text-sm">No active IP blocks across the network.</p>
        )}
      </div>

      <LogsViewer />

      <div className="bg-rose-950/20 border border-rose-500/20 rounded-2xl p-6">
        <h2 className="text-lg font-bold text-rose-400 mb-2">Danger Zone</h2>
        <p className="text-sm text-rose-400/70 mb-4">Destructive actions regarding system persistence.</p>
        <button
          onClick={wipeSystem}
          disabled={loadingAction === "wipe"}
          className="flex items-center gap-2 bg-rose-500 hover:bg-rose-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium px-4 py-2 rounded-xl transition"
        >
          {loadingAction === "wipe" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
          Wipe System Data
        </button>
      </div>

    </div>
  );
}
