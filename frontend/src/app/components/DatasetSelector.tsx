"use client";

import { useState, useEffect } from "react";
import { Database, HardDrive, CheckCircle2, AlertTriangle } from "lucide-react";
import type { DatasetInfo, DatasetStats } from "../lib/types";
import { apiUrl } from "../lib/api";

interface Props {
  selected: string[];
  onChange: (datasets: string[]) => void;
  disabled?: boolean;
}

export function DatasetSelector({ selected, onChange, disabled }: Props) {
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);
  const [stats, setStats] = useState<Record<string, DatasetStats>>({});
  const [loadingStats, setLoadingStats] = useState<string | null>(null);

  useEffect(() => {
    fetch(apiUrl("/api/datasets"))
      .then((r) => r.json())
      .then((data) => setDatasets(data))
      .catch(() => {});
  }, []);

  const loadStats = async (name: string) => {
    if (stats[name]) return;
    setLoadingStats(name);
    try {
      const res = await fetch(apiUrl(`/api/datasets/${name}/stats`));
      const data = await res.json();
      setStats((prev) => ({ ...prev, [name]: data }));
    } catch {
      setStats((prev) => ({
        ...prev,
        [name]: { downloaded: false, name, error: "Failed to load stats" },
      }));
    } finally {
      setLoadingStats(null);
    }
  };

  const toggle = (name: string) => {
    if (disabled) return;
    const next = selected.includes(name)
      ? selected.filter((d) => d !== name)
      : [...selected, name];
    onChange(next.length > 0 ? next : [name]);
  };

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
          Training Datasets
        </label>
        <span className="text-[10px] text-slate-600">
          {selected.length} selected
        </span>
      </div>
      <div className="space-y-2">
        {datasets.map((ds) => {
          const isActive = selected.includes(ds.name);
          const dsStats = stats[ds.name];
          return (
            <div key={ds.name}>
              <button
                type="button"
                onClick={() => {
                  toggle(ds.name);
                  loadStats(ds.name);
                }}
                disabled={disabled}
                className={`w-full text-left px-3 py-2.5 rounded-xl border transition-all duration-150 ${
                  isActive
                    ? "bg-emerald-500/[0.06] border-emerald-500/30"
                    : "bg-slate-950 border-white/5 hover:border-white/10"
                } ${disabled ? "opacity-55 cursor-not-allowed" : "cursor-pointer"}`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-3.5 h-3.5 rounded border-2 flex items-center justify-center transition ${
                        isActive
                          ? "bg-emerald-500 border-emerald-500"
                          : "border-slate-600"
                      }`}
                    >
                      {isActive && (
                        <CheckCircle2 className="w-2.5 h-2.5 text-white" />
                      )}
                    </div>
                    <Database
                      className={`w-3.5 h-3.5 ${
                        isActive ? "text-emerald-400" : "text-slate-500"
                      }`}
                    />
                    <div>
                      <span
                        className={`text-xs font-bold ${
                          isActive ? "text-white" : "text-slate-400"
                        }`}
                      >
                        {ds.label}
                      </span>
                      <span className="text-[10px] text-slate-600 ml-2 font-mono">
                        {ds.name}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {ds.downloaded ? (
                      <span className="flex items-center gap-1 text-[9px] text-emerald-500/70">
                        <HardDrive className="w-3 h-3" />
                        {ds.size_human}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[9px] text-slate-600">
                        <AlertTriangle className="w-3 h-3" />
                        Not downloaded
                      </span>
                    )}
                  </div>
                </div>
              </button>
              {dsStats && dsStats.downloaded && dsStats.total_samples && (
                <div className="mt-1 px-3 flex gap-3 text-[9px] text-slate-500">
                  <span>
                    {dsStats.total_samples.toLocaleString()} samples
                  </span>
                  <span className="text-rose-400/60">
                    {dsStats.attack_samples?.toLocaleString()} attack
                  </span>
                  <span className="text-emerald-400/60">
                    {dsStats.benign_samples?.toLocaleString()} benign
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>
      <p className="text-[10px] text-slate-600 leading-normal">
        Combining multiple datasets diversifies the training corpus for improved
        generalisation.
      </p>
    </div>
  );
}
