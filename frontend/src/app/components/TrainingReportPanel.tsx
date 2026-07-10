"use client";

import { useState, useEffect } from "react";
import {
  BarChart3,
  TrendingUp,
  ChevronDown,
  ChevronUp,
  Image as ImageIcon,
} from "lucide-react";
import type { TrainingReport } from "../lib/types";
import { apiUrl } from "../lib/api";

interface Props {
  version: string;
}

export function TrainingReportPanel({ version }: Props) {
  const [report, setReport] = useState<TrainingReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [imgTab, setImgTab] = useState<"cm" | "roc">("cm");

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(apiUrl(`/api/models/reports/${version}`))
      .then((r) => {
        if (!r.ok) throw new Error("No report");
        return r.json();
      })
      .then((data) => setReport(data))
      .catch(() => setError("No training report available"))
      .finally(() => setLoading(false));
  }, [version]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 text-[10px] text-slate-500">
        <div className="w-3 h-3 rounded-full border-2 border-emerald-400 border-t-transparent animate-spin" />
        Loading report...
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="px-3 py-2 text-[10px] text-slate-600 italic">
        {error || "No report"}
      </div>
    );
  }

  const { overall, confusion_matrix: cm, per_class } = report;
  const cmImgUrl = apiUrl(
    `/api/models/reports/${version}/images/confusion_matrix.png`
  );
  const rocImgUrl = apiUrl(`/api/models/reports/${version}/images/roc_curve.png`);

  const perClassRows = Object.entries(per_class).filter(
    ([k]) => k !== "accuracy" && k !== "macro avg" && k !== "weighted avg"
  );

  return (
    <div className="border border-white/5 rounded-xl overflow-hidden bg-slate-950">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-900/50 transition"
      >
        <div className="flex items-center gap-2">
          <BarChart3 className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-[11px] font-bold text-white">Training Report</span>
          {overall.auc_roc !== null && (
            <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-violet-500/10 text-violet-400 border border-violet-500/20">
              AUC {(overall.auc_roc * 100).toFixed(1)}%
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUp className="w-3.5 h-3.5 text-slate-500" />
        ) : (
          <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-4">
          {/* Metric chips */}
          <div className="grid grid-cols-5 gap-2">
            {([
              ["Accuracy", overall.accuracy],
              ["Precision", overall.precision],
              ["Recall", overall.recall],
              ["F1", overall.f1_score],
              ["AUC-ROC", overall.auc_roc],
            ] as [string, number | null][]).map(([label, val]) => (
              <div
                key={label}
                className="bg-slate-900 border border-white/5 rounded-lg px-3 py-2 text-center"
              >
                <div className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">
                  {label}
                </div>
                <div className="text-sm font-mono font-bold text-white mt-0.5">
                  {val !== null ? (val * 100).toFixed(1) + "%" : "N/A"}
                </div>
              </div>
            ))}
          </div>

          <div className="text-[10px] text-slate-500">
            {overall.test_samples.toLocaleString()} test samples (
            {overall.attack_samples.toLocaleString()} attack,{" "}
            {overall.benign_samples.toLocaleString()} benign)
          </div>

          {/* Confusion matrix JSON view */}
          <div className="bg-slate-900 border border-white/5 rounded-xl p-3">
            <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-2">
              Confusion Matrix
            </div>
            <div className="grid grid-cols-3 gap-1 text-center font-mono text-[11px]">
              <div />
              <div className="text-[9px] text-slate-500">Pred Attack</div>
              <div className="text-[9px] text-slate-500">Pred Benign</div>
              <div className="text-[9px] text-slate-500 text-left">Actual Attack</div>
              <div className="bg-rose-500/10 text-rose-400 rounded py-1 font-bold">
                {cm.tp.toLocaleString()}
              </div>
              <div className="bg-amber-500/10 text-amber-400 rounded py-1">
                {cm.fn.toLocaleString()}
              </div>
              <div className="text-[9px] text-slate-500 text-left">Actual Benign</div>
              <div className="bg-amber-500/10 text-amber-400 rounded py-1">
                {cm.fp.toLocaleString()}
              </div>
              <div className="bg-emerald-500/10 text-emerald-400 rounded py-1 font-bold">
                {cm.tn.toLocaleString()}
              </div>
            </div>
          </div>

          {/* Images toggle */}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setImgTab("cm")}
              className={`text-[10px] font-bold px-3 py-1.5 rounded-lg border transition ${
                imgTab === "cm"
                  ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                  : "bg-slate-900 border-white/5 text-slate-500 hover:text-slate-300"
              }`}
            >
              Confusion Matrix
            </button>
            <button
              type="button"
              onClick={() => setImgTab("roc")}
              className={`text-[10px] font-bold px-3 py-1.5 rounded-lg border transition ${
                imgTab === "roc"
                  ? "bg-violet-500/10 border-violet-500/30 text-violet-400"
                  : "bg-slate-900 border-white/5 text-slate-500 hover:text-slate-300"
              }`}
            >
              ROC Curve
            </button>
          </div>
          <div className="bg-slate-900 border border-white/5 rounded-xl p-2">
            <img
              src={imgTab === "cm" ? cmImgUrl : rocImgUrl}
              alt={imgTab === "cm" ? "Confusion Matrix" : "ROC Curve"}
              className="w-full rounded-lg"
              onError={(e) => {
                (e.target as HTMLImageElement).style.display = "none";
              }}
            />
          </div>

          {/* Per-class table */}
          <div className="bg-slate-900 border border-white/5 rounded-xl overflow-hidden">
            <div className="px-3 py-2 text-[10px] text-slate-400 font-bold uppercase tracking-wider border-b border-white/5">
              Per-Class Metrics
            </div>
            <table className="w-full text-[11px] text-slate-300">
              <thead className="bg-slate-950/50 text-[9px] text-slate-500 uppercase tracking-wider">
                <tr>
                  <th className="px-3 py-2 text-left">Class</th>
                  <th className="px-3 py-2 text-right">Precision</th>
                  <th className="px-3 py-2 text-right">Recall</th>
                  <th className="px-3 py-2 text-right">F1</th>
                  <th className="px-3 py-2 text-right">Support</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {perClassRows.map(([cls, m]) => (
                  <tr key={cls} className="hover:bg-slate-800/30">
                    <td className="px-3 py-2 font-bold text-white">{cls}</td>
                    <td className="px-3 py-2 text-right font-mono text-emerald-400">
                      {(m.precision * 100).toFixed(1)}%
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-violet-400">
                      {(m.recall * 100).toFixed(1)}%
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-sky-400">
                      {(m["f1-score"] * 100).toFixed(1)}%
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-slate-500">
                      {m.support.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
