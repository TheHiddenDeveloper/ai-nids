"use client";
import { useState } from "react";
import useSWR from "swr";
import { Pencil } from "lucide-react";
import type { Signature } from "../lib/types";
import { apiUrl, fetcher } from "../lib/api";
import { SignatureRuleEditor } from "./SignatureRuleEditor";

export function SignaturesTab() {
  const { data: rules, error, mutate } = useSWR<Signature[]>(apiUrl("/api/signatures"), fetcher);
  const [editingRule, setEditingRule] = useState<Signature | null>(null);

  const toggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      await fetch(apiUrl(`/api/signatures/${ruleId}/toggle`), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled })
      });
      mutate();
    } catch {
      console.error("Failed to toggle rule");
    }
  };

  if (error) {
    return (
      <div className="p-8 text-center">
        <p className="text-rose-400 mb-3">Failed to load signatures.</p>
        <button onClick={() => mutate()} className="bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium px-4 py-2 rounded-xl transition">
          Retry
        </button>
      </div>
    );
  }

  if (!rules) return <div className="text-slate-400 p-8">Loading signatures...</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Signature Rules</h2>
          <p className="text-slate-400 text-sm mt-1">Manage static detection rules and hot-reload behavior. Click any rule to edit.</p>
        </div>
      </div>

      <div className="bg-slate-900 border border-white/5 rounded-2xl overflow-hidden">
        {rules.length === 0 ? (
          <div className="px-6 py-12 text-center text-slate-500 text-sm">
            No signature rules loaded. The engine will poll <code className="text-slate-400">rules.yaml</code> for updates.
          </div>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950/50 border-b border-white/5">
              <tr>
                <th className="px-6 py-4 font-medium text-slate-400 w-24">Status</th>
                <th className="px-6 py-4 font-medium text-slate-400 w-48">Rule ID</th>
                <th className="px-6 py-4 font-medium text-slate-400">Name</th>
                <th className="px-6 py-4 font-medium text-slate-400 w-32">Severity</th>
                <th className="px-6 py-4 font-medium text-slate-400 w-48">Tags</th>
                <th className="px-6 py-4 font-medium text-slate-400 w-16"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {rules.map((rule: Signature) => (
                <tr key={rule.id} className="hover:bg-white/[0.02] transition-colors">
                  <td className="px-6 py-4">
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        className="sr-only peer"
                        checked={rule.enabled}
                        onChange={(e) => toggleRule(rule.id, e.target.checked)}
                      />
                      <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500" />
                    </label>
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-slate-300">{rule.id}</td>
                  <td className="px-6 py-4">
                    <div className="font-medium text-slate-200">{rule.name}</div>
                    <div className="text-xs text-slate-500 mt-1">{rule.description}</div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      rule.severity === 'high' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                      rule.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                      'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    }`}>
                      {rule.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-wrap gap-2">
                      {rule.tags.map((t: string) => (
                        <span key={`${rule.id}-${t}`} className="px-2 py-1 rounded bg-slate-800 border border-white/5 text-slate-400 text-[10px] uppercase tracking-wider">{t}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => setEditingRule(rule)}
                      className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition"
                      aria-label={`Edit rule ${rule.id}`}
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {editingRule && (
        <SignatureRuleEditor
          rule={editingRule}
          onClose={() => { setEditingRule(null); mutate(); }}
        />
      )}
    </div>
  );
}
