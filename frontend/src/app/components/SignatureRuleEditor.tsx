"use client";

import { useState, useEffect } from "react";
import { X, Save, Tag, AlertTriangle } from "lucide-react";
import type { Signature } from "../lib/types";
import { apiUrl } from "../lib/api";
import { useSWRConfig } from "swr";

interface Props {
  rule: Signature;
  onClose: () => void;
}

export function SignatureRuleEditor({ rule, onClose }: Props) {
  const { mutate } = useSWRConfig();
  const [name, setName] = useState(rule.name);
  const [description, setDescription] = useState(rule.description || "");
  const [severity, setSeverity] = useState(rule.severity);
  const [enabled, setEnabled] = useState(rule.enabled);
  const [tagInput, setTagInput] = useState("");
  const [tags, setTags] = useState<string[]>([...rule.tags]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const addTag = () => {
    const t = tagInput.trim();
    if (t && !tags.includes(t)) {
      setTags([...tags, t]);
      setTagInput("");
    }
  };

  const removeTag = (t: string) => setTags(tags.filter((x) => x !== t));

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(apiUrl(`/api/signatures/${rule.id}`), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description, severity, tags, enabled }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Save failed");
      }
      await mutate(apiUrl("/api/signatures"));
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" role="dialog" aria-modal="true" aria-label={`Edit rule ${rule.id}`}>
      <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg bg-slate-900 border border-white/10 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/5">
          <div>
            <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-widest">Edit Rule</span>
            <h3 className="text-lg font-bold text-white font-mono mt-0.5">{rule.id}</h3>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {error && (
            <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg px-4 py-2">
              {error}
            </div>
          )}

          {/* Name */}
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-1.5">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950/60 border border-white/5 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500/40 transition"
            />
          </div>

          {/* Description */}
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-1.5">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 bg-slate-950/60 border border-white/5 rounded-lg text-sm text-white focus:outline-none focus:border-emerald-500/40 transition resize-none"
            />
          </div>

          {/* Severity */}
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-1.5">Severity</label>
            <div className="flex gap-2">
              {(["high", "medium", "low"] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverity(sev)}
                  className={`flex-1 py-2 rounded-lg text-xs font-bold border transition ${
                    severity === sev
                      ? sev === "high" ? "bg-rose-500/15 border-rose-500/30 text-rose-400"
                        : sev === "medium" ? "bg-amber-500/15 border-amber-500/30 text-amber-400"
                        : "bg-slate-500/15 border-slate-500/30 text-slate-300"
                      : "bg-slate-950/40 border-white/5 text-slate-600 hover:text-slate-400"
                  }`}
                >
                  {sev.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Enabled */}
          <label className="flex items-center justify-between cursor-pointer">
            <span className="text-sm text-slate-300">Enabled</span>
            <div
              onClick={() => setEnabled(!enabled)}
              className={`w-10 h-5 rounded-full transition-colors relative ${enabled ? "bg-emerald-500" : "bg-slate-700"}`}
              role="switch"
              aria-checked={enabled}
            >
              <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform ${enabled ? "translate-x-5" : "translate-x-0.5"}`} />
            </div>
          </label>

          {/* Tags */}
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-1.5">Tags</label>
            <div className="flex flex-wrap gap-1.5 mb-2">
              {tags.map((t) => (
                <span key={t} className="flex items-center gap-1 px-2 py-0.5 bg-slate-800 border border-white/5 rounded text-[11px] text-slate-300">
                  <Tag className="w-2.5 h-2.5" />
                  {t}
                  <button onClick={() => removeTag(t)} className="text-slate-500 hover:text-rose-400 ml-0.5" aria-label={`Remove tag ${t}`}>×</button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
                placeholder="Add tag..."
                className="flex-1 px-3 py-1.5 bg-slate-950/60 border border-white/5 rounded-lg text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/40 transition"
              />
              <button onClick={addTag} className="px-3 py-1.5 bg-slate-800 border border-white/5 rounded-lg text-xs text-slate-400 hover:text-white transition">
                Add
              </button>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="px-6 py-4 border-t border-white/5 flex gap-3">
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex-1 py-2.5 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-600 text-slate-950 transition flex items-center justify-center gap-2"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? "Saving..." : "Save Changes"}
          </button>
          <button
            onClick={onClose}
            className="px-5 py-2.5 rounded-xl text-xs font-bold bg-slate-950/60 hover:bg-slate-900 border border-white/5 text-slate-400 hover:text-white transition"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
