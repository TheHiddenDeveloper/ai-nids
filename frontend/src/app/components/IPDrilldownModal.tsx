"use client";

import { useMemo, useState, useEffect } from "react";
import useSWR from "swr";
import {
  X,
  Globe,
  MapPin,
  Shield,
  ShieldAlert,
  Lock,
  Unlock,
  Clock,
  Network,
  AlertTriangle,
  Copy,
  Check,
} from "lucide-react";

import type { Alert } from "../lib/types";
import { apiUrl, fetcher } from "../lib/api";
import { useSWRConfig } from "swr";

interface IPDrilldownModalProps {
  ip: string;
  alerts: Alert[];
  onClose: () => void;
}

export function IPDrilldownModal({ ip, alerts, onClose }: IPDrilldownModalProps) {
  const [copied, setCopied] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const { mutate } = useSWRConfig();
  const { data: blockedIPs } = useSWR<string[]>(apiUrl("/api/settings/blocked_ips"), fetcher);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const ipAlerts = useMemo(
    () => alerts.filter((a) => a._src_ip === ip || a._dst_ip === ip),
    [alerts, ip]
  );

  const asSource = useMemo(() => ipAlerts.filter((a) => a._src_ip === ip), [ipAlerts, ip]);
  const asTarget = useMemo(() => ipAlerts.filter((a) => a._dst_ip === ip), [ipAlerts, ip]);

  const severityBreakdown = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    for (const a of ipAlerts) counts[a.severity]++;
    return counts;
  }, [ipAlerts]);

  const relatedIPs = useMemo(() => {
    const map: Record<string, { count: number; role: "src" | "dst" }> = {};
    for (const a of ipAlerts) {
      const other = a._src_ip === ip ? a._dst_ip : a._src_ip;
      const role = a._src_ip === ip ? "src" : "dst";
      if (!map[other]) map[other] = { count: 0, role };
      map[other].count++;
    }
    return Object.entries(map)
      .map(([otherIP, data]) => ({ ip: otherIP, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [ipAlerts, ip]);

  const timeline = useMemo(() => {
    if (ipAlerts.length === 0) return [];
    const windowSize = 300;
    const buckets: Record<number, number> = {};
    for (const a of ipAlerts) {
      const bucket = Math.floor(a._alerted_at / windowSize) * windowSize;
      buckets[bucket] = (buckets[bucket] || 0) + 1;
    }
    return Object.entries(buckets)
      .map(([ts, count]) => ({
        time: new Date(Number(ts) * 1000),
        count,
      }))
      .sort((a, b) => a.time.getTime() - b.time.getTime());
  }, [ipAlerts]);

  const maxTimelineCount = timeline.length > 0 ? Math.max(...timeline.map((t) => t.count)) : 1;

  const latestAlert = ipAlerts.length > 0 ? ipAlerts[0] : null;
  const isBlocked = blockedIPs?.includes(ip) || false;

  const handleCopy = () => {
    navigator.clipboard.writeText(ip);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleBlockToggle = async () => {
    setBlocking(true);
    try {
      await fetch(apiUrl("/api/settings/firewall"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: isBlocked ? "unblock" : "block", ip }),
      });
      await mutate(apiUrl("/api/settings/blocked_ips"));
    } catch (err) {
      console.error(err);
    } finally {
      setBlocking(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" role="dialog" aria-modal="true" aria-label={`IP details for ${ip}`}>
      <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm" onClick={onClose} />

      <div className="relative w-full max-w-2xl max-h-[85vh] bg-slate-900 border border-white/10 rounded-2xl shadow-[0_0_80px_rgba(0,0,0,0.8)] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur-sm border-b border-white/5 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg border ${isBlocked ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-rose-500/10 border-rose-500/20'}`}>
              <Shield className={`w-5 h-5 ${isBlocked ? 'text-emerald-400' : 'text-rose-400'}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white font-mono">{ip}</h2>
                <button onClick={handleCopy} className="text-slate-500 hover:text-white transition" aria-label="Copy IP">
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                {ipAlerts.length} alert{ipAlerts.length !== 1 ? 's' : ''} associated
                {isBlocked && <span className="text-emerald-400 ml-2 font-semibold">BLOCKED</span>}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition" aria-label="Close">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-3 text-center">
              <span className="text-[9px] text-slate-500 uppercase tracking-wider block">As Source</span>
              <span className="text-xl font-bold text-rose-400 mt-1">{asSource.length}</span>
            </div>
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-3 text-center">
              <span className="text-[9px] text-slate-500 uppercase tracking-wider block">As Target</span>
              <span className="text-xl font-bold text-cyan-400 mt-1">{asTarget.length}</span>
            </div>
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-3 text-center">
              <span className="text-[9px] text-slate-500 uppercase tracking-wider block">High Sev</span>
              <span className="text-xl font-bold text-rose-400 mt-1">{severityBreakdown.high}</span>
            </div>
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-3 text-center">
              <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Unique Pairs</span>
              <span className="text-xl font-bold text-white mt-1">{relatedIPs.length}</span>
            </div>
          </div>

          {/* Geo / Threat Intel */}
          {latestAlert && (latestAlert.country || latestAlert.asn) && (
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-4">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 mb-3">
                <Globe className="w-4 h-4 text-purple-400" />
                Threat Intelligence
              </h4>
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div>
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Geography</span>
                  <p className="text-white font-semibold flex items-center gap-1.5 mt-0.5">
                    <MapPin className="w-3 h-3 text-purple-400" />
                    {latestAlert.country || "Private"}
                    {latestAlert.city && <span className="text-slate-400 font-normal">({latestAlert.city})</span>}
                  </p>
                </div>
                <div>
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">ASN / ISP</span>
                  <p className="text-white font-semibold mt-0.5 truncate" title={latestAlert.isp}>
                    {latestAlert.asn || "N/A"} {latestAlert.isp ? `/ ${latestAlert.isp}` : ""}
                  </p>
                </div>
                {latestAlert.threat_level && (
                  <div>
                    <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Reputation</span>
                    <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-bold border mt-0.5 ${
                      latestAlert.threat_level === "high"
                        ? "bg-rose-500/10 border-rose-500/25 text-rose-400"
                        : latestAlert.threat_level === "medium"
                        ? "bg-amber-500/10 border-amber-500/25 text-amber-400"
                        : "bg-emerald-500/10 border-emerald-500/25 text-emerald-400"
                    }`}>
                      {latestAlert.threat_level.toUpperCase()}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Activity Timeline */}
          {timeline.length > 0 && (
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-4">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 mb-3">
                <Clock className="w-4 h-4 text-emerald-400" />
                Activity Timeline
              </h4>
              <div className="flex items-end gap-1 h-16">
                {timeline.map((t, i) => (
                  <div
                    key={i}
                    className="flex-1 bg-emerald-500/60 rounded-t hover:bg-emerald-400 transition-colors relative group"
                    style={{ height: `${(t.count / maxTimelineCount) * 100}%`, minHeight: "4px" }}
                    title={`${t.time.toLocaleTimeString()} — ${t.count} alerts`}
                  />
                ))}
              </div>
              <div className="flex justify-between text-[9px] text-slate-600 mt-1">
                <span>{timeline[0].time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                <span>{timeline[timeline.length - 1].time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
              </div>
            </div>
          )}

          {/* Related IPs */}
          {relatedIPs.length > 0 && (
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-4">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 mb-3">
                <Network className="w-4 h-4 text-cyan-400" />
                Related IPs
              </h4>
              <div className="space-y-1.5">
                {relatedIPs.map((r) => (
                  <div key={r.ip} className="flex items-center justify-between text-xs py-1 border-b border-white/5 last:border-0">
                    <div className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full ${r.role === "src" ? "bg-rose-400" : "bg-cyan-400"}`} />
                      <span className="font-mono text-slate-200">{r.ip}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-slate-500 text-[10px] uppercase">{r.role === "src" ? "attacker" : "victim"}</span>
                      <span className="font-mono text-slate-400">{r.count}x</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent Alerts */}
          {ipAlerts.length > 0 && (
            <div className="bg-slate-950/60 border border-white/5 rounded-xl p-4">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 mb-3">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Recent Alerts
              </h4>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {ipAlerts.slice(0, 10).map((a, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs py-1.5 border-b border-white/5 last:border-0">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                      a.severity === "high" ? "bg-rose-500/15 text-rose-400" :
                      a.severity === "medium" ? "bg-amber-500/15 text-amber-400" :
                      "bg-slate-500/15 text-slate-400"
                    }`}>
                      {a.severity.toUpperCase()}
                    </span>
                    <span className="font-mono text-slate-400 text-[10px]">
                      {new Date(a._alerted_at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </span>
                    <span className="font-mono text-cyan-400 truncate flex-1">{a._src_ip}</span>
                    <span className="text-slate-600">&rarr;</span>
                    <span className="font-mono text-slate-300 truncate flex-1">{a._dst_ip}</span>
                    <span className="font-mono text-white font-semibold">{(a.score * 100).toFixed(0)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {ipAlerts.length === 0 && (
            <div className="text-center py-8 text-slate-500">
              <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <p className="text-sm">No alerts found for this IP.</p>
            </div>
          )}

          {/* Action */}
          <div className="flex gap-3 pt-2">
            <button
              onClick={handleBlockToggle}
              disabled={blocking}
              className={`flex-1 py-3 rounded-xl text-xs font-bold border transition flex items-center justify-center gap-2 ${
                isBlocked
                  ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/25"
                  : "bg-rose-500 hover:bg-rose-600 text-slate-950 border-rose-500"
              }`}
            >
              {isBlocked ? (
                <><Unlock className="w-4 h-4" /> Unblock IP</>
              ) : (
                <><Lock className="w-4 h-4 fill-current" /> Block IP</>
              )}
            </button>
            <button
              onClick={onClose}
              className="bg-slate-950/60 hover:bg-slate-900 border border-white/5 text-slate-400 hover:text-white px-5 py-3 rounded-xl text-xs font-bold transition"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
