"use client";

import { useState } from "react";
import useSWR, { useSWRConfig } from "swr";
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  Network, 
  Globe, 
  Lock, 
  Unlock, 
  Info, 
  Terminal,
  X,
  Copy,
  Check,
  ChevronRight,
  TrendingUp,
  Sliders,
  MapPin,
  Cpu
} from "lucide-react";

import { apiUrl } from "../lib/api";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export function AlertsTab({ alerts }: any) {
  const [selectedAlertForDrawer, setSelectedAlertForDrawer] = useState<any | null>(null);
  const [mitigatingIP, setMitigatingIP] = useState<string | null>(null);
  const [copiedIP, setCopiedIP] = useState<string | null>(null);
  const { mutate } = useSWRConfig();

  // Fetch the active blocked list to dynamically show current firewall status
  const { data: blockedIPs } = useSWR(apiUrl("/api/settings/blocked_ips"), fetcher);

  if (!alerts) return <div className="text-slate-400 p-8 animate-pulse text-center">Loading Alert History...</div>;

  const isBlocked = (ip: string) => {
    return blockedIPs?.includes(ip) || false;
  };

  const handleCopy = (ip: string, event: React.MouseEvent) => {
    event.stopPropagation();
    navigator.clipboard.writeText(ip);
    setCopiedIP(ip);
    setTimeout(() => setCopiedIP(null), 2000);
  };

  const handleFirewallAction = async (ip: string, action: "block" | "unblock", event?: React.MouseEvent) => {
    if (event) event.stopPropagation();
    setMitigatingIP(ip);
    try {
      const response = await fetch(apiUrl("/api/settings/firewall"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ip })
      });
      if (response.ok) {
        // Mutate blocked_ips cache immediately to trigger a UI update
        await mutate(apiUrl("/api/settings/blocked_ips"));
      } else {
        alert(`Failed to execute firewall action: ${response.statusText}`);
      }
    } catch (err) {
      console.error(err);
      alert("Network error executing firewall action.");
    } finally {
      setMitigatingIP(null);
    }
  };

  return (
    <div className="relative">
      {/* Table Container */}
      <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 bg-slate-900 border border-white/5 rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-white/5 flex justify-between items-center bg-slate-900/50">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-500" />
              Alert Explorer
            </h2>
            <p className="text-sm text-slate-400 mt-1">Real-time log of security events matching active signatures or high ML thresholds. Click any alert to inspect explainability features and network paths.</p>
          </div>
          <button className="bg-emerald-500/10 text-emerald-400 px-4 py-2 rounded-lg font-medium text-sm hover:bg-emerald-500/20 transition duration-200 border border-emerald-500/20">
            Export Alerts
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300 border-collapse">
            <thead className="text-xs uppercase bg-slate-950/70 text-slate-400 border-b border-white/5 font-semibold tracking-wider">
              <tr>
                <th className="px-6 py-4">Timestamp</th>
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4">Source IP</th>
                <th className="px-6 py-4">Target IP</th>
                <th className="px-6 py-4">Confidence Score</th>
                <th className="px-6 py-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {alerts.slice(0, 30).map((alert: any, idx: number) => {
                const ipCurrentlyBlocked = isBlocked(alert._src_ip);
                const isSelected = selectedAlertForDrawer && selectedAlertForDrawer._alerted_at === alert._alerted_at && selectedAlertForDrawer._src_ip === alert._src_ip;

                return (
                  <tr 
                    key={idx} 
                    onClick={() => setSelectedAlertForDrawer(alert)}
                    className={`hover:bg-slate-800/40 transition-all cursor-pointer select-none ${isSelected ? 'bg-slate-800/45 border-l-2 border-emerald-500' : ''}`}
                  >
                    <td className="px-6 py-4 font-mono text-slate-400 text-xs">
                      {new Date(alert._alerted_at * 1000).toISOString().split('T')[1].slice(0, 8)}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider ${
                        alert.severity === 'high' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20 shadow-[0_0_12px_rgba(244,63,94,0.1)]' :
                        alert.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                        'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                      }`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-cyan-400 font-semibold">{alert._src_ip}</td>
                    <td className="px-6 py-4 font-mono text-slate-300">{alert._dst_ip}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white">{(alert.score * 100).toFixed(1)}%</span>
                        <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden border border-white/5">
                          <div 
                            className={`h-full rounded-full ${alert.score >= 0.85 ? 'bg-rose-500' : alert.score >= 0.65 ? 'bg-amber-500' : 'bg-emerald-500'}`} 
                            style={{ width: `${alert.score * 100}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex justify-end items-center gap-3">
                        <button
                          onClick={(e) => handleFirewallAction(alert._src_ip, ipCurrentlyBlocked ? "unblock" : "block", e)}
                          disabled={mitigatingIP === alert._src_ip}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition duration-200 ${
                            ipCurrentlyBlocked 
                              ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/25'
                              : 'bg-rose-500/10 border-rose-500/20 text-rose-400 hover:bg-rose-500/20 animate-pulse'
                          }`}
                        >
                          {ipCurrentlyBlocked ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
                          {ipCurrentlyBlocked ? 'Unblock' : 'Block'}
                        </button>
                        <ChevronRight className="w-4 h-4 text-slate-500" />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Side Slide-over Drawer for explainability enrichment */}
      {selectedAlertForDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end overflow-hidden animate-in fade-in duration-200">
          {/* Backdrop Overlay */}
          <div 
            className="absolute inset-0 bg-slate-950/60 backdrop-blur-sm transition-opacity" 
            onClick={() => setSelectedAlertForDrawer(null)}
          />

          {/* Drawer Body Panel */}
          <div className="relative w-full max-w-lg bg-slate-900 border-l border-white/10 shadow-[0_0_50px_rgba(0,0,0,0.8)] backdrop-blur-xl h-screen flex flex-col justify-between transform transition-all duration-300 translate-x-0 overflow-y-auto text-slate-100 p-6 space-y-6">
            
            {/* Header section with closing */}
            <div className="flex justify-between items-start border-b border-white/5 pb-4">
              <div>
                <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-widest block">Security Event Analysis</span>
                <h3 className="text-lg font-bold text-white mt-1 flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-rose-500" />
                  Alert Attributions
                </h3>
              </div>
              <button 
                type="button" 
                onClick={() => setSelectedAlertForDrawer(null)}
                className="bg-slate-950/50 p-2 rounded-lg border border-white/5 text-slate-400 hover:text-white transition duration-150"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Core Info & Score Gauge card */}
            <div className="bg-slate-950 p-5 rounded-2xl border border-white/5 space-y-4 shadow-inner relative overflow-hidden">
              <div className="absolute top-0 right-0 p-8 opacity-[0.02] pointer-events-none">
                <ShieldCheck className="w-44 h-44 text-emerald-400" />
              </div>
              
              <div className="flex justify-between items-center">
                <div>
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Severity Status</span>
                  <span className={`inline-flex px-2.5 py-0.5 rounded-full text-[10px] font-bold mt-1 ${
                    selectedAlertForDrawer.severity === 'high' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                    selectedAlertForDrawer.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                    'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                  }`}>
                    {selectedAlertForDrawer.severity.toUpperCase()}
                  </span>
                </div>
                
                <div className="text-right">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">ML Confidence</span>
                  <span className="text-lg font-mono font-bold text-white">
                    {(selectedAlertForDrawer.score * 100).toFixed(1)}%
                  </span>
                </div>
              </div>

              {/* Progress gauge visual */}
              <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden border border-white/5">
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    selectedAlertForDrawer.score >= 0.85 ? 'bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,0.4)]' : 
                    selectedAlertForDrawer.score >= 0.65 ? 'bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.4)]' : 
                    'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.4)]'
                  }`} 
                  style={{ width: `${selectedAlertForDrawer.score * 100}%` }}
                />
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs pt-2 border-t border-white/5">
                <div>
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider">Timestamp</span>
                  <span className="block font-semibold text-slate-300 mt-0.5">
                    {new Date(selectedAlertForDrawer._alerted_at * 1000).toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider">Correlation ID</span>
                  <span className="block font-mono text-slate-300 mt-0.5 truncate" title={selectedAlertForDrawer.incident_id}>
                    {selectedAlertForDrawer.incident_id || "Uncorrelated"}
                  </span>
                </div>
              </div>
            </div>

            {/* IP Connection path diagram */}
            <div className="bg-slate-950 p-5 rounded-2xl border border-white/5 space-y-4 shadow-inner">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Network className="w-4 h-4 text-cyan-400" />
                Network Flow Mapping
              </h4>

              <div className="flex items-center justify-between bg-slate-900/60 p-3 rounded-xl border border-white/5">
                <div className="flex-1 min-w-0">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Source Node</span>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <code className="text-xs font-mono text-cyan-400 font-bold truncate">
                      {selectedAlertForDrawer._src_ip}
                    </code>
                    <button 
                      onClick={(e) => handleCopy(selectedAlertForDrawer._src_ip, e)}
                      className="text-slate-500 hover:text-white transition duration-150"
                    >
                      {copiedIP === selectedAlertForDrawer._src_ip ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono mt-0.5 block">Port: {selectedAlertForDrawer._src_port}</span>
                </div>

                <div className="px-4 text-slate-600 flex flex-col items-center">
                  <span className="text-[9px] text-slate-500 uppercase font-mono tracking-wider">TCP</span>
                  <ChevronRight className="w-5 h-5 text-slate-500 mt-0.5 animate-pulse" />
                </div>

                <div className="flex-1 min-w-0 text-right">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Destination Target</span>
                  <div className="flex items-center justify-end gap-1.5 mt-0.5">
                    <code className="text-xs font-mono text-slate-200 font-bold truncate">
                      {selectedAlertForDrawer._dst_ip}
                    </code>
                    <button 
                      onClick={(e) => handleCopy(selectedAlertForDrawer._dst_ip, e)}
                      className="text-slate-500 hover:text-white transition duration-150"
                    >
                      {copiedIP === selectedAlertForDrawer._dst_ip ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono mt-0.5 block">Port: {selectedAlertForDrawer._dst_port}</span>
                </div>
              </div>
            </div>

            {/* AI Explainability & Contributing Features */}
            <div className="bg-slate-950 p-5 rounded-2xl border border-white/5 space-y-4 shadow-inner">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-fuchsia-400" />
                AI Inference Driver & Contributors
              </h4>

              {selectedAlertForDrawer.explanation ? (
                <div className="space-y-4">
                  <div className="space-y-1">
                    <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Ensemble Driver Model</span>
                    <span className={`inline-flex px-3 py-1 rounded-xl text-xs font-bold ${
                      selectedAlertForDrawer.explanation.driver.includes("Random Forest") 
                        ? "bg-sky-500/10 text-sky-400 border border-sky-500/20" 
                        : "bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20"
                    }`}>
                      {selectedAlertForDrawer.explanation.driver}
                    </span>
                  </div>

                  <div className="space-y-3">
                    <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Top Contributing Feature Metrics</span>
                    {selectedAlertForDrawer.explanation.features && selectedAlertForDrawer.explanation.features.length > 0 ? (
                      <div className="space-y-3">
                        {selectedAlertForDrawer.explanation.features.slice(0, 3).map((feat: any, fIdx: number) => {
                          const maxScore = Math.max(...selectedAlertForDrawer.explanation.features.map((f: any) => f.score)) || 1.0;
                          const pct = (feat.score / maxScore) * 100;
                          const isRF = selectedAlertForDrawer.explanation.driver.includes("Random Forest");
                          
                          return (
                            <div key={fIdx} className="space-y-1.5">
                              <div className="flex justify-between text-xs">
                                <span className="text-slate-300 font-medium">{feat.name}</span>
                                <span className="font-mono text-slate-400 font-semibold">{feat.score.toFixed(3)}</span>
                              </div>
                              <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-white/5">
                                <div 
                                  className={`h-full rounded-full transition-all duration-300 ${isRF ? 'bg-sky-500' : 'bg-fuchsia-500'}`} 
                                  style={{ width: `${pct}%` }}
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <p className="text-xs text-slate-500 italic">No feature attribution data recorded.</p>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-3 pt-3 border-t border-white/5">
                    <div className="bg-slate-900/60 p-2.5 rounded-xl border border-white/5 text-center">
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider block">RF Classifier Probability</span>
                      <span className="text-xs font-mono font-bold text-sky-400 mt-1 block">{(selectedAlertForDrawer.rf_score * 100).toFixed(1)}%</span>
                    </div>
                    <div className="bg-slate-900/60 p-2.5 rounded-xl border border-white/5 text-center">
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider block">AE Anomaly MSE</span>
                      <span className="text-xs font-mono font-bold text-fuchsia-400 mt-1 block">{(selectedAlertForDrawer.ae_score * 100).toFixed(1)}%</span>
                    </div>
                  </div>

                </div>
              ) : (
                <div className="space-y-2">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Attribution Source</span>
                  <div className="bg-amber-500/10 border border-amber-500/20 p-4 rounded-xl text-amber-400">
                    <p className="text-xs font-semibold flex items-center gap-1.5 mb-1">
                      <ShieldCheck className="w-4 h-4" />
                      Signature Match Rule
                    </p>
                    <p className="text-[11px] leading-relaxed text-amber-400/80">
                      This network connection triggered a matching signature definition ruleset. The anomaly status was labeled dynamically.
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Geolocation Threat Intel */}
            <div className="bg-slate-950 p-5 rounded-2xl border border-white/5 space-y-4 shadow-inner">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-purple-400" />
                Threat Intelligence Enrichment
              </h4>

              {selectedAlertForDrawer.country || selectedAlertForDrawer.asn || selectedAlertForDrawer.threat_level ? (
                <div className="space-y-3.5">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Geographic Origin</span>
                      <p className="text-xs font-semibold text-white flex items-center gap-1.5">
                        <MapPin className="w-3.5 h-3.5 text-purple-400" />
                        <span>{selectedAlertForDrawer.country || "Private IP"}</span>
                        {selectedAlertForDrawer.city && <span className="text-slate-400 font-normal">({selectedAlertForDrawer.city})</span>}
                      </p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      selectedAlertForDrawer.threat_level === 'high' ? 'bg-rose-500/10 border-rose-500/25 text-rose-400' :
                      selectedAlertForDrawer.threat_level === 'medium' ? 'bg-amber-500/10 border-amber-500/25 text-amber-400' :
                      'bg-emerald-500/10 border-emerald-500/25 text-emerald-400'
                    }`}>
                      Reputation: {(selectedAlertForDrawer.threat_level || "Clean").toUpperCase()}
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    <span className="text-[9px] text-slate-500 uppercase tracking-wider block">ASN & ISP Details</span>
                    <div className="bg-slate-900/60 rounded-xl border border-white/5 p-3 space-y-1 text-xs text-slate-400 font-mono">
                      <div className="flex justify-between">
                        <span>Autonomous System:</span>
                        <span className="text-slate-200 font-semibold">{selectedAlertForDrawer.asn || "N/A"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>ISP / Owner:</span>
                        <span className="text-slate-200 font-semibold truncate max-w-[180px]" title={selectedAlertForDrawer.isp}>
                          {selectedAlertForDrawer.isp || "Local Intranet"}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-4 text-slate-500 text-center gap-2">
                  <Info className="w-5 h-5 text-slate-600" />
                  <p className="text-xs">No public geolocation / reputation records.</p>
                  <span className="text-[9px] text-slate-600">Source IP resides in a local or reserved intranet subnet range.</span>
                </div>
              )}
            </div>

            {/* Operational controls / Firewall block action */}
            <div className="pt-4 border-t border-white/5 flex gap-3">
              <button
                type="button"
                onClick={() => handleFirewallAction(
                  selectedAlertForDrawer._src_ip, 
                  isBlocked(selectedAlertForDrawer._src_ip) ? "unblock" : "block"
                )}
                disabled={mitigatingIP === selectedAlertForDrawer._src_ip}
                className={`flex-1 py-3 rounded-xl text-xs font-bold border transition duration-200 flex items-center justify-center gap-2 ${
                  isBlocked(selectedAlertForDrawer._src_ip)
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/25'
                    : 'bg-rose-500 hover:bg-rose-600 text-slate-950 font-bold border-rose-500'
                }`}
              >
                {isBlocked(selectedAlertForDrawer._src_ip) ? (
                  <>
                    <Unlock className="w-4 h-4" />
                    Unblock IP on Firewall
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4 fill-current" />
                    Mitigate Threat: Block IP
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={() => setSelectedAlertForDrawer(null)}
                className="bg-slate-950/60 hover:bg-slate-900 border border-white/5 text-slate-400 hover:text-white px-5 py-3 rounded-xl text-xs font-bold transition duration-150"
              >
                Dismiss
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
