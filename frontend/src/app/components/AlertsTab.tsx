"use client";

import { useState, useEffect, useMemo } from "react";
import useSWR, { useSWRConfig } from "swr";
import { 
  ShieldAlert, 
  ShieldCheck, 
  Network, 
  Globe, 
  Lock, 
  Unlock, 
  Info, 
  X,
  Copy,
  Check,
  ChevronRight,
  MapPin,
  Cpu,
  Search,
  Filter,
  SlidersHorizontal
} from "lucide-react";

import type { Alert } from "../lib/types";
import { apiUrl, fetcher } from "../lib/api";
import { IPDrilldownModal } from "./IPDrilldownModal";

const PAGE_SIZE = 30;

export function AlertsTab({ alerts }: { alerts: Alert[] }) {
  const [selectedAlertForDrawer, setSelectedAlertForDrawer] = useState<Alert | null>(null);
  const [mitigatingIP, setMitigatingIP] = useState<string | null>(null);
  const [copiedIP, setCopiedIP] = useState<string | null>(null);
  const [displayCount, setDisplayCount] = useState(PAGE_SIZE);
  const { mutate } = useSWRConfig();

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Set<Alert["severity"]>>(new Set(["high", "medium", "low"]));
  const [minScore, setMinScore] = useState(0);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [drilldownIP, setDrilldownIP] = useState<string | null>(null);

  const { data: blockedIPs } = useSWR<string[]>(apiUrl("/api/settings/blocked_ips"), fetcher);

  useEffect(() => {
    if (!selectedAlertForDrawer) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSelectedAlertForDrawer(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selectedAlertForDrawer]);

  useEffect(() => {
    setDisplayCount(PAGE_SIZE);
  }, [alerts.length]);

  const filteredAlerts = useMemo(() => {
    if (!alerts) return [];
    const q = searchQuery.toLowerCase().trim();
    return alerts.filter((alert) => {
      if (!severityFilter.has(alert.severity)) return false;
      if (alert.score * 100 < minScore) return false;
      if (dateFrom) {
        const fromTs = new Date(dateFrom).getTime() / 1000;
        if (alert._alerted_at < fromTs) return false;
      }
      if (dateTo) {
        const toTs = new Date(dateTo).getTime() / 1000 + 86400;
        if (alert._alerted_at > toTs) return false;
      }
      if (q) {
        const hay = `${alert._src_ip} ${alert._dst_ip} ${alert.severity} ${alert.incident_id || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [alerts, searchQuery, severityFilter, minScore, dateFrom, dateTo]);

  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (searchQuery.trim()) count++;
    if (severityFilter.size < 3) count++;
    if (minScore > 0) count++;
    if (dateFrom || dateTo) count++;
    return count;
  }, [searchQuery, severityFilter, minScore, dateFrom, dateTo]);

  if (!alerts) return <div className="text-slate-400 p-8 animate-pulse text-center">Loading Alert History...</div>;

  const visibleAlerts = filteredAlerts.slice(0, displayCount);
  const hasMore = filteredAlerts.length > displayCount;

  const toggleSeverity = (sev: Alert["severity"]) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) {
        if (next.size > 1) next.delete(sev);
      } else {
        next.add(sev);
      }
      return next;
    });
  };

  const clearFilters = () => {
    setSearchQuery("");
    setSeverityFilter(new Set(["high", "medium", "low"]));
    setMinScore(0);
    setDateFrom("");
    setDateTo("");
  };

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
        await mutate(apiUrl("/api/settings/blocked_ips"));
      } else {
        console.error(`Failed to execute firewall action: ${response.statusText}`);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setMitigatingIP(null);
    }
  };

  return (
    <div className="relative">
      {/* Table Container */}
      <div className="bg-slate-900 border border-white/5 rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-white/5 flex justify-between items-center bg-slate-900/50">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-500" aria-hidden="true" />
              Alert Explorer
            </h2>
            <p className="text-sm text-slate-400 mt-1">Real-time log of security events matching active signatures or high ML thresholds. Click any alert to inspect explainability features and network paths.</p>
          </div>
          <button className="bg-emerald-500/10 text-emerald-400 px-4 py-2 rounded-lg font-medium text-sm hover:bg-emerald-500/20 transition duration-200 border border-emerald-500/20">
            Export Alerts
          </button>
        </div>

        {/* Filter Bar */}
        <div className="px-6 py-3 border-b border-white/5 bg-slate-900/30">
          <div className="flex items-center gap-3">
            {/* Search Input */}
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" aria-hidden="true" />
              <input
                type="text"
                placeholder="Search IP, severity, incident..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setDisplayCount(PAGE_SIZE); }}
                className="w-full pl-9 pr-3 py-2 bg-slate-950/60 border border-white/5 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500/40 focus:ring-1 focus:ring-emerald-500/20 transition"
                aria-label="Search alerts"
              />
            </div>

            {/* Filter Toggle */}
            <button
              onClick={() => setFiltersOpen(!filtersOpen)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition ${
                filtersOpen || activeFilterCount > 0
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : 'bg-slate-950/60 border-white/5 text-slate-400 hover:text-slate-200 hover:border-white/10'
              }`}
              aria-expanded={filtersOpen}
              aria-label={`Advanced filters${activeFilterCount > 0 ? ` (${activeFilterCount} active)` : ''}`}
            >
              <SlidersHorizontal className="w-4 h-4" />
              Filters
              {activeFilterCount > 0 && (
                <span className="bg-emerald-500 text-slate-950 text-[10px] font-bold rounded-full w-4.5 h-4.5 flex items-center justify-center leading-none px-1">
                  {activeFilterCount}
                </span>
              )}
            </button>

            {/* Result count */}
            <span className="text-xs text-slate-500 hidden sm:block">
              {filteredAlerts.length} alert{filteredAlerts.length !== 1 ? 's' : ''}
              {filteredAlerts.length !== alerts.length && (
                <span className="text-slate-600"> / {alerts.length} total</span>
              )}
            </span>
          </div>

          {/* Expanded Filters Panel */}
          {filtersOpen && (
            <div className="mt-3 pt-3 border-t border-white/5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Severity Chips */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-2">Severity</label>
                <div className="flex gap-2">
                  {(["high", "medium", "low"] as const).map((sev) => {
                    const active = severityFilter.has(sev);
                    return (
                      <button
                        key={sev}
                        onClick={() => { toggleSeverity(sev); setDisplayCount(PAGE_SIZE); }}
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition ${
                          active
                            ? sev === 'high' ? 'bg-rose-500/15 border-rose-500/30 text-rose-400'
                              : sev === 'medium' ? 'bg-amber-500/15 border-amber-500/30 text-amber-400'
                              : 'bg-slate-500/15 border-slate-500/30 text-slate-300'
                            : 'bg-slate-950/40 border-white/5 text-slate-600'
                        }`}
                      >
                        {sev.toUpperCase()}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Min Score */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-2">
                  Min Confidence: <span className="text-emerald-400">{minScore}%</span>
                </label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  step="5"
                  value={minScore}
                  onChange={(e) => { setMinScore(Number(e.target.value)); setDisplayCount(PAGE_SIZE); }}
                  className="accent-emerald-500 w-full"
                  aria-label={`Minimum confidence score: ${minScore}%`}
                />
              </div>

              {/* Date From */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-2">From Date</label>
                <input
                  type="date"
                  value={dateFrom}
                  onChange={(e) => { setDateFrom(e.target.value); setDisplayCount(PAGE_SIZE); }}
                  className="w-full px-3 py-1.5 bg-slate-950/60 border border-white/5 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-emerald-500/40 transition"
                  aria-label="Filter from date"
                />
              </div>

              {/* Date To */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-2">To Date</label>
                <div className="flex gap-2">
                  <input
                    type="date"
                    value={dateTo}
                    onChange={(e) => { setDateTo(e.target.value); setDisplayCount(PAGE_SIZE); }}
                    className="flex-1 px-3 py-1.5 bg-slate-950/60 border border-white/5 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-emerald-500/40 transition"
                    aria-label="Filter to date"
                  />
                  {activeFilterCount > 0 && (
                    <button
                      onClick={clearFilters}
                      className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-white/5 transition"
                      aria-label="Clear all filters"
                    >
                      Clear
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300 border-collapse" aria-label="Alert events table">
            <thead className="text-xs uppercase bg-slate-950/70 text-slate-400 border-b border-white/5 font-semibold tracking-wider">
              <tr>
                <th className="px-6 py-4">Timestamp</th>
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4">Detection</th>
                <th className="px-6 py-4">Source IP</th>
                <th className="px-6 py-4">Target IP</th>
                <th className="px-6 py-4">Confidence Score</th>
                <th className="px-6 py-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {visibleAlerts.map((alert: Alert) => {
                const ipCurrentlyBlocked = isBlocked(alert._src_ip);
                const isSelected = selectedAlertForDrawer && selectedAlertForDrawer._alerted_at === alert._alerted_at && selectedAlertForDrawer._src_ip === alert._src_ip;

                return (
                  <tr
                    key={`${alert._alerted_at}-${alert._src_ip}-${alert._dst_ip}`}
                    onClick={() => setSelectedAlertForDrawer(alert)}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedAlertForDrawer(alert); } }}
                    tabIndex={0}
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
                    <td className="px-6 py-4">
                      {(() => {
                        const drv = alert.driver;
                        let sigName: string | null = null;
                        if (alert.matched_rules?.length) {
                          sigName = alert.matched_rules[0].name;
                        } else if (alert.signature_match) {
                          try {
                            const parsed = typeof alert.signature_match === 'string' ? JSON.parse(alert.signature_match) : alert.signature_match;
                            sigName = Array.isArray(parsed) ? parsed[0]?.name : parsed?.name;
                          } catch { /* ignore */ }
                        }
                        if (drv === 'signature' || drv === 'both') {
                          return (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider bg-purple-500/10 text-purple-400 border border-purple-500/20">
                              <ShieldCheck className="w-3 h-3" />
                              {drv === 'both' ? 'AI + Signature' : 'Signature'}
                              {sigName ? ` · ${sigName}` : ''}
                            </span>
                          );
                        }
                        const driver = alert.explanation?.driver;
                        if (driver?.includes("Random Forest")) {
                          return (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider bg-sky-500/10 text-sky-400 border border-sky-500/20">
                              <Cpu className="w-3 h-3" />
                              RF Classifier
                            </span>
                          );
                        }
                        if (driver?.includes("Autoencoder")) {
                          return (
                            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20">
                              <Cpu className="w-3 h-3" />
                              AE Anomaly
                            </span>
                          );
                        }
                        return (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <ShieldAlert className="w-3 h-3" />
                            AI Detection
                          </span>
                        );
                      })()}
                    </td>
                    <td className="px-6 py-4 font-mono text-cyan-400 font-semibold">
                      <button
                        onClick={(e) => { e.stopPropagation(); setDrilldownIP(alert._src_ip); }}
                        className="hover:underline hover:text-cyan-300 transition text-left"
                      >
                        {alert._src_ip}
                      </button>
                    </td>
                    <td className="px-6 py-4 font-mono text-slate-300">
                      <button
                        onClick={(e) => { e.stopPropagation(); setDrilldownIP(alert._dst_ip); }}
                        className="hover:underline hover:text-slate-200 transition text-left"
                      >
                        {alert._dst_ip}
                      </button>
                    </td>
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
                          {ipCurrentlyBlocked ? <Unlock className="w-3.5 h-3.5" aria-hidden="true" /> : <Lock className="w-3.5 h-3.5" aria-hidden="true" />}
                          {ipCurrentlyBlocked ? 'Unblock' : 'Block'}
                        </button>
                        <ChevronRight className="w-4 h-4 text-slate-500" aria-hidden="true" />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {hasMore && (
            <div className="p-4 border-t border-white/5 flex justify-center">
              <button
                onClick={() => setDisplayCount((c) => c + PAGE_SIZE)}
                className="px-5 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-white/5 transition"
              >
                Show {Math.min(PAGE_SIZE, filteredAlerts.length - displayCount)} More Alerts
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Side Slide-over Drawer for explainability enrichment */}
      {selectedAlertForDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end overflow-hidden" role="dialog" aria-modal="true" aria-label="Alert detail drawer">
          {/* Backdrop Overlay */}
          <div
            className="absolute inset-0 bg-slate-950/60 backdrop-blur-sm transition-opacity"
            onClick={() => setSelectedAlertForDrawer(null)}
            aria-hidden="true"
          />

          {/* Drawer Body Panel */}
          <div className="relative w-full max-w-lg bg-slate-900 border-l border-white/10 shadow-[0_0_50px_rgba(0,0,0,0.8)] backdrop-blur-xl h-screen flex flex-col justify-between transform transition-all duration-300 translate-x-0 overflow-y-auto text-slate-100 p-6 space-y-6">
            
            {/* Header section with closing */}
            <div className="flex justify-between items-start border-b border-white/5 pb-4">
              <div>
                <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-widest block">Security Event Analysis</span>
                <h3 className="text-lg font-bold text-white mt-1 flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-rose-500" aria-hidden="true" />
                  Alert Attributions
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedAlertForDrawer(null)}
                className="bg-slate-950/50 p-2 rounded-lg border border-white/5 text-slate-400 hover:text-white transition duration-150"
                aria-label="Close drawer"
              >
                <X className="w-4 h-4" aria-hidden="true" />
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
                  <div className="flex items-center gap-1.5 mt-1">
                    <span className={`inline-flex px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                      selectedAlertForDrawer.severity === 'high' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                      selectedAlertForDrawer.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                      'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                    }`}>
                      {selectedAlertForDrawer.severity.toUpperCase()}
                    </span>
                    {selectedAlertForDrawer.driver && (
                      <span className={`inline-flex px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider ${
                        selectedAlertForDrawer.driver === 'signature' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' :
                        selectedAlertForDrawer.driver === 'both' ? 'bg-violet-500/10 text-violet-400 border border-violet-500/20' :
                        'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                      }`}>
                        {selectedAlertForDrawer.driver === 'both' ? 'AI + Signature' : selectedAlertForDrawer.driver === 'signature' ? 'Signature' : 'AI'}
                      </span>
                    )}
                  </div>
                </div>
                
                <div className="text-right">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">AI Confidence</span>
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

              {typeof selectedAlertForDrawer.signature_confidence === 'number' && selectedAlertForDrawer.signature_confidence > 0 && (
                <div className="space-y-1.5">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-[9px] text-slate-500 uppercase tracking-wider">Signature Confidence</span>
                    <span className="font-mono font-bold text-purple-400">
                      {(selectedAlertForDrawer.signature_confidence * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-white/5">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${selectedAlertForDrawer.signature_confidence >= 0.8 ? 'bg-purple-500' : 'bg-fuchsia-500'}`}
                      style={{ width: `${selectedAlertForDrawer.signature_confidence * 100}%` }}
                    />
                  </div>
                </div>
              )}

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
                <Network className="w-4 h-4 text-cyan-400" aria-hidden="true" />
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
                      aria-label={`Copy source IP ${selectedAlertForDrawer._src_ip}`}
                    >
                      {copiedIP === selectedAlertForDrawer._src_ip ? <Check className="w-3 h-3 text-emerald-400" aria-hidden="true" /> : <Copy className="w-3 h-3" aria-hidden="true" />}
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
                      aria-label={`Copy destination IP ${selectedAlertForDrawer._dst_ip}`}
                    >
                      {copiedIP === selectedAlertForDrawer._dst_ip ? <Check className="w-3 h-3 text-emerald-400" aria-hidden="true" /> : <Copy className="w-3 h-3" aria-hidden="true" />}
                    </button>
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono mt-0.5 block">Port: {selectedAlertForDrawer._dst_port}</span>
                </div>
              </div>
            </div>

            {/* AI Explainability & Contributing Features */}
            <div className="bg-slate-950 p-5 rounded-2xl border border-white/5 space-y-4 shadow-inner">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-fuchsia-400" aria-hidden="true" />
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
                    {selectedAlertForDrawer.explanation!.features && selectedAlertForDrawer.explanation!.features.length > 0 ? (
                      <div className="space-y-3">
                        {selectedAlertForDrawer.explanation!.features.slice(0, 3).map((feat: { name: string; score: number }, fIdx: number) => {
                          const maxScore = Math.max(...selectedAlertForDrawer.explanation!.features.map((f: { score: number }) => f.score)) || 1.0;
                          const pct = (feat.score / maxScore) * 100;
                          const isRF = selectedAlertForDrawer.explanation!.driver.includes("Random Forest");
                          
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
                      <span className="text-xs font-mono font-bold text-sky-400 mt-1 block">{((selectedAlertForDrawer.rf_score ?? 0) * 100).toFixed(1)}%</span>
                    </div>
                    <div className="bg-slate-900/60 p-2.5 rounded-xl border border-white/5 text-center">
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider block">AE Anomaly MSE</span>
                      <span className="text-xs font-mono font-bold text-fuchsia-400 mt-1 block">{((selectedAlertForDrawer.ae_score ?? 0) * 100).toFixed(1)}%</span>
                    </div>
                  </div>

                </div>
              ) : (
                <div className="space-y-2">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Attribution Source</span>
                  <div className="bg-amber-500/10 border border-amber-500/20 p-4 rounded-xl text-amber-400">
                    <p className="text-xs font-semibold flex items-center gap-1.5 mb-1">
                      <ShieldCheck className="w-4 h-4" aria-hidden="true" />
                      Signature Rule Match
                    </p>
                    <p className="text-[11px] leading-relaxed text-amber-400/80">
                      This alert was driven by a signature rule match with an explicit
                      confidence of {(selectedAlertForDrawer.signature_confidence ?? 0) * 100}%.
                      No ML feature attribution was recorded.
                    </p>
                  </div>
                </div>
              )}

              {selectedAlertForDrawer.matched_rules && selectedAlertForDrawer.matched_rules.length > 0 && (
                <div className="space-y-3 pt-3 border-t border-white/5">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Matched Signature Rules</span>
                  <div className="space-y-2">
                    {selectedAlertForDrawer.matched_rules.map((rule, rIdx) => (
                      <div key={rIdx} className="bg-slate-900/60 p-2.5 rounded-xl border border-white/5 space-y-1.5">
                        <div className="flex justify-between items-center text-xs">
                          <span className="text-slate-300 font-medium flex items-center gap-1.5">
                            <ShieldCheck className="w-3.5 h-3.5 text-purple-400" aria-hidden="true" />
                            <span className="font-mono text-purple-300">{rule.rule_id}</span>
                          </span>
                          <span className="font-mono font-bold text-purple-400">
                            {(rule.confidence ?? 0.7) * 100}%
                          </span>
                        </div>
                        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden border border-white/5">
                          <div
                            className="h-full rounded-full bg-purple-500"
                            style={{ width: `${(rule.confidence ?? 0.7) * 100}%` }}
                          />
                        </div>
                        <span className="block text-[10px] text-slate-500">{rule.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Geolocation Threat Intel */}
            <div className="bg-slate-950 p-5 rounded-2xl border border-white/5 space-y-4 shadow-inner">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-purple-400" aria-hidden="true" />
                Threat Intelligence Enrichment
              </h4>

              {selectedAlertForDrawer.country || selectedAlertForDrawer.asn || selectedAlertForDrawer.threat_level ? (
                <div className="space-y-3.5">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider block">Geographic Origin</span>
                      <p className="text-xs font-semibold text-white flex items-center gap-1.5">
                        <MapPin className="w-3.5 h-3.5 text-purple-400" aria-hidden="true" />
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
                  <Info className="w-5 h-5 text-slate-600" aria-hidden="true" />
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
                    <Unlock className="w-4 h-4" aria-hidden="true" />
                    Unblock IP on Firewall
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4 fill-current" aria-hidden="true" />
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
      {/* IP Drilldown Modal */}
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
