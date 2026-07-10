"use client";

import { useState, useEffect, useRef } from "react";
import useSWR from "swr";
import { ShieldAlert, Activity, BarChart3, Settings as SettingsIcon, Globe2, MonitorPlay, ShieldCheck, Menu, X, Crosshair, Sun, Moon } from "lucide-react";
import { OverviewTab } from "./components/OverviewTab";
import { AlertsTab } from "./components/AlertsTab";
import { IncidentsTab } from "./components/IncidentsTab";
import { AnalyticsTab } from "./components/AnalyticsTab";
import { SettingsTab } from "./components/SettingsTab";
import { SignaturesTab } from "./components/SignaturesTab";
import { TasksWidget } from "./components/TasksWidget";
import { MLPlaybookTab } from "./components/MLPlaybookTab";
import { TopOffendersTab } from "./components/TopOffendersTab";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ThemeProvider, useTheme } from "./components/ThemeProvider";

import type { KPIs, Flow, Alert } from "./lib/types";
import { apiUrl, fetcher } from "./lib/api";

function SidebarSkeleton() {
  return (
    <div className="hidden md:flex w-72 bg-slate-900 border-r border-white/5 flex-col h-screen sticky top-0 shrink-0">
      <div className="h-16 px-6 border-b border-white/5 flex items-center gap-3">
        <div className="bg-slate-800 w-9 h-9 rounded-lg animate-pulse" />
        <div className="bg-slate-800 h-5 w-24 rounded animate-pulse" />
      </div>
      <div className="p-4 space-y-2">
        {Array.from({ length: 7 }).map((_, i) => (
          <div key={i} className="bg-slate-800 h-11 rounded-xl animate-pulse" />
        ))}
      </div>
      <div className="p-4 mb-4">
        <div className="bg-slate-950 p-5 rounded-2xl border border-white/5 space-y-4">
          <div className="bg-slate-800 h-3 w-24 rounded animate-pulse" />
          <div className="bg-slate-800 h-5 w-full rounded animate-pulse" />
          <div className="bg-slate-800 h-3 w-20 rounded animate-pulse" />
          <div className="bg-slate-800 h-2 w-full rounded animate-pulse" />
        </div>
      </div>
    </div>
  );
}

function Sidebar({
  tabs,
  activeTab,
  onTabChange,
  autoRefresh,
  onAutoRefreshChange,
  historyLim,
  onHistoryLimChange,
  sidebarOpen,
  onClose,
  isConnected,
  lastUpdated,
  theme,
  onThemeToggle,
}: {
  tabs: { id: string; label: string; icon: React.ComponentType<{ className?: string }> }[];
  activeTab: string;
  onTabChange: (id: string) => void;
  autoRefresh: boolean;
  onAutoRefreshChange: (v: boolean) => void;
  historyLim: number;
  onHistoryLimChange: (v: number) => void;
  sidebarOpen: boolean;
  onClose: () => void;
  isConnected: boolean;
  lastUpdated: Date | null;
  theme: "dark" | "light";
  onThemeToggle: () => void;
}) {
  return (
    <>
      {sidebarOpen && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm z-40 md:hidden" onClick={onClose} aria-hidden="true" />
      )}
      <aside className={`${sidebarOpen ? "translate-x-0" : "-translate-x-full"} md:translate-x-0 fixed md:sticky top-0 left-0 z-50 md:z-0 w-72 bg-slate-900 border-r border-white/5 flex flex-col h-screen transition-transform duration-300 shrink-0`} aria-label="Main navigation">
        <div>
           <div className="h-16 flex items-center px-6 border-b border-white/5 gap-3">
             <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20" aria-hidden="true">
               <ShieldAlert className="w-5 h-5 text-emerald-400" />
             </div>
              <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">AI-NIDS</h1>
              <button onClick={onThemeToggle} className="ml-auto p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition" aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
                {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              </button>
              <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 md:hidden" aria-label="Close sidebar">
               <X className="w-5 h-5" aria-hidden="true" />
             </button>
           </div>
           
           <nav className="p-4 space-y-2" aria-label="Dashboard tabs">
             {tabs.map((tab) => {
               const Icon = tab.icon;
               const isActive = activeTab === tab.id;
               return (
                 <button key={tab.id} onClick={() => { onTabChange(tab.id); onClose(); }} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${isActive ? "bg-slate-800 text-emerald-400 shadow-sm border border-emerald-500/20" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"}`} aria-current={isActive ? "page" : undefined}>
                   <Icon className="w-5 h-5" aria-hidden="true" />
                   {tab.label}
                 </button>
               );
             })}
           </nav>
        </div>

        <div className="p-4 mb-4">
           <div className="bg-slate-950 p-5 rounded-2xl border border-white/5">
             <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4" id="master-controls-heading">Master Controls</h3>
             <div role="group" aria-labelledby="master-controls-heading">
               <label className="flex items-center justify-between text-sm text-slate-300 cursor-pointer mb-4">
                 Live Mapping
                 <input type="checkbox" className="accent-emerald-500 w-4 h-4 cursor-pointer" checked={autoRefresh} onChange={e => onAutoRefreshChange(e.target.checked)}/>
               </label>
               <label className="flex flex-col gap-2 text-sm text-slate-300">
                 Log History: <span className="font-mono text-emerald-400">{historyLim} flows</span>
                 <input type="range" className="accent-emerald-500 w-full" min="500" max="5000" step="500" value={historyLim} onChange={(e) => onHistoryLimChange(Number(e.target.value))} aria-label={`Log history limit: ${historyLim} flows`}/>
               </label>
             </div>
           </div>
        </div>

        {/* Connection Status */}
        <div className="mt-auto p-4 border-t border-white/5">
          <div className="flex items-center gap-2 text-[11px]">
            <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 shadow-[0_0_6px_rgba(16,185,129,0.6)]' : 'bg-rose-400 shadow-[0_0_6px_rgba(244,63,94,0.6)]'} ${isConnected ? 'animate-pulse' : ''}`} />
            <span className={isConnected ? 'text-emerald-400' : 'text-rose-400'}>
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          {lastUpdated && (
            <p className="text-[10px] text-slate-600 mt-1 font-mono">
              Updated {lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
            </p>
          )}
        </div>
      </aside>
    </>
  );
}

function DashboardInner() {
  const { theme, toggle } = useTheme();
  const [activeTab, setActiveTab] = useState("overview");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [autoRefresh, setAutoRefresh] = useState(true);
  const [historyLim, setHistoryLim] = useState(2000);
  const [sevFilter] = useState<Alert["severity"][]>(["high", "medium", "low"]);

  const tabIDs = ["overview", "alerts", "incidents", "top_offenders", "analytics", "ml_playbook", "signatures", "settings"];

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;

      if (e.key === "r" || e.key === "R") {
        e.preventDefault();
        setAutoRefresh((v) => !v);
        return;
      }
      if (e.key === "/") {
        e.preventDefault();
        const searchInput = document.querySelector<HTMLInputElement>('[aria-label="Search alerts"]');
        if (searchInput) searchInput.focus();
        return;
      }
      const num = parseInt(e.key, 10);
      if (num >= 1 && num <= tabIDs.length) {
        setActiveTab(tabIDs[num - 1]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const { data: kpis, isValidating: kpisValidating, error: kpisError } = useSWR<KPIs>(apiUrl("/api/kpis"), fetcher, { refreshInterval: autoRefresh ? 3000 : 0 });
  const { data: alertsRaw } = useSWR<Alert[]>(apiUrl(`/api/alerts?limit=${historyLim}`), fetcher, { refreshInterval: autoRefresh ? 3000 : 0 });
  const { data: flows } = useSWR<Flow[]>(apiUrl("/api/flows?limit=1500"), fetcher, { refreshInterval: autoRefresh ? 5000 : 0 });

  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const prevKpisRef = useRef(kpis);
  useEffect(() => {
    if (kpis && kpis !== prevKpisRef.current) {
      setLastUpdated(new Date());
      prevKpisRef.current = kpis;
    }
  }, [kpis]);

  const isConnected = !kpisError && kpis !== undefined;

  const alerts = alertsRaw?.filter((a: Alert) => sevFilter.includes(a.severity)) || [];

  const tabs = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "alerts", label: "Alerts Explorer", icon: ShieldAlert },
    { id: "incidents", label: "Active Incidents", icon: Globe2 },
    { id: "top_offenders", label: "Top Offenders", icon: Crosshair },
    { id: "analytics", label: "Analytics & ML", icon: BarChart3 },
    { id: "ml_playbook", label: "ML Playbook", icon: MonitorPlay },
    { id: "signatures", label: "Signatures", icon: ShieldCheck },
    { id: "settings", label: "Settings", icon: SettingsIcon },
  ];

  if (!kpis) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-50 font-sans flex">
        <SidebarSkeleton />
        <main className="flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-4">
            <div className="w-12 h-12 border-2 border-emerald-500/30 border-t-emerald-400 rounded-full animate-spin" />
            <p className="text-slate-400 text-sm animate-pulse">Connecting to AI-NIDS engine...</p>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-emerald-500/30 flex">
      <button
        onClick={() => setSidebarOpen(true)}
        className="fixed top-4 left-4 z-50 p-2 bg-slate-900 border border-white/10 rounded-xl text-slate-300 hover:text-white md:hidden"
        aria-label="Open sidebar"
      >
        <Menu className="w-5 h-5" />
      </button>

      <Sidebar
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        historyLim={historyLim}
        onHistoryLimChange={setHistoryLim}
        sidebarOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        isConnected={isConnected}
        lastUpdated={lastUpdated}
        theme={theme}
        onThemeToggle={toggle}
      />

      <main className="flex-1 w-full max-w-7xl mx-auto md:px-8 px-4 md:pt-8 pt-16 pb-8 h-screen overflow-y-auto">
        <ErrorBoundary name="Overview tab">
          {activeTab === "overview" && <OverviewTab kpis={kpis} alerts={alerts} />}
        </ErrorBoundary>
        <ErrorBoundary name="Alerts tab">
          {activeTab === "alerts" && <AlertsTab alerts={alerts} />}
        </ErrorBoundary>
        <ErrorBoundary name="Incidents tab">
          {activeTab === "incidents" && <IncidentsTab alerts={alerts} />}
        </ErrorBoundary>
        <ErrorBoundary name="Top Offenders tab">
          {activeTab === "top_offenders" && <TopOffendersTab alerts={alerts} flows={flows} />}
        </ErrorBoundary>
        <ErrorBoundary name="Analytics tab">
          {activeTab === "analytics" && <AnalyticsTab flows={flows} />}
        </ErrorBoundary>
        <ErrorBoundary name="ML Playbook tab">
          {activeTab === "ml_playbook" && <MLPlaybookTab />}
        </ErrorBoundary>
        <ErrorBoundary name="Signatures tab">
          {activeTab === "signatures" && <SignaturesTab />}
        </ErrorBoundary>
        <ErrorBoundary name="Settings tab">
          {activeTab === "settings" && <SettingsTab />}
        </ErrorBoundary>
      </main>
      <TasksWidget />
    </div>
  );
}

export default function Dashboard() {
  return (
    <ThemeProvider>
      <DashboardInner />
    </ThemeProvider>
  );
}
