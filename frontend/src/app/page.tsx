"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import useSWR from "swr";
import { ShieldAlert, Activity, BarChart3, Settings as SettingsIcon, Globe2, MonitorPlay, ShieldCheck, Crosshair, Sun, Moon, SlidersHorizontal, ChevronDown } from "lucide-react";
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
import { NotificationPanel } from "./components/NotificationPanel";
import { ExportReport } from "./components/ExportReport";
import { BottomNavBar } from "./components/BottomNavBar";

import type { KPIs, Flow, Alert } from "./lib/types";
import { apiUrl, fetcher } from "./lib/api";

function NavbarSkeleton() {
  return (
    <div className="h-14 bg-slate-900/80 backdrop-blur-xl border-b border-white/[0.06] flex items-center px-6 gap-6 shrink-0">
      <div className="bg-slate-800 w-8 h-8 rounded-lg animate-pulse" />
      <div className="bg-slate-800 h-4 w-16 rounded animate-pulse" />
      <div className="bg-slate-800 h-4 w-16 rounded animate-pulse" />
      <div className="bg-slate-800 h-4 w-16 rounded animate-pulse" />
    </div>
  );
}

function Navbar({
  tabs,
  activeTab,
  onTabChange,
  autoRefresh,
  onAutoRefreshChange,
  historyLim,
  onHistoryLimChange,
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
  isConnected: boolean;
  lastUpdated: Date | null;
  theme: "dark" | "light";
  onThemeToggle: () => void;
}) {
  const [controlsOpen, setControlsOpen] = useState(false);
  const controlsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (controlsRef.current && !controlsRef.current.contains(e.target as Node)) {
        setControlsOpen(false);
      }
    };
    if (controlsOpen) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [controlsOpen]);

  return (
    <header className="h-14 bg-slate-900/80 backdrop-blur-xl border-b border-white/[0.06] flex items-center px-5 shrink-0 sticky top-0 z-40" role="banner">
      {/* Logo */}
      <div className="flex items-center gap-2.5 mr-6">
        <div className="relative">
          <div className="bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 p-1.5 rounded-lg border border-emerald-500/20">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
          </div>
          <span className={`absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full border-[1.5px] border-slate-900 ${isConnected ? 'bg-emerald-400' : 'bg-rose-400'}`} />
        </div>
        <span className="text-sm font-bold tracking-tight bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent hidden sm:block">AI-NIDS</span>
      </div>

      {/* Tabs */}
      <nav className="flex items-center gap-0.5 overflow-x-auto no-scrollbar" aria-label="Dashboard tabs">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[13px] font-medium whitespace-nowrap transition-all duration-150 ${
                isActive
                  ? "bg-emerald-500/10 text-emerald-400"
                  : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.04]"
              }`}
              aria-current={isActive ? "page" : undefined}
            >
              <Icon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span className="hidden md:inline">{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Right actions */}
      <div className="ml-auto flex items-center gap-1">
        {/* Connection indicator */}
        <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg mr-1">
          <span className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-emerald-400 shadow-[0_0_6px_rgba(16,185,129,0.5)]' : 'bg-rose-400 shadow-[0_0_6px_rgba(244,63,94,0.5)]'} ${isConnected ? 'animate-pulse' : ''}`} />
          <span className={`text-[10px] font-medium ${isConnected ? 'text-emerald-400/80' : 'text-rose-400/80'} hidden lg:inline`}>
            {isConnected ? 'Online' : 'Offline'}
          </span>
        </div>

        {/* Controls dropdown */}
        <div className="relative" ref={controlsRef}>
          <button
            onClick={() => setControlsOpen(!controlsOpen)}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.05] transition relative"
            aria-label="Dashboard controls"
          >
            <SlidersHorizontal className="w-4 h-4" />
          </button>
          {controlsOpen && (
            <div className="absolute right-0 top-full mt-2 w-64 bg-slate-900 border border-white/[0.08] rounded-xl shadow-2xl shadow-black/50 p-4 space-y-3 z-50">
              <h3 className="text-[10px] font-bold text-slate-500/70 uppercase tracking-[0.15em]">Controls</h3>
              <label className="flex items-center justify-between cursor-pointer group">
                <span className="text-xs text-slate-400 group-hover:text-slate-300 transition">Live Mapping</span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={autoRefresh}
                  onClick={() => onAutoRefreshChange(!autoRefresh)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${autoRefresh ? 'bg-emerald-500' : 'bg-slate-700'}`}
                >
                  <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${autoRefresh ? 'translate-x-[18px]' : 'translate-x-[2px]'}`} />
                </button>
              </label>
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">History</span>
                  <span className="text-[11px] font-mono text-emerald-400/80">{historyLim.toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  className="w-full h-1 bg-slate-800 rounded-full appearance-none cursor-pointer accent-emerald-500 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-emerald-400"
                  min="500" max="5000" step="500"
                  value={historyLim}
                  onChange={(e) => onHistoryLimChange(Number(e.target.value))}
                  aria-label={`Log history limit: ${historyLim} flows`}
                />
              </div>
              {lastUpdated && (
                <p className="text-[9px] text-slate-600 font-mono pt-1 border-t border-white/[0.04]">
                  Last update: {lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                </p>
              )}
            </div>
          )}
        </div>

        <NotificationPanel />
        <button onClick={onThemeToggle} className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.05] transition" aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>
      </div>
    </header>
  );
}

function DashboardInner() {
  const { theme, toggle } = useTheme();
  const [activeTab, setActiveTab] = useState("overview");

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

  const alerts = useMemo(
    () => alertsRaw?.filter((a: Alert) => sevFilter.includes(a.severity)) || [],
    [alertsRaw, sevFilter]
  );

  const tabs = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "alerts", label: "Alerts", icon: ShieldAlert },
    { id: "incidents", label: "Incidents", icon: Globe2 },
    { id: "top_offenders", label: "Offenders", icon: Crosshair },
    { id: "analytics", label: "Analytics", icon: BarChart3 },
    { id: "ml_playbook", label: "ML Playbook", icon: MonitorPlay },
    { id: "signatures", label: "Signatures", icon: ShieldCheck },
    { id: "settings", label: "Settings", icon: SettingsIcon },
  ];

  if (!kpis) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-50 font-sans flex flex-col">
        <NavbarSkeleton />
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
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-emerald-500/30 flex flex-col">
      <Navbar
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        autoRefresh={autoRefresh}
        onAutoRefreshChange={setAutoRefresh}
        historyLim={historyLim}
        onHistoryLimChange={setHistoryLim}
        isConnected={isConnected}
        lastUpdated={lastUpdated}
        theme={theme}
        onThemeToggle={toggle}
      />

      <main className="flex-1 w-full max-w-7xl mx-auto md:px-8 px-4 md:py-8 py-4 pb-24 lg:pb-8 overflow-y-auto">
        {/* Page Header */}
        <div className="flex items-center justify-between mb-6 lg:mb-8">
          <div className="flex items-center gap-4">
            <div className="w-1 h-8 bg-gradient-to-b from-emerald-400 to-cyan-400 rounded-full" />
            <div>
              <h2 className="text-xl font-bold text-white capitalize tracking-tight">{activeTab.replace("_", " ")}</h2>
              <p className="text-[11px] text-slate-500 mt-0.5 font-mono">{new Date().toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric" })}</p>
            </div>
          </div>
          <ExportReport />
        </div>

        <div className="animate-fade-in" key={activeTab}>
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
        </div>
      </main>
      <TasksWidget />
      <BottomNavBar activeTab={activeTab} onTabChange={setActiveTab} alertCount={alerts.filter((a: Alert) => a.severity === "high").length} />
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
