"use client";

import { useState } from "react";
import useSWR from "swr";
import { ShieldAlert, Activity, BarChart3, Settings as SettingsIcon, Globe2, ActivitySquare, MonitorPlay, ShieldCheck } from "lucide-react";
import { OverviewTab } from "./components/OverviewTab";
import { AlertsTab } from "./components/AlertsTab";
import { IncidentsTab } from "./components/IncidentsTab";
import { AnalyticsTab } from "./components/AnalyticsTab";
import { SettingsTab } from "./components/SettingsTab";
import { SignaturesTab } from "./components/SignaturesTab";
import { TasksWidget } from "./components/TasksWidget";
import { MLPlaybookTab } from "./components/MLPlaybookTab";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("overview");

  // Global Sidebar States
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [historyLim, setHistoryLim] = useState(2000);
  const [sevFilter, setSevFilter] = useState(["high", "medium", "low"]);

  // Global Polling API
  const { data: kpis } = useSWR("http://localhost:8000/api/kpis", fetcher, { refreshInterval: autoRefresh ? 3000 : 0 });
  const { data: alertsRaw } = useSWR(`http://localhost:8000/api/alerts?limit=${historyLim}`, fetcher, { refreshInterval: autoRefresh ? 3000 : 0 });
  const { data: flows } = useSWR("http://localhost:8000/api/flows?limit=1500", fetcher, { refreshInterval: autoRefresh ? 5000 : 0 });

  // Apply visual filtering
  const alerts = alertsRaw?.filter((a: any) => sevFilter.includes(a.severity)) || [];

  const tabs = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "alerts", label: "Alerts Explorer", icon: ShieldAlert },
    { id: "incidents", label: "Active Incidents", icon: Globe2 },
    { id: "analytics", label: "Analytics & ML", icon: BarChart3 },
    { id: "ml_playbook", label: "ML Playbook", icon: MonitorPlay },
    { id: "signatures", label: "Signatures", icon: ShieldCheck },
    { id: "settings", label: "Settings", icon: SettingsIcon },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-emerald-500/30 flex">
      {/* Dynamic Sidebar Setup */}
      <aside className="w-72 bg-slate-900 border-r border-white/5 flex flex-col justify-between sticky top-0 h-screen">
        <div>
           <div className="h-16 flex items-center px-6 border-b border-white/5 gap-3">
             <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20">
               <ShieldAlert className="w-5 h-5 text-emerald-400" />
             </div>
             <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">AI-NIDS</h1>
           </div>
           
           <nav className="p-4 space-y-2">
             {tabs.map((tab) => {
               const Icon = tab.icon;
               const isActive = activeTab === tab.id;
               return (
                 <button key={tab.id} onClick={() => setActiveTab(tab.id)} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-200 ${isActive ? "bg-slate-800 text-emerald-400 shadow-sm border border-emerald-500/20" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"}`}>
                   <Icon className="w-5 h-5" />
                   {tab.label}
                 </button>
               );
             })}
           </nav>
        </div>

        <div className="p-4 mb-4">
           <div className="bg-slate-950 p-5 rounded-2xl border border-white/5">
             <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4">Master Controls</h3>
             <label className="flex items-center justify-between text-sm text-slate-300 cursor-pointer mb-4">
               Live Mapping
               <input type="checkbox" className="accent-emerald-500 w-4 h-4 cursor-pointer" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)}/>
             </label>
             <label className="flex flex-col gap-2 text-sm text-slate-300">
               Log Log History: <span className="font-mono text-emerald-400">{historyLim} flows</span>
               <input type="range" className="accent-emerald-500 w-full" min="500" max="5000" step="500" value={historyLim} onChange={(e) => setHistoryLim(Number(e.target.value))}/>
             </label>
           </div>
        </div>
      </aside>

      {/* Main Panel Content Segment */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-8 py-8 h-screen overflow-y-auto">
        {activeTab === "overview" && <OverviewTab kpis={kpis} flows={flows} alerts={alerts} />}
        {activeTab === "alerts" && <AlertsTab alerts={alerts} />}
        {activeTab === "incidents" && <IncidentsTab />}
        {activeTab === "analytics" && <AnalyticsTab flows={flows} />}
        {activeTab === "ml_playbook" && <MLPlaybookTab />}
        {activeTab === "signatures" && <SignaturesTab />}
        {activeTab === "settings" && <SettingsTab />}
      </main>
      <TasksWidget />
    </div>
  );
}
