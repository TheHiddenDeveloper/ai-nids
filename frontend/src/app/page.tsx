"use client";

import { useState } from "react";
import useSWR from "swr";
import {
  ShieldAlert,
  Activity,
  BarChart3,
  Settings as SettingsIcon,
  Globe2,
} from "lucide-react";
import { OverviewTab } from "./components/OverviewTab";
import { AlertsTab } from "./components/AlertsTab";
import { IncidentsTab } from "./components/IncidentsTab";
import { AnalyticsTab } from "./components/AnalyticsTab";
import { SettingsTab } from "./components/SettingsTab";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("overview");

  // Global Polling API
  const { data: kpis } = useSWR("http://localhost:8000/api/kpis", fetcher, {
    refreshInterval: 3000,
  });
  const { data: alerts } = useSWR("http://localhost:8000/api/alerts?limit=1000", fetcher, {
    refreshInterval: 3000,
  });
  const { data: flows } = useSWR("http://localhost:8000/api/flows?limit=1500", fetcher, {
    refreshInterval: 5000,
  });

  const tabs = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "alerts", label: "Alerts Explorer", icon: ShieldAlert },
    { id: "incidents", label: "Active Incidents", icon: Globe2 },
    { id: "analytics", label: "Analytics & ML", icon: BarChart3 },
    { id: "settings", label: "Settings", icon: SettingsIcon },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-emerald-500/30">
      {/* Top Navigation */}
      <header className="border-b border-white/5 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 w-full h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20">
              <ShieldAlert className="w-5 h-5 text-emerald-400" />
            </div>
            <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
              AI-NIDS Central
            </h1>
          </div>

          <nav className="flex gap-1 bg-slate-900 p-1 rounded-xl border border-white/5">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                    isActive
                      ? "bg-slate-800 text-emerald-400 shadow-sm border border-white/5"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {activeTab === "overview" && <OverviewTab kpis={kpis} flows={flows} alerts={alerts} />}
        {activeTab === "alerts" && <AlertsTab alerts={alerts} />}
        {activeTab === "incidents" && <IncidentsTab />}
        {activeTab === "analytics" && <AnalyticsTab flows={flows} />}
        {activeTab === "settings" && <SettingsTab />}
      </main>
    </div>
  );
}
