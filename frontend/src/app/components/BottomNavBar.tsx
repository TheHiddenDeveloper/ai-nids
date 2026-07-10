"use client";

import {
  LayoutDashboard,
  AlertTriangle,
  Activity,
  Globe,
  Shield,
  FileText,
  Settings,
  Bell,
} from "lucide-react";

interface Props {
  activeTab: string;
  onTabChange: (tab: string) => void;
  alertCount: number;
}

const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "alerts", label: "Alerts", icon: AlertTriangle },
  { id: "topology", label: "Topology", icon: Activity },
  { id: "signatures", label: "Rules", icon: Shield },
  { id: "models", label: "Models", icon: FileText },
  { id: "settings", label: "Settings", icon: Settings },
];

export function BottomNavBar({ activeTab, onTabChange, alertCount }: Props) {
  return (
    <nav className="fixed bottom-0 left-0 right-0 z-40 bg-slate-950/95 backdrop-blur-md border-t border-white/5 lg:hidden safe-area-bottom" role="navigation" aria-label="Mobile navigation">
      <div className="flex items-center justify-around px-2 py-1.5">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`flex flex-col items-center gap-0.5 py-1 px-2 rounded-lg transition relative ${
                isActive ? "text-emerald-400" : "text-slate-500"
              }`}
              aria-label={item.label}
              aria-current={isActive ? "page" : undefined}
            >
              <div className="relative">
                <Icon className="w-5 h-5" strokeWidth={isActive ? 2.2 : 1.5} />
                {item.id === "alerts" && alertCount > 0 && (
                  <span className="absolute -top-1 -right-1.5 min-w-[14px] h-3.5 flex items-center justify-center rounded-full bg-rose-500 text-white text-[8px] font-bold px-0.5">
                    {alertCount > 9 ? "9+" : alertCount}
                  </span>
                )}
              </div>
              <span className={`text-[9px] font-semibold ${isActive ? "text-emerald-400" : ""}`}>
                {item.label}
              </span>
              {isActive && (
                <div className="absolute -bottom-1.5 w-4 h-0.5 rounded-full bg-emerald-400" />
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
