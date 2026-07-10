"use client";

import { useMemo } from "react";
import { XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import type { KPIs, Alert } from "../lib/types";
import { AlertTimeline } from "./AlertTimeline";

function MetricCard({ title, value, delta }: { title: string; value: string | number; delta?: number }) {
  return (
    <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 relative overflow-hidden group">
      <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"/>
      <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-2">{title}</h3>
      <div className="flex items-end gap-3">
        <span className="text-3xl font-bold tracking-tight text-white">{value}</span>
        {delta !== undefined && (
          <span className={`text-sm font-medium mb-1 ${delta >= 0 ? "text-emerald-400" : "text-rose-400"}`}>
            {delta > 0 ? "+" : ""}{delta.toFixed(1)}%
          </span>
        )}
      </div>
    </div>
  );
}

function buildTimeline(alerts: Alert[]): { time: string; count: number }[] {
  if (!alerts || alerts.length === 0) return [];

  const windowSize = 300;
  const buckets: Record<number, number> = {};

  for (const a of alerts) {
    const bucketStart = Math.floor(a._alerted_at / windowSize) * windowSize;
    buckets[bucketStart] = (buckets[bucketStart] || 0) + 1;
  }

  return Object.entries(buckets)
    .map(([ts, count]) => ({
      time: new Date(Number(ts) * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      count,
    }))
    .sort((a, b) => a.time.localeCompare(b.time))
    .slice(-10);
}

export function OverviewTab({ kpis, alerts }: { kpis: KPIs | undefined; alerts: Alert[] | undefined }) {
  const timelineData = useMemo(() => buildTimeline(alerts || []), [alerts]);
  const lastCount = timelineData.length > 0 ? timelineData[timelineData.length - 1].count : 0;

  const deltas = useMemo(() => {
    if (timelineData.length < 2) return { alerts: undefined };
    const last = timelineData[timelineData.length - 1].count;
    const prevAvg = timelineData.slice(0, -1).reduce((s, b) => s + b.count, 0) / (timelineData.length - 1);
    const alertsDelta = prevAvg > 0 ? ((last - prevAvg) / prevAvg) * 100 : 0;
    return { alerts: alertsDelta };
  }, [timelineData]);

  if (!kpis) return <div className="text-slate-400 p-8 text-center animate-pulse">Loading Analytics Engine...</div>;

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard title="Total Traffic" value={kpis.comparison_stats?.flows?.[0]?.toLocaleString() || 0} />
        <MetricCard title="Total Alerts" value={kpis.recent_alerts?.toLocaleString() || 0} delta={deltas.alerts} />
        <MetricCard title="Critical Hits" value={kpis.high_severity_count?.toLocaleString() || 0} />
        <MetricCard title="Uptime" value={`${Math.floor(kpis.uptime_seconds / 60)}m`} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col">
           <h3 className="text-slate-300 font-medium mb-6 w-full text-left">Alert Volume Timeline</h3>
           {timelineData.length > 0 ? (
             <ResponsiveContainer width="100%" height="100%">
               <AreaChart data={timelineData}>
                 <defs>
                   <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                     <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                     <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                   </linearGradient>
                 </defs>
                 <XAxis dataKey="time" stroke="#475569" fontSize={12} tickLine={false} axisLine={false}/>
                 <YAxis stroke="#475569" fontSize={12} tickLine={false} axisLine={false}/>
                 <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}/>
                 <Area type="monotone" dataKey="count" stroke="#10b981" strokeWidth={3} fillOpacity={1} fill="url(#colorAlerts)" />
               </AreaChart>
             </ResponsiveContainer>
           ) : (
             <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
               No alert data available for timeline.
             </div>
           )}
        </div>
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col items-center justify-center">
           <div className="w-20 h-20 bg-rose-500/10 rounded-full flex items-center justify-center mb-4 border border-rose-500/20 shadow-[0_0_50px_-12px_rgba(244,63,94,0.5)]">
             <span className="text-rose-400 font-bold text-2xl">{lastCount}</span>
           </div>
           <h3 className="text-slate-300 font-medium mb-1">Current Spike Intensity</h3>
            <p className="text-slate-500 text-sm text-center">Active anomalies registering dynamically.</p>
         </div>
      </div>

      {/* Event Timeline */}
      <AlertTimeline alerts={alerts || []} />
    </div>
  );
}
