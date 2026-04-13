export function OverviewTab({ kpis, flows, alerts }: any) {
  if (!kpis) return <div className="text-slate-400 p-8 text-center animate-pulse">Loading Analytics Engine...</div>;

  const MetricCard = ({ title, value, delta }: any) => (
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

  return (
    <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard title="Total Traffic" value={kpis.comparison_stats?.flows[0]?.toLocaleString() || 0} delta={12.4} />
        <MetricCard title="Total Alerts" value={kpis.recent_alerts?.toLocaleString() || 0} delta={-5.2} />
        <MetricCard title="Critical Hits" value={kpis.high_severity_count?.toLocaleString() || 0} delta={1.2} />
        <MetricCard title="Uptime" value={`${Math.floor(kpis.uptime_seconds / 60)}m`} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex items-center justify-center">
           <span className="text-slate-500 font-mono text-sm">[ Global Threat Map Placeholder — Recharts ]</span>
        </div>
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex items-center justify-center">
           <span className="text-slate-500 font-mono text-sm">[ Alert Intensity Tracker Placeholder ]</span>
        </div>
      </div>
    </div>
  );
}
