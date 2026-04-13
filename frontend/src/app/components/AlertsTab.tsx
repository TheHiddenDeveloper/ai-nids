export function AlertsTab({ alerts }: any) {
  if (!alerts) return <div className="text-slate-400 p-8 animate-pulse text-center">Loading Alert History...</div>;

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 bg-slate-900 border border-white/5 rounded-2xl overflow-hidden">
      <div className="p-6 border-b border-white/5 flex justify-between items-center bg-slate-900/50">
        <div>
          <h2 className="text-lg font-bold text-white">Alert Explorer</h2>
          <p className="text-sm text-slate-400 mt-1">Real-time log of security events matching active signatures or high ML thresholds.</p>
        </div>
        <button className="bg-emerald-500/10 text-emerald-400 px-4 py-2 rounded-lg font-medium text-sm hover:bg-emerald-500/20 transition">
          Export CSV
        </button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="text-xs uppercase bg-slate-950/50 text-slate-400 border-b border-white/5">
            <tr>
              <th className="px-6 py-4 font-medium tracking-wider">Timestamp</th>
              <th className="px-6 py-4 font-medium tracking-wider">Severity</th>
              <th className="px-6 py-4 font-medium tracking-wider">Source IP</th>
              <th className="px-6 py-4 font-medium tracking-wider">Target IP</th>
              <th className="px-6 py-4 font-medium tracking-wider">Confidence Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {alerts.slice(0, 15).map((alert: any, idx: number) => (
              <tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                <td className="px-6 py-4 font-mono">{new Date(alert._alerted_at * 1000).toISOString().split('T')[1].slice(0, 8)}</td>
                <td className="px-6 py-4">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
                    alert.severity === 'high' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                    alert.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                    'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                  }`}>
                    {alert.severity.toUpperCase()}
                  </span>
                </td>
                <td className="px-6 py-4 font-mono text-cyan-400">{alert._src_ip}</td>
                <td className="px-6 py-4 font-mono">{alert._dst_ip}</td>
                <td className="px-6 py-4">{(alert.score * 100).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
