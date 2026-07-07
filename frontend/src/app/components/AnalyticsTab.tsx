"use client";

import { useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';
import type { Flow } from "../lib/types";

const BUCKETS = [
  { range: '0.0-0.2' },
  { range: '0.2-0.4' },
  { range: '0.4-0.6' },
  { range: '0.6-0.8' },
  { range: '0.8-1.0' },
];

const COLOR_PALETTE = ['#f43f5e', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6'];
const PORT_LABELS: Record<number, string> = {
  22: '22 (SSH)',
  80: '80 (HTTP)',
  443: '443 (HTTPS)',
  445: '445 (SMB)',
  8000: '8000 (API)',
  6379: '6379 (Redis)',
};

function computeMlScores(flows: Flow[] | undefined) {
  const counts = [0, 0, 0, 0, 0];
  if (flows) {
    for (const flow of flows) {
      const score = flow.score ?? 0;
      if (score < 0.2) counts[0]++;
      else if (score < 0.4) counts[1]++;
      else if (score < 0.6) counts[2]++;
      else if (score < 0.8) counts[3]++;
      else counts[4]++;
    }
  }
  return BUCKETS.map((b, i) => ({ range: b.range, count: counts[i] }));
}

function computePortData(flows: Flow[] | undefined) {
  if (!flows || flows.length === 0) return [];
  const portCounts: Record<string, number> = {};
  for (const flow of flows) {
    const port = flow._dst_port ?? flow.dst_port;
    if (port !== null && port !== undefined) {
      const key = String(port);
      portCounts[key] = (portCounts[key] || 0) + 1;
    }
  }
  return Object.entries(portCounts)
    .map(([portStr, count]) => {
      const port = parseInt(portStr, 10);
      return { name: PORT_LABELS[port] ?? `Port ${port}`, value: count };
    })
    .sort((a, b) => b.value - a.value)
    .slice(0, 4)
    .map((item, i) => ({ ...item, color: COLOR_PALETTE[i % COLOR_PALETTE.length] }));
}

export function AnalyticsTab({ flows }: { flows: Flow[] | undefined }) {
  const mlScores = useMemo(() => computeMlScores(flows), [flows]);
  const portData = useMemo(() => computePortData(flows), [flows]);
  const hasFlows = flows !== undefined && flows.length > 0;

  return (
    <div className="space-y-6">
      {flows === undefined && (
        <div className="flex items-center justify-center py-12 text-slate-500 animate-pulse">
          Loading flow telemetry...
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col relative overflow-hidden">
           <div className="flex justify-between items-center mb-4">
             <h3 className="text-slate-300 font-medium">ML Probability Score Distribution</h3>
             {hasFlows && (
               <span className="flex items-center gap-1.5 text-xs text-emerald-400">
                 <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                 Live Telemetry ({flows.length} flows)
               </span>
             )}
           </div>
           <div className="flex-1">
             {flows === undefined ? (
               <div className="h-full flex items-center justify-center text-slate-600 text-sm">Loading...</div>
             ) : !hasFlows ? (
               <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                 No flow data available yet.
               </div>
             ) : (
               <ResponsiveContainer width="100%" height="100%">
                 <BarChart data={mlScores}>
                   <XAxis dataKey="range" stroke="#475569" fontSize={11} tickLine={false} axisLine={false} />
                   <YAxis stroke="#475569" fontSize={11} tickLine={false} axisLine={false} />
                   <Tooltip
                     contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                     itemStyle={{ color: '#10b981' }}
                   />
                   <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]}>
                     {mlScores.map((entry, index) => (
                       <Cell key={`ml-bar-${index}`} fill={index >= 2 ? '#f43f5e' : '#10b981'} />
                     ))}
                   </Bar>
                 </BarChart>
               </ResponsiveContainer>
             )}
           </div>
        </div>

        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col relative overflow-hidden">
           <div className="flex justify-between items-center mb-4">
             <h3 className="text-slate-300 font-medium">Port Vulnerability Penetration</h3>
             {hasFlows && (
               <span className="text-xs text-slate-400 font-mono">Top 4 Active Ports</span>
             )}
           </div>
           <div className="flex-1 flex items-center justify-center">
             {flows === undefined ? (
               <div className="text-slate-600 text-sm">Loading...</div>
             ) : !hasFlows || portData.length === 0 ? (
               <div className="text-slate-500 text-sm">No port data available yet.</div>
             ) : (
               <div className="w-full h-full flex items-center justify-center gap-8">
                 <div className="w-1/2 h-full">
                   <ResponsiveContainer width="100%" height="90%">
                     <PieChart>
                       <Pie
                         data={portData}
                         cx="50%"
                         cy="50%"
                         innerRadius={50}
                         outerRadius={80}
                         paddingAngle={5}
                         dataKey="value"
                       >
                         {portData.map((entry, i) => (
                           <Cell key={`port-pie-${i}`} fill={entry.color} stroke="rgba(0,0,0,0)" />
                         ))}
                       </Pie>
                       <Tooltip
                         contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                         itemStyle={{ color: '#f8fafc' }}
                       />
                     </PieChart>
                   </ResponsiveContainer>
                 </div>
                 <div className="w-1/2 flex flex-col gap-3">
                   {portData.map((entry) => (
                     <div key={entry.name} className="flex items-center justify-between text-xs border-b border-white/5 pb-1">
                       <div className="flex items-center gap-2">
                         <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
                         <span className="text-slate-300 font-medium">{entry.name}</span>
                       </div>
                       <span className="font-mono text-slate-400 font-semibold">{entry.value}</span>
                     </div>
                   ))}
                 </div>
               </div>
             )}
           </div>
        </div>
      </div>
    </div>
  );
}
