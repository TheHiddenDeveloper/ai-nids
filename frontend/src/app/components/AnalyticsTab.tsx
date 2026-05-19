import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export function AnalyticsTab({ flows: initialFlows }: any) {
  const { data: flows } = useSWR("http://localhost:8000/api/flows?limit=1500", fetcher, {
    fallbackData: initialFlows,
    refreshInterval: 3000
  });

  // 1. Calculate ML Probability Score Distribution dynamically from flows
  const mlScores = [
    { range: '0.0-0.2', count: 0 },
    { range: '0.2-0.4', count: 0 },
    { range: '0.4-0.6', count: 0 },
    { range: '0.6-0.8', count: 0 },
    { range: '0.8-1.0', count: 0 },
  ];

  if (flows && flows.length > 0) {
    flows.forEach((flow: any) => {
      const score = flow.score ?? 0;
      if (score >= 0.0 && score < 0.2) mlScores[0].count++;
      else if (score >= 0.2 && score < 0.4) mlScores[1].count++;
      else if (score >= 0.4 && score < 0.6) mlScores[2].count++;
      else if (score >= 0.6 && score < 0.8) mlScores[3].count++;
      else if (score >= 0.8 && score <= 1.0) mlScores[4].count++;
    });
  } else {
    // Elegant fallback mock data when no flows exist yet
    mlScores[0].count = 4000;
    mlScores[1].count = 1200;
    mlScores[2].count = 300;
    mlScores[3].count = 150;
    mlScores[4].count = 50;
  }

  // 2. Tally Destination Ports dynamically from flows
  const portCounts: { [key: string]: number } = {};
  if (flows && flows.length > 0) {
    flows.forEach((flow: any) => {
      const port = flow._dst_port ?? flow.dst_port;
      if (port !== undefined && port !== null) {
        portCounts[port] = (portCounts[port] || 0) + 1;
      }
    });
  }

  const colorPalette = ['#f43f5e', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6'];
  const portLabels: { [key: number]: string } = {
    22: '22 (SSH)',
    80: '80 (HTTP)',
    443: '443 (HTTPS)',
    445: '445 (SMB)',
    8000: '8000 (API)',
    6379: '6379 (Redis)',
  };

  let portData = Object.entries(portCounts)
    .map(([portStr, count]) => {
      const port = parseInt(portStr, 10);
      return {
        name: portLabels[port] ?? `Port ${port}`,
        value: count,
      };
    })
    .sort((a, b) => b.value - a.value)
    .slice(0, 4)
    .map((item, index) => ({
      ...item,
      color: colorPalette[index % colorPalette.length],
    }));

  if (portData.length === 0) {
    // Elegant fallback mock data when no flows exist yet
    portData = [
      { name: '445 (SMB)', value: 400, color: '#f43f5e' },
      { name: '22 (SSH)', value: 300, color: '#f59e0b' },
      { name: '80 (HTTP)', value: 300, color: '#10b981' },
      { name: '443 (HTTPS)', value: 200, color: '#3b82f6' },
    ];
  }

  const hasRealData = flows && flows.length > 0;

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 space-y-6">
      {!hasRealData && (
        <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 px-4 py-3 rounded-xl text-sm flex items-center justify-between">
          <span>📊 Showing historical benchmark data. Start live traffic capture to view real-time dynamic charts.</span>
          <span className="text-xs bg-emerald-500/20 px-2 py-0.5 rounded font-medium">Demo Mode</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col items-center justify-center relative overflow-hidden">
           <div className="absolute top-6 left-6 right-6 flex justify-between items-center">
             <h3 className="text-slate-300 font-medium">ML Probability Score Distribution</h3>
             {hasRealData && (
               <span className="flex items-center gap-1.5 text-xs text-emerald-400">
                 <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                 Live Telemetry ({flows.length} flows)
               </span>
             )}
           </div>
           <div className="w-full h-full mt-8">
             <ResponsiveContainer width="100%" height="80%">
               <BarChart data={mlScores}>
                 <XAxis dataKey="range" stroke="#475569" fontSize={11} tickLine={false} axisLine={false} />
                 <YAxis stroke="#475569" fontSize={11} tickLine={false} axisLine={false} />
                 <Tooltip 
                   contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                   itemStyle={{ color: '#10b981' }}
                 />
                 <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]}>
                   {mlScores.map((entry, index) => (
                     <Cell key={`cell-${index}`} fill={index >= 2 ? '#f43f5e' : '#10b981'} />
                   ))}
                 </Bar>
               </BarChart>
             </ResponsiveContainer>
           </div>
        </div>

        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col items-center justify-center relative overflow-hidden">
           <div className="absolute top-6 left-6 right-6 flex justify-between items-center">
             <h3 className="text-slate-300 font-medium">Port Vulnerability Penetration</h3>
             {hasRealData && (
               <span className="text-xs text-slate-400 font-mono">
                 Top 4 Active Ports
               </span>
             )}
           </div>
           <div className="w-full h-full mt-8 flex items-center justify-center gap-8">
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
                     {portData.map((entry, index) => (
                       <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0)" />
                     ))}
                   </Pie>
                   <Tooltip 
                     contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                     itemStyle={{ color: '#f8fafc' }}
                   />
                 </PieChart>
               </ResponsiveContainer>
             </div>
             
             {/* Dynamic Legends */}
             <div className="w-1/2 flex flex-col gap-3">
               {portData.map((entry, index) => (
                 <div key={index} className="flex items-center justify-between text-xs border-b border-white/5 pb-1">
                   <div className="flex items-center gap-2">
                     <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: entry.color }}></span>
                     <span className="text-slate-300 font-medium">{entry.name}</span>
                   </div>
                   <span className="font-mono text-slate-400 font-semibold">{entry.value}</span>
                 </div>
               ))}
             </div>
           </div>
        </div>
      </div>
    </div>
  );
}
