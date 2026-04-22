"use client";
import { ScatterChart, Scatter, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import useSWR from 'swr';
const fetcher = (url: string) => fetch(url).then(res => res.json());

export function IncidentsTab() {
  const { data: alerts } = useSWR("http://localhost:8000/api/alerts?limit=500", fetcher);
  
  // Transform alerts with valid lat/lon into visual data points
  const geoData = (alerts || [])
    .filter((a: any) => a._src_ip_lat && a._src_ip_lon)
    .map((a: any) => ({
      x: a._src_ip_lon,
      y: a._src_ip_lat,
      z: a.score * 100, // Z represents size of bubble
      ip: a._src_ip,
      severity: a.severity
    }));

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-[600px] flex flex-col items-center justify-center">
        <h2 className="text-xl font-bold text-white mb-2 w-full text-left">Geo-IP Correlation Matrix</h2>
        <p className="text-slate-400 mb-6 w-full text-left text-sm">Visualizing incident origins dynamically mapped against longitudinal vectors.</p>
        
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
            <XAxis type="number" dataKey="x" domain={[-180, 180]} hide />
            <YAxis type="number" dataKey="y" domain={[-90, 90]} hide />
            <Tooltip 
              cursor={{ strokeDasharray: '3 3' }}
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                     <div className="bg-slate-950 border border-white/10 p-3 rounded-lg shadow-xl">
                        <p className="font-mono text-emerald-400 text-sm mb-1">{data.ip}</p>
                        <p className="text-xs text-slate-300">Lon: {data.x.toFixed(2)} | Lat: {data.y.toFixed(2)}</p>
                        <p className="text-xs text-rose-400 mt-1 uppercase font-bold">{data.severity}</p>
                     </div>
                  );
                }
                return null;
              }}
            />
            <Scatter name="Attack Origins" data={geoData} opacity={0.6}>
              {geoData.map((entry: any, index: number) => (
                <Cell key={`cell-${index}`} fill={entry.severity === 'high' ? '#f43f5e' : entry.severity === 'medium' ? '#f59e0b' : '#3b82f6'} />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
