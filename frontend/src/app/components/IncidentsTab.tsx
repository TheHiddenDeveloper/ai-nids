"use client";
import { ScatterChart, Scatter, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { useMemo } from 'react';
import { Globe2 } from 'lucide-react';
import type { Alert } from "../lib/types";

function formatCoord(n: number) {
  return n.toFixed(1);
}

export function IncidentsTab({ alerts }: { alerts?: Alert[] }) {
  const geoData = useMemo(() => (alerts || [])
    .filter((a: Alert): a is Alert & { _src_ip_lat: number; _src_ip_lon: number } => !!(a._src_ip_lat && a._src_ip_lon))
    .map((a: Alert & { _src_ip_lat: number; _src_ip_lon: number }) => ({
      x: a._src_ip_lon,
      y: a._src_ip_lat,
      z: a.score * 100,
      ip: a._src_ip,
      severity: a.severity
    })), [alerts]);

  return (
    <div>
      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-[600px] flex flex-col">
        <h2 className="text-xl font-bold text-white mb-2 w-full text-left">Geo-IP Correlation Matrix</h2>
        <p className="text-slate-400 mb-6 w-full text-left text-sm">Visualizing incident origins dynamically mapped against longitudinal vectors.</p>
        
        {alerts === undefined ? (
          <div className="flex-1 flex items-center justify-center text-slate-500 animate-pulse">
            Loading geolocation data...
          </div>
        ) : geoData.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-500 gap-2">
            <Globe2 className="w-10 h-10 text-slate-600" />
            <p className="text-sm">No geolocated incidents available.</p>
            <span className="text-xs text-slate-600">Source IPs have no recorded latitude/longitude coordinates.</span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
              <XAxis type="number" dataKey="x" domain={[-180, 180]} tickFormatter={formatCoord} stroke="#475569" fontSize={11} tickLine={false} axisLine={false} label={{ value: 'Longitude', position: 'insideBottom', offset: -10, style: { fill: '#64748b', fontSize: 11 } }} />
              <YAxis type="number" dataKey="y" domain={[-90, 90]} tickFormatter={formatCoord} stroke="#475569" fontSize={11} tickLine={false} axisLine={false} label={{ value: 'Latitude', angle: -90, position: 'insideLeft', style: { fill: '#64748b', fontSize: 11 } }} />
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
                {geoData.map((entry, index: number) => (
                  <Cell key={`cell-${index}`} fill={entry.severity === 'high' ? '#f43f5e' : entry.severity === 'medium' ? '#f59e0b' : '#3b82f6'} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
