import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';

export function AnalyticsTab({ flows }: any) {
  // Mock data for Port Vulnerability Penetration
  const portData = [
    { name: '445 (SMB)', value: 400, color: '#f43f5e' },
    { name: '22 (SSH)', value: 300, color: '#f59e0b' },
    { name: '80 (HTTP)', value: 300, color: '#10b981' },
    { name: '443 (HTTPS)', value: 200, color: '#3b82f6' },
  ];

  // Mock data for ML Probability Score Distribution
  const mlScores = [
    { range: '0.0-0.2', count: 4000 },
    { range: '0.2-0.4', count: 3000 },
    { range: '0.4-0.6', count: 1200 },
    { range: '0.6-0.8', count: 500 },
    { range: '0.8-1.0', count: 200 },
  ];

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col items-center justify-center">
           <h3 className="text-slate-300 font-medium mb-6 w-full text-left">ML Probability Score Distribution</h3>
           <ResponsiveContainer width="100%" height="100%">
             <BarChart data={mlScores}>
               <XAxis dataKey="range" stroke="#475569" fontSize={12} tickLine={false} axisLine={false} />
               <YAxis stroke="#475569" fontSize={12} tickLine={false} axisLine={false} />
               <Tooltip 
                 contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                 itemStyle={{ color: '#10b981' }}
               />
               <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]}>
                 {mlScores.map((entry, index) => (
                   <Cell key={`cell-${index}`} fill={entry.count < 1000 ? '#ef4444' : '#10b981'} />
                 ))}
               </Bar>
             </BarChart>
           </ResponsiveContainer>
        </div>

        <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-96 flex flex-col items-center justify-center">
           <h3 className="text-slate-300 font-medium mb-6 w-full text-left">Port Vulnerability Penetration</h3>
           <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={portData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
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
      </div>
    </div>
  );
}
