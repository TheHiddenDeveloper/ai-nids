"use client";
import useSWR from "swr";
const fetcher = (url: string) => fetch(url).then((res) => res.json());

export function SettingsTab() {
  const { data: health } = useSWR("http://localhost:8000/api/settings/health", fetcher);
  const { data: ips } = useSWR("http://localhost:8000/api/settings/blocked_ips", fetcher);

  const wipeSystem = async () => {
    if (!confirm("Are you sure? This deletes ALL alerts and logs!")) return;
    await fetch("http://localhost:8000/api/settings/wipe", { method: "POST" });
    alert("System Data Wiped Successfully.");
  };

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 max-w-3xl mx-auto space-y-6">
      
      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-bold text-white mb-4">Engine Health</h2>
        <div className="grid grid-cols-2 gap-4">
           <div className="bg-slate-800/50 p-4 rounded-xl border border-white/5">
              <p className="text-sm text-slate-400">Redis Cache</p>
              <p className="text-lg font-bold text-emerald-400">{health?.redis_connected ? "Connected" : "Disconnected"}</p>
           </div>
           <div className="bg-slate-800/50 p-4 rounded-xl border border-white/5">
              <p className="text-sm text-slate-400">AI Models</p>
              <p className="text-lg font-bold text-cyan-400">
                {health?.models?.random_forest ? "RF Active" : "Waiting"}
              </p>
           </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6">
        <h2 className="text-lg font-bold text-white mb-4">Managed Blocked IPs</h2>
        {ips?.length > 0 ? (
          <div className="space-y-2">
            {ips.map((ip: string) => (
              <div key={ip} className="flex justify-between items-center bg-slate-800/50 p-3 rounded-xl border border-white/5">
                 <code className="text-rose-400">{ip}</code>
                 <button className="text-sm bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded-lg text-white transition">
                   Unblock
                 </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-slate-400 text-sm">No active IP blocks across the network.</p>
        )}
      </div>

      <div className="bg-rose-950/20 border border-rose-500/20 rounded-2xl p-6">
        <h2 className="text-lg font-bold text-rose-400 mb-2">Danger Zone</h2>
        <p className="text-sm text-rose-400/70 mb-4">Destructive actions regarding system persistence.</p>
        <button onClick={wipeSystem} className="bg-rose-500 hover:bg-rose-600 text-white font-medium px-4 py-2 rounded-xl transition">
          Wipe System Data
        </button>
      </div>

    </div>
  );
}
