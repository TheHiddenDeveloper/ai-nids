"use client";

import { useMemo, useState, Fragment } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { AlertTriangle, Crosshair, Network, Lock } from "lucide-react";

import type { Alert, Flow } from "../lib/types";
import { apiUrl, fetcher } from "../lib/api";
import useSWR from "swr";
import { IPDrilldownModal } from "./IPDrilldownModal";

const BAR_COLORS = ["#f43f5e", "#f59e0b", "#10b981", "#3b82f6", "#8b5cf6", "#ec4899"];

const PORT_LABELS: Record<number, string> = {
  22: "SSH",
  80: "HTTP",
  443: "HTTPS",
  445: "SMB",
  3389: "RDP",
  8000: "API",
  6379: "Redis",
  3306: "MySQL",
  5432: "PostgreSQL",
  8080: "Alt-HTTP",
};

function aggregateTopSourceIPs(alerts: Alert[], limit = 8) {
  const counts: Record<string, { count: number; high: number; medium: number; low: number }> = {};
  for (const a of alerts) {
    if (!counts[a._src_ip]) counts[a._src_ip] = { count: 0, high: 0, medium: 0, low: 0 };
    counts[a._src_ip].count++;
    counts[a._src_ip][a.severity]++;
  }
  return Object.entries(counts)
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function aggregateTopPorts(flows: Flow[] | undefined, limit = 8) {
  if (!flows) return [];
  const counts: Record<number, number> = {};
  for (const f of flows) {
    const port = f._dst_port ?? f.dst_port;
    if (port != null) counts[port] = (counts[port] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([port, count]) => ({
      port: Number(port),
      label: PORT_LABELS[Number(port)] || `Port ${port}`,
      count,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function aggregateTopSeverityPairs(alerts: Alert[], limit = 6) {
  const counts: Record<string, { count: number; severity: string }> = {};
  for (const a of alerts) {
    const key = `${a._src_ip} -> ${a._dst_ip}`;
    if (!counts[key]) counts[key] = { count: 0, severity: a.severity };
    counts[key].count++;
  }
  return Object.entries(counts)
    .map(([pair, data]) => ({ pair, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function aggregateSeverityDistribution(alerts: Alert[]) {
  const dist = { high: 0, medium: 0, low: 0 };
  for (const a of alerts) dist[a.severity]++;
  return [
    { name: "HIGH", value: dist.high, color: "#f43f5e" },
    { name: "MEDIUM", value: dist.medium, color: "#f59e0b" },
    { name: "LOW", value: dist.low, color: "#64748b" },
  ];
}

function ChartCard({
  title,
  icon,
  children,
  count,
  countLabel,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  count?: number;
  countLabel?: string;
}) {
  return (
    <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 flex flex-col relative overflow-hidden">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-slate-300 font-medium flex items-center gap-2">
          {icon}
          {title}
        </h3>
        {count !== undefined && (
          <span className="text-xs text-slate-500 font-mono">
            {count} {countLabel || ""}
          </span>
        )}
      </div>
      <div className="flex-1 min-h-0">{children}</div>
    </div>
  );
}

export function TopOffendersTab({
  alerts,
  flows,
}: {
  alerts: Alert[];
  flows: Flow[] | undefined;
}) {
  const [drilldownIP, setDrilldownIP] = useState<string | null>(null);
  const { data: blockedIPs } = useSWR<string[]>(
    apiUrl("/api/settings/blocked_ips"),
    fetcher
  );

  const topSourceIPs = useMemo(() => aggregateTopSourceIPs(alerts), [alerts]);
  const topPorts = useMemo(() => aggregateTopPorts(flows), [flows]);
  const topPairs = useMemo(() => aggregateTopSeverityPairs(alerts), [alerts]);
  const severityDist = useMemo(() => aggregateSeverityDistribution(alerts), [alerts]);

  const totalAlerts = alerts.length;
  const totalHigh = severityDist.find((s) => s.name === "HIGH")?.value || 0;

  if (alerts.length === 0 && !flows) {
    return (
      <div className="text-slate-400 p-12 text-center animate-pulse">
        Loading offender analytics...
      {/* IP Drilldown Modal */}
      {drilldownIP && (
        <IPDrilldownModal
          ip={drilldownIP}
          alerts={alerts}
          onClose={() => setDrilldownIP(null)}
        />
      )}
    </div>
  );
}

  return (
    <div className="space-y-6">
      {/* Summary Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-4">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            Unique Sources
          </span>
          <p className="text-2xl font-bold text-white mt-1">
            {topSourceIPs.length}
          </p>
        </div>
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-4">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            High Severity
          </span>
          <p className="text-2xl font-bold text-rose-400 mt-1">
            {totalHigh.toLocaleString()}
          </p>
        </div>
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-4">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            Blocked IPs
          </span>
          <p className="text-2xl font-bold text-emerald-400 mt-1">
            {blockedIPs?.length || 0}
          </p>
        </div>
        <div className="bg-slate-900 border border-white/5 rounded-2xl p-4">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            Targeted Ports
          </span>
          <p className="text-2xl font-bold text-cyan-400 mt-1">
            {topPorts.length}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Source IPs */}
        <ChartCard
          title="Top Source IPs"
          icon={<Crosshair className="w-4 h-4 text-rose-400" />}
          count={totalAlerts}
          countLabel="total alerts"
        >
          {topSourceIPs.length === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
              No alert data yet.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={topSourceIPs}
                layout="vertical"
                margin={{ left: 0, right: 10, top: 0, bottom: 0 }}
              >
                <XAxis
                  type="number"
                  stroke="#475569"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="ip"
                  stroke="#475569"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  width={110}
                  tickFormatter={(v: string) =>
                    v.length > 16 ? v.slice(0, 14) + ".." : v
                  }
                  tick={(props: Record<string, unknown>) => {
                    const x = Number(props.x);
                    const y = Number(props.y);
                    const value = String((props.payload as { value: string })?.value ?? "");
                    return (
                      <text
                        x={x}
                        y={y}
                        dy={4}
                        textAnchor="end"
                        className="fill-cyan-400 text-[11px] font-mono cursor-pointer hover:fill-cyan-300"
                        onClick={() => setDrilldownIP(value)}
                      >
                        {value.length > 16 ? value.slice(0, 14) + ".." : value}
                      </text>
                    );
                  }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#1e293b",
                    borderRadius: "8px",
                  }}
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const d = payload[0].payload;
                    return (
                      <div className="bg-slate-900 border border-white/10 rounded-lg p-3 text-xs shadow-xl">
                        <p className="font-mono text-cyan-400 font-bold mb-1.5">
                          {d.ip}
                        </p>
                        <p className="text-slate-400">
                          Total:{" "}
                          <span className="text-white font-semibold">
                            {d.count}
                          </span>
                        </p>
                        <div className="flex gap-3 mt-1">
                          <span className="text-rose-400">
                            High: {d.high}
                          </span>
                          <span className="text-amber-400">
                            Med: {d.medium}
                          </span>
                          <span className="text-slate-400">
                            Low: {d.low}
                          </span>
                        </div>
                        {blockedIPs?.includes(d.ip) && (
                          <span className="inline-block mt-1.5 px-1.5 py-0.5 bg-emerald-500/15 border border-emerald-500/25 text-emerald-400 rounded text-[10px] font-bold">
                            BLOCKED
                          </span>
                        )}
                      </div>
                    );
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {topSourceIPs.map((entry, i) => (
                    <Cell
                      key={entry.ip}
                      fill={entry.high > 0 ? BAR_COLORS[0] : BAR_COLORS[2]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        {/* Top Targeted Ports */}
        <ChartCard
          title="Top Targeted Ports"
          icon={<Network className="w-4 h-4 text-cyan-400" />}
          count={flows?.length || 0}
          countLabel="flows"
        >
          {topPorts.length === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
              No flow data yet.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={topPorts}
                layout="vertical"
                margin={{ left: 0, right: 10, top: 0, bottom: 0 }}
              >
                <XAxis
                  type="number"
                  stroke="#475569"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  stroke="#475569"
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                  width={90}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#1e293b",
                    borderRadius: "8px",
                  }}
                  formatter={(value, _name, props) => [
                    `${Number(value).toLocaleString()} flows`,
                    `Port ${props.payload?.port ?? "?"}`,
                  ]}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {topPorts.map((_, i) => (
                    <Cell key={`port-${i}`} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        {/* Severity Distribution */}
        <ChartCard
          title="Severity Distribution"
          icon={<AlertTriangle className="w-4 h-4 text-amber-400" />}
          count={totalAlerts}
          countLabel="alerts"
        >
          {totalAlerts === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
              No alerts yet.
            </div>
          ) : (
            <div className="h-full flex flex-col justify-center gap-4">
              {severityDist.map((sev) => {
                const pct = totalAlerts > 0 ? (sev.value / totalAlerts) * 100 : 0;
                return (
                  <div key={sev.name}>
                    <div className="flex justify-between text-xs mb-1.5">
                      <span className="font-semibold" style={{ color: sev.color }}>
                        {sev.name}
                      </span>
                      <span className="text-slate-400 font-mono">
                        {sev.value.toLocaleString()} ({pct.toFixed(1)}%)
                      </span>
                    </div>
                    <div className="w-full bg-slate-950/60 rounded-full h-3 overflow-hidden border border-white/5">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${pct}%`,
                          backgroundColor: sev.color,
                          boxShadow: pct > 10 ? `0 0 10px ${sev.color}40` : undefined,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </ChartCard>

        {/* Top Attack Pairs */}
        <ChartCard
          title="Top Attack Paths"
          icon={<AlertTriangle className="w-4 h-4 text-fuchsia-400" />}
          count={topPairs.length}
          countLabel="unique paths"
        >
          {topPairs.length === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
              No attack paths yet.
            </div>
          ) : (
            <div className="h-full flex flex-col justify-center">
              <div className="grid grid-cols-[1fr_auto_1fr_auto] gap-x-3 gap-y-2.5 text-xs items-center">
                {topPairs.map((p, i) => {
                  const sevColor =
                    p.severity === "high"
                      ? "text-rose-400"
                      : p.severity === "medium"
                      ? "text-amber-400"
                      : "text-slate-400";
                  return (
                    <Fragment key={`pair-${i}`}>
                      <span
                        className="font-mono text-cyan-400 truncate cursor-pointer hover:underline"
                        title={p.pair.split(" -> ")[0]}
                        onClick={() => setDrilldownIP(p.pair.split(" -> ")[0])}
                      >
                        {p.pair.split(" -> ")[0]}
                      </span>
                      <span className="text-slate-600">
                        &rarr;
                      </span>
                      <span
                        className="font-mono text-slate-300 truncate cursor-pointer hover:underline"
                        title={p.pair.split(" -> ")[1]}
                        onClick={() => setDrilldownIP(p.pair.split(" -> ")[1])}
                      >
                        {p.pair.split(" -> ")[1]}
                      </span>
                      <span
                        className={`font-mono font-bold ${sevColor} text-right`}
                      >
                        {p.count}x
                      </span>
                    </Fragment>
                  );
                })}
              </div>
            </div>
          )}
        </ChartCard>
      </div>
    </div>
  );
}
