"use client";

import { useState, useEffect, useRef } from "react";
import useSWR from "swr";
import { Terminal, RefreshCw, ArrowDown, Search } from "lucide-react";
import { apiUrl, fetcher } from "../lib/api";

interface LogResponse {
  lines: string[];
  total: number;
}

const LOG_COLORS: Record<string, string> = {
  ERROR: "text-rose-400",
  WARNING: "text-amber-400",
  INFO: "text-emerald-400",
  ALERT: "text-fuchsia-400",
  DEBUG: "text-slate-500",
};

function colorize(line: string): { text: string; className: string } {
  const upper = line.toUpperCase();
  for (const [level, cls] of Object.entries(LOG_COLORS)) {
    if (upper.includes(`[${level}]`) || upper.includes(` ${level} `)) {
      return { text: line, className: cls };
    }
  }
  if (upper.includes("ERROR") || upper.includes("FAIL")) {
    return { text: line, className: "text-rose-400" };
  }
  if (upper.includes("WARN")) {
    return { text: line, className: "text-amber-400" };
  }
  return { text: line, className: "text-slate-400" };
}

export function LogsViewer() {
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState("");
  const [lineCount, setLineCount] = useState(200);
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data, isValidating } = useSWR<LogResponse>(
    apiUrl(`/api/system/logs?lines=${lineCount}`),
    fetcher,
    { refreshInterval: 2000 }
  );

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [data, autoScroll]);

  const filteredLines = data?.lines?.filter((l) => {
    if (!filter) return true;
    return l.toLowerCase().includes(filter.toLowerCase());
  }) || [];

  return (
    <div className="bg-slate-900 border border-white/5 rounded-2xl overflow-hidden flex flex-col" style={{ height: 480 }}>
      {/* Header */}
      <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between bg-slate-950/50">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-bold text-white">System Logs</h3>
          {data && (
            <span className="text-[10px] text-slate-500 font-mono">
              {filteredLines.length}/{data.total} lines
            </span>
          )}
          {isValidating && (
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Filter..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="pl-7 pr-2 py-1 bg-slate-950/60 border border-white/5 rounded text-[11px] text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/40 w-32"
              aria-label="Filter log lines"
            />
          </div>
          {/* Line count */}
          <select
            value={lineCount}
            onChange={(e) => setLineCount(Number(e.target.value))}
            className="bg-slate-950/60 border border-white/5 rounded text-[11px] text-slate-400 px-1.5 py-1 focus:outline-none"
            aria-label="Number of log lines"
          >
            <option value={100}>100</option>
            <option value={200}>200</option>
            <option value={500}>500</option>
            <option value={1000}>1000</option>
          </select>
          {/* Auto-scroll */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1 rounded transition ${
              autoScroll
                ? "text-emerald-400 bg-emerald-500/10"
                : "text-slate-500 hover:text-slate-300"
            }`}
            aria-label={autoScroll ? "Disable auto-scroll" : "Enable auto-scroll"}
          >
            <ArrowDown className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Log lines */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto overflow-x-hidden font-mono text-[11px] leading-relaxed p-3 space-y-0.5 bg-slate-950/30"
      >
        {filteredLines.length === 0 ? (
          <div className="text-slate-600 text-center py-8">
            {data ? "No matching log lines." : "Loading logs..."}
          </div>
        ) : (
          filteredLines.map((line, i) => {
            const { text, className } = colorize(line);
            return (
              <div key={i} className={`whitespace-pre-wrap break-all ${className}`}>
                {text}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
