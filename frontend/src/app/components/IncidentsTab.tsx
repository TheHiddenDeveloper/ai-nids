"use client";
import { useState } from "react";
import { Globe2, Network } from "lucide-react";
import type { Alert } from "../lib/types";
import { NetworkTopology } from "./NetworkTopology";
import { GeoMap } from "./GeoMap";

export function IncidentsTab({ alerts }: { alerts?: Alert[] }) {
  const [view, setView] = useState<"topology" | "geo">("topology");
  const alertList = alerts || [];

  return (
    <div className="space-y-4">
      {/* View Toggle */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setView("topology")}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium border transition ${
            view === "topology"
              ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
              : "bg-slate-900 border-white/5 text-slate-400 hover:text-slate-200"
          }`}
        >
          <Network className="w-4 h-4" />
          Topology
        </button>
        <button
          onClick={() => setView("geo")}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium border transition ${
            view === "geo"
              ? "bg-purple-500/10 border-purple-500/30 text-purple-400"
              : "bg-slate-900 border-white/5 text-slate-400 hover:text-slate-200"
          }`}
        >
          <Globe2 className="w-4 h-4" />
          Geo Map
        </button>
      </div>

      {view === "topology" ? (
        <NetworkTopology alerts={alertList} />
      ) : (
        <GeoMap alerts={alertList} />
      )}
    </div>
  );
}
