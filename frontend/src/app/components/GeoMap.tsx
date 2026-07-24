"use client";

import { useMemo, useState, useEffect, useRef } from "react";
import { Globe2, Info } from "lucide-react";
import type { Alert } from "../lib/types";
import { IPDrilldownModal } from "./IPDrilldownModal";

const SEVERITY_COLOR: Record<string, string> = {
  high: "#f43f5e",
  medium: "#f59e0b",
  low: "#3b82f6",
};

const SEVERITY_RADIUS: Record<string, number> = {
  high: 8,
  medium: 6,
  low: 5,
};

function MapLegend() {
  return (
    <div       className="absolute bottom-4 left-4 z-[3000] bg-slate-900/90 backdrop-blur-sm border border-white/10 rounded-lg p-3 text-xs shadow-lg">
      <p className="text-slate-400 font-semibold mb-2">Severity</p>
      {Object.entries(SEVERITY_COLOR).map(([sev, color]) => (
        <div key={sev} className="flex items-center gap-2 mb-1">
          <span
            className="w-3 h-3 rounded-full"
            style={{ backgroundColor: color }}
          />
          <span className="text-slate-300 capitalize">{sev}</span>
        </div>
      ))}
    </div>
  );
}

function MapView({
  points,
  onIPClick,
}: {
  points: {
    lat: number;
    lng: number;
    count: number;
    severity: string;
    ip: string;
    city?: string;
    country?: string;
  }[];
  onIPClick: (ip: string) => void;
}) {
  const [L, setL] = useState<typeof import("leaflet") | null>(null);
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<import("leaflet").Map | null>(null);
  const markersRef = useRef<import("leaflet").CircleMarker[]>([]);
  const pointsKeyRef = useRef<string>("");

  useEffect(() => {
    import("leaflet").then((mod) => {
      setL(mod.default || mod);
    });
    if (!document.getElementById("leaflet-css")) {
      const link = document.createElement("link");
      link.id = "leaflet-css";
      link.rel = "stylesheet";
      link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
      document.head.appendChild(link);
    }
  }, []);

  useEffect(() => {
    if (!L || !mapRef.current || mapInstanceRef.current) return;

    const map = L.map(mapRef.current, {
      center: [20, 0],
      zoom: 2,
      zoomControl: false,
      attributionControl: false,
      worldCopyJump: true,
    });

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      maxZoom: 19,
    }).addTo(map);

    mapInstanceRef.current = map;

    return () => {
      map.remove();
      mapInstanceRef.current = null;
    };
  }, [L]);

  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map || !L) return;

    const newKey = points
      .map((p) => `${p.lat},${p.lng}:${p.severity}:${p.count}`)
      .join("|");
    if (newKey === pointsKeyRef.current) return;
    pointsKeyRef.current = newKey;

    for (const m of markersRef.current) {
      m.remove();
    }
    markersRef.current = [];

    for (const p of points) {
      const marker = L.circleMarker([p.lat, p.lng], {
        radius: SEVERITY_RADIUS[p.severity as keyof typeof SEVERITY_RADIUS] + Math.min(p.count, 5),
        color: SEVERITY_COLOR[p.severity],
        fillColor: SEVERITY_COLOR[p.severity],
        fillOpacity: 0.6,
        weight: 1,
      }).addTo(map);

      marker.bindTooltip(
        `<div style="font-family: system-ui, sans-serif; font-size: 11px; line-height: 1.4;">
          <span style="font-family: monospace; font-weight: bold; color: #059669;">${p.ip}</span><br/>
          <span style="color: #94a3b8;">${p.city ? p.city + ", " : ""}${p.country || "Private"}</span><br/>
          <span style="color: ${SEVERITY_COLOR[p.severity]}; text-transform: capitalize; font-weight: 600;">${p.severity}</span>
          <span style="color: #64748b;"> &middot; ${p.count} alert${p.count !== 1 ? "s" : ""}</span>
        </div>`,
        { direction: "top", offset: [0, -10], opacity: 1, className: "nids-tooltip" }
      );

      marker.on("click", () => onIPClick(p.ip));
      markersRef.current.push(marker);
    }

    if (points.length > 0) {
      const bounds = L.latLngBounds(points.map((p) => [p.lat, p.lng] as [number, number]));
      map.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 });
    }
  }, [L, points, onIPClick]);

  return (
    <div
      ref={mapRef}
      className="h-full w-full"
      style={{ background: "#0f172a" }}
    />
  );
}

export function GeoMap({ alerts }: { alerts: Alert[] }) {
  const [drilldownIP, setDrilldownIP] = useState<string | null>(null);

  const geoPoints = useMemo(
    () =>
      alerts
        .filter(
          (a): a is Alert & { _src_ip_lat: number; _src_ip_lon: number } =>
            !!(a._src_ip_lat && a._src_ip_lon)
        )
        .map((a) => ({
          lat: a._src_ip_lat,
          lng: a._src_ip_lon,
          ip: a._src_ip,
          severity: a.severity,
          score: a.score,
          city: a.city,
          country: a.country,
        })),
    [alerts]
  );

  const uniquePoints = useMemo(() => {
    const seen = new Map<
      string,
      { lat: number; lng: number; count: number; severity: string; ip: string; city?: string; country?: string }
    >();
    for (const p of geoPoints) {
      const key = `${p.lat},${p.lng}`;
      const existing = seen.get(key);
      if (existing) {
        existing.count++;
        if (p.severity === "high") existing.severity = "high";
        else if (p.severity === "medium" && existing.severity !== "high")
          existing.severity = "medium";
      } else {
        seen.set(key, { ...p, count: 1 });
      }
    }
    return Array.from(seen.values());
  }, [geoPoints]);

  if (alerts.length === 0) {
    return (
      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-[600px] flex flex-col items-center justify-center text-slate-500">
        <Globe2 className="w-10 h-10 text-slate-600 mb-2" />
        <p className="text-sm">No alert data available.</p>
      </div>
    );
  }

  if (geoPoints.length === 0) {
    return (
      <div className="bg-slate-900 border border-white/5 rounded-2xl p-6 h-[600px] flex flex-col items-center justify-center text-slate-500 gap-2">
        <Info className="w-8 h-8 text-slate-600" />
        <p className="text-sm">No geolocated incidents.</p>
        <span className="text-xs text-slate-600">
          Source IPs have no recorded coordinates.
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <Globe2 className="w-5 h-5 text-purple-400" />
          Geo-IP Attack Map
        </h2>
        <span className="text-xs text-slate-500 font-mono">
          {geoPoints.length} geolocated alerts / {uniquePoints.length} unique
          origins
        </span>
      </div>

      <div
        className="bg-slate-900 border border-white/5 rounded-2xl relative"
        style={{ height: 520 }}
      >
        <MapView points={uniquePoints} onIPClick={setDrilldownIP} />
        <MapLegend />
      </div>

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
