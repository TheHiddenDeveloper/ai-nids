"use client";

import { useState } from "react";
import useSWR from "swr";
import { Download, FileText, Loader2 } from "lucide-react";
import { apiUrl, fetcher } from "../lib/api";
import type { Alert, KPIs } from "../lib/types";

export function ExportReport() {
  const [generating, setGenerating] = useState(false);

  const { data: alerts } = useSWR<Alert[]>(apiUrl("/api/alerts?limit=500"), fetcher);
  const { data: kpis } = useSWR<KPIs>(apiUrl("/api/kpis"), fetcher);

  const generateReport = async () => {
    setGenerating(true);
    try {
      const { jsPDF } = await import("jspdf");
      const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

      const pageW = doc.internal.pageSize.getWidth();
      const margin = 16;
      let y = 20;

      // Header
      doc.setFontSize(22);
      doc.setFont("helvetica", "bold");
      doc.text("AI-NIDS Incident Report", margin, y);
      y += 8;

      doc.setFontSize(10);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(120);
      doc.text(`Generated: ${new Date().toLocaleString()}`, margin, y);
      y += 10;

      // Divider
      doc.setDrawColor(200);
      doc.setLineWidth(0.3);
      doc.line(margin, y, pageW - margin, y);
      y += 8;

      // KPI Summary
      doc.setFontSize(13);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(0);
      doc.text("Summary", margin, y);
      y += 7;

      doc.setFontSize(10);
      doc.setFont("helvetica", "normal");
      if (kpis) {
        const rows = [
          ["Total Flows", (kpis.comparison_stats?.flows?.[0] || 0).toLocaleString()],
          ["Recent Alerts", (kpis.recent_alerts || 0).toLocaleString()],
          ["High Severity", (kpis.high_severity_count || 0).toLocaleString()],
          ["Uptime", `${Math.floor(kpis.uptime_seconds / 60)} minutes`],
        ];
        for (const [label, value] of rows) {
          doc.setTextColor(80);
          doc.text(label, margin + 2, y);
          doc.setTextColor(0);
          doc.text(value, margin + 60, y);
          y += 5.5;
        }
      }
      y += 6;

      // Alerts table
      doc.setFontSize(13);
      doc.setFont("helvetica", "bold");
      doc.text("Recent Alerts", margin, y);
      y += 7;

      if (alerts && alerts.length > 0) {
        // Table header
        doc.setFontSize(8);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(80);
        const cols = ["Time", "Source IP", "Dst Port", "Signature", "Severity"];
        const colX = [margin, margin + 30, margin + 65, margin + 82, margin + 145];
        for (let i = 0; i < cols.length; i++) {
          doc.text(cols[i], colX[i], y);
        }
        y += 5;

        doc.setDrawColor(200);
        doc.setLineWidth(0.2);
        doc.line(margin, y, pageW - margin, y);
        y += 3;

        // Table rows
        doc.setFont("helvetica", "normal");
        for (const alert of alerts.slice(0, 80)) {
          if (y > 275) {
            doc.addPage();
            y = 20;
          }

          const time = new Date(alert._alerted_at * 1000).toLocaleTimeString();
          const sig = "alert";
          const sev = (alert.severity || "low").toUpperCase();

          doc.setTextColor(40);
          doc.text(time, colX[0], y);
          doc.text(alert._src_ip, colX[1], y);
          doc.text(String(alert._dst_port), colX[2], y);
          doc.text(sig, colX[3], y);

          // Severity color
          if (alert.severity === "high") doc.setTextColor(220, 50, 50);
          else if (alert.severity === "medium") doc.setTextColor(200, 150, 0);
          else doc.setTextColor(60, 160, 200);
          doc.text(sev, colX[4], y);

          y += 4.2;
        }
      } else {
        doc.setFontSize(10);
        doc.setTextColor(120);
        doc.text("No alerts recorded.", margin + 2, y);
      }

      // Footer on every page
      const totalPages = doc.getNumberOfPages();
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(160);
        doc.text(
          `AI-NIDS Report — Page ${i}/${totalPages}`,
          pageW / 2,
          doc.internal.pageSize.getHeight() - 8,
          { align: "center" }
        );
      }

      doc.save(`ai-nids-report-${Date.now()}.pdf`);
    } catch (err) {
      console.error("PDF generation failed:", err);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <button
      onClick={generateReport}
      disabled={generating || !kpis}
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold hover:bg-emerald-500/20 transition disabled:opacity-40 disabled:cursor-not-allowed"
      aria-label="Export PDF report"
    >
      {generating ? (
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
      ) : (
        <FileText className="w-3.5 h-3.5" />
      )}
      {generating ? "Generating..." : "Export PDF"}
    </button>
  );
}
