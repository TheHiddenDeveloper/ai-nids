export const SEVERITY_COLORS = {
  high: { bg: "bg-rose-500/10", text: "text-rose-400", border: "border-rose-500/20", dot: "bg-rose-400", hex: "#f43f5e" },
  medium: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/20", dot: "bg-amber-400", hex: "#f59e0b" },
  low: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/20", dot: "bg-blue-400", hex: "#3b82f6" },
} as const;

export const SEVERITY_HEX: Record<string, string> = {
  high: "#f43f5e",
  medium: "#f59e0b",
  low: "#3b82f6",
};

export const PORT_LABELS: Record<number, string> = {
  20: "FTP-Data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  993: "IMAPS",
  995: "POP3S",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
};

export const DETECTION_DRIVER_LABELS: Record<string, string> = {
  "Supervised Random Forest": "RF Classifier",
  "Unsupervised Autoencoder": "AE Anomaly",
};

export function getPortLabel(port: number): string {
  return PORT_LABELS[port] || `:${port}`;
}

export function getScoreColor(score: number): string {
  if (score >= 0.85) return "text-rose-400";
  if (score >= 0.65) return "text-amber-400";
  return "text-emerald-400";
}

export function getScoreBarColor(score: number): string {
  if (score >= 0.85) return "bg-rose-400";
  if (score >= 0.65) return "bg-amber-400";
  return "bg-emerald-400";
}
