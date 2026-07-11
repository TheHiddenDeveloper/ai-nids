export interface Alert {
  _alerted_at: number;
  severity: "high" | "medium" | "low";
  _src_ip: string;
  _dst_ip: string;
  score: number;
  _src_port: number;
  _dst_port: number;
  incident_id?: string;
  explanation?: AlertExplanation;
  rf_score?: number;
  ae_score?: number;
  country?: string;
  city?: string;
  asn?: string;
  isp?: string;
  threat_level?: string;
  _src_ip_lat?: number;
  _src_ip_lon?: number;
}

export interface AlertExplanation {
  driver: string;
  features: { name: string; score: number }[];
}

export interface Flow {
  score?: number;
  _dst_port?: number;
  dst_port?: number;
}

export interface KPIs {
  comparison_stats?: { flows?: number[] };
  recent_alerts?: number;
  high_severity_count?: number;
  uptime_seconds: number;
}

export interface Job {
  job_id: string;
  name: string;
  status: "Running" | "Completed" | "Failed";
  start_time: number;
  end_time?: number;
  output: string[];
}

export interface JobMetrics {
  metrics: { epoch: number; loss: number; val_loss: number }[];
}

export interface ModelVersion {
  version: string;
  timestamp?: string;
  status: "deployed" | "available";
  hyperparameters?: {
    epochs?: number;
    batch_size?: number;
    learning_rate?: number;
    smote_ratio?: number;
    datasets?: string[];
  };
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  auc_roc?: number | null;
  attack_types?: Record<string, number>;
  data_sources?: {
    research?: string;
    live_db?: boolean;
  };
}

export interface DeploymentStatus {
  success: boolean;
  msg?: string;
}

export interface Signature {
  id: string;
  name: string;
  description?: string;
  severity: "high" | "medium" | "low";
  tags: string[];
  enabled: boolean;
}

export interface TrainingReport {
  version: string;
  overall: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    auc_roc: number | null;
    test_samples: number;
    attack_samples: number;
    benign_samples: number;
  };
  confusion_matrix: {
    labels: string[];
    matrix: number[][];
    tn: number;
    fp: number;
    fn: number;
    tp: number;
  };
  per_class: Record<string, {
    precision: number;
    recall: number;
    "f1-score": number;
    support: number;
  }>;
  per_class_accuracy?: Record<string, number>;
  attack_types?: Record<string, number>;
  datasets_used?: string[];
}

export interface DatasetInfo {
  name: string;
  label: string;
  csv_count: number;
  size_bytes: number;
  size_human: string;
  downloaded: boolean;
  has_invalid_files?: boolean;
}

export interface DatasetStats {
  downloaded: boolean;
  name: string;
  total_samples?: number;
  attack_samples?: number;
  benign_samples?: number;
  features?: string[];
  attack_types?: Record<string, number>;
  error?: string;
}
