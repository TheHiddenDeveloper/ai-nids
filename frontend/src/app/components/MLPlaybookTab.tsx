"use client";

import { useState, useEffect, useRef, Fragment } from "react";
import useSWR, { useSWRConfig } from "swr";
import {
  Play,
  Sliders,
  Activity,
  Cpu,
  TrendingDown,
  Terminal as TerminalIcon,
  CheckCircle2,
  AlertTriangle,
  RotateCw,
  Database,
  Calendar,
  Layers,
  Sparkles,
  ChevronDown,
  ChevronUp,
  BarChart3,
  Shield
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from "recharts";

import type { Job, JobMetrics, ModelVersion } from "../lib/types";
import { apiUrl, fetcher } from "../lib/api";
import { TrainingReportPanel } from "./TrainingReportPanel";
import { DatasetSelector } from "./DatasetSelector";

export function MLPlaybookTab() {
  const { mutate } = useSWRConfig();
  const [precision, setPrecision] = useState<"standard" | "high">("high");
  const [epochs, setEpochs] = useState<number>(100);
  const [batchSize, setBatchSize] = useState<number>(128);
  const [learningRate, setLearningRate] = useState<number>(0.001);
  const [smoteRatio, setSmoteRatio] = useState<number>(1.0);
  const [selectedDatasets, setSelectedDatasets] = useState<string[]>(["cicids2017"]);
  const [expandedReport, setExpandedReport] = useState<string | null>(null);

  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const { data: versions, error: versionsError } = useSWR<ModelVersion[]>(apiUrl("/api/models/versions"), fetcher, {
    refreshInterval: 5000
  });

  const { data: jobs } = useSWR<Job[]>(apiUrl("/api/jobs"), fetcher, {
    refreshInterval: activeJobId ? 2000 : 5000
  });

  const { data: jobMetrics } = useSWR<JobMetrics>(
    activeJobId ? apiUrl(`/api/jobs/${activeJobId}/metrics`) : null,
    fetcher,
    { refreshInterval: 2000 }
  );

  const { data: activeJobDetails } = useSWR<Job>(
    activeJobId ? apiUrl(`/api/jobs/${activeJobId}`) : null,
    fetcher,
    { refreshInterval: 2000 }
  );

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [activeJobDetails?.output]);

  useEffect(() => {
    if (jobs && jobs.length > 0) {
      const runningTrainJob = jobs.find(
        (j: Job) => j.status === "Running" && j.name.includes("Model Retraining")
      );
      if (runningTrainJob) {
        setActiveJobId(runningTrainJob.job_id);
      }
    }
  }, [jobs]);

  useEffect(() => {
    if (activeJobDetails && activeJobDetails.status !== "Running") {
      if (activeJobDetails.status === "Completed") {
        mutate(apiUrl("/api/models/versions"));
      }
    }
  }, [activeJobDetails, mutate]);

  const handleStartRetraining = async () => {
    try {
      const res = await fetch(apiUrl("/api/models/retrain"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          precision,
          epochs,
          batch_size: batchSize,
          learning_rate: learningRate,
          smote_ratio: smoteRatio,
          datasets: selectedDatasets
        })
      });
      const data = await res.json();
      if (data.job_id) {
        setActiveJobId(data.job_id);
        mutate(apiUrl("/api/jobs"));
      }
    } catch {
      console.error("Retrain launch error:");
    }
  };

  const deployedModel = versions?.find((v: ModelVersion) => v.status === "deployed");

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Cpu className="w-6 h-6 text-emerald-400" />
            MLOps Control Center & Playbook
          </h2>
          <p className="text-slate-400 mt-1">Configure, trigger, monitor, and deploy bespoke anomaly detection neural network models inline.</p>
        </div>
        {deployedModel && (
          <div className="bg-slate-900 border border-white/5 px-4 py-2.5 rounded-2xl flex items-center gap-3">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
            <div>
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold block">Active Model</span>
              <span className="font-mono text-xs text-white font-semibold">{deployedModel.version}</span>
            </div>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        <div className="lg:col-span-5 bg-slate-900 border border-white/5 rounded-3xl p-6 shadow-2xl space-y-6">
          <div className="flex items-center gap-2 border-b border-white/5 pb-4">
            <Sliders className="w-5 h-5 text-emerald-400" />
            <h3 className="text-base font-bold text-white">Retraining Playbook Parameters</h3>
          </div>

          <div className="space-y-5">
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Training Density</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setPrecision("standard")}
                  disabled={!!activeJobId}
                  className={`py-3 px-4 rounded-xl text-xs font-bold border transition-all duration-200 ${
                    precision === "standard"
                      ? "bg-slate-800 border-white/20 text-white shadow-lg"
                      : "bg-slate-950 border-white/5 text-slate-500 hover:text-slate-300"
                  } ${activeJobId ? 'opacity-55 cursor-not-allowed' : ''}`}
                >
                  Standard Anomaly (Fast)
                </button>
                <button
                  type="button"
                  onClick={() => setPrecision("high")}
                  disabled={!!activeJobId}
                  className={`py-3 px-4 rounded-xl text-xs font-bold border transition-all duration-200 ${
                    precision === "high"
                      ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.1)]"
                      : "bg-slate-950 border-white/5 text-slate-500 hover:text-slate-300"
                  } ${activeJobId ? 'opacity-55 cursor-not-allowed' : ''}`}
                >
                  High Precision (Deep)
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between text-xs font-bold text-slate-400 uppercase tracking-wider">
                <span>Dataset Balancing (SMOTE)</span>
                <span className="font-mono text-emerald-400">{smoteRatio.toFixed(1)}x</span>
              </div>
              <input
                type="range"
                min="0.2"
                max="2.0"
                step="0.2"
                value={smoteRatio}
                disabled={!!activeJobId}
                onChange={(e) => setSmoteRatio(parseFloat(e.target.value))}
                className="w-full accent-emerald-500 disabled:opacity-40 cursor-pointer"
              />
              <p className="text-[10px] text-slate-500 leading-normal">Determines synthetic generation density for anomaly under-samples in the training corpus.</p>
            </div>

            <DatasetSelector
              selected={selectedDatasets}
              onChange={setSelectedDatasets}
              disabled={!!activeJobId}
            />

            <div className="space-y-2">
              <div className="flex justify-between text-xs font-bold text-slate-400 uppercase tracking-wider">
                <span>Training Epochs</span>
                <span className="font-mono text-emerald-400">{epochs}</span>
              </div>
              <input
                type="range"
                min="10"
                max="300"
                step="10"
                value={epochs}
                disabled={!!activeJobId}
                onChange={(e) => setEpochs(parseInt(e.target.value))}
                className="w-full accent-emerald-500 disabled:opacity-40 cursor-pointer"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Batch Size</label>
                <select
                  value={batchSize}
                  disabled={!!activeJobId}
                  onChange={(e) => setBatchSize(parseInt(e.target.value))}
                  className="w-full bg-slate-950 border border-white/5 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50 disabled:opacity-55 cursor-pointer"
                >
                  <option value={32}>32</option>
                  <option value={64}>64</option>
                  <option value={128}>128</option>
                  <option value={256}>256</option>
                  <option value={512}>512</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Learning Rate</label>
                <select
                  value={learningRate}
                  disabled={!!activeJobId}
                  onChange={(e) => setLearningRate(parseFloat(e.target.value))}
                  className="w-full bg-slate-950 border border-white/5 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50 disabled:opacity-55 cursor-pointer"
                >
                  <option value={0.01}>0.01 (Aggressive)</option>
                  <option value={0.005}>0.005</option>
                  <option value={0.001}>0.001 (Recommended)</option>
                  <option value={0.0005}>0.0005</option>
                  <option value={0.0001}>0.0001 (Conservative)</option>
                </select>
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={handleStartRetraining}
            disabled={!!activeJobId}
            className="w-full bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 font-bold py-3.5 rounded-2xl transition duration-200 flex items-center justify-center gap-2 shadow-[0_4px_20px_rgba(16,185,129,0.2)] disabled:shadow-none"
          >
            {activeJobId ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin" />
                Retraining Cycle Running...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                Initiate Model Retraining
              </>
            )}
          </button>
        </div>

        <div className="lg:col-span-7 bg-slate-900 border border-white/5 rounded-3xl p-6 shadow-2xl flex flex-col justify-between min-h-[480px]">
          <div className="flex items-center justify-between border-b border-white/5 pb-4">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400 animate-pulse" />
              <h3 className="text-base font-bold text-white">Live Training Diagnostics</h3>
            </div>
            {activeJobDetails && (
              <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                activeJobDetails.status === "Running" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse" :
                activeJobDetails.status === "Completed" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                "bg-rose-500/10 text-rose-400 border border-rose-500/20"
              }`}>
                {activeJobDetails.status}
              </span>
            )}
          </div>

          {activeJobId ? (
            <div className="flex-1 flex flex-col justify-between mt-4 space-y-4">

              <div className="bg-slate-950 p-4 rounded-2xl border border-white/5 h-56 relative overflow-hidden">
                <div className="absolute top-3 left-4 flex items-center gap-1.5 text-[10px] text-slate-500 font-bold uppercase tracking-wider">
                  <TrendingDown className="w-3.5 h-3.5 text-rose-400" />
                  Real-time Neural Loss Curve
                </div>

                {jobMetrics?.metrics && jobMetrics.metrics.length > 0 ? (
                  <div className="w-full h-full pt-4">
                    <ResponsiveContainer width="100%" height="90%">
                      <LineChart data={jobMetrics.metrics}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                        <XAxis dataKey="epoch" stroke="#475569" fontSize={9} tickLine={false} />
                        <YAxis stroke="#475569" fontSize={9} tickLine={false} domain={['auto', 'auto']} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                          itemStyle={{ fontSize: '11px' }}
                        />
                        <Legend wrapperStyle={{ fontSize: '10px', paddingTop: '5px' }} />
                        <Line type="monotone" dataKey="loss" name="Training Loss" stroke="#f43f5e" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="val_loss" name="Validation Loss" stroke="#3b82f6" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="w-full h-full flex flex-col items-center justify-center text-slate-500 gap-2">
                    <RotateCw className="w-6 h-6 animate-spin text-emerald-500/40" />
                    <p className="text-xs">Preparing epoch logs...</p>
                  </div>
                )}
              </div>

              <div className="bg-slate-950 p-4 rounded-2xl border border-white/5 flex-1 flex flex-col overflow-hidden h-44 font-mono">
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider pb-2 border-b border-white/5 mb-2 flex items-center gap-1.5">
                  <TerminalIcon className="w-3.5 h-3.5 text-emerald-400" />
                  Neural Network Output Terminal
                </div>
                <div className="flex-1 overflow-y-auto space-y-1 text-slate-400 text-[10px] leading-relaxed pr-2 scrollbar-thin scrollbar-thumb-slate-800">
                  {activeJobDetails?.output && activeJobDetails.output.length > 0 ? (
                    activeJobDetails.output.map((line: string, lIdx: number) => (
                      <div key={`line-${lIdx}`} className="whitespace-pre-wrap font-mono">
                        {line.includes("[METRIC]") ? (
                          <span className="text-emerald-400 font-bold">{line}</span>
                        ) : line.includes("Error") || line.includes("FAILED") ? (
                          <span className="text-rose-400 font-bold">{line}</span>
                        ) : (
                          <span>{line}</span>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="text-slate-600 italic">No output logged yet. Waiting for subprocess stream...</div>
                  )}
                  <div ref={terminalEndRef} />
                </div>
              </div>

            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-500 text-center gap-3 p-8">
              <div className="bg-slate-950 p-5 rounded-full border border-white/5 shadow-inner">
                <Activity className="w-8 h-8 text-slate-700" />
              </div>
              <div>
                <h4 className="text-white font-semibold text-sm">System Idle</h4>
                <p className="text-xs text-slate-400 mt-1 max-w-sm">No active retraining cycles currently running. Configure hyperparameter payloads on the left and trigger a manual training epoch loop.</p>
              </div>
            </div>
          )}

        </div>
      </div>

      <div className="bg-slate-900 border border-white/5 rounded-3xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-white/5 bg-slate-900/50 flex justify-between items-center">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Database className="w-5 h-5 text-emerald-400" />
              Model Architecture Registry
            </h3>
            <p className="text-xs text-slate-400 mt-1">Audit historic training logs, metric metrics (F1, Accuracy, Precision, Recall), and seamlessly toggle back active checkpoints.</p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 border-collapse">
            <thead className="uppercase bg-slate-950/70 text-slate-400 border-b border-white/5 font-semibold tracking-wider">
              <tr>
                <th className="px-6 py-4">Version</th>
                <th className="px-6 py-4">Retrained At</th>
                <th className="px-6 py-4">Hyperparameters</th>
                <th className="px-6 py-4">Accuracy</th>
                <th className="px-6 py-4">Precision</th>
                <th className="px-6 py-4">Recall</th>
                <th className="px-6 py-4">F1 Score</th>
                <th className="px-6 py-4">Report</th>
                <th className="px-6 py-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {versions && versions.length > 0 ? (
                versions.map((ver: ModelVersion) => {
                  const isCurrent = ver.status === "deployed";
                  const params = ver.hyperparameters || {};
                  const isReportExpanded = expandedReport === ver.version;

                  return (
                    <Fragment key={ver.version}>
                    <tr className={`hover:bg-slate-800/30 transition-all ${isCurrent ? 'bg-emerald-500/[0.02]' : ''}`}>
                      <td className="px-6 py-4 font-mono font-bold text-white flex items-center gap-2">
                        <Layers className="w-3.5 h-3.5 text-cyan-400" />
                        {ver.version}
                      </td>
                      <td className="px-6 py-4 text-slate-400 font-medium">
                        <span className="flex items-center gap-1.5">
                          <Calendar className="w-3.5 h-3.5" />
                          {ver.timestamp ? new Date(ver.timestamp).toLocaleString() : "N/A"}
                        </span>
                      </td>
                      <td className="px-6 py-4 font-mono text-[10px] text-slate-400 max-w-[200px]">
                        <div className="truncate">
                          e:{params.epochs || 100} | b:{params.batch_size || 128} | lr:{params.learning_rate || 0.001}
                        </div>
                        {params.datasets && params.datasets.length > 0 && (
                          <div className="text-[9px] text-slate-600 mt-0.5 flex items-center gap-1">
                            <Database className="w-2.5 h-2.5" />
                            {params.datasets.join(" + ")}
                          </div>
                        )}
                        {ver.attack_types && Object.keys(ver.attack_types).length > 0 && (
                          <div className="text-[9px] text-slate-600 mt-0.5 flex items-center gap-1">
                            <Shield className="w-2.5 h-2.5" />
                            {Object.keys(ver.attack_types).length} attack types
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 font-mono font-semibold text-slate-300">
                        {ver.accuracy ? (ver.accuracy * 100).toFixed(1) + "%" : "N/A"}
                      </td>
                      <td className="px-6 py-4 font-mono font-semibold text-sky-400">
                        {ver.precision ? (ver.precision * 100).toFixed(1) + "%" : "N/A"}
                      </td>
                      <td className="px-6 py-4 font-mono font-semibold text-fuchsia-400">
                        {ver.recall ? (ver.recall * 100).toFixed(1) + "%" : "N/A"}
                      </td>
                      <td className="px-6 py-4 font-mono font-semibold text-emerald-400">
                        {ver.f1_score ? (ver.f1_score * 100).toFixed(1) + "%" : "N/A"}
                      </td>
                      <td className="px-6 py-4">
                        <button
                          type="button"
                          onClick={() => setExpandedReport(isReportExpanded ? null : ver.version)}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-[10px] font-bold transition ${
                            isReportExpanded
                              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                              : "bg-slate-900 border-white/5 text-slate-500 hover:text-slate-300 hover:border-white/10"
                          }`}
                        >
                          <BarChart3 className="w-3 h-3" />
                          {isReportExpanded ? (
                            <ChevronUp className="w-3 h-3" />
                          ) : (
                            <ChevronDown className="w-3 h-3" />
                          )}
                        </button>
                      </td>
                      <td className="px-6 py-4 text-right">
                        {isCurrent ? (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Active
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-600 font-medium">
                            Archived
                          </span>
                        )}
                      </td>
                    </tr>
                    {isReportExpanded && (
                      <tr>
                        <td colSpan={9} className="px-6 py-3 bg-slate-950/30">
                          <TrainingReportPanel version={ver.version} />
                        </td>
                      </tr>
                    )}
                    </Fragment>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={9} className="px-6 py-8 text-center text-slate-500 italic">
                    {versionsError ? "Failed to load model versions registry." : "No model versions registered. Trigger your first retraining cycle above!"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
