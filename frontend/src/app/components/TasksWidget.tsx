"use client";
import useSWR from "swr";
import { Terminal, CheckCircle, XCircle, Loader2 } from "lucide-react";
import { useState } from "react";
import type { Job } from "../lib/types";
import { apiUrl, fetcher } from "../lib/api";

const MAX_DISPLAYED = 8;

export function TasksWidget() {
  const { data: jobs } = useSWR<Job[]>(apiUrl("/api/jobs"), fetcher, { refreshInterval: 2000 });
  const [expandedJob, setExpandedJob] = useState<string | null>(null);

  if (!jobs || jobs.length === 0) return null;

  const activeJobs = jobs.filter((j: Job) => j.status === "Running");
  const finishedJobs = jobs.filter((j: Job) => j.status !== "Running").slice(0, 3);
  const displayJobs = [...activeJobs, ...finishedJobs].slice(0, MAX_DISPLAYED);

  if (displayJobs.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 sm:w-96 w-[calc(100vw-2rem)]" role="region" aria-label="Active jobs">
      {displayJobs.map((job: Job) => (
        <div key={job.job_id} className="bg-slate-900 border border-white/10 rounded-xl overflow-hidden shadow-2xl">
          <button
            className="w-full p-4 flex items-center justify-between hover:bg-slate-800/50 transition-colors text-left"
            onClick={() => setExpandedJob(expandedJob === job.job_id ? null : job.job_id)}
            aria-expanded={expandedJob === job.job_id}
            aria-controls={`job-output-${job.job_id}`}
          >
            <div className="flex items-center gap-3">
              {job.status === "Running" && <Loader2 className="w-5 h-5 text-emerald-400 animate-spin" aria-hidden="true" />}
              {job.status === "Completed" && <CheckCircle className="w-5 h-5 text-emerald-500" aria-hidden="true" />}
              {job.status === "Failed" && <XCircle className="w-5 h-5 text-red-500" aria-hidden="true" />}
              <div>
                <h4 className="text-sm font-semibold text-slate-200">{job.name}</h4>
                <p className="text-xs text-slate-400">{job.status}</p>
              </div>
            </div>
            <Terminal className="w-4 h-4 text-slate-500" aria-hidden="true" />
          </button>

          {expandedJob === job.job_id && job.output && job.output.length > 0 && (
            <div id={`job-output-${job.job_id}`} className="bg-slate-950 p-4 border-t border-white/5 max-h-48 overflow-y-auto">
              <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap break-all">
                {job.output.slice(-30).join("\n")}
              </pre>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
