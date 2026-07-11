"""
================================================================================
BACKGROUND JOBS — Async Subprocess Management
================================================================================
Purpose:
  Manages asynchronous background jobs (e.g., model retraining) via asyncio
  subprocess. Job output is captured and stored in memory for querying via
  the API.

Usage:
  job_id = start_job(name="Retrain", cmd=["python", "scripts/train.py", ...])
  job = get_job(job_id)
  all_jobs = list_jobs()

Design:
  - Jobs run via asyncio.create_subprocess_exec (non-blocking)
  - stdout and stderr are read concurrently via asyncio.gather
  - Job status: Running → Completed/Failed (based on return code)
  - Jobs stored in a module-level dict (JOBS) — in-memory, lost on restart
  - Job metrics (epoch/loss/val_loss) parsed from output via regex [METRIC] pattern
================================================================================
"""

import asyncio
import uuid
import time
from typing import Dict, List, Optional
from pydantic import BaseModel

class JobStatus(BaseModel):
    job_id: str
    name: str
    status: str  # "Running", "Completed", "Failed"
    start_time: float
    end_time: Optional[float] = None
    output: List[str]

JOBS: Dict[str, JobStatus] = {}

async def _read_stream(stream, job_id: str):
    while True:
        line = await stream.readline()
        if not line:
            break
        decoded = line.decode('utf-8', errors='replace').rstrip('\n')
        JOBS[job_id].output.append(decoded)

async def _run_subprocess(job_id: str, cmd: List[str]):
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Read stdout and stderr concurrently
        await asyncio.gather(
            _read_stream(process.stdout, job_id),
            _read_stream(process.stderr, job_id)
        )
        
        await process.wait()
        
        JOBS[job_id].end_time = time.time()
        if process.returncode == 0:
            JOBS[job_id].status = "Completed"
        else:
            JOBS[job_id].status = "Failed"
            JOBS[job_id].output.append(f"Process exited with code {process.returncode}")
            
    except Exception as e:
        JOBS[job_id].end_time = time.time()
        JOBS[job_id].status = "Failed"
        JOBS[job_id].output.append(f"Exception: {str(e)}")

def start_job(name: str, cmd: List[str]) -> str:
    job_id = str(uuid.uuid4())
    JOBS[job_id] = JobStatus(
        job_id=job_id,
        name=name,
        status="Running",
        start_time=time.time(),
        output=[]
    )
    # Start background task
    asyncio.create_task(_run_subprocess(job_id, cmd))
    return job_id

def get_job(job_id: str) -> Optional[JobStatus]:
    return JOBS.get(job_id)

def list_jobs() -> List[JobStatus]:
    # Return jobs sorted by start_time descending
    return sorted(list(JOBS.values()), key=lambda j: j.start_time, reverse=True)
