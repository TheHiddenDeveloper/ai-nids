import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import time

from api.data import (
    load_from_db, load_incidents, get_comparison_stats,
    send_firewall_command
)
from core.redis_client import get_redis_client
from monitor.db import clear_db_data
from api.jobs import start_job, get_job, list_jobs
from signatures.loader import load_rules
import yaml
import subprocess

app = FastAPI(title="AI-NIDS API", version="1.0.0")

# Enable CORS for local Next.js development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup Time Tracking
START_TIME = time.time()

# -----------------
# Pydantic Models
# -----------------
class FirewallAction(BaseModel):
    action: str  # "block" or "unblock"
    ip: str

# -----------------
# API Routing
# -----------------

@app.get("/api/kpis")
async def get_kpis():
    comp = get_comparison_stats()
    uptime_secs = time.time() - START_TIME
    
    # Calculate some basic metrics by peeking at db
    flows = load_from_db("flows", limit=1)
    alerts = load_from_db("alerts", limit=5000)
    
    total_alerts = len(alerts)
    high_count = sum(1 for a in alerts if a.get("severity") in ("high", "medium"))
    
    return {
        "uptime_seconds": uptime_secs,
        "comparison_stats": comp,
        "recent_alerts": total_alerts,
        "high_severity_count": high_count
    }

@app.get("/api/alerts")
async def get_alerts(limit: int = 2000):
    return load_from_db("alerts", limit=limit)

@app.get("/api/flows")
async def get_flows(limit: int = 5000):
    return load_from_db("flows", limit=limit)

@app.get("/api/incidents")
async def get_incidents(limit: int = 100):
    return load_incidents(limit=limit)

@app.get("/api/settings/health")
async def get_engine_health():
    redis_conn = get_redis_client()
    rf_exists = Path("data/models/nids_model.joblib").exists()
    ae_exists = Path("data/models/autoencoder.keras").exists()
    
    return {
        "redis_connected": bool(redis_conn),
        "models": {
            "random_forest": rf_exists,
            "autoencoder": ae_exists
        }
    }

@app.get("/api/settings/blocked_ips")
async def get_blocked_ips():
    redis_conn = get_redis_client()
    if not redis_conn:
        return []
    blocked = redis_conn.smembers("nids:blocked:ips")
    if not blocked: return []
    return sorted(list(blocked))

@app.post("/api/settings/firewall")
async def firewall_action(action: FirewallAction):
    if action.action not in ["block", "unblock"]:
        raise HTTPException(status_code=400, detail="Invalid action")
    success = send_firewall_command(action.action, action.ip)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send firewall command")
    return {"status": "success", "action": action.action, "ip": action.ip}

@app.post("/api/settings/wipe")
async def wipe_database():
    success = clear_db_data()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to wipe database")
    return {"status": "success"}

# -----------------
# Jobs & Background Tasks
# -----------------

@app.get("/api/jobs")
async def get_all_jobs():
    return list_jobs()

@app.get("/api/jobs/{job_id}")
async def get_single_job(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

class RetrainRequest(BaseModel):
    precision: str = "high" # "standard" or "high"

@app.post("/api/models/retrain")
async def retrain_models(req: RetrainRequest):
    python_bin = sys.executable
    cmd = [python_bin, "scripts/train.py", "--precision", req.precision]
    job_id = start_job(name=f"Model Retraining ({req.precision})", cmd=cmd)
    return {"job_id": job_id, "status": "started"}

# -----------------
# Signatures API
# -----------------

RULES_PATH = Path("signatures/rules.yaml")

@app.get("/api/signatures")
async def get_signatures():
    rules = load_rules(str(RULES_PATH))
    # Convert rules to dict
    return [
        {
            "id": r.id,
            "name": r.name,
            "severity": r.severity,
            "tags": r.tags,
            "enabled": r.enabled,
            "description": r.description
        } for r in rules
    ]

class SignatureToggle(BaseModel):
    enabled: bool

@app.post("/api/signatures/{rule_id}/toggle")
async def toggle_signature(rule_id: str, req: SignatureToggle):
    # Safe load and update
    with open(RULES_PATH) as f:
        data = yaml.safe_load(f)
    
    idx = -1
    for i, r in enumerate(data.get("rules", [])):
        if r.get("id") == rule_id:
            idx = i
            break
            
    if idx == -1:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    data["rules"][idx]["enabled"] = req.enabled
    with open(RULES_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        
    return {"status": "success", "rule_id": rule_id, "enabled": req.enabled}

# -----------------
# System Monitor Control
# -----------------

@app.post("/api/system/monitor/restart")
async def restart_monitor():
    try:
        # NOTE: This assumes the user running FastAPI has sudoers NOPASSWD for this service,
        # or the API is running as root. If it fails, it will return 500.
        subprocess.run(["sudo", "systemctl", "restart", "ai-nids-monitor.service"], check=True)
        return {"status": "success"}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to restart monitor: {str(e)}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="systemctl command not found")

# Serve the Next.js static export ONLY if it exists (for production)
out_dir = Path("frontend/out")
if out_dir.exists():
    app.mount("/", StaticFiles(directory=str(out_dir), html=True), name="frontend")
