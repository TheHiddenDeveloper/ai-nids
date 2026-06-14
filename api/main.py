import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import os
import time
import json
import shutil
import re

from api.data import (
    load_from_db, count_rows, load_incidents, get_comparison_stats,
    send_firewall_command
)
from core.redis_client import get_redis_client
from core.config_validator import validate_config
from monitor.db import clear_db_data
from api.jobs import start_job, get_job, list_jobs
from signatures.loader import load_rules
import yaml
import subprocess

# H4 + O7: optional API key + config validation
API_KEY = None
try:
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    if not validate_config(cfg):
        import logging
        logging.warning("config.yaml validation failed — continuing with loaded values")
    API_KEY = cfg.get("api", {}).get("key") or None
except Exception:
    pass

app = FastAPI(title="AI-NIDS API", version="1.0.0")

if API_KEY:
    @app.middleware("http")
    async def api_key_middleware(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            key = request.headers.get("X-API-Key")
            if key != API_KEY:
                return Response(status_code=403, content='{"detail":"Invalid or missing API key"}', media_type="application/json")
        return await call_next(request)
    print(f"API key authentication enabled")

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
    total_alerts = count_rows("alerts")
    high_count = sum(1 for a in load_from_db("alerts", limit=5000) if a.get("severity") in ("high", "medium"))
    
    return {
        "uptime_seconds": uptime_secs,
        "comparison_stats": comp,
        "recent_alerts": total_alerts,
        "high_severity_count": high_count
    }

@app.get("/api/alerts")
async def get_alerts(limit: int = 200, offset: int = 0, response: Response = None):
    data = load_from_db("alerts", limit=limit, offset=offset)
    if response is not None:
        response.headers["X-Total-Count"] = str(count_rows("alerts"))
    return data

@app.get("/api/flows")
async def get_flows(limit: int = 200, offset: int = 0, response: Response = None):
    data = load_from_db("flows", limit=limit, offset=offset)
    if response is not None:
        response.headers["X-Total-Count"] = str(count_rows("flows"))
    return data

@app.get("/api/incidents")
async def get_incidents(limit: int = 100):
    return load_incidents(limit=limit)

@app.get("/api/settings/health")
async def get_engine_health():
    redis_conn = get_redis_client()
    models_dir = Path("data/models")
    rf_path  = models_dir / "nids_model.joblib"
    ae_path  = models_dir / "autoencoder.keras"
    rf_valid = False
    ae_valid = False

    # Model sanity check: try loading RF and making a prediction
    if rf_path.exists():
        try:
            from joblib import load as jload
            from sklearn.preprocessing import StandardScaler
            scaler_path = models_dir / "scaler.joblib"
            rf_model = jload(rf_path)
            scaler = jload(scaler_path) if scaler_path.exists() else None
            from core.features import FEATURE_COLS
            import numpy as np
            dummy = np.zeros((1, len(FEATURE_COLS)), dtype=np.float32)
            if scaler:
                dummy = scaler.transform(dummy)
            rf_model.predict(dummy)
            rf_valid = True
        except Exception as e:
            rf_valid = f"error: {e}"

    if ae_path.exists():
        try:
            from tensorflow.keras.models import load_model
            ae_model = load_model(ae_path)
            from core.features import FEATURE_COLS
            import numpy as np
            dummy = np.zeros((1, len(FEATURE_COLS)), dtype=np.float32)
            ae_model.predict(dummy, verbose=0)
            ae_valid = True
        except Exception as e:
            ae_valid = f"error: {e}"

    return {
        "redis_connected": bool(redis_conn),
        "models": {
            "random_forest": {"exists": rf_path.exists(), "healthy": rf_valid},
            "autoencoder":  {"exists": ae_path.exists(), "healthy": ae_valid},
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
    precision: str = Field(default="high", pattern="^(standard|high)$")
    epochs: int = Field(default=100, ge=1, le=1000)
    batch_size: int = Field(default=128, ge=16, le=1024)
    learning_rate: float = Field(default=0.001, gt=0, le=1.0)
    smote_ratio: float = Field(default=1.0, ge=0.0, le=10.0)

class DeployRequest(BaseModel):
    version: str

@app.post("/api/models/retrain")
async def retrain_models(req: RetrainRequest):
    venv_py = Path("ai-venv/bin/python")
    python_bin = str(venv_py) if venv_py.exists() else sys.executable
    cmd = [
        python_bin, "scripts/train.py",
        "--precision", req.precision,
        "--epochs", str(req.epochs),
        "--batch_size", str(req.batch_size),
        "--learning_rate", str(req.learning_rate),
        "--smote_ratio", str(req.smote_ratio)
    ]
    job_id = start_job(name=f"Model Retraining ({req.precision})", cmd=cmd)
    return {"job_id": job_id, "status": "started"}

@app.get("/api/models/versions")
async def get_model_versions():
    registry_path = Path("data/models/registry.json")
    if not registry_path.exists():
        return []
    try:
        with open(registry_path, "r") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read registry: {e}")

@app.post("/api/models/deploy")
async def deploy_model_version(req: DeployRequest):
    model_dir = Path("data/models")
    registry_path = model_dir / "registry.json"
    if not registry_path.exists():
        raise HTTPException(status_code=404, detail="No model registry found.")
        
    try:
        with open(registry_path, "r") as f:
            registry = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read registry: {e}")
        
    version_entry = None
    for entry in registry:
        if entry.get("version") == req.version:
            version_entry = entry
            break
            
    if not version_entry:
        raise HTTPException(status_code=404, detail=f"Version {req.version} not found in registry.")
        
    version_dir = model_dir / "versions" / req.version
    if not version_dir.exists():
        raise HTTPException(status_code=404, detail=f"Version directory {req.version} not found on disk.")
        
    artifacts = [
        "nids_model.joblib",
        "scaler.joblib",
        "autoencoder.keras",
        "ae_scaler.joblib",
        "ae_threshold.joblib"
    ]
    
    # H5: atomic copy — write to .tmp suffix, then rename (atomic on same fs)
    try:
        for art in artifacts:
            src = version_dir / art
            if not src.exists():
                continue
            tmp = model_dir / (art + ".deploy_tmp")
            shutil.copy2(src, tmp)
            os.replace(tmp, model_dir / art)
    except Exception as e:
        logger.error(f"Deploy copy failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to copy model artifacts: {e}")
        
    for entry in registry:
        if entry.get("version") == req.version:
            entry["status"] = "deployed"
        else:
            entry["status"] = "available"
            
    try:
        with open(registry_path, "w") as f:
            json.dump(registry, f, indent=2)
    except Exception as e:
        pass
        
    service_restarted = False
    try:
        subprocess.run(["sudo", "systemctl", "restart", "ai-nids-monitor.service"], check=True)
        service_restarted = True
    except Exception as e:
        pass
        
    return {
        "status": "success",
        "deployed_version": req.version,
        "service_restarted": service_restarted
    }

@app.get("/api/jobs/{job_id}/metrics")
async def get_job_metrics(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    metrics = []
    pattern = re.compile(r"\[METRIC\]\s+epoch:\s+(\d+),\s+loss:\s+([0-9.]+),\s+val_loss:\s+([0-9.]+)")
    
    for line in job.output:
        match = pattern.search(line)
        if match:
            epoch = int(match.group(1))
            loss = float(match.group(2))
            val_loss = float(match.group(3))
            metrics.append({
                "epoch": epoch,
                "loss": loss,
                "val_loss": val_loss
            })
            
    return {
        "job_id": job_id,
        "status": job.status,
        "metrics": metrics
    }

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
        subprocess.run(["sudo", "systemctl", "restart", "ai-nids-monitor.service"], check=True)
        return {"status": "success"}
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to restart monitor: {e}. Ensure the API user has NOPASSWD sudo for systemctl restart ai-nids-monitor.service"
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="systemctl command not found — is systemd installed?")

# Serve the Next.js static export ONLY if it exists (for production)
out_dir = Path("frontend/out")
if out_dir.exists():
    app.mount("/", StaticFiles(directory=str(out_dir), html=True), name="frontend")
