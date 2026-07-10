"""
================================================================================
FASTAPI APPLICATION — REST API for AI-NIDS
================================================================================
Purpose:
  FastAPI backend that powers the Next.js dashboard. Provides REST endpoints
  for querying alerts, flows, incidents, model health, signatures, jobs, and
  firewall control. Serves the Next.js static export at / when available.

Endpoints:
  GET  /api/kpis                  — comparison stats + uptime
  GET  /api/alerts                — paginated alerts (limit, offset)
  GET  /api/flows                 — paginated flows
  GET  /api/incidents             — incident list
  GET  /api/settings/health       — model + Redis health check
  GET  /api/settings/blocked_ips  — currently blocked IPs
  POST /api/settings/firewall     — block/unblock IP
  POST /api/settings/wipe         — clear all data
  GET  /api/jobs                  — list background jobs
  GET  /api/jobs/{id}             — job status + output
  GET  /api/jobs/{id}/metrics     — training metrics
  POST /api/models/retrain        — trigger model retraining
  GET  /api/models/versions       — model version registry
  POST /api/models/deploy         — deploy specific version
  GET  /api/signatures            — list all rules
  POST /api/signatures/{id}/toggle — enable/disable rule
  POST /api/system/monitor/restart — restart systemd service

Design:
  - H4 + O7: optional API key auth via X-API-Key header (loaded from config.yaml)
  - OP9: rate limiting per-endpoint via slowapi (no default_limits to avoid
    throttling the static frontend)
  - Rate limits: KPIs/Alerts 100/min, Incidents 60/min, Retrain 2/min, Wipe 2/min
  - H5: atomic deploy — write .tmp suffix then os.replace (atomic on same fs)
  - Frontend served from frontend/out if exists (static export)
================================================================================
"""

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
from loguru import logger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

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

# OP9: rate limiting per-endpoint (no default_limits — would throttle static frontend)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
@limiter.limit("100/minute")
async def get_kpis(request: Request):
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
@limiter.limit("100/minute")
async def get_alerts(request: Request, limit: int = 200, offset: int = 0, response: Response = None):
    data = load_from_db("alerts", limit=limit, offset=offset)
    if response is not None:
        response.headers["X-Total-Count"] = str(count_rows("alerts"))
    return data

@app.get("/api/flows")
@limiter.limit("100/minute")
async def get_flows(request: Request, limit: int = 200, offset: int = 0, response: Response = None):
    data = load_from_db("flows", limit=limit, offset=offset)
    if response is not None:
        response.headers["X-Total-Count"] = str(count_rows("flows"))
    return data

@app.get("/api/incidents")
@limiter.limit("60/minute")
async def get_incidents(request: Request, limit: int = 100):
    return load_incidents(limit=limit)

@app.get("/api/settings/health")
@limiter.limit("30/minute")
async def get_engine_health(request: Request):
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
@limiter.limit("30/minute")
async def get_blocked_ips(request: Request):
    redis_conn = get_redis_client()
    if not redis_conn:
        return []
    blocked = redis_conn.smembers("nids:blocked:ips")
    if not blocked: return []
    return sorted(list(blocked))

@app.post("/api/settings/firewall")
@limiter.limit("10/minute")
async def firewall_action(request: Request, action: FirewallAction):
    if action.action not in ["block", "unblock"]:
        raise HTTPException(status_code=400, detail="Invalid action")
    success = send_firewall_command(action.action, action.ip)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send firewall command")
    return {"status": "success", "action": action.action, "ip": action.ip}

@app.post("/api/settings/wipe")
@limiter.limit("2/minute")
async def wipe_database(request: Request):
    success = clear_db_data()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to wipe database")
    return {"status": "success"}

# -----------------
# Jobs & Background Tasks
# -----------------

@app.get("/api/jobs")
@limiter.limit("30/minute")
async def get_all_jobs(request: Request):
    return list_jobs()

@app.get("/api/jobs/{job_id}")
@limiter.limit("30/minute")
async def get_single_job(request: Request, job_id: str):
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
    datasets: list[str] = Field(default=["cicids2017"])

class DeployRequest(BaseModel):
    version: str

@app.post("/api/models/retrain")
@limiter.limit("2/minute")
async def retrain_models(request: Request, req: RetrainRequest):
    venv_py = Path("ai-venv/bin/python")
    python_bin = str(venv_py) if venv_py.exists() else sys.executable
    cmd = [
        python_bin, "scripts/train.py",
        "--precision", req.precision,
        "--epochs", str(req.epochs),
        "--batch_size", str(req.batch_size),
        "--learning_rate", str(req.learning_rate),
        "--smote_ratio", str(req.smote_ratio),
        "--dataset", ",".join(req.datasets)
    ]
    job_id = start_job(name=f"Model Retraining ({req.precision})", cmd=cmd)
    return {"job_id": job_id, "status": "started"}

@app.get("/api/models/versions")
@limiter.limit("30/minute")
async def get_model_versions(request: Request):
    registry_path = Path("data/models/registry.json")
    if not registry_path.exists():
        return []
    try:
        with open(registry_path, "r") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read registry: {e}")

@app.post("/api/models/deploy")
@limiter.limit("5/minute")
async def deploy_model_version(request: Request, req: DeployRequest):
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

# -----------------
# Training Reports API
# -----------------

REPORTS_DIR = Path("data/models/reports")

@app.get("/api/models/reports")
@limiter.limit("30/minute")
async def list_reports(request: Request):
    if not REPORTS_DIR.exists():
        return []
    reports = []
    for d in sorted(REPORTS_DIR.iterdir(), reverse=True):
        if d.is_dir() and (d / "report.json").exists():
            try:
                with open(d / "report.json") as f:
                    reports.append(json.load(f))
            except Exception:
                continue
    return reports

@app.get("/api/models/reports/{version}")
@limiter.limit("30/minute")
async def get_report(request: Request, version: str):
    report_file = REPORTS_DIR / version / "report.json"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Report for {version} not found")
    try:
        with open(report_file) as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read report: {e}")

@app.get("/api/models/reports/{version}/images/{name}")
@limiter.limit("30/minute")
async def get_report_image(request: Request, version: str, name: str):
    allowed = {"confusion_matrix.png", "roc_curve.png"}
    if name not in allowed:
        raise HTTPException(status_code=400, detail="Invalid image name")
    img = REPORTS_DIR / version / name
    if not img.exists():
        raise HTTPException(status_code=404, detail=f"Image {name} not found for {version}")
    return Response(content=img.read_bytes(), media_type="image/png")

# -----------------
# Dataset Info API
# -----------------

DATASETS_DIR = Path("data/raw")

@app.get("/api/datasets")
@limiter.limit("30/minute")
async def list_datasets(request: Request):
    available = []
    for name in ("cicids2017", "ciciot2023"):
        ds_dir = DATASETS_DIR / name
        csv_files = list(ds_dir.glob("*.csv")) if ds_dir.exists() else []
        total_bytes = sum(f.stat().st_size for f in csv_files)
        available.append({
            "name": name,
            "label": "CICIDS2017" if name == "cicids2017" else "CICIoT2023",
            "csv_count": len(csv_files),
            "size_bytes": total_bytes,
            "size_human": f"{total_bytes / (1024**2):.1f} MB" if total_bytes else "0 MB",
            "downloaded": len(csv_files) > 0,
        })
    return available

@app.get("/api/datasets/{name}/stats")
@limiter.limit("10/minute")
async def get_dataset_stats(request: Request, name: str):
    if name not in ("cicids2017", "ciciot2023"):
        raise HTTPException(status_code=400, detail="Unknown dataset")
    ds_dir = DATASETS_DIR / name
    if not ds_dir.exists() or not list(ds_dir.glob("*.csv")):
        return {"downloaded": False, "name": name}
    try:
        from ai_engine.dataset import load_cicids2017, load_ciciot2023
        if name == "cicids2017":
            df = load_cicids2017(str(ds_dir))
        else:
            df = load_ciciot2023(str(ds_dir))
        total = len(df)
        n_attack = int(df["is_attack"].sum()) if "is_attack" in df.columns else 0
        return {
            "downloaded": True,
            "name": name,
            "total_samples": total,
            "attack_samples": n_attack,
            "benign_samples": total - n_attack,
            "features": list(df.columns),
        }
    except Exception as e:
        return {"downloaded": True, "name": name, "error": str(e)}

@app.get("/api/jobs/{job_id}/metrics")
@limiter.limit("30/minute")
async def get_job_metrics(request: Request, job_id: str):
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
@limiter.limit("30/minute")
async def get_signatures(request: Request):
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
@limiter.limit("20/minute")
async def toggle_signature(request: Request, rule_id: str, req: SignatureToggle):
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

class SignatureUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    tags: list[str] | None = None
    enabled: bool | None = None

@app.put("/api/signatures/{rule_id}")
@limiter.limit("20/minute")
async def update_signature(request: Request, rule_id: str, req: SignatureUpdate):
    with open(RULES_PATH) as f:
        data = yaml.safe_load(f)

    idx = -1
    for i, r in enumerate(data.get("rules", [])):
        if r.get("id") == rule_id:
            idx = i
            break

    if idx == -1:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule = data["rules"][idx]
    if req.name is not None:
        rule["name"] = req.name
    if req.description is not None:
        rule["description"] = req.description
    if req.severity is not None:
        if req.severity not in ("high", "medium", "low"):
            raise HTTPException(status_code=400, detail="Severity must be high, medium, or low")
        rule["severity"] = req.severity
    if req.tags is not None:
        rule["tags"] = req.tags
    if req.enabled is not None:
        rule["enabled"] = req.enabled

    with open(RULES_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return {"status": "success", "rule_id": rule_id, "rule": rule}

# -----------------
# System Monitor Control
# -----------------

@app.post("/api/system/monitor/restart")
@limiter.limit("1/minute")
async def restart_monitor(request: Request):
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

# -----------------
# System Logs
# -----------------

LOG_FILE = Path("data/nids.log")

@app.get("/api/system/logs")
@limiter.limit("30/minute")
async def get_logs(request: Request, lines: int = 100):
    """Return the last N lines of the system log file."""
    if not LOG_FILE.exists():
        return {"lines": [], "total": 0}
    try:
        with open(LOG_FILE, "r", errors="replace") as f:
            all_lines = f.readlines()
        tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
        return {
            "lines": [l.rstrip("\n") for l in tail],
            "total": len(all_lines),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {e}")

# Serve the Next.js static export ONLY if it exists (for production)
out_dir = Path("frontend/out")
if out_dir.exists():
    app.mount("/", StaticFiles(directory=str(out_dir), html=True), name="frontend")
