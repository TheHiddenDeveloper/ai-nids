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

# Serve the Next.js static export ONLY if it exists (for production)
out_dir = Path("frontend/out")
if out_dir.exists():
    app.mount("/", StaticFiles(directory=str(out_dir), html=True), name="frontend")
