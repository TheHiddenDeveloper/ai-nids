# AI-NIDS Agent Guide

## Project
Python-based NIDS: RF ensemble (65%) + Autoencoder (35%) + hot-reloadable YAML signature engine, with a FastAPI backend + Next.js dashboard.

## Not a pip package
Flat scripts layout. All scripts and tests use `sys.path.insert(0, ...)` to find imports. **Always run from project root.**

## Key commands

| Action | Command |
|--------|---------|
| Live capture + inference | `python scripts/run_monitor.py --interface eth0` |
| Pcap replay | `python scripts/run_monitor.py --pcap file.pcap` |
| Signature-only mode | `python scripts/run_monitor.py --no-model` |
| Full training | `python scripts/train.py --precision high` |
| Quick training | `python scripts/train.py --precision standard --epochs 5` |
| Self-contained demo | `python scripts/demo.py` |
| Run all tests | `pytest tests/ -v` |
| Run focused test | `pytest tests/ -v -k "test_syn"` |
| Start FastAPI directly | `uvicorn api.main:app --host 0.0.0.0 --port 8000` |
| Frontend dev server | `npm run dev` (in `frontend/`) |
| Install systemd services | `sudo bash scripts/deploy.sh` |

## Testing quirks
- **Hybrid setup**: Some tests use pytest (`tests/test_*.py`), others are standalone scripts run as `python tests/test_*.py` with `sys.exit(1)` on failure.
- **Redis-dependent tests** (`test_redis_integration.py`, `test_redis_flows.py`, `test_threat_intel.py`, `test_correlation.py`) skip gracefully if Redis is down, but `flushdb()` wipes Redis DB 0.
- **Model-dependent tests** (`test_ai_inference.py`) require trained models in `data/models/`.
- `test_correlation.py` calls `clear_db_data()` which **deletes all data** from SQLite.

## Architecture gotchas
- `FEATURE_COLS` lives in **`core/features.py`** — single source of truth. All other modules import from there. `config.yaml:features.selected_features` is a documentation-only mirror.
- **Redis is optional** but enabled by default (`redis.active: true` in `config.yaml`). Components have in-memory fallbacks but behavior varies.
- **SQLite auto-inits** on `import monitor.db` — schema creation and migrations happen at import time.
- **Hot-reload**: `signatures/checker.py` polls `rules.yaml` every 10s (no filesystem events).
- **Dual logging**: `monitor/logger.py` writes JSONL, `monitor/db.py` writes SQLite. Some scripts still read legacy JSONL paths (`alerts.jsonl`, `flows.jsonl`).
- **No CI/CD** (no `.github/workflows/`). No linter/formatter config (no eslint, prettier, editorconfig).

## Config
Central `config.yaml` (no `.env`). Change interface, Redis toggle, severity thresholds, model paths there.

## Frontend
Next.js with `output: 'export'` (static site served by FastAPI at `/`). See `frontend/AGENTS.md` — this Next.js version has breaking changes from agent training data.
- **API base URL**: Defined in `frontend/src/app/lib/api.ts` — change `API_BASE` there if the backend is on a different host/port.
- **No separate dashboard service**: FastAPI serves the frontend at `/` on port 8000. The `ai-nids-dashboard.service` was removed as redundant.
- **`npm start`** only serves the static export (no rebuild): `npx serve@latest -s out -l 3000`.
- **Frontend build on deploy**: `scripts/deploy.sh` runs `npm run build` in `frontend/`. May need `sudo rm -rf frontend/.next frontend/out` if permissions get corrupted from prior root-owned builds.

## Sudo / WSL
Live capture needs `cap_net_raw`. On WSL, use the full venv path with sudo:
```bash
sudo /path/to/ai-venv/bin/python scripts/run_monitor.py --interface eth0
```
