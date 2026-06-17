# Changelog

All changes from project inception (`da0fb05`, Apr 1 2026) to present (`239f84e`, Jun 17 2026) — 45 commits, ~160 files, ~30k lines added.

---

### Apr 1 — Project Init
- Repository initialized with base project scaffolding
- `.gitignore` configured

### Apr 2 — Signature Engine & Dependencies
- Implemented YAML-backed signature checker with hot-reload capability (10s polling loop)
- Requirements.txt published with project dependencies

### Apr 3 — Protocol Handling
- Switched protocol classification to use destination port instead of protocol type field
- Updated feature extraction and matching logic accordingly

### Apr 4 — Core Architecture & Systemd
- Fixed signature matching to skip empty conditions; cleaned up YAML test formatting
- Added demo mode with synthetic test PCAP generation and online retrainer
- Optimized flow aggregation to O(1) memory (removed unbounded growth)
- Created systemd service files and deployment scripts for monitor and API
- Replaced static dataset loading with a recursive, auto-translating hybrid loader
- Updated documentation to reflect expanded feature set and systemd deployment

### Apr 6 — SQLite Migration
- Migrated flow and alert logging from JSONL files to SQLite database
- All existing scripts updated to use new DB backend

### Apr 7 — Database & Logging Overhaul
- Dynamic systemd service deployment with template-based configuration
- Migrated all loggers to use SQLite instead of JSONL
- Implemented alert label promotion for multi-stage severity classification
- Added validation tests for signature matching logic

### Apr 8 — Redis, Firewall & Dashboard
- Enhanced dashboard UI with custom metric cards, alert ticker, and data filtering
- Implemented Redis-backed alert deduplication with directional flow tracking
- Added database maintenance utilities (wipe, compact)
- Implemented Redis-backed firewall engine for distributed block/unblock commands
- Distributed flow aggregation via Redis pub/sub

### Apr 10 — Incident Correlation
- Implemented incident correlation engine linking related alerts
- Added flow directionality tracking (inbound/outbound)
- Updated signature rules with new detection patterns

### Apr 12 — Threat Intel & First Dashboard
- Implemented threat intelligence enrichment (geo-IP, ASN, ISP lookup for alerts)
- Added AI inference testing scripts and data bootstrapping utilities
- Built multi-page Streamlit dashboard with modular visualization components and alert management
- Fixed typo in classification label and updated database state

### Apr 13 — Dashboard Consolidation & Next.js Migration
- Consolidated multi-page Streamlit dashboard into a single-page tabbed application
- Migrated dashboard from Streamlit to Next.js frontend with FastAPI backend integration

### Apr 22 — Visualizations
- Integrated Recharts for network analytics, incident geo-correlation, and alert volume timelines
- Implemented interactive Geo-IP scatter charts and alert volume area charts
- Added configurable dashboard polling intervals

### May 14 — MLOps & Signature Management
- Finalized Next.js + FastAPI dashboard migration with updated deployment config
- Added virtual environment validation to all scripts
- Implemented signature management UI (toggle rules on/off)
- Added model retraining background tasks with terminal output monitoring
- Replaced setup guide with comprehensive documentation
- Cleaned up signature rule definitions

### May 19 — Model Registry & Explainability
- Added model explainability with SHAP-style feature scoring for alerts
- Implemented automated model versioning registry with deploy/rollback
- Model artifacts versioned and tracked in `data/models/registry.json`

### Jun 14 — Infrastructure Hardening & Deployment Fixes
- Fixed project root paths across all scripts and logs
- Added AGENTS.md documentation for AI-assisted development
- **Centralized API URL management**: extracted 25 hardcoded `localhost:8000` references into `frontend/src/app/lib/api.ts` with `apiUrl()` helper
- **Removed redundant dashboard service**: FastAPI now serves the frontend at `/` on port 8000; the separate `ai-nids-dashboard.service` was deleted
- `npm start` no longer rebuilds — just serves the existing static export
- `serve` moved from devDependencies to dependencies
- Fixed venv shebangs broken by project directory rename (old `Dev Work/` path with space → `Dev/`)
- Deploy script cleaned up to only manage `ai-nids-monitor` and `ai-nids-api` services
- Added Postman API collection (`tests/api-collection.json`) covering all 17 endpoints

### Jun 14 — Feature Centralization, IPv6, Backpressure & Model Diagnostics
- **Centralized feature definitions** in `core.features` as single source of truth; `config.yaml` features list now documentation-only
- **Async threat intel enrichment** — non-blocking geo-IP/ASN lookups for alerts
- Fixed IAT (inter-arrival time) reset logic in flow re-orientation
- Decoupled configuration loading and JSON utilities into standalone modules
- **Lazy SQLite initialization** — schema creation deferred until first write
- Optimized ensemble engine parameters (RF estimator count, AE compression ratio)
- **Graceful shutdown** for FirewallEngine — clean Redis connection teardown
- Fixed IAT calculation bugs during flow re-orientation (directional swap)
- **Model feature hashing** — consistent feature column mapping between training and inference
- **Autoencoder threshold calibration** — automated anomaly threshold tuning on validation set
- **Score drift tracking** — monitors model score distribution shifts over time
- Added `protocol` field to feature set (TCP=6, UDP=17, ICMP=1, other=0)
- Enhanced autoencoder architecture with dropout layers for regularization
- Updated training metadata schema with calibration metrics
- **Minimum TTL tracking** integrated into flow aggregation
- **IPv6 support** in packet capture and flow aggregation
- **ICMP parsing** — type/code extraction for ICMP flows
- **Backpressure mechanism** — queue backpressure signal when processing falls behind
- **Maintenance loops** for expired flow eviction (configurable TTL-based cleanup)
- **Data retention policies** — automatic pruning of old alerts and flows from SQLite
- Threat intelligence integration in maintenance pipeline
- **Automated config validation** on startup — validates `config.yaml` structure and required fields
- **Model health diagnostics** — periodic checks for model file integrity, staleness, and prediction consistency

---

### Jun 17 — Codebase Documentation & Pipeline Optimizations
- **Comprehensive section headers** added to all 60 source files across every module (`core/`, `ai_engine/`, `monitor/`, `signatures/`, `api/`, `scripts/`, `tests/`, `frontend/`, `config.yaml`, systemd templates)
  - Each header explains: purpose, usage, design decisions, and important gotchas
  - Test files now document run commands, dependencies, and side effects (e.g., `flushdb()`, `clear_db_data()`)
  - Config sections now clearly labelled with section dividers
- **OP4: NumPy pre-allocation** in FeatureExtractor — replaces pandas list-of-dicts with pre-allocated `np.zeros` array for ~10x faster DataFrame construction
- **OP2: ShardedFlowStore** — reduces lock contention in flow aggregation via hash-based sharding (16 shards, per-shard RLock)
- **Removed packet queue** from capture pipeline — packets forwarded directly to aggregator, reducing latency and memory pressure
- **Purged stale log files** and updated SQLite `.gitignore` patterns
- Updated CHANGELOG boundary to 45 commits, ~160 files, ~30k lines total

### API Surface (final)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/kpis` | GET | Uptime, alert counts, comparison stats |
| `/api/alerts` | GET | Alert history with limit param |
| `/api/flows` | GET | Flow records with limit param |
| `/api/incidents` | GET | Active incidents |
| `/api/settings/health` | GET | Redis connection + model file status |
| `/api/settings/blocked_ips` | GET | Firewall block list |
| `/api/settings/firewall` | POST | Block or unblock an IP |
| `/api/settings/wipe` | POST | Clear all DB data |
| `/api/jobs` | GET | List background jobs |
| `/api/jobs/{id}` | GET | Job details + output |
| `/api/jobs/{id}/metrics` | GET | Training epoch loss/val_loss |
| `/api/models/retrain` | POST | Start model retraining job |
| `/api/models/versions` | GET | Model version registry |
| `/api/models/deploy` | POST | Deploy specific model version |
| `/api/signatures` | GET | List all signature rules |
| `/api/signatures/{id}/toggle` | POST | Enable/disable a rule |
| `/api/system/monitor/restart` | POST | Restart capture service |

### Architecture (final)

```
ai-nids-monitor.service   (raw packet capture → SQLite + Redis)
        │
        ▼  reads from
ai-nids-api.service       (FastAPI :8000)
        ├── /  → serves frontend/out/ (Next.js static export)
        └── /api/*  → Python handlers → SQLite/Redis
```
