# AI-NIDS System Analysis: Data Flow, Weaknesses & Optimizations

## Overview

This document traces the full AI data flow from packet capture to alert storage, covering every component, its weaknesses, and specific optimization opportunities. It reflects the codebase as of the most recent fixes (feature hash, drift monitoring, AE regularization, dedup protocol, etc.) and identifies remaining issues.

---

## 1. Full Data Flow Diagram

```
Packets (interface/pcap)
    │
    ▼
┌──────────────────┐
│  PacketCapture   │  monitor/capture.py
│  _parse_packet() │  Extracts: ip, ports, flags, protocol, ttl, len
└────────┬─────────┘
         │ callback(packet_dict)
         ▼
┌──────────────────┐
│  FlowAggregator  │  monitor/flow_aggregator.py
│  Flow            │  Bidirectional 5-tuple: (src_ip,src_port,dst_ip,dst_port,proto)
│                  │  O(1) stats: counts, bytes, IAT, flags
│  to_features()   │  → dict with 22 feature keys + 5 metadata keys
└────────┬─────────┘
         │ completed flows (on eviction or flush)
         ▼
┌──────────────────┐
│ FeatureExtractor │  monitor/feature_extractor.py
│ transform()      │  → DataFrame with FEATURE_COLS (20 cols) + META_COLS (6 cols)
│                  │  Handles NaN/Inf, clips outliers, fills missing cols
└────────┬─────────┘
         │ DataFrame
         ▼
┌─────────────────────────┐
│ EnsembleInferenceEngine │  ai_engine/ensemble.py
│ predict()               │  → rf_score + ae_score → ensemble_score → label + confidence
│                         │  → _batch_explain() for anomalous flows (driver + top-3 features)
└────────┬────────────────┘
         │ list[result]
         ▼
┌──────────────────┐
│ process_results()│  ai_engine/alert_engine.py
│ severity          │  classify_severity() from config thresholds
│ signature_check   │  Checker.check(result) → signature_match
└────────┬─────────┘
         │ list[alert]
         ▼
┌──────────────────┐
│ AlertDeduplicator│  core/deduplicator.py
│ should_fire()    │  Redis SET NX + TTL or in-memory dict
└────────┬─────────┘
         │ deduplicated alerts
         ▼
┌──────────────────┐
│ ThreadPoolExecutor│  core/pipeline.py
│ ThreatIntel       │  Off-hot-path: get_enrichment(ip) → geo + reputation
└────────┬─────────┘
         │ enriched alerts
         ▼
┌──────────────────┬──────────────────┬──────────────────┐
│ IncidentCorrelator│  AlertLogger     │  StatsTracker     │
│ (per IP grouping) │  (SQLite store)  │  (rolling window) │
│                   │  + event_bus pub │  + drift check    │
└──────────────────┴──────────────────┴──────────────────┘
         │
         ▼
┌──────────────────┐
│ EventBus          │  core/event_bus.py
│ → local handlers  │  → Redis pubsub (cross-instance)
│ → FlowLogger      │  → StatsTracker → snapshot
│ → API reads SQLite│  api/data.py → FastAPI → dashboard
└──────────────────┘
```

---

## 2. Pipeline Weaknesses (by component)

### 2.1 PacketCapture (`monitor/capture.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| P1 | Only IPv4 — IPv6 packets are silently dropped by `pkt.haslayer(IP)` | Misses all IPv6 traffic (increasingly common) | Check `haslayer(IPv6)` and extract from `pkt[IPv6]` |
| P2 | ICMP detected at import level (`from scapy.all import ... ICMP`) but never parsed in `_parse_packet()` | ICMP packets pass through with `src_port=None, dst_port=None, tcp_flags=None` and 0 flags — flow aggregator creates degenerate flows | Extract ICMP type/code as pseudo-port or skip ICMP entirely |
| P3 | TTL is captured but never used in features or signatures | Lost signal — TTL anomalies can indicate spoofing or scanning | Add `min_ttl` / `ttl_change` to flow features or signature conditions |
| P4 | `max_packets` cap in live capture — sniffs up to N packets per window, not N packets total | After N packets, capture stops until next window. Late packets in burst are dropped | Use `stop_filter` or set `count=0` (infinite) with timeout-based stop |

### 2.2 FlowAggregator / Flow (`monitor/flow_aggregator.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| F1 | **Redis sync on every packet** — `sync_to_redis()` is called for every packet in `ingest()`. Each call does multiple `HSET`/`HINCRBY`/`ZADD` operations via pipeline | O(RTT) latency per packet — can saturate Redis and block capture for high-throughput interfaces | Batch Redis updates: throttle to every N packets or every M seconds. Use local accumulation and flush periodically |
| F2 | **Direction re-orientation only works for TCP** — UDP and ICMP flows never re-orient. If first packet seen is the response, direction is permanently wrong | Broken direction for half of all non-TCP flows in the pipeline | Track first-seen IPs, re-orient when the "other" IP initiates. Use `_is_init_labeled` logic extended to first-packet heuristic |
| F3 | `to_features()` computes `fwd_packet_count` and `bwd_packet_count` but these are NOT in `FEATURE_COLS` | Wasted computation — these fields are computed, serialized, then immediately dropped by `FeatureExtractor` | Remove from `to_features()` or add to `FEATURE_COLS` (they're useful features) |
| F4 | No lock on `FlowAggregator._flows` dict — `ingest()` (capture thread) and maintenance thread both access it | Race condition: dict corruption under concurrent access | Use `threading.Lock` around `_flows` reads/writes |
| F5 | `to_features()` drops flows with `packet_count < 2`. But single-packet flows (SYN scans, DNS queries) are legitimate attack signals | Port scans with 1 SYN packet per flow are silently dropped — the model never sees them | Lower threshold to 1 or add a config option. The model can learn from 1-packet flows |
| F6 | IAT computation: `iat = max(0.0, current_ts - self.last_seen)` — time can go backwards on clock adjustments | Negative IATs are clamped to 0, which silently corrupts timing statistics | Use `monotonic_ns()` instead of `time.time()` for IAT |
| F7 | `_protocol` field is set once (first packet) and never updated. If protocol changes mid-flow (e.g., Teredo tunneling), it's silently wrong | Rare but incorrect metadata | Validate protocol consistency or don't set it on non-first packets |

### 2.3 FeatureExtractor (`monitor/feature_extractor.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| E1 | `FlowAggregator.to_features()` adds `direction` to flow dicts, but `META_COLS` doesn't include it. Direction is dropped before inference | Dashboard can't filter by direction; signatures can't match on it | Add `direction` to `META_COLS` or include it in result dicts explicitly |
| E2 | NaN/Inf fill with 0 is unconditional — no distinction between "missing" and "genuinely 0" | Malformed packets produce all-zeros feature vectors that look benign (score ~0) | Add a `_is_malformed` flag to the flow when NaN is replaced |
| E3 | `clip(upper=1e9)` on `flow_bytes_per_sec` and `flow_packets_per_sec` uses a hard limit | Legitimate high-rate flows (10Gbps+) get clipped, making them indistinguishable from lower-rate ones | Make the clip threshold configurable or derive from network speed |
| E4 | `to_numpy()` is dead code — never called from anywhere | Unnecessary method | Remove or use it in `predict()` instead of inline `feature_df[FEATURE_COLS].to_numpy()` |

### 2.4 EnsembleInferenceEngine (`ai_engine/ensemble.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| M1 | `predict()` assumes `feature_df[FEATURE_COLS]` indexing always works. If a column is missing, pandas raises KeyError | Unhandled crash if FEATURE_COLS changes without retraining | Catch KeyError and raise a clear message referencing the hash check |
| M2 | `_ae_score()` transforms the full batch, then `_batch_explain()` transforms the anomalous subset again | Double normalization of same data — wasteful | Cache the scaled array in `predict()` and pass it to `_batch_explain()` |
| M3 | `_batch_explain()` has bare `except Exception` in both branches with just a log message | Silent failures: if explanation computation fails, the flow still gets a score with no explanation and no notification | Return a minimal explanation with `"error": str(e)` so the caller knows it failed |
| M4 | `_ae_score()` normalisation: `min(mse / (threshold * 3), 1.0)` — the 3x factor is arbitrary | The AE score range isn't calibrated to any principled scale | Store the calibration set's MSE distribution (mean, std) and use that for normalisation instead of an arbitrary multiplier |
| M5 | RF predict_proba returns probabilities that are already calibrated to training distribution. AE score is a raw distance measure. Weighted combination assumes both are on the same scale | The ensemble weights (0.65/0.35) are heuristic — there's no principled calibration mapping AE scores to probability space | Train a logistic regression calibration layer on a validation set, or use Platt scaling on AE scores |

### 2.5 AlertEngine (`ai_engine/alert_engine.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| A1 | `SEVERITY_THRESHOLDS` loaded at **module import time** (line 27). Config changes require restart | No hot-reload for severity thresholds — operational friction | Add a `reload()` method or check mtime periodically |
| A2 | Signature matches always set `alert["severity"] = "high"` regardless of the rule's own severity | Signature severity levels in `rules.yaml` are cosmetic — all sig hits are "high" | Use `sig_match["severity"]` from `check_with_metadata()` when available |
| A3 | Signature matches always force `label = "ATTACK"` even for low-confidence signatures | No way to distinguish "certain attack" from "maybe attack, sig triggered" | Keep label as ATTACK but leverage `model_label` + `confidence` in dashboard; signal:signature severity already controls alert severity |
| A4 | `process_results()` overwrites `result["label"]` before `model_label` is captured | `model_label` captures the post-overwrite value (always "ATTACK") instead of the original | Capture `model_label` FIRST, then overwrite `label` (now fixed in alert_engine.py:64-66 — verify order is correct) |

### 2.6 AlertDeduplicator (`core/deduplicator.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| D1 | Suppression count key is deleted on first occurrence (line 63: `self.redis.delete(f"{redis_key}:count")`). Then incremented on subsequent occurrences. If two different alerts with same key fire, the count resets | `suppression_note()` may report 0 even when alerts were suppressed | Don't delete the count key — use a single SETNX-style approach with separate TTL tracking |
| D2 | `should_fire()` falls back to in-memory on Redis error, but the in-memory fallback has no TTL cleanup for the suppression counts | Suppressed count dict grows unboundedly if Redis is down for long periods | Add periodic eviction of stale suppression counts in `evict_expired()` |
| D3 | Dedup key doesn't include source port — two attacks from same src to same dst:port but different src ports are treated as one | An attacker using multiple source ports (e.g., port scan) will have all alerts deduped to one | This is by design (prevent storm) but worth documenting. Add `src_port` for completeness? Tradeoff: more distinct keys = fewer suppressions. |

### 2.7 Pipeline (`core/pipeline.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| L1 | `_process_flows()` calls `self.stats.record_flow(flow)` per flow in a Python loop. For large batches this is slow | O(n) lock acquisitions for the stats tracker | Pass all flows to a `record_flows_batch()` method or use a single lock acquisition |
| L2 | Maintenance thread runs every 60s for dedup eviction + incident closing. But `FlowAggregator._evict_expired()` runs in-band on packet ingestion | Flow eviction latency is tied to packet arrival — if traffic stops, flows never expire | Move eviction to the maintenance thread (simple: stop doing rate-limited eviction in `ingest()` and let the maint thread evict) |
| L3 | `stop()` calls `self._intel_pool.shutdown(wait=False)` then immediately calls `_process_flows()` | In-flight enrichment futures may still be running when the pipeline shuts down | Call `shutdown(wait=True, timeout=5)` before processing remaining flows, or cancel pending futures |
| L4 | No rate limiting or backpressure. If inference can't keep up with capture, the in-memory flow dict grows unboundedly | OOM crash under high throughput | Add a `max_active_flows` cap with earliest-expiry eviction |

### 2.8 EventBus (`core/event_bus.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| B1 | Local handlers are called synchronously in `publish()`. A slow handler blocks all downstream handlers | StatsTracker or logger latency can delay alert processing for all subscribers | Either document that handlers must be fast (non-blocking), or use a `ThreadPoolExecutor` for publisher dispatch |
| B2 | Redis listener uses `get_message(timeout=1.0)` polling loop. On each message, it acquires the handler lock, copies handlers, then releases | Under high alert volume, lock contention between publish and listener threads can cause latency spikes | Use `rwlock` or a lock-free handler list |
| B3 | `stop()` joins the listener thread with `timeout=5` but doesn't kill the Redis pubsub connection | On unclean shutdown, the Redis connection stays open until timeout | Call `self._pubsub.close()` immediately, then join with shorter timeout |

### 2.9 Logger + DB (`monitor/logger.py`, `monitor/db.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| S1 | SQLite grows unboundedly — no data retention policy | Database file grows indefinitely; queries slow down; disk fills up | Add a periodic cleanup job (delete rows older than N days) or use `VACUUM` on a schedule |
| S2 | `FlowLogger` and `AlertLogger` each create their own DB connection via `get_db_connection()` (line 38, 55). Each connection uses WAL mode | Multiple WAL connections are fine but each has its own transaction scope — no atomicity across loggers | Share a single connection or use explicit transactions where atomicity matters |
| S3 | `FlowLogger.log_batch()` uses `executemany` which is auto-commit (since `isolation_level=None`). Each batch is its own transaction, but there's no explicit commit | Fine for logging but means partial batches on crash are invisible | For production: explicit commit per batch for observability |
| S4 | `clear_db_data()` does `DELETE FROM` then `VACUUM` — VACUUM requires exclusive lock and blocks all readers/writers | Brief outage for all other DB operations | Schedule VACUUM during maintenance window or use auto_vacuum |

### 2.10 StatsTracker (`core/stats_tracker.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| T1 | Drift detection compares recent half vs full history. Once baseline is set (at 50+ benign scores), it never updates | Drift detection anchors to first 50 observations — if those are anomalous, the baseline is corrupted | Re-baseline periodically (e.g., every 1000 samples) or use a rolling window comparison |
| T2 | `_benign_scores` is a fixed 5000-element deque. In high-throughput environments, this rolls over in minutes | Drift detection only looks at recent history, losing long-term trend | Use a larger capacity or implement hierarchical storage (recent + daily aggregates) |
| T3 | `host_score_stats()` returns raw stats with no aggregation window — grows unboundedly for popular hosts | Memory leak for busy hosts | Limit per-host storage or drop old entries |

### 2.11 ThreatIntel (`core/threat_intel.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| I1 | `sync_feeds()` is called in `__init__()` constructor (daemon thread) | Every ThreatIntelManager instantiation triggers a feed sync thread, even if one is already running | Use a module-level lock to ensure only one sync runs at a time |
| I2 | ip-api.com is free but rate-limited to 45 req/min. No rate limiting or circuit breaker | Under high alert volume with distinct external IPs, all lookups will fail with HTTP 429 | Implement simple in-process rate limiter (e.g., token bucket, max 40/min) |
| I3 | Feed URLs are hardcoded — no config option for custom feeds | Can't add internal threat intelligence sources | Make feed URLs configurable in config.yaml |

### 2.12 IncidentCorrelator (`core/correlator.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| C1 | Groups alerts by src_ip only — one incident per source IP. An attacker using multiple IPs creates separate incidents | Can't correlate multi-IP attacks (botnet, DDoS) | Add optional grouping by dst_ip, dst_port, or attack signature |
| C2 | `_resume_active_incidents()` loads all active incidents into memory on startup. With thousands of incidents, this is slow | Startup delay grows with incident table size | Paginate or limit to last N active incidents |
| C3 | Process alert always creates incident for new src_ip. No minimum severity threshold | One low-severity alert creates an incident that stays active for 180s | Skip incident creation for "low" severity alerts |

### 2.13 API (`api/main.py`, `api/data.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| H1 | `load_from_db()` parses raw_json with `.replace('NaN', 'null')` — post-hoc cleanup for legacy NaN serialization | Fragile — if the NaN format changes, the replace misses | Remove this after NumpyEncoder has been in use long enough, or store raw_json properly from the start |
| H2 | `get_comparison_stats()` searches severity via `LIKE '%"severity": "high"%'` in raw_json TEXT | Slow (full table scan), fragile (format-dependent), and the severity column exists separately | Query the structured column directly: `SELECT severity, count(*) ... GROUP BY severity` |
| H3 | `/api/alerts` and `/api/flows` have no pagination — they load up to 2000/5000 records into memory at once | Memory spike for each request; slow responses for large datasets | Add `offset`/`limit` pagination, return total count header |
| H4 | No authentication or rate limiting on any endpoint | Anyone on the network can query alerts, trigger retraining, wipe DB | Add API key or at least network-level restriction (bind to localhost if frontend is on same host) |
| H5 | `/api/models/deploy` copies artifacts from version directory to model directory. If version directory is missing, it raises 404 | OK, but the copy isn't atomic — partial state on crash | Copy to temp dir, then rename (atomic on same filesystem) |
| H6 | `/api/system/monitor/restart` runs `sudo systemctl restart` — requires `NOPASSWD` sudo config | Works on preconfigured systems but fails with unclear error otherwise | Return clear error message explaining sudo requirement |
| H7 | Model retraining endpoint (`/api/models/retrain`) uses config directly from request body without validation | Malformed requests could trigger training with invalid params | Add Pydantic field validation (min/max for epochs, etc.) |

### 2.14 Signature Checker (`signatures/checker.py`, `signatures/loader.py`)

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| R1 | Hot-reload polling interval is 10s — too slow for real-time rule updates | When a new rule is added, there's a 10s delay before it's active | Reduce to 2-5s or use inotify for instant reload |
| R2 | `check()` returns only the first matching rule. `check_all()` returns all. But `process_results()` only calls `check()` | Only the first matching rule is reported per flow, even if multiple rules fire | Switch to `check_all()` or `check_with_metadata()` in `process_results()` |
| R3 | Rule severity in rules.yaml is never used by the alert engine — signature matches always get "high" in `process_results()` | Rule severity is cosmetic | Use the rule's own severity from `check_with_metadata()` |

---

## 3. Model Weaknesses

### 3.1 Training Dataset

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| TD1 | **Training uses only 2 of 8 CICIDS2017 subsets** (Friday DDoS + Friday PortScan). The model has never seen brute force, web attacks, botnets, infiltration, or DoS variants | Model is blind to ~75% of attack types — only detects DDoS and port scans | Download all CSVs: `fetch_cicids.py` currently only lists 2 files. Add remaining CICIDS2017 subsets |
| TD2 | `bootstrap_data.py` (generates synthetic training data) is never called by `train.py` | Dead code — 10,000 synthetic samples sitting unused | Either integrate into `train.py` as warm-start data or remove if CICIDS2017 is sufficient |
| TD3 | Live data labeling in `fetch_live_data()` uses a fragile 5-second window join | Wrong labels for burst traffic, shared services, NAT | Label by confirmed incident association or use semi-supervised approach (high-confidence alerts only) |

### 3.2 Retraining

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| RT1 | `retrain.py` only retrains the RF — never the AE | AE becomes increasingly stale as network patterns drift. AE threshold is fixed at CICIDS2017 calibration time | Add AE retraining step (train on recent benign flows) |
| RT2 | Retrained models are saved directly to `nids_model.joblib` (with backup), but `registry.json` is NOT updated | No version tracking for retrained models — can't roll back to a pre-retrain state | Update registry on retrain with `eval_source: online_retrain` and new metrics |
| RT3 | Retraining evaluates on the training set (meaningless 100% accuracy). No holdout or cross-validation | User has no idea if the retrained model is actually better | Hold out 20% of online data for evaluation |
| RT4 | Retraining uses only the last 5000 alerts/flows. If those happen to be from a single source, the model overfits | Model learns one attack pattern and forgets others | Stratify: sample across time, source IP, and attack type |

### 3.3 Feature Engineering

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| FV1 | 20 features but several are highly correlated: `flow_iat_mean/std/max/min` (4 IAT), `fwd/bwd_packet_len_max` + `avg_packet_len` (3 length), flag counts (5 flags) | Multicollinearity dilutes AE reconstruction error; RF handles it but importance scores are less interpretable | PCA or feature selection before AE training. Keep all features for RF |
| FV2 | `dst_port` is used as a raw integer feature. Model must learn port semantics from scratch | Port 80 and port 8080 (both HTTP) are treated as different numbers; port 22 (SSH) and 23 (Telnet) are close numerically but semantically different | One-hot encode well-known port ranges, or use port as a categorical embedding |
| FV3 | TCP flag counts are absolute (e.g., `syn_flag_count = 80`) instead of ratios (e.g., `syn_ratio = syn / total) | A 100-packet flow with 80 SYNs looks very different from a 10-packet flow with 8 SYNs, but both have the same ratio. The model must learn this relationship | Add ratio features or normalize by packet_count |

### 3.4 Evaluation

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| EV1 | All reported metrics are from CICIDS2017 test split (20% of the 2 loaded CSVs) | Metrics don't reflect real-world performance. The model may be 99% accurate on CICIDS2017 but 60% on live traffic | Add a `scripts/evaluate.py` that runs against labeled production traffic or a held-out portion of live data |
| EV2 | No per-class metrics (only binary: BENIGN vs ATTACK) | Dashboard can't show whether the model detects scans better than brute force | Add multi-class tracking: precision/recall per attack type from CICIDS2017 (which has labels) |
| EV3 | Threshold chosen by `np.percentile(mse, 95.0)` on calibration set — assumes exactly 5% of flows are anomalous | If real-world anomalous rate is 1% or 20%, the threshold is wrong | Make threshold_percentile configurable; tune on a held-out validation set from CICIDS2017 |

---

## 4. Architecture & Operational Weaknesses

| # | Weakness | Impact | Fix |
|---|----------|--------|-----|
| O1 | **No data retention policy** — SQLite, JSONL, and logs grow unboundedly | Eventual disk exhaustion; query performance degrades | Add retention config option (e.g., `retention_days: 30`) with periodic cleanup |
| O2 | **Two parallel logging paths** — JSONL files (`flows.jsonl`, `alerts.jsonl`) AND SQLite (`nids.db`). Some scripts read JSONL, others read SQLite | Double writes, inconsistent data if one path fails | Deprecate JSONL path; make SQLite the single source of truth. Remove JSONL writing from loggers |
| O3 | **No health check endpoint** for the ML model — `api/settings/health` checks if model files exist but not if they load correctly | Model file corruption detected only on next inference crash | Add a model health endpoint that actually loads and runs a sanity check |
| O4 | **`run_monitor.py` captures in windows** (capture_timeout=30s, then process). Between windows, no packets are captured | 30s blind spots between capture windows | Continuous capture: background thread for sniffing, in-process queue for pipeline |
| O5 | **Two signal handlers registered** — `_shutdown` first, then `_shutdown_with_ui` overwrites it | Only `_shutdown_with_ui` is active (it calls `_shutdown`). Refactoring residue | Remove redundant first handler registration |
| O6 | **No structured logging** — loguru format is human-readable | Machine parsing of logs for alerting/monitoring is fragile | Use structured JSON logging (`serialize=True` in loguru) |
| O7 | **`config.yaml` has no schema validation** — typos in keys silently fall back to defaults | Misconfiguration is undetected until weird behavior appears | Use Pydantic or cerberus to validate config on startup |

---

## 5. Optimization Opportunities

| # | Optimization | Component | Expected Gain |
|---|-------------|-----------|---------------|
| OP1 | Batch Redis IAT/flush updates instead of per-packet | `flow_aggregator.py` | 5-10x throughput improvement on high-traffic interfaces |
| OP2 | Lock-free flow table (e.g., `concurrentdict` or sharded dict) | `flow_aggregator.py` | Eliminates contention on multi-core capture |
| OP3 | Use `monotonic_ns()` instead of `time.time()` for IAT | `flow.py` | Eliminates IAT corruption from clock adjustments |
| OP4 | Pre-allocate `feature_df[FEATURE_COLS]` numpy array instead of building via pandas | `feature_extractor.py` | 2-3x faster feature extraction |
| OP5 | Cache normalized array in `predict()` to avoid double transform | `ensemble.py` | ~30% reduction in inference latency per batch |
| OP6 | Use ONNX runtime for RF and TF Lite for AE instead of sklearn/tf full runtimes | `ensemble.py` | 2-5x faster inference, smaller memory footprint |
| OP7 | Replace JSONL writes with structured async logging | `pipeline.py` | Eliminates I/O blocking on disk writes |
| OP8 | Add pagination to API endpoints | `api/data.py` | Prevents memory spikes on dashboard load with large datasets |
| OP9 | Add Auth + rate limiting to API | `api/main.py` | Security hardening |
| OP10 | Replace per-packet Redis sync with batch flush | `flow_aggregator.py` | Major Redis load reduction |
| OP11 | Make signature hot-reload use inotify instead of polling | `signatures/checker.py` | Instant rule update detection |
| OP12 | Add data retention policy + auto-cleanup | `monitor/db.py` | Prevents disk exhaustion |

---

## 6. Summary of All Remaining Weaknesses by Severity

### Critical (production-impacting)
- **TD1**: Model trained on only 2 of 8 CICIDS2017 subsets — blind to 75% of attack types
- **F1**: Per-packet Redis sync saturates Redis under load
- **RT1**: AE never retrained — goes stale over time
- **S1/S4**: SQLite grows unboundedly — eventual disk exhaustion

### High (accuracy/reliability)
- **P1**: IPv6 packets silently dropped
- **F2**: Non-TCP flows have broken direction
- **F4**: Race condition on flow table
- **F5**: Single-packet flows dropped from training
- **F6**: IAT corrupted by clock adjustments
- **M2/M4**: AE score normalization is arbitrary
- **M5**: Ensemble weights are heuristic, not calibrated
- **A2**: Signature severity levels are cosmetic
- **H4**: No API security
- **O2**: Dual logging path redundancy

### Medium (maintainability/monitoring)
- **P4**: Capture window gaps (30s blind spot)
- **E2**: No malformed-flow flag
- **E4**: Dead code (`to_numpy`)
- **L2**: Eviction tied to packet arrival
- **L4**: No backpressure → OOM risk
- **B1**: Blocking handler dispatch in event bus
- **D1**: Suppression count tracking is buggy
- **T1**: Static drift baseline (never re-baselines)
- **I2**: No rate limiting on geo API
- **O6**: No structured logging
- **O7**: Config has no schema validation

---

## 7. Recent Fixes Status (for reference)

| Fix | Status | File |
|-----|--------|------|
| Canonical FEATURE_COLS | ✅ | `core/features.py` |
| IAT re-orientation | ✅ | `monitor/flow_aggregator.py` |
| ThreadPoolExecutor for threat intel | ✅ | `core/pipeline.py` |
| Batch AE inference | ✅ | `ai_engine/ensemble.py` |
| Config-driven weights/thresholds | ✅ | `ai_engine/ensemble.py`, `ai_engine/alert_engine.py`, `config.yaml` |
| Lazy DB init | ✅ | `monitor/db.py` |
| Bugfixes (except:pass, f-string, variance) | ✅ | `run_monitor.py`, `logger.py`, `flow_aggregator.py` |
| NumpyEncoder + dead code removal | ✅ | `core/json_utils.py`, deleted `geo_utils.py` |
| Logger `_flow_row()` helper | ✅ | `monitor/logger.py` |
| AE threshold persistence | ✅ | `ai_engine/trainer.py:139` |
| Eval weights from config | ✅ | `scripts/train.py:160` |
| Retraining FP filter | ✅ | `scripts/retrain.py:45` |
| Feature hash for drift detection | ✅ | `ai_engine/trainer.py:67`, `ai_engine/ensemble.py:85` |
| Concept drift monitoring | ✅ | `core/stats_tracker.py` |
| AE holdout calibration set | ✅ | `ai_engine/trainer.py:112` |
| Input validation (NaN warnings) | ✅ | `monitor/feature_extractor.py:39`, `ai_engine/ensemble.py:255` |
| `model_label` preservation | ✅ | `ai_engine/alert_engine.py:66` |
| Confidence field | ✅ | `ai_engine/ensemble.py:280` |
| Dedup key includes protocol | ✅ | `core/deduplicator.py:38`, `core/features.py:39` |
| AE dropout regularization | ✅ | `ai_engine/trainer.py:129` |
| Registry eval source | ✅ | `scripts/train.py:229` |
| Graceful shutdown | ✅ | `firewall_engine.py`, `event_bus.py` |
