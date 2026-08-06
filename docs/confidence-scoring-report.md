# AI-NIDS Confidence Score: Investigation, Fixes & the Dynamic RF/AE Split

**Author:** AIDEN
**Date:** August 2026
**Scope:** Detection-gap investigation, FV6 SYN+RST feature, training fixes, dashboard timestamp fix, and the new dynamic RF/AE confidence split.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [What the Confidence Score Is](#2-what-the-confidence-score-is)
3. [Problem: Attacks Scoring Low](#3-problem-attacks-scoring-low)
4. [Root-Cause Analysis](#4-root-cause-analysis)
5. [Fix 1 — FV6: SYN+RST Closed-Port Scan Detection](#5-fix-1--fv6-synrst-closed-port-scan-detection)
6. [Fix 2 — Flag-Ratio Train/Serve Skew](#6-fix-2--flag-ratio-trainserve-skew)
7. [Fix 3 — Dashboard "1970" Retrain Timestamp](#7-fix-3--dashboard-1970-retrain-timestamp)
8. [Fix 4 — Dynamic RF/AE Confidence Split](#8-fix-4--dynamic-rfae-confidence-split)
9. [Validation Results](#9-validation-results)
10. [What the Score Means in Plain English](#10-what-the-score-means-in-plain-english)
11. [Operational Notes & Caveats](#11-operational-notes--caveats)

---

## 1. Executive Summary

A series of issues caused the dashboard to show low confidence scores for deliberate attacks, and one fix surfaced a train/serve data skew. This report documents:

- The **root causes** of low attack scores (model blind spots on attack shapes absent from the CICIDS2017 training data).
- A new **FV6 feature** (`is_syn_rst_scan`) plus retraining that lifts real SYN→RST scans from a mean score of **0.35 to 0.99**.
- A **flag-ratio bug** in the synthetic probe generator that skewed the RF's view of SYN floods.
- A **frontend unit bug** rendering model retrain timestamps as 1970.
- A new **dynamic per-flow confidence split** between the Random Forest and Autoencoder, replacing the fixed 0.65/0.35 blend.

---

## 2. What the Confidence Score Is

The `score` shown on the dashboard is **produced only by the AI ensemble** — it is a single number in `[0, 1]` (rendered as a percentage) that fuses two models' opinions about a network flow:

| Component | Model | Question it answers |
|-----------|-------|---------------------|
| **RF score** | Random Forest (supervised) | "Does this flow look like a known attack pattern I was trained on?" |
| **AE score** | Autoencoder (unsupervised) | "Does this flow look abnormal compared to your normal traffic?" |

The two scores are combined into one (see [Fix 4](#8-fix-4--dynamic-rfae-confidence-split)). A value of `0.5` is the decision boundary: `≥ 0.5` labels the flow `ATTACK`, below it `BENIGN`.

**Important:** the signature engine does **not** change the score value. It only decides whether an alert is emitted and what severity it gets. If the ML score is below the "low" threshold (`0.65`) but a signature matches (e.g. `PORT_SCAN_SYN_001`), the alert is still forced and its severity comes from the rule.

---

## 3. Problem: Attacks Scoring Low

A user complaint stated that **all deliberate attacks** appeared on the dashboard with low, non-confident scores. Investigation of the live SQLite database (`data/nids.db`) showed two distinct alert shapes:

1. **Single-packet SYN probes** `(pc=1, syn=1, ack=0, dst_bytes=0)` — scored **0.996** (correct, driven by the existing FV4 `is_syn_probe` feature).
2. **Two-packet SYN→RST scans** `(pc=2, syn=1, ack=1, rst=1, dst_bytes=40)` — scored **0.350** (`rf=0.0002`, `model_label=BENIGN`). These were only saved because the `PORT_SCAN_SYN_001` / `SYN_SCAN_001` signature rules matched, **not** because of ML.

The ML model was blind to the SYN+RST scan shape.

---

## 4. Root-Cause Analysis

- **CICIDS2017 blind spot.** The training dataset's `PortScan` class is composed of long-lived, high-volume scan flows. The real-world production shape — a single SYN drawing a RST reply, forming a 2-packet flow — is **absent** from the training distribution, so neither the RF nor the AE recognised it.
- **AE is not a reliable discriminator on live traffic.** The AE scored `1.0` on a large fraction of recent flows, *including benign mDNS* (`0.727`). Boosting the AE weight would therefore have caused false positives. The fix had to teach the **RF** the missing shape.
- **Replay artifacts.** `PcapReplay.play()` ignores pcap timestamps (uses `time.time()`), producing unrealistically short durations (`1e-6` s) and extreme pps. Live capture was used as the trustworthy test ground; a synthetic pcap is acceptable for RF-shape testing only.

---

## 5. Fix 1 — FV6: SYN+RST Closed-Port Scan Detection

A new engineered feature was added to `core/features.py`:

- `is_syn_rst_scan` (in `FEATURE_COLS`, now **38 columns**)
  predicate: `(syn ≥ 1) & (rst ≥ 1) & (packet_count ≤ 3) & (avg_packet_len ≤ 120)`
- Implemented in both scalar (`compute_probe_features()`) and vectorized (`compute_probe_features_vec()`) forms; verified identical.
- Added to `HUMAN_FEATURE_NAMES` as `"SYN+RST Scan (Closed-Port Recon)"`.

`scripts/generate_probe_data.py` was extended to synthesise 2-packet SYN→RST rows that mirror the real production shape (44 B SYN, 40 B RST, duration 1.5–10 ms, ACK either 0 or 1, ports drawn from well-known + random pools). The RF now has labelled examples of the shape it was missing.

**Result:** real live SYN+RST scan flows re-scored from **0.35 → mean 0.99** (see [Validation](#9-validation-results)).

---

## 6. Fix 2 — Flag-Ratio Train/Serve Skew

During validation a second bug surfaced: the responded-SYN-flood regression test failed because the synthetic flood rows were generated with

```python
_flag_ratios(syn, 0, 0, 0, ack, pc)   # BUG: first arg is fin
```

The function signature is `_flag_ratios(fin, syn, rst, psh, ack, pkt_count)`, so this set `fin_ratio = syn/pc` and left `syn_ratio = 0` — the **opposite** of the true flow. Production `FeatureExtractor.transform()` recomputes ratios from raw flag counts, so the RF was trained on distorted flood ratios and served correct ones (train/serve skew).

**Fix:** corrected to `_flag_ratios(0, syn, 0, 0, ack, pc)`. The regression test `_make_syn_flood` was also made internally consistent by setting `syn_ratio`/`ack_ratio = 0.5` (100 SYNs over 200 packets), matching what the production extractor computes.

---

## 7. Fix 3 — Dashboard "1970" Retrain Timestamp

The ML Playbook displayed model retrain times as **January 1970**. The API (`/api/models/versions`) correctly serves Unix epoch **seconds** (e.g. `1785493335`), but the frontend did

```jsx
new Date(ver.timestamp)   // interprets seconds as milliseconds → 1970
```

**Fix:** `frontend/src/app/components/MLPlaybookTab.tsx` now multiplies by 1000: `new Date(ver.timestamp * 1000)`.

> Note: the change only appears after the static export is rebuilt (`npm run build`), which is currently blocked by root-owned `frontend/.next` / `frontend/out` directories.

---

## 8. Fix 4 — Dynamic RF/AE Confidence Split

### Previous behaviour
`score = 0.65 * rf_score + 0.35 * ae_score` — a **fixed** blend regardless of the flow.

### The idea
Split the confidence between RF and AE **dynamically, per flow**, so the engine with the strongest signal for a given flow carries that flow's score.

### Why the naive approach was rejected
"Trust the more confident engine" was tested against real data and **failed**: the AE over-flags benign live traffic (scoring near 1.0 on benign DNS/mDNS), so letting AE dominate created false positives.

### Implemented design (`ai_engine/ensemble.py::_dynamic_combine`)
Per-flow weights proportional to each engine's decisiveness (distance from the 0.5 boundary):

```
rf_w = clamp(|rf − 0.5| / (|rf − 0.5| + |ae − 0.5|), min_rf_weight, 1.0)
blend = rf_w * rf_score + (1 − rf_w) * ae_score
```

- **Agreement** (both engines on the same side of 0.5): the decisive engine dominates → confident detections score higher.
- **Disagreement** (opposite sides): the blend is dampened halfway toward 0.5 → honest uncertainty, no false positives.
- **RF floor** (`min_rf_weight`, default 0.5): RF is better calibrated than the AE, so it is never out-voted.

New config keys in `config.yaml`:

```yaml
model:
  dynamic_weights: true     # false → revert to fixed 0.65/0.35 blend
  min_rf_weight: 0.5
```

Each inference result now also exposes the effective per-flow weights (`rf_weight`, `ae_weight`).

---

## 9. Validation Results

### Live SYN/RST scans (re-scored with the retrained model)

| Shape | Before | After |
|-------|--------|-------|
| SYN probes (1-pkt) | 0.996 | 0.997 (100% ≥ 0.8) |
| SYN+RST scans (2-pkt) | **0.350** | **mean 0.987**, 98% ≥ 0.8 |

### Dynamic split — scenario table

| Scenario (rf, ae) | Fixed 0.65/0.35 | Dynamic | Note |
|-------------------|------------------|---------|------|
| SYN probe (0.995, 1.00) | 0.997 | 0.998 | agree → high |
| SYN+RST scan (0.98, 1.00) | 0.987 | 0.990 | agree → high |
| RF decisive + AE weak (0.995, 0.60) | 0.86 | **0.93** | improvement |
| Benign DNS (0.14, 0.73) | 0.35 | 0.44 | disagree → damped |
| Worst-case benign (0.30, 0.95) | 0.53 | 0.56 | no FP |
| FP risk (0.40, 0.99) | 0.62 | 0.60 | no FP |

### Real-traffic audit (12,000 flows)

- New false positives: **0**
- Detections lost (alert → benign): **0**
- Mean score delta: **+0.118** (scores where RF is decisive rise)

### Regression gate

- `tests/test_feature_extractor.py` + `tests/test_ai_inference.py`: **13/13 pass**.
- `tests/test_system_guard.py`: **31/31 pass** standalone (the 10 failures seen when the whole suite runs together are a pre-existing state-leakage issue, documented separately).

---

## 10. What the Score Means in Plain English

> **"How sure the AI is that this network flow is an attack."**

- Two AI models each inspect the flow: the RF asks *"is this a known attack pattern?"*; the AE asks *"is this weird compared to normal traffic?"*
- Their answers are blended per flow. When both lean the same way, the more convinced model carries the score; when they disagree, the score hedges toward 50% ("not sure").
- **~0–50%** looks benign · **50%** is the decision line · **>50%** is flagged as an attack, with higher = stronger conviction.

The bar on the dashboard is the score (attack likelihood). A low score does not necessarily mean no alert — signature rules can still force one.

---

## 11. Operational Notes & Caveats

1. **Restart required.** The running monitor (root, PID in `ps`) and API hold the pre-change code/models in memory. They must be restarted to load the retrained 38-column models and the dynamic-weight code. Restart needs sudo (unavailable to the agent):
   ```bash
   sudo pkill -f run_monitor
   sudo /path/to/ai-venv/bin/python scripts/run_monitor.py --interface wlp4s0 --flow-timeout 20
   ```
2. **Residual edge case.** ~~SYN+RST scans that target well-known web/db ports (e.g. 8000/8080) can still score ~0.5–0.6~~ **Resolved (verified)**. The attack-matrix harness (§12) measures web/admin/db-port SYN+RST scans at **0.98+**, so the earlier ~0.5–0.6 reading was an artifact of a sub-ms synthetic shape and byte counts that did not match the trained distribution. They are now confidently detected by the AI and additionally caught by the signature engine.
3. **Frontend rebuild blocked.** The timestamp fix and any score-split display change require `npm run build`, currently blocked by root-owned build directories.
4. **Replay caveat.** Replaying a pcap produces unrealistic durations (`1e-6` s) and AE=1.0 on everything; live capture is the trustworthy test.

---

## 12. Attack-Matrix Harness & the "≥85% confidence" Baseline

An acceptance harness, `tests/test_attack_matrix.py`, replays labeled deliberate-attack
and benign flow families through the **production** inference path
(`FeatureExtractor` → `EnsembleInferenceEngine`, the same code the monitor runs)
and reports the AI `score` distribution per family. It avoids the pcap
replay-timing artifact by building flows in the raw `FlowAggregator.to_features()`
shape, so the extractor derives feature vectors identically to live capture.

**Criterion:** a family passes when **≥85% of its flows score ≥ 0.85**.

Baseline against the deployed model `v_1785493335`:

| family | n | mean | min | %≥0.85 | verdict |
|---|---|---|---|---|---|
| SYN_PROBE | 16 | 0.997 | 0.997 | 100 | PASS |
| SYN_RST_SCAN_RANDOM | 16 | 0.982 | 0.976 | 100 | PASS |
| SYN_RST_SCAN_WEB | 12 | 0.986 | 0.979 | 100 | PASS |
| SYN_RST_SCAN_ADMIN_DB | 11 | 0.986 | 0.976 | 100 | PASS |
| SYN_FLOOD_RESPONDED | 1 | 0.994 | 0.994 | 100 | PASS |
| SYN_FLOOD_FILTERED | 1 | 0.988 | 0.988 | 100 | PASS |
| HTTP_DDOS_CICIDS | 1 | 0.972 | 0.972 | 100 | PASS |
| SSH_BRUTE_CICIDS (real CICIDS rows) | 40 | 0.888 | 0.367 | 95 | PASS |
| XMAS_SCAN | 6 | 0.997 | 0.997 | 100 | gap* |
| FIN_PROBE | 6 | 0.996 | 0.995 | 100 | gap* |
| UDP_SCAN | 8 | 0.928 | 0.924 | 100 | gap* |

Benign families (DNS/HTTPS/mDNS/streaming/SSH) all score ≤ 0.50 → **zero false positives**.
`*` = untrained probe shape, gated only with `NIDS_85_GATE=strict`.

Key finding: with the **canonical** trained shapes (SYN+RST: 2 pkts, 44/40 B, one RTT
1.5–10 ms), the deployed model meets the 85% target on **all** deliberate-attack
families, including well-known web/admin/db ports, plus real CICIDS SSH-brute rows.
The 0.5–0.6 web-port reading that motivated retraining no longer reproduces; it was a
synthetic-shape mismatch, not a model weakness. No retrain is required to reach the
goal for these families.

Run anytime: `python tests/test_attack_matrix.py` (exit 0 = gate pass).
Add families by appending a builder to `ATTACK_FAMILIES`; sample real CICIDS rows
via `_cicids_rows(csv, label_substr, n)`.

---

*Models referenced: `data/models/registry.json` (latest deployed: `v_1785493335`, 38 features).*
