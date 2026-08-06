# AI-NIDS Detection Test Guide

Live-fire test guide for validating attack detection using a second machine
(e.g. Kali Linux) attacking the machine that runs the NIDS.

## Scope

This guide covers end-to-end validation of the AI + signature pipeline:

- The AI ensemble (RF 65% / AE 35% blend, dynamic per-flow split) is the primary
  attack/normal judge and must score deliberate attacks **≥ 0.85**.
- Signature rules carry their own explicit `confidence`; alerts can be driven by
  the AI, the signature engine, or both (`driver: ai | signature | both`).
- Benign traffic must stay quiet (zero false positives).

## Prerequisites

| Requirement | Detail |
|---|---|
| NIDS box | This repo, monitor + API running as systemd services |
| Interface | `wlp4s0` (auto-detected from `config.yaml`) |
| HOME_NET | Derived as the interface IP `/32` — only traffic to/from this box is "home" |
| Kali box | Same WiFi/LAN as the NIDS box; root access for raw-packet tools |
| Backend | Restarted so it runs the current alert engine (see below) |

## 1. Restart the backend with current code

The monitor and API hold code in memory at startup — always restart after any
code change before testing:

```bash
sudo systemctl restart ai-nids-api ai-nids-monitor
```

Verify both are healthy:

```bash
systemctl status ai-nids-api --no-pager | head -5
systemctl status ai-nids-monitor --no-pager | head -5
journalctl -u ai-nids-monitor --since "1 min ago" --no-pager | tail
```

The monitor should show it is counting packets on `wlp4s0`.

## 2. Get IPs

```bash
# NIDS box (this machine)
ip -4 -o addr show wlp4s0

# Kali box
ip a | grep inet
```

Both machines must be on the same subnet. Throughout this guide,
`NIDS=<NIDS box IP>`.

## 3. Watch for alerts

**Dashboard:** open `http://<NIDS-IP>:8000` → **Alerts** tab (refresh after each test).

**Live CLI watcher** (on the NIDS box):

```bash
watch -n2 'curl -s "http://localhost:8000/api/alerts?limit=15" | python3 -m json.tool | grep -E "severity|driver|signature_confidence|rule_id|label"'
```

**Or raw JSON for one alert** — what the new fields look like:

```bash
curl -s "http://localhost:8000/api/alerts?limit=1" | python3 -m json.tool
```

Expect the newest alerts to carry:
- `score` — the AI ensemble confidence (0–1)
- `signature_confidence` — probabilistic OR across matched rules (0–1)
- `driver` — `"ai"`, `"signature"`, or `"both"`
- `matched_rules` — array of `{rule_id, name, severity, confidence}`

## 4. Attack test matrix

Run each of the following **as root on Kali**, replacing `NIDS` with the NIDS
box IP. Run the tests in order — each targets a different detection path.

| # | Test | Command (Kali) | Expected detection |
|---|---|---|---|
| 1 | SYN probe, single closed port | `nmap -n -sS -p 8080 $NIDS` | Score ≈ 0.98; `PORT_SCAN` family; 2-pkt SYN→RST canonical shape |
| 2 | Multi-port closed-port scan | `nmap -n -sS -p 8080,8081,9090 $NIDS` | Multiple `PORT_SCAN_*` rules; likely `driver: both` |
| 3 | SYN flood | `hping3 -S -p 80 --flood -c 2000 $NIDS` | Score ≈ 0.99; `SYN_FLOOD_001`; `driver: both` |
| 4 | XMAS scan | `nmap -n -sX -p 443 $NIDS` | Score ≈ 0.99 (untrained probe shape, `NIDS_85_GATE=strict` family) |
| 5 | FIN scan | `nmap -n -sF -p 443 $NIDS` | Score ≈ 0.99; `FIN_SCAN_001` |
| 6 | UDP scan | `nmap -n -sU -p 53 $NIDS` | Score ≈ 0.93 |
| 7 | SSH brute-force | `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$NIDS -o /dev/null` | `BRUTEFORCE_SSH_*`; AI-driven for trained shapes (start with a short wordlist to keep it quick) |

## 5. Control — benign traffic must NOT alert

Run these **on Kali** and confirm **no alerts** appear:

```bash
curl -s -o /dev/null http://$NIDS:8000/   # web request to the API box
ping -c 4 $NIDS                            # ICMP echo
ssh $NIDS 'exit'                           # normal SSH handshake
```

These should stay completely quiet — this is the zero-false-positive check.

## 6. Reading the results

| Signal | Meaning |
|---|---|
| `score` ≥ 0.85 | AI is confident this is an attack (the acceptance gate) |
| `score` < 0.30 | AI is confident this is benign — **suppresses even a rule match** |
| `driver: ai` | Alert came purely from AI conviction |
| `driver: signature` | Alert came from a rule match in the uncertain band (0.30–0.65) |
| `driver: both` | AI and signature engine agree |
| `signature_confidence` | Explicit probability carried by the matched rules alone |

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| No alerts at all | Monitor not capturing: check `journalctl -u ai-nids-monitor` for packet counts; confirm Kali traffic reaches the NIDS IP (same subnet/VLAN) |
| Score is low on an attack | Check the shape: canonical trained shapes (2-pkt SYN→RST, 44/40 B, 1.5–10 ms RTT) score 0.98+; sub-ms RTT or unusual byte counts drop toward 0.5–0.85 |
| Only old fields in API response | Backend not restarted — run step 1 |
| Dashboard looks stale | The UI reads `frontend/out` from disk and updates on refresh; ensure `npm run build` was run after frontend changes and the API is serving it |
| Redis-related noise | `redis.active: true` by default; components fall back to in-memory if Redis is down |

## 8. Reference

- Acceptance harness: `tests/test_attack_matrix.py` — automated 85%-confidence gate (does not need live traffic or a second machine).
- Confidence semantics: `docs/confidence-scoring-report.md` (§10 score meaning, §12 attack-matrix baseline, §13 signature-confidence fusion).
