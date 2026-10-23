# SensorGrind_AI Architecture

## 1. Data model -- the four canonical Parquet tables

The parser emits four Parquet tables, daily-partitioned at
`output/parquet/<table>/dt=YYYY-MM-DD/part-*.parquet`. Every downstream
analyzer reads them via the DuckDB views set up in `sg.lib.register_views`.

### 1.1 `packets`

Per-packet observation. One row per packet seen by the sensor.

| column | type | notes |
| --- | --- | --- |
| ts | timestamp(us, UTC) | packet arrival, microsecond precision |
| src_ip | string | source IPv4 / IPv6 string |
| src_port | uint16 | 0 when L4 has none (ICMP etc.) |
| dst_ip | string | sensor IP the packet hit |
| dst_port | uint16 | 0 when L4 has none |
| proto | uint8 | IANA L4 number (6 TCP, 17 UDP, 1 ICMP, ...) |
| pkt_len | uint16 | wire bytes |
| ip_id, tos, ttl, dg_len | uint8/16 | IP header passthrough |
| tcp_flags | uint8 | bitfield: URG/ACK/PSH/RST/SYN/FIN |
| tcp_seq, tcp_ack | uint32 | sequence numbers |
| tcp_win, tcp_len | uint32/uint16 | window + payload length |
| icmp_type, icmp_code | uint8 | ICMP only |
| sensor_resp | uint8 | sensor response enum (drop/ack/syn-ack/banner/...) |
| payload_sha256 | binary(32) | SHA-256 of the payload bytes (zero-length when no payload) |
| payload_len | uint16 | payload length in bytes |
| l7_proto | uint8 | parser's L7 guess (0=unknown, 1=http, 2=tls, ...) |

The `payload_sha256` deduplicates payloads -- 1.1B packets distil down to
97M distinct payload blobs.

### 1.2 `payload_blobs`

The deduplicated payload corpus. One row per distinct SHA-256.

| column | type | notes |
| --- | --- | --- |
| payload_sha256 | binary(32) | primary key |
| payload_len | uint16 | bytes |
| l7_proto | uint8 | parser's classification |
| bytes | binary | full payload (capped per parser config) |
| strings | list&lt;string&gt; | strings(1)-style extraction over the bytes |

### 1.3 `l7_events`

When the parser recognizes a layer-7 protocol (HTTP, TLS, SSH, RDP, ...) it
emits a structured event with parsed fields. One row per recognized event.

| column | type | notes |
| --- | --- | --- |
| ts | timestamp(us, UTC) | |
| src_ip | string | |
| dst_port | uint16 | |
| l7_proto | uint8 | see `sg.lib.L7_NAME` |
| payload_sha256 | binary(32) | join back to `payload_blobs` |
| fields_json | string | protocol-specific structured payload |

`l7_proto` values: 0 unknown, 1 http, 2 tls, 3 ssh, 4 ftp, 5 smtp, 6 dns,
7 telnet, 8 rdp, 9 smb, 10 mqtt, 11 irc, 12 bittorrent, 13 mirai, 14 mongo,
15 redis, 16 vnc.

### 1.4 `iocs`

Extracted indicators of compromise -- one row per (src_ip, ioc_kind, value).

| column | type | notes |
| --- | --- | --- |
| ts | timestamp(us, UTC) | |
| src_ip | string | who emitted it |
| ioc_kind | uint8 | enum, see `sg.lib.IOC_NAME` |
| value | string | the IOC itself (URL, domain, hash, ...) |
| context | string | free-form context the parser captured |
| l7_proto | uint8 | originating L7 if known |
| payload_sha256 | binary(32) | originating payload |

`ioc_kind` values: 0 url, 1 domain, 2 ipv4, 3 ipv6, 4 file_hash, 5 cmd,
6 cred, 7 mstshash, 8 user_agent, 9 ssh_banner, 10 tls_sni, 11 http_host,
12 http_uri, 13 dns_query.

## 2. Pipeline DAG

37 stages (analyzers, features, ML chain, pattern + longitudinal, deep
packet / payload / behavior, non-IP / origin / attribution, blind-spot
analyzers, **cross-signal conclusions**, output).  Preceded by an
out-of-DAG stage:

- **`scripts/consolidate_logs.py`** -- consolidates raw rotated honeypi00
  syslog `.gz` files into a single sorted, deduplicated, clock-skew-
  corrected `merged.log.gz`.  Honeypi00's RTC has been intermittently
  resetting to 2019-02-14 since 2025-09-23; the consolidator detects
  per-run skew via FortiGate `date= time= tz=` and newsyslog ISO-UTC
  prefix anchors in the same syslog stream, then rewrites both the
  leading ISO column AND each event's body `PacketTime:` field with the
  corrected wallclock time.  Outputs:
    `~/temp/sensor_logs/consolidated/{merged.log.gz, manifest.tsv}`
    `output/reports/clock_skew/clock_skew.{md,parquet}`
    `output/reports/clock_skew/clock_runs.parquet` (one row per clock
    run: corrected start, offset, line count)

The orchestrator (`src/evolve.py`) builds the dependency graph from:

1. **Explicit edges** in `EXPLICIT_DEPS` (the hard ordering requirements).
2. **Inferred edges** by glob-overlap between each stage's declared inputs
   and outputs in `STAGE_IO`.

Topological sort runs first; `--parallel N` then dispatches independent
stages to a `ProcessPoolExecutor`.

### Stage groups

**Foundation**
- `analyzers` -- meta-runner over ~16 base analyzers (`src/sgquery.py`)
- `features` -- builds the per-IP feature snapshot

**ML chain**
- `model` -- `train_threat_classifier` (LightGBM, temporal split, SHAP)
- `score` -- batch-score every IP with the current model
- `risk` -- composite risk score (ML * persistence * breadth * exploit *
  botnet * infra)
- `dossiers` -- per-IP markdown dossiers for tier >= high

**Pattern + longitudinal**
- `mining`, `promote` -- FP-Growth + Wilson-LCB promotion
- `actors` -- HDBSCAN cluster discovery
- `drift` -- Wasserstein + PSI + BH-FDR
- `longitudinal`, `chains`, `sequences`, `coordination`, `rotation`,
  `cross_modal`, `survival`

**Deep packet / payload / behavior**
- `pktanalysis`, `payloadanalysis`, `pacing`, `landscape`, `protocolanomaly`,
  `isc_compare`

**Non-IP / origin / attribution**
- `nonipproto` -- non-IP-protocol decoding
- `aipayloaddecode` -- AI-driven payload understanding (downstream of nonipproto)
- `asnintel`, `cidrintel`, `tooling`
- `actorlink` -- Leiden community detection on the cooperating-actor graph
- `originintel` -- AI-driven actor profiling per community

**Blind-spot analyzers (v2.5, added per multi-AI review)**
- `slowlow` -- slow-and-low scanners with /24 distributed-scan roll-up
- `dnstlsintel` -- TLS SNI + DNS qname intel with DGA-entropy and
  brand-mimic flags
- `selfmimic` -- detects inbound echo of the sensor's own banners
- `adversarysim` -- synthetic-archetype regression harness.  With
  `--inject NAME --day D` it instead writes full `packets`-schema rows
  for one background day to `output/eval/inject/NAME/` (plus
  `truth.parquet`); `sg.lib.register_eval_views(con, NAME)` overlays them
  on the real corpus as one `packets` view.  Operator-run, not a DAG step.

**Sensor mask + baselines (v3.3, Phase 0 of the neuromorphic plan)**
- `sensormask` -- intervals that stateful detectors must drop from fit
  windows and reset state at: `gap` (>= 30 silent minutes, from packets)
  and `run_boundary` (+/- 5 s around each clock-skew run start, from
  `clock_runs.parquet`).  Read via `sg.lib.load_sensor_mask()` or the SQL
  fragment `sg.lib.mask_predicate('ts')`.
- `bench/baselines.py --eval NAME` (operator-run) -- source-level
  (random, pkt_count, n_ports, new_port_24, IForest, ECOD) and
  global-minute (random, hour-of-day z, STL residual z, per-port hourly z)
  detectors, fit on the 7 recorded days before the injection day.
  Reports recall@k with its chance level, no point adjustment.  Any new
  detector must beat these numbers on the same injection set.
  See section 9 for the full plan and the data contracts.

**Cross-signal conclusions (v2.6, added 2026-05-29)**
- `correlate` -- runs 18 hand-coded cross-analyzer rules over every
  per-analyzer parquet + the risk snapshot, producing
  `output/conclusions/findings.parquet`.  Rules include:
    * `telco_ss7_recon` -- SCTP from sources also scanning telco TCP
      ports (SIP 5060/5061, M3UA 2905, Diameter 3868, S1AP 36412, GTP
      2123/2152)
    * `routing_proto_on_public_ip` -- OSPF/EIGRP/PIM/VRRP arrivals
    * `ipsec_probe_from_scanner` -- ESP/AH arrivals from scanners
    * `covert_tunnel_setup` -- IP-in-IP / 6to4 / GRE / ETHERIP arrivals
    * `multi_transport_bulletproof` -- sources mixing TCP+UDP+ICMP with
      payload from bulletproof ASNs
    * `botnet_in_coordination_wave` -- confirmed-botnet IPs inside
      payload-synchronized waves
    * `synchronized_campaign_burst` -- >=5 distinct campaigns sharing
      the same peak day (coordinated push)
    * `recent_tight_campaign` -- last-60-days campaigns with burst < 7d
      and >= 500 IPs
    * `bulletproof_high_density_asns` -- abuse-tolerant ASNs with
      >50% threat density
    * `rdp_credential_spray` -- single mstshash reused across many IPs
    * `low_slow_subnet_coordinated`, `wrong_proto_for_port`,
      `icmp_payload_anomalies`, `tcp_midstream_or_syn_payload`,
      `global_arrival_burst`, `local_only_targeted_ports`,
      `honeypot_aware_self_mimic`, `critical_persistent_botnet`
- `conclude` -- for each finding, calls the configured LLM
  (anthropic / openai / xai / mistral / gemini, first key + SDK wins;
  same provider-discovery pattern as `aipayloaddecode`) to write a
  structured narrative: `ai_title`, `ai_what`, `ai_why_noteworthy`,
  `ai_threat_model`, `ai_risk_if_realized`, `ai_recommended_action`,
  `ai_confidence`.  Responses are cached by sha256 of the rendered
  prompt under `output/ai_cache/conclude_*.json`, so re-runs are free
  unless `--force`.  Outputs `output/conclusions/conclusions.{parquet,md}`
  which the comprehensive report consumes as Section 0.5.

**Output**
- `report` -- composes 25+ sections incl. Section 0 (TL;DR), Section 0.5
  (Cross-Signal Findings & Conclusions), and Section 6
  (campaign-onset).  Campaign Gantt is rendered as a matplotlib SVG
  (`svg_gantt_chart` in `src/report/render.py`) with month-year axis
  labels, gray dashed gridlines, and on-bar labels (white inside,
  black outside with gray connector for short bars).
- `aireview` -- multi-AI self-review (Claude, OpenAI, xAI, Mistral, Gemini)

### Skip-if-fresh cache

Each stage entry in `STAGE_IO` declares input + output globs. Before
running a stage, the orchestrator:

1. Loads `.evolve/freshness.json`.
2. Looks up `cmd_hash` (SHA-1 of the command + the stage's source mtime).
3. If `cmd_hash` matches AND every output exists AND the oldest output is
   newer than the newest input, **skip**.
4. Otherwise, run; on success, record the new `cmd_hash` + timestamp.

`--force` bypasses; `--no-cache` disables read AND write.

### Failure propagation

When a stage fails, its downstream dependents are **aborted without
running** rather than silently re-using stale output. The orchestrator
reports `passed / skipped / failed` at the end with the failed-stage
names so the operator knows exactly what to re-run.

## 3. Model registry contract

Trained models are persisted via `sg.models` to
`output/models/<name>/v<N>/`. The contract:

```
output/models/
  registry.json                  # cross-process file-locked
  threat_classifier/
    v1/
      model.joblib               # joblib.dump of the LGBMClassifier
      metadata.json              # ModelInfo as JSON
      shap_explainer.joblib      # TreeExplainer (when SHAP is installed)
      shap_val_sample.npy        # SHAP value matrix on the val sample
    v2/
    ...
  actor_clusterer/
    v1/ ...
```

### `ModelInfo` (dataclass in `sg/models.py`)

| field | meaning |
| --- | --- |
| name | model name (`threat_classifier`, `actor_clusterer`, ...) |
| version | monotonically increasing int (allocated under the registry lock) |
| model_type | `"lightgbm.LGBMClassifier"`, `"hdbscan.HDBSCAN"`, ... |
| feature_set | `"ip:v1"` etc. -- joins to the feature snapshot used |
| training_rows | n rows used to fit |
| training_range | (since, until) ISO strings |
| trained_at | ISO timestamp |
| metrics | free-form dict; see per-model conventions below |
| is_current | bool -- whether `load_current()` will return this entry |

### `registry.json` write protocol

The registry is a JSON file `{ "<name>": [ModelInfo dicts, ...] }`. Both
`next_version` and `save_model` wrap their read-modify-write cycle in
a `filelock.FileLock` on `registry.json.lock` -- this stops parallel
training stages losing each other's entries.

Corrupt-JSON recovery: if `registry.json` ever fails to parse, it is
backed up to `registry.json.corrupt.<unix-ts>` and a fresh registry is
started. The original is never deleted.

### threat_classifier metrics

```json
{
  "auc": 0.9970,
  "ap": 0.9990,
  "brier": 0.0143,
  "split_mode": "temporal",
  "unlabeled_positive_rate": 0.214,
  "n_train": 793000,
  "n_val": 199000,
  "n_threat": 167000,
  "n_benign": 825000,
  "n_unknown": 532000,
  "feature_importance": { "anomaly_score": 1830, ... },
  "shap_global": { "anomaly_score": 0.412, ... }
}
```

`split_mode = "temporal"` means the val set is the most-recent 20% by
`first_seen`. `brier` is the calibration metric (lower = better-calibrated
probabilities). `unlabeled_positive_rate` is the fraction of unlabeled IPs
the model scores above 0.5 -- a PU-learning sanity check.

### actor_clusterer metrics

```json
{
  "n_clusters": 28,
  "n_noise": 19450,
  "n_stable_clusters": 14,
  "min_cluster_size": 30,
  "min_samples": 5,
  "min_persistence": 0.10,
  "relative_validity_dbcv": 0.317,
  "mean_persistence": 0.184
}
```

`n_stable_clusters` is the count above the persistence gate. The
per-cluster persistence is in the cluster summary parquet; report consumers
gate "real" clusters on `stable=true`.

## 4. Feature snapshot contract

Built by `src/features/build_ip_features.py`. Persisted at
`output/features/ip/v<FEATURE_VERSION>/<snapshot_date>/part-0000.parquet`
with a sibling `manifest.json` listing the columns + their version.

Each row is one source IP. The columns currently consumed by
`threat_classifier` and `actor_clusterer` are:

```
pkt_count, byte_count, day_count, span_days, pkts_per_active_day,
pct_tcp, pct_udp, pct_icmp, pct_syn_only,
ttl_mode, tcp_win_mode, port_count, port_diversity,
pct_with_payload, distinct_payloads, avg_payload_len,
l7_event_count, l7_distinct_protos,
ioc_count, distinct_uas, distinct_uris,
anomaly_score, burstiness_cv,
country_iso, asn, asn_org, l7_dominant, benign_org, botnet_family,
first_seen, last_seen, ...
```

Heavy-tailed counts (`pkt_count`, `byte_count`, `port_count`, ...) are
log1p-transformed and robust-z-scored (median / 1.4826 * MAD) before
clustering, so wild-tail IPs do not dominate the distance metric.

The `latest_snapshot(name, version)` helper is the canonical way to find
the current snapshot; never glob the directory directly.

## 5. The `Report` writer

Every analyzer module returns a `sg.lib.Report(name, rows, schema, markdown)`
which `lib.Report.write()` atomically persists as `output/reports/<name>/<name>.parquet`
plus a `.md` summary. Two important properties:

1. **Atomic writes**: data goes to `<name>.parquet.tmp` first, then
   renamed. A crash mid-write never leaves a half-written parquet.
2. **Empty-table safety**: when `rows` is empty, an empty Arrow table is
   still written with the declared schema -- not zero bytes. Downstream
   `read_parquet(...)` therefore works even on empty results, removing a
   class of "schema not found" failures.

## 6. Determinism + reproducibility

- All randomized algorithms (LightGBM, HDBSCAN, Leiden, train/test split,
  itemset sampling) seed deterministically.
- The freshness cache hashes both the CLI invocation AND the source file's
  mtime. Editing a stage's defaults invalidates its cache automatically.
- Stages write to `<output>.tmp` and rename, so an interrupted run does
  not leave a half-written file masquerading as fresh.
- The model registry write is file-locked, so parallel `--parallel N`
  runs cannot lose each other's entries.

## 7. Configuration surfaces

- **`SG_DUCK_MEM`** -- DuckDB memory budget override (default per-stage).
- **`SG_DUCK_TMPDIR`** -- DuckDB spill directory (defaults to system temp).
- **`SG_MMDC`** -- path to the `mmdc` binary for PDF Mermaid pre-rendering.
- **`SG_PUPPETEER_CONFIG`** -- Puppeteer config JSON for sandboxed `mmdc`.

CLI arguments override defaults; see each stage's `--help`.

## 8. What is NOT here

- **`scripts/`** is legacy -- do not put new code there.
- **`data/`** is for SOURCE input -- do not write outputs to it.
- **Sensitive data**: `*.key.txt` are gitignored. The honeypot log is large
  and operator-specific; do not commit it.

## 9. Neuromorphic detection plan

The plan comes from `reports/Neuromorphic anomaly detection for honeypi.md`.
The research notes are in `research_notes/Neuromorphic anomaly detection for honeypi/`.

The research found no published result where an SNN, HDC, reservoir, or
HTM model is better than isolation forest or ECOD on network anomaly data.
Also, no study used honeypot, darknet, or telescope data. Thus the plan does
not try to get a better accuracy number. It adds three signals that the
current batch, per-IP, threshold pipeline cannot calculate:

| Signal | Primitive | Current module that it extends |
| --- | --- | --- |
| Graded similarity between session chains | HDC (MAP or BSC) on `chainfp` tokens | `chainfp`, `compositeprint` |
| Adaptive baseline for the global arrival series | ESN or NG-RC, with the HTM anomaly-likelihood layer | `detect_coordination` (5x tail-median rule) |
| Timing surprise for each event of a source | Event-driven LIF or ALIF | `pacing` (full-history IAT quantiles) |

### 9.1 Phases and exit gates

Each phase has an exit gate. Do not start the next phase until the current
phase passes its gate.

| Phase | Build | Status | Exit gate |
| --- | --- | --- | --- |
| 0. Prerequisites | `sensormask`, `clock_runs.parquet`, `adversarysim --inject`, `bench/baselines.py` | Built (v3.3) | The baselines give numbers on injected archetypes |
| 1. HDC choreography novelty | n-gram session vectors from `chainfp` tokens and tempo, `k` sub-prototypes for each day, fast and slow actor prototypes | Not started | Better than string rarity and the RFF baseline on `chain_mutation`. The top-k is stable across seeds. |
| 2. Global arrival detector | ESN or NG-RC on vectors for each minute, residual into the HTM likelihood layer (`W` of 2 to 8 weeks, Benjamini-Hochberg across series) | Not started | Flags the three known events. Fewer incorrect alarms each year than the 5x tail-median rule and `stl_z`. |
| 3. Timing for each source | Event-driven LIF or ALIF with some different `tau` values, only for sources with 20 or more packets | Not started | Better than `pacing` and an untrained LIF on `jittered_beacon` and `rhythm_change` |
| 4. Feature and risk inputs | Score columns in `build_ip_features`, then a capped risk term | Not started | Operator precision@k increases. Balance the tier counts again. |
| 5. Optional research | WTA-STDP port-retina prototypes, Akida demonstration on a Pi 5 | Not started | Only if Phases 1 to 3 show value |

The three known events for Phase 2 are:

1. The 2024-06-24 burst from 07:30 to 07:50 PDT.
2. The SSH campaign from 2026-04-27 to 2026-05-01.
3. The coordinated push on 2026-05-19.

### 9.2 Phase 0 data contracts

**`output/reports/clock_skew/clock_runs.parquet`** (written by
`scripts/consolidate_logs.py`, one row for each clock run that has lines)

| Column | Type | Meaning |
| --- | --- | --- |
| `src` | string | Source log file |
| `run_idx` | uint32 | Run number in the file |
| `run_start_ts` | timestamp UTC | Corrected start of the run |
| `orig_pt` | timestamp UTC | PacketTime before the correction |
| `offset_s` | float64 | Offset that the consolidator applied |
| `anchor_kind` | string | `anchor` or `filename` |
| `lines` | uint64 | Sensor lines in the run |

This file exists only after a consolidator run with the v3.3 code. If the
file is not there, `sensormask` writes `gap` intervals only.

**`output/reports/sensormask/sensormask.parquet`** (`lib.SENSORMASK_SCHEMA`)

| Column | Type | Meaning |
| --- | --- | --- |
| `start_ts` | timestamp UTC | Start of the interval in the mask |
| `end_ts` | timestamp UTC | End of the interval in the mask (not included) |
| `kind` | string | `gap` or `run_boundary` |
| `duration_s` | float64 | Interval length |
| `source` | string | Origin of the interval |

A `gap` is 30 or more minutes, one after the other, with zero packets
(`--gap-minutes`). A `run_boundary` is 5 s before and after each clock-run
start (`--boundary-pad-seconds`). The 2025-11-12 to 2026-01-28 outage is a
`gap` interval.

**`output/eval/inject/<NAME>/`** (written by `adversarysim.py --inject NAME --day D`)

- `packets/dt=D/*.parquet` has the `packets` columns. The header fields
  come from samples of the recorded SYN traffic of day D.
- The injected sources are new routable addresses that are not in the
  corpus.
- `truth.parquet` has one row for each injected archetype instance:
  `archetype`, `level` (`source` or `global`), `src_ip` (NULL for
  `global`), `start_ts`, `end_ts`, `n_packets`, `is_control`, `note`.

The inject archetypes are `fast_scanner`, `slow_scanner`,
`distributed_brute`, `jittered_beacon`, `lockstep_24`, `rhythm_change`,
`chain_mutation`, `burst_replay` (global), and `control_replay`. The
`control_replay` rows are copies of ordinary sources from the corpus, with
new addresses.
A good detector does not flag them.

**`output/reports/baselines/baselines_<NAME>.parquet`** (written by
`bench/baselines.py --eval NAME`)

| Column | Meaning |
| --- | --- |
| `eval_name`, `level`, `detector`, `archetype`, `is_control` | Row key |
| `n_truth`, `k`, `hits`, `recall` | Recall at a fixed alert budget `k` |
| `chance` | Recall that a random score gets at the same `k` |
| `median_rank` | Median rank of the archetype sources (source level) |
| `ttd_s` | Time to detection in seconds (global level) |

The baselines fit on the 7 recorded days before D (`--fit-days`), without the
intervals in the mask. The default budgets are `k` = 10, 100, 1000 for
sources and `k` = 10, 60 for minutes. The harness skips global windows
longer than 120 minutes (`--max-global-window-min`), because a random
detector can hit a long window.

### 9.3 Rules for each detector that keeps state

1. Remove the time in the mask from fit windows. Use `lib.mask_predicate('ts')` in
   SQL, or `lib.load_sensor_mask()` in Python. Both give "no mask" when
   the `sensormask` stage did not run.
2. Reset the state for each entity at each `end_ts` of the mask. If you do
   not do this, the detector learns the outage as usual quiet time and
   flags the restart as a large burst.
3. Keep the state file out of the `STAGE_IO` outputs glob. If not, the
   skip-if-fresh cache gives incorrect results.
4. Keep the `neuro` stage upstream of `features`. Read
   `benignfilter.parquet` directly. If `features` joins `neuro.parquet` and
   `neuro` reads the feature snapshot, the DAG has a cycle.
5. Do not put a neuromorphic score into `bootstrap_label`. Those labels come
   from the same features that LightGBM uses. Thus the result is circular.
6. Do not use `truth.parquet` as operator labels. Injected rows do not go
   into `label_queue`.
7. Compare each new detector with `bench/baselines.py` and with an untrained
   copy of the same model, on the same injection set. Do not use
   point-adjusted F1.

### 9.4 Planned `neuro` stage

The `neuro` stage follows the `chainfp` precedent:

```python
STAGES["neuro"] = [str(SRC / "neuro.py")]
EXPLICIT_DEPS["neuro"] = ["analyzers", "cluster", "chainfp", "sensormask"]
STAGE_IO["neuro"] = {
  "inputs":  ["output/parquet/packets/**/*.parquet", "src/neuro.py"],
  "outputs": ["output/reports/neuro/neuro.parquet",
              "output/models/neuro_detector/**/model.joblib"]}
```

Use this toolchain:

1. Write numba kernels for LIF, ALIF, and HDC. A local benchmark gave
   74.8M LIF events/s and 21.6M HDC packets/s on the workstation CPU.
2. Use NumPy for the ESN and NG-RC ridge readouts and for the HTM
   likelihood layer.
3. Do not use Lava or lava-dl. Intel archived them in May 2026.
4. Do not use htm.core. It has the AGPL-3.0 license and had no release
   since 2021.
