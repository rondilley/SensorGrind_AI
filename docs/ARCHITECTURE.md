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

35 stages. The orchestrator (`src/evolve.py`) builds the dependency graph
from:

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
- `adversarysim` -- synthetic-archetype regression harness

**Output**
- `report` -- composes the 17-section comprehensive report (+ Section 0)
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
