# SensorGrind_AI Architecture

## 1. Data model: the four canonical Parquet tables

The parser writes four Parquet tables, with one partition for each day, at
`output/parquet/<table>/dt=YYYY-MM-DD/part-*.parquet`. Each analyzer reads
them through the DuckDB views that `sg.lib.register_views` makes.

The `parse` step of the DAG (`src/parser.py`) makes these tables from the
raw sensor log. `src/sg/sensorlog.py` reads the log for the parser and for
`nonipproto`. The input can be one of these types:

- **A gzip file.** The reader finds the gzip format from the first two
  bytes (`1f 8b`), not from the file name. `zcat` decompresses it in a
  child process.
- **An ASCII file.** An example is `honeypi_sensor.log` from
  `honeypi_logs.py`.
- **A folder.** The reader uses each gzip file and each ASCII file in the
  folder. It does not read the subfolders. Thus a folder that holds a
  merged log and the `raw/` files of that log does not give each line two
  times.

The reader removes the `<ISO_UTC>\t` prefix of the `merged.log.gz` lines.
For a folder, the lines of each file must be in time sequence. The
reader merges the files in these steps:

1. The reader gets the first `PacketTime` of each file. It ignores binary
   files and files with no `PacketTime` line in the first 4 MB.
2. It puts the files in the sequence of their first `PacketTime`.
3. It opens a file only when the merge gets to the first `PacketTime` of
   that file. Thus files with no overlap open one at a time, and files
   with an overlap merge correctly.

The reader does not remove duplicate lines that occur in more than one
file.

The parser does not write into a Parquet root that has data in it. The
day files of a previous parse can mix with the new parse. Thus the parser
does these steps:

1. It writes the tables to `<output>.partial`.
2. When the parse completes, it moves the root of the last parse to
   `<output>.prev`. It deletes the `<output>.prev` of the run before. The
   `*_clustered` tables move with that root, and the `cluster` step
   makes them again.
3. It moves `<output>.partial` to `<output>`.

If the writer process stops, the parser stops the workers and gives the
exit code 1. `<output>` does not change. The next parse deletes the
remaining `<output>.partial`.

### 1.1 `packets`

This table has one row for each packet that the sensor saw.

| Column | Type | Notes |
| --- | --- | --- |
| ts | timestamp(us, UTC) | Packet arrival time, with microsecond precision |
| src_ip | string | Source IPv4 or IPv6 address |
| src_port | uint16 | 0 when the L4 protocol has no port (ICMP and others) |
| dst_ip | string | Sensor IP address that the packet went to |
| dst_port | uint16 | 0 when the L4 protocol has no port |
| proto | uint8 | IANA L4 number (6 TCP, 17 UDP, 1 ICMP, and others) |
| pkt_len | uint16 | Bytes on the wire |
| ip_id, tos, ttl, dg_len | uint8/16 | Values from the IP header |
| tcp_flags | uint8 | Bit field: URG, ACK, PSH, RST, SYN, FIN |
| tcp_seq, tcp_ack | uint32 | Sequence numbers |
| tcp_win, tcp_len | uint32/uint16 | Window and payload length |
| icmp_type, icmp_code | uint8 | ICMP only |
| sensor_resp | uint8 | Sensor response enum (drop, ack, syn-ack, banner, and others) |
| payload_sha256 | binary(32) | SHA-256 of the payload bytes (zero length when there is no payload) |
| payload_len | uint16 | Payload length in bytes |
| l7_proto | uint8 | L7 protocol that the parser found (0 unknown, 1 http, 2 tls, and others) |

The `payload_sha256` column removes the duplicate payloads. The 1.1 billion
packets have only 97 million different payload blobs.

### 1.2 `payload_blobs`

This table is the payload corpus without duplicates. It has one row for each
different SHA-256.

| Column | Type | Notes |
| --- | --- | --- |
| payload_sha256 | binary(32) | Primary key |
| payload_len | uint16 | Bytes |
| l7_proto | uint8 | Parser protocol class |
| bytes | binary | Full payload (the parser configuration sets the maximum length) |
| strings | `list<string>` | Text strings from the bytes, as `strings(1)` finds them |

### 1.3 `l7_events`

The parser writes one row when it finds a layer-7 protocol (HTTP, TLS, SSH,
RDP, and others). Each row has the fields that the parser got from the
protocol.

| Column | Type | Notes |
| --- | --- | --- |
| ts | timestamp(us, UTC) | |
| src_ip | string | |
| dst_port | uint16 | |
| l7_proto | uint8 | Refer to `sg.lib.L7_NAME` |
| payload_sha256 | binary(32) | Join key to `payload_blobs` |
| fields_json | string | Protocol fields, as JSON |

`l7_proto` values: 0 unknown, 1 http, 2 tls, 3 ssh, 4 ftp, 5 smtp, 6 dns,
7 telnet, 8 rdp, 9 smb, 10 mqtt, 11 irc, 12 bittorrent, 13 mirai, 14 mongo,
15 redis, 16 vnc.

### 1.4 `iocs`

This table has the indicators of compromise (IOC) that the parser found. It
has one row for each combination of `src_ip`, `ioc_kind` and `value`.

| Column | Type | Notes |
| --- | --- | --- |
| ts | timestamp(us, UTC) | |
| src_ip | string | Source that sent the IOC |
| ioc_kind | uint8 | Enum, refer to `sg.lib.IOC_NAME` |
| value | string | The IOC (URL, domain, hash, and others) |
| context | string | Text near the IOC that the parser kept |
| l7_proto | uint8 | Source L7 protocol, if the parser knows it |
| payload_sha256 | binary(32) | Source payload |

`ioc_kind` values: 0 url, 1 domain, 2 ipv4, 3 ipv6, 4 file_hash, 5 cmd,
6 cred, 7 mstshash, 8 user_agent, 9 ssh_banner, 10 tls_sni, 11 http_host,
12 http_uri, 13 dns_query.

## 2. Pipeline DAG

The DAG has 48 steps in these groups:

- Parse
- Analyzers, features and the ML chain
- Pattern and longitudinal analysis
- Deep packet, payload and behavior analysis
- Non-IP, source-country and attribution analysis
- Blind-spot analyzers
- **Cross-signal results** (`correlate`, `conclude`)
- Output

One step can run before the DAG:

- **`scripts/consolidate_logs.py`** puts the raw honeypi00 syslog `.gz`
  files into one sorted `merged.log.gz` file. It removes duplicate lines and
  corrects the clock skew.
- Since 2025-09-23, the honeypi00 RTC sometimes goes back to 2019-02-14.
- The consolidator finds the skew of each clock run from two anchors in the
  same syslog stream: the FortiGate `date= time= tz=` fields and the
  newsyslog ISO-UTC prefix.
- Then it writes the corrected wall-clock time into the first ISO column
  and into the `PacketTime:` field of each line.
- Outputs:
  - `~/temp/sensor_logs/consolidated/{merged.log.gz, manifest.tsv}`
  - `output/reports/clock_skew/clock_skew.{md,parquet}`
  - `output/reports/clock_skew/clock_runs.parquet` (one row for each clock
    run: corrected start, offset, line count)
- `honeypi_logs.py` (outside the repository) makes an equivalent log,
  `honeypi_sensor.log`. This log is ASCII, with no ISO prefix.
- Give one of the two logs to `evolve.py --input`.

The orchestrator (`src/evolve.py`) makes the dependency graph from two
sources:

1. **Explicit edges** in `EXPLICIT_DEPS`. These edges are the hard order
   requirements.
2. **Inferred edges**. The orchestrator finds these edges where the input
   globs of a step in `STAGE_IO` match the output globs of a different step.

Each step with no other parent step gets `parse` as its parent. Thus a new
parse completes before each other step that reads the Parquet tables.

The topological sort runs first. Then `--parallel N` sends the steps that have no
dependency between them to a `ProcessPoolExecutor`.

### Step groups

**Parse**
- `parse`: makes the four Parquet tables from the raw sensor log
  (`src/parser.py`).
  - It starts only with `evolve.py --input LOG`. The orchestrator adds LOG
    to the command of the step.
  - Without `--input`, the orchestrator does not start the step, and the
    other steps use the tables that are on the disk.
  - `nonipproto` is the other step that reads the raw log. It gets the
    same `--input`, and it has the same rule.

**Foundation**
- `analyzers`: runs approximately 16 base analyzers (`src/sgquery.py`).
- `features`: makes the feature snapshot for each IP address.

**ML chain**
- `model`: `train_threat_classifier` (LightGBM, temporal split, SHAP).
- `score`: gives a score to each IP address with the current model.
- `risk`: composite risk score (ML × persistence × `breadth` × exploit ×
  botnet × infrastructure). `breadth` counts the different ports and
  payloads of the source.
- `dossiers`: one markdown dossier for each IP address with a tier of high
  or more.

**Pattern and longitudinal**
- `mining`, `promote`: FP-Growth and Wilson-LCB promotion.
- `actors`: HDBSCAN cluster discovery.
- `drift`: Wasserstein, PSI and BH-FDR.
- `longitudinal`, `chains`, `sequences`, `coordination`, `rotation`,
  `cross_modal`, `survival`.

**Deep packet, payload and behavior**
- `pktanalysis`, `payloadanalysis`, `pacing`, `landscape`, `protocolanomaly`,
  `isc_compare`.

**Non-IP, source country and attribution**
- `nonipproto`: decodes protocols that are not IP.
- `aipayloaddecode`: AI analysis of payloads (after `nonipproto`).
- `asnintel`, `cidrintel`, `tooling`.
- `actorlink`: Leiden community detection on the graph of actors that
  operate together.
- `originintel`: an AI profile of the actors in each community.

**Blind-spot analyzers (v2.5, from the multi-AI review)**
- `slowlow`: finds slow scanners that send a small number of packets, with a roll-up of
  scans that come from many addresses in one /24.
- `dnstlsintel`: TLS SNI and DNS qname analysis, with flags for DGA entropy
  and for names that copy a brand.
- `selfmimic`: finds inbound traffic that sends back the banners of the
  sensor.
- `adversarysim`: a regression harness with synthetic archetypes.
  - With `--inject NAME --day D`, it writes full rows in the `packets`
    schema for one background day to `output/eval/inject/NAME/`. It also
    writes `truth.parquet`.
  - `sg.lib.register_eval_views(con, NAME)` adds these rows to the recorded
    corpus in one `packets` view.
  - The operator runs it. It is not a DAG step.

**Sensor mask and baselines (v3.3, Phase 0 of the neuromorphic plan)**
- `sensormask`: makes the intervals that each stateful detector must remove
  from its fit windows. The detector must also set its state to zero at
  these intervals.
  - `gap`: 30 or more minutes with no packets.
  - `run_boundary`: 5 s before and after the start of each clock-skew run,
    from `clock_runs.parquet`.
  - Read the mask with `sg.lib.load_sensor_mask()` or with the SQL fragment
    `sg.lib.mask_predicate('ts')`.
- `bench/baselines.py --eval NAME` (the operator runs it): baseline
  detectors that fit on the 7 recorded days before the injection day.
  - Source level: random, pkt_count, n_ports, new_port_24, IForest, ECOD.
  - Global minute level: `random`, `hour-of-day z`, `STL residual z`,
    and an hourly z for each port.
  - It gives recall@k with its chance level, and no point adjustment.
  - Each new detector must be better than these numbers on the same
    injection set.
  - Refer to section 9 for the full plan and the data contracts.

**Cross-signal results (v2.6, added 2026-05-29)**
- `correlate`: applies 18 cross-analyzer rules to all the analyzer
  parquet files and the risk snapshot. It writes
  `output/conclusions/findings.parquet`. Some of the rules are:
  - `telco_ss7_recon`: SCTP from sources that also scan telco TCP ports
    (SIP 5060/5061, M3UA 2905, Diameter 3868, S1AP 36412, GTP 2123/2152).
  - `routing_proto_on_public_ip`: OSPF, EIGRP, PIM or VRRP arrivals.
  - `ipsec_probe_from_scanner`: ESP or AH arrivals from scanners.
  - `covert_tunnel_setup`: IP-in-IP, 6to4, GRE or ETHERIP arrivals.
  - `multi_transport_bulletproof`: sources that send TCP, UDP and ICMP,
    with payload, from bulletproof ASNs.
  - `botnet_in_coordination_wave`: known botnet IP addresses in waves that
    send the same payload at the same time.
  - `synchronized_campaign_burst`: 5 or more different campaigns that have
    the same peak day (a coordinated push).
  - `recent_tight_campaign`: campaigns in the last 60 days with a burst of
    less than 7 days and 500 or more IP addresses.
  - `bulletproof_high_density_asns`: ASNs that permit abuse, with a threat
    density of more than 50%.
  - `rdp_credential_spray`: one mstshash that many IP addresses use.
  - `low_slow_subnet_coordinated`, `wrong_proto_for_port`,
    `icmp_payload_anomalies`, `tcp_midstream_or_syn_payload`,
    `global_arrival_burst`, `local_only_targeted_ports`,
    `honeypot_aware_self_mimic`, `critical_persistent_botnet`.
- `conclude`: sends each finding to the configured LLM, and gets a
  structured narrative back.
  - The providers are anthropic, openai, xai, mistral and gemini. The first
    provider with a key and an installed SDK is the one that the step uses.
    `aipayloaddecode` uses the same method to find its provider.
  - The narrative fields are `ai_title`, `ai_what`, `ai_why_noteworthy`,
    `ai_threat_model`, `ai_risk_if_realized`, `ai_recommended_action` and
    `ai_confidence`.
  - The step keeps each response in `output/ai_cache/conclude_*.json`, with
    the sha256 of the prompt as the key. Thus a second run costs nothing,
    unless you use `--force`.
  - It writes `output/conclusions/conclusions.{parquet,md}`. The full report
    uses this file for Section 0.5.

**Output**
- `report`: makes 25 or more sections. These include Section 0 (summary),
  Section 0.5 (`Cross-Signal Findings & Conclusions`) and Section 6
  (campaign start).
  - Section 1 shows the sensor outages. An outage is a run of UTC days
    with no `packets` day partition. `sensor_outages()` reads the
    partition names, and it does not start a query.
  - The campaign Gantt chart is a matplotlib SVG (`svg_gantt_chart` in
    `src/report/render.py`).
  - It has month-year labels on the axis and gray dashed grid lines.
  - Each bar has a label. The label is white in the bar, or black near a
    short bar with a gray line to the bar.
- `aireview`: a review of the report by many AI providers (Claude, OpenAI,
  xAI, Mistral, Gemini).

### Skip-if-fresh cache

Each step in `STAGE_IO` has input and output globs. Before the
orchestrator starts a step, it does these steps:

1. It loads `.evolve/freshness.json`.
2. It gets the `cmd_hash`: the SHA-1 of the command and the mtime of the
   source file of the step.
3. It does not start the step when it finds all these conditions:
   - The `cmd_hash` is the same.
   - All outputs are there.
   - The oldest output is newer than the newest input.
4. If not, it starts the step. If the step completes, it keeps the new
   `cmd_hash` and the time.

For `parse` and `nonipproto`, the inputs also include the `--input` file,
or the files in the `--input` folder. The `cmd_hash` includes the
`--input` path. Thus a different log, a changed log or a different path
makes the step stale.

`--force` starts the step at all times. `--no-cache` stops the read and the
write of the cache.

### Failure of a step

When a step has a failure, the orchestrator does not start the steps that
use its outputs. Thus these steps do not use stale outputs. At the end, the
orchestrator gives the counts `passed / skipped / failed`. It also gives the
names of the steps with a failure. The operator then knows which steps to
start again.

## 3. Model registry contract

After training, `sg.models` keeps the models in `output/models/<name>/v<N>/`. The
contract is:

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

| Field | Meaning |
| --- | --- |
| name | Model name (`threat_classifier`, `actor_clusterer`, and others) |
| version | Integer that only increases. The code sets it while it has the registry lock. |
| model_type | `"lightgbm.LGBMClassifier"`, `"hdbscan.HDBSCAN"`, and others |
| feature_set | `"ip:v1"` and others. It shows the feature snapshot that the model used. |
| training_rows | Number of rows for the fit |
| training_range | (since, until) ISO strings |
| trained_at | ISO timestamp |
| metrics | Dict with no fixed fields. Refer to the model metrics below. |
| is_current | Bool. It shows if `load_current()` gives this entry. |

### `registry.json` write protocol

The registry is a JSON file: `{ "<name>": [ModelInfo dicts, ...] }`.
`next_version` and `save_model` each do their read, change and write in a
`filelock.FileLock` on `registry.json.lock`. This lock stops two parallel
training steps when they try to replace the entries of the other step.

Recovery from bad JSON: if the code cannot parse `registry.json`, it moves
the file to `registry.json.corrupt.<unix-ts>` and starts a new registry. The
code does not delete the corrupt file.

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

- `split_mode = "temporal"`: the validation set is the 20% of rows with the
  most recent `first_seen`.
- `brier`: the calibration metric. A lower value shows a better calibration.
- `unlabeled_positive_rate`: the fraction of IP addresses with no label that
  get a score of more than 0.5. This value is a check for PU learning.

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

`n_stable_clusters` is the number of clusters above the persistence limit.
The cluster summary parquet file has the persistence of each cluster. The
report uses only the clusters with `stable=true`.

## 4. Feature snapshot contract

`src/features/build_ip_features.py` makes the snapshot. The file is at
`output/features/ip/v<FEATURE_VERSION>/<snapshot_date>/part-0000.parquet`.
A `manifest.json` file in the same directory gives the columns and their
version.

Each row is one source IP address. `threat_classifier` and
`actor_clusterer` use these columns at this time:

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

Before the cluster step, the code changes the counts with a long tail
(`pkt_count`, `byte_count`, `port_count` and others). It applies `log1p`,
and then a robust z-score (median and 1.4826 × MAD). Thus a small number of
IP addresses with very large counts do not control the distance metric.

Use the `latest_snapshot(name, version)` helper to find the current
snapshot. Do not use a glob on the directory.

## 5. The `Report` writer

Each analyzer module gives a `sg.lib.Report(name, rows, schema, markdown)`.
`lib.Report.write()` writes it as `output/reports/<name>/<name>.parquet`,
with a `.md` summary. The writer has two important properties:

1. **Atomic writes**: the data goes to `<name>.parquet.tmp` first. Then the
   writer changes the name of the file. If a crash occurs during the write,
   no parquet file with only part of the data stays.
2. **Empty tables**: when `rows` is empty, the writer writes an empty Arrow
   table with the declared schema, not a file of zero bytes. Thus
   `read_parquet(...)` works on empty results, and "schema not found"
   failures do not occur.

## 6. Determinism and reproducibility

- All the random algorithms (LightGBM, HDBSCAN, Leiden, the selection of
  the train and test sets, itemset samples) use a fixed seed.
- The freshness cache uses a hash of the CLI command and of the mtime of
  the source file. When you change the defaults of a step, its cache
  becomes stale.
- Each step writes to `<output>.tmp` and then changes the name. If a run
  stops before the end, no file with only part of the data looks new.
- The `parse` step uses the same method for the full Parquet root. It
  writes `<output>.partial`, and it changes the name only after a parse
  that completes. Refer to section 1.
- The model registry write has a file lock. Thus two parallel runs from
  `--parallel N` cannot replace the entries of the other run.

## 7. Configuration variables

- **`SG_PARQUET`**: the Parquet root. The default is `output/parquet`.
  The parser writes to this root, and the analyzers read from it.
- **`SG_DUCK_MEM`**: sets the DuckDB memory limit. Each step has its own
  default.
- **`SG_DUCK_TMPDIR`**: the directory where DuckDB writes data when it has
  no more memory. The default is the system temporary directory.
- **`SG_MMDC`**: the path to the `mmdc` binary that makes the Mermaid
  images for the PDF.
- **`SG_PUPPETEER_CONFIG`**: the Puppeteer configuration JSON for `mmdc` in
  a sandbox.

The CLI arguments replace the defaults. Refer to the `--help` of each step.

## 8. Items that are not in the repository

- **`scripts/`** has only legacy code. Do not put new code there.
- **`data/`** is for the source input. Do not write outputs to it. The
  raw log can also be at a different location, because `--input` gives
  its path.
- **Sensitive data**: git ignores the `*.key.txt` files. The honeypot log
  is large and it belongs to the operator. Do not add it to git.

## 9. Neuromorphic detection plan

The plan comes from `reports/Neuromorphic anomaly detection for honeypi.md`.
The research notes are in `research_notes/Neuromorphic anomaly detection for honeypi/`.

The research found no published result where an SNN, HDC, reservoir, or
HTM model is better than isolation forest or ECOD on network anomaly data.
Also, no study used honeypot, darknet, or telescope data. Thus the plan does
not try to get better detection numbers. It adds three signals that the
current batch, per-IP, threshold pipeline cannot calculate:

| Signal | Primitive | Current module that it extends |
| --- | --- | --- |
| Graded similarity between session chains | HDC (MAP or BSC) on `chainfp` tokens | `chainfp`, `compositeprint` |
| Adaptive baseline for the global arrival series | ESN or NG-RC, with the HTM anomaly-likelihood layer | `detect_coordination` (5x tail-median rule) |
| Timing surprise for each event of a source | Event-driven LIF or ALIF | `pacing` (full-history IAT quantiles) |

### 9.1 Phases and exit gates

Each phase has an exit gate. On 2026-10-24 the operator gave the
instruction to build and test all phases on all the data, also after a
gate failure.

| Phase | Build | Status | Exit gate |
| --- | --- | --- | --- |
| 0. Prerequisites | `sensormask`, `clock_runs.parquet`, `adversarysim --inject`, `bench/baselines.py` | Built (v3.3) | The baselines give numbers on injected archetypes |
| 1. HDC choreography novelty | n-gram session vectors from `chainfp` tokens and tempo, `k` sub-prototypes for each day, fast and slow actor prototypes | Built, gate failure (§9.5) | Better than string rarity and the RFF baseline on `chain_mutation`. The top-k is stable across seeds. |
| 2. Global arrival detector | ESN or NG-RC on vectors for each minute, the prediction error goes into the HTM likelihood layer (`W` of 2 to 8 weeks, Benjamini-Hochberg across series) | Built, gate failure (§9.6) | Flags the three known events. Fewer incorrect alarms each year than the 5x tail-median rule and `stl_z`. |
| 3. Timing for each source | Event-driven LIF or ALIF with some different `tau` values, only for sources with 20 or more packets | Built, gate failure by 0.01 (§9.7) | Better than `pacing` and an untrained LIF on `jittered_beacon` and `rhythm_change` |
| 4. Feature and risk inputs | Score columns in `build_ip_features`, then a capped risk term | Built, in the DAG (§9.8). The gate needs operator labels. | Operator precision@k increases. Balance the tier counts again. |
| 5. Optional research | WTA-STDP port-retina prototypes, Akida demonstration on a Pi 5 | WTA-STDP built, gate failure (§9.9). No Akida hardware. | Only if Phases 1 to 3 show value |

The three known events for Phase 2 are:

1. The large increase of traffic on 2024-06-24 from 07:30 to 07:50 PDT.
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
start (`--boundary-pad-seconds`). The 2025-11-11 to 2026-02-05 outage is a
`gap` interval.

NTP replies (UDP from port 123) do not make a minute active. The sensor
gets one NTP reply each 2048 s, also when no Internet traffic gets to it.
If these replies count, one outage becomes many gaps of 33 to 34 minutes.
On the full corpus, this change decreased the gap count from 605 to 37.

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

### 9.3 Rules for each stateful detector

1. Remove the time in the mask from fit windows. Use `lib.mask_predicate('ts')` in
   SQL, or `lib.load_sensor_mask()` in Python. Both give "no mask" when
   the `sensormask` step did not run.
2. Reset the state for each entity at each `end_ts` of the mask. If you do
   not do this, the detector learns the outage as usual quiet time and
   flags the restart as a large burst.
3. Keep the state file out of the `STAGE_IO` outputs glob. If not, the
   skip-if-fresh cache gives incorrect results.
4. Keep the `neuro` step upstream of `features`. Read
   `benignfilter.parquet` directly. If `features` uses `neuro.parquet` and
   `neuro` reads the feature snapshot, the DAG has a cycle.
5. Do not put a neuromorphic score into `bootstrap_label`. Those labels come
   from the same features that LightGBM uses. Thus the result is circular.
6. Do not use `truth.parquet` as operator labels. Injected rows do not go
   into `label_queue`.
7. Compare each new detector with `bench/baselines.py` and with an untrained
   copy of the same model, on the same injection set. Do not use
   point-adjusted F1.

### 9.4 The `neuro` step (built in Phase 4, see §9.8)

The `neuro` step uses the same pattern as `chainfp`:

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

### 9.5 Phase 1 result

The Phase 1 exit gate gave a failure in two tests. The code stays in the
repository as a tool for research: `src/sg/hdc.py` (encoder, RFF twin,
1-NN) and `src/bench/hdc_eval.py` (gate harness). After round 1, the
decision was not to connect it to `evolve.py`. Round 2 changed this
decision for `hdc_proto` and `hdc_drift` only (§9.10, result 7). Since
2026-10-27, the `neuro` step calculates these two scores (§9.8).

Each test used 7 test days with 10 `chain_mutation` sources and 5
`control_replay` sources on each day (`adversarysim --replay-copies 10`).
The encoder used D = 8192, and seeds 1, 2 and 3. Recall is at k = 100, for
all 7 days together. The chance level is 0.017. The plan set the primary
score and the test days before each test. The design work used only other
days.

Test 1 (test days `p1test_*`):

1. The primary score was `hdc_variant`. This score is the best cosine for a
   session that has a chain that the fit window does not have.
2. On 5 days (50 sources), `hdc_variant` found 1, `string_rarity` found 2,
   and `rff_variant` found 3. The other 2 days did not run.
3. Cause: a session with a changed port is the same as a usual scanner
   session on a random port. No score for each session can find the
   difference.

Test 2 (development sets `p1dev_*`, test days `p1test2_*`):

1. The primary score was `hdc_align`. Y is the fit source-day with the
   nearest bundle (cosine B). Each chain of a source goes into the bundle
   one time. The score is B to the power 4, multiplied by the largest
   deviation of a D session from the sessions of Y.
2. `rff_align` and `str_align` are its twins. They use the same steps with
   RFF vectors and with the chain strings.

| Score | `chain_mutation` (of 70) | Controls flagged (of 35) | `rhythm_change` (of 70) | Top-100 Jaccard |
| --- | ---: | ---: | ---: | ---: |
| `hdc_align` (primary) | 22 | 2 | 4 | 0.90 |
| `rff_align` | 24 | 6 | 29 | 0.85 |
| `str_align` | 18 | 7 | 0 | 1.00 |
| `string_rarity` | 5 | 2 | 3 | 1.00 |
| `new_port_24` | 24 | 8 | 38 | — |
| `ecod` | 15 | 3 | 18 | — |

`hdc_align` is better than `string_rarity` and `str_align`, and it is
stable. But it is not better than its RFF twin. Thus the gate result is
a failure. On the development sets, the two encoders were also equal.

The alignment step causes the better recall, not the HDC encoder. `hdc_align` flags
fewer controls than all other scores that find `chain_mutation`. The gate
does not include this result.

Defects found and corrected in Phase 1:

1. `chainfp` and `compositeprint` put packets with the same `ts` and token
   into different sessions in different runs. The fix adds `boundary DESC`
   to the sort of the session-id window.
2. `adversarysim` `chain_mutation` changed a NULL (ICMP) port when ICMP was
   the most frequent "port" of the source. The fix uses only port numbers.

`hdc_eval.py` streams the data. The DuckDB window functions cannot spill to
disk. Thus the session query runs in `hash(src_ip)` buckets, with one bucket
for each 4 million packets. The vectors and bundles go to disk-backed files.

The largest test day (2025-07-25: 6.8 million sessions, 390,108 chains) has a
peak of 17.3 GB. Before the streaming change, the peak was 34.1 GB. The
scores did not change: the reports of all 7 test days are the same as before.

### 9.6 Phase 2 plan and pre-registered gate

The operator started Phase 2 on 2026-10-24, after the Phase 1 gate failure.
The plan rule in section 9.1 says to wait for a pass. The operator made
the decision to continue. `docs/NEUROMORPHIC_COMPANIONS.md` gives the
research for the companion methods of this phase.

**Minute vector.** `src/bench/arrival_series.py` writes
`output/reports/arrival/arrival_series.parquet`, with one row for each UTC
minute that has packets. It does not count NTP replies (UDP from port 123).
The columns are:

| Column | Meaning |
| --- | --- |
| `minute` | Start of the minute, UTC |
| `pkts` | Packets |
| `n_src` | Different source addresses |
| `n_24` | Different source /24 prefixes (IPv4), or /48 prefixes (IPv6) |
| `new_src` | Sources with their first packet of the corpus in this minute |
| `n_ports` | Different destination ports |
| `syn_share` | Fraction of packets with only the SYN flag |
| `pay_pkts` | Packets with a payload |
| `no_port` | Packets with no destination port (ICMP and others) |
| `pb00` to `pb15` | Packets for each of 16 hash buckets of the destination port |

**Detectors.** All detectors are causal. The fit for day D uses only the
recorded days before D. A recorded day has 720 or more minutes that are
not in the mask.

- The fit window is the last 7 recorded days before the day of the score.
  These days must come after the end of the last mask interval of 1 day or
  more. A detector
  gives no score on D if its window has fewer than 3 days.
- The HTM likelihood and SPOT also use the scores of the 2 recorded days
  before the day of the score. Thus the first score of a segment comes on its sixth recorded
  day.
- The minutes in the sensor mask are not fit data and get no score. At
  each mask end, each detector sets its state to zero, and the first 60
  minutes after the mask end get no score.
- The gate uses only the minutes where all the gate detectors have a
  score.

| Name | Role | Steps |
| --- | --- | --- |
| `ngrc_htm` | Primary | NG-RC (2 lags, linear and quadratic terms, daily phase) on `log1p` of each column. The lag inputs are standardized and clipped to ±3, and the ridge does not apply to the bias. Ridge readout, refit at 00:00 UTC on the fit window. Residual of each column into the HTM likelihood (10-minute window against the 7-day window). Benjamini-Hochberg across the columns. Score = `−log10` of the smallest adjusted p-value. |
| `ar_htm` | Twin | The same steps with linear terms only |
| `ngrc_spot` | Twin | The same NG-RC residual, with SPOT (`q` = 1e-4) in place of the HTM likelihood |
| `untrained_htm` | Untrained copy | The prediction is the mean for each hour of the day in the fit window, with no readout training |
| `tail5x` | Baseline | `new_src` divided by the tail median of `detect_coordination` (the 5x rule) |
| `stl_z` | Baseline | The `bench/baselines.py` STL residual z, fit on the fit window |
| `hawkes` | Reported | Discrete Hawkes model on `new_src` and `pkts`. Poisson tail p-value. |
| `hst` | Reported | `river` 0.26.1 Half-Space Trees (10 trees, height 8, window 250) on the minute vector. Score, then learn, for each minute. A new segment starts a new model. |
| `bocpd` | Reported | Adams-MacKay BOCPD (Normal-Gamma model, hazard of one change each week) on 10-minute means of the signed NG-RC residual of the 7 count columns. Score = probability of a change in the last hour. BOCPD starts again at each 00:00 refit and at each mask end, and the first hour after a start gets no score. |
| `ngrc_bocpd` | Reported | `ngrc_htm`, but a day keeps the readout of the day before when `bocpd` was 0.5 or more in the 24 hours before the 00:00 refit |
| `deeplog` | Reported | The DeepLog parameter-value model: an LSTM (2 layers, 64 units) predicts the minute vector from the 10 minutes before it. It trains for 5 epochs on a new fit window, then 1 epoch each day from the weights of the day before. The squared error of each column gets a Gaussian tail against the errors of the 2 recorded days before, then Benjamini-Hochberg. The DeepLog log-key model is not used, because the minute series has no event keys. |
| `markov` | Reported | A first-order Markov chain of the packet tokens of each source. Token = (protocol, TCP flags, destination port). The transition table comes from the fit window, with `P(b|a) = (c(a,b) + P(b)) / (c(a) + 1)` and an add-one token prior. Minute score = mean surprise of the transitions of the minute, in bits. |
| `som` | Reported | A batch self-organizing map (12 × 12 cells) of the standardized minute vector. A new map starts from 144 random fit minutes and does 10 steps (σ from 4 to 1). Each day after, it continues from the map of the day before with 2 steps (σ = 1). Score = distance to the best cell, divided by the median distance in the fit window. |
| `rrcf` | Reported | Robust Random Cut Forest (Guha and others, 2016), written in numba. Each day builds 40 trees from 256 random minutes of the fit window. Each minute goes into each tree with the RRCF insertion rule, and the tree does not keep it. Score = mean CoDisp of the 40 trees. This is a forest of the fit window. It is not the sliding-window stream of the paper. |
| `cms` | Reported | A Count-Min sketch (4 rows, 2048 columns) of destination ports, written in numba. It has two copies with an exponential decay, like a leaky neuron: τ = 10 minutes and τ = 1 day. Score = largest rate ratio of the ports of the minute, `log2((fast/τf + 1) / (slow/τs + 1))`. The fast copy starts again at each mask end. The first day of a segment gets no score. |
| `hll` | Reported | HyperLogLog (DuckDB `approx_count_distinct`) of the different ports of each source, for each 10-minute block. Block value = largest fan-out of a source. Score = robust z of `log1p` of the block value against the fit window, applied to the next block. |
| `midas_r` | Reported | MIDAS-R on (source /24, destination port) edges, with one tick for each unmasked minute. Sketch of 2 rows and 1024 columns, decay 0.5 (the defaults of the authors). Minute score = largest edge, source or destination score. |

**Periods.**

| Period | Dates (UTC) | Use |
| --- | --- | --- |
| Warm-up | 2024-02-08 to 2024-02-21 | Fit only, no score |
| Test 1 | 2024-02-22 to 2024-07-31 | Gate (event E1) |
| Development | 2024-08-01 to 2025-11-10 | All design work. `ngrc_htm` and `ar_htm` each use the ridge value with the smallest one-step error on this period. The values are 1e-3, 1e-2, 1e-1 and 1, multiplied by the number of fit rows. |
| Test 2 | 2026-02-06 to 2026-05-29 | Gate (events E2 and E3) |

Development results changed the design before the code freeze:

- On 20 development days, the quadratic terms made large errors on
  traffic spikes. Out of sample, the `pkts` error was 1.23, and the
  variance of `pkts` was 0.33. The clip to ±3 decreases this error.
- The first ridge also applied to the bias. Thus a large ridge moved the
  prediction of `log1p(pkts)` (approximately 7) near zero. The bias has
  no ridge at this time.
- With these changes, the one-step error of NG-RC was 0.72 to 0.74, and
  the error of the linear AR was 0.68 to 0.69. The nonlinear terms did not
  make the prediction better. The gate measures the detection, not the
  prediction.
- On the full development period, the smallest one-step errors were 0.620
  for NG-RC (ridge 1) and 0.614 for AR (ridge 0.1). These ridge values are
  the defaults of `arrival_eval.py`.
- The 00:00 refit moves the level of the residual. Thus a BOCPD that runs
  across days found a change at 00:00 on most days. Thus BOCPD starts again
  at each refit.
- The DeepLog Gaussian tail on squared errors gives a median score of 1.24
  on 20 development days. The median of the other detectors was
  approximately 0.15. The squared errors have a skewed distribution, and
  the Gaussian does not fit it.
- On 20 development days, the HyperLogLog fan-out had a bias of +0.17% and
  a mean absolute error of 0.58% against the count with no error.
- The median `cms` score was 3.66 bits. Each minute, one port or more gets
  a small burst from one scanner. Thus the largest ratio of a minute is
  high most of the time.
- For an edge that is new, the MIDAS-R score increases with the tick count.
  The sensor sees new edges each minute. Thus the MIDAS-R scores increase
  during a long segment.

**Development run (2026-10-24, 17 detectors, 704 s, peak 14.0 GB).** The
budget is one alarm minute for each day of the development period (382
minutes). With this budget:

| Detector | Episodes | Longest episodes |
| --- | ---: | --- |
| `ngrc_htm`, `ar_htm`, `ngrc_bocpd` | 5 | 2025-07-10 (281 and 271 min) |
| `untrained_htm` | 13 | 2025-07-10 (270 min) |
| `deeplog` | 13 | 2025-07-10 (764 min), 2025-10-28 (336 min) |
| `markov` | 1 | 2025-07-04 (446 min) |
| `stl_z` | 17 | 2025-09-29 (203 min), 2025-02-17 (128 min) |
| `tail5x` | 39 | 2025-02-19 (400 min), 2025-02-17 (157 min) |
| `hll` | 14 | 2025-08-11 (140 min) |
| `bocpd` | 24 | 2025-06-28 (30 min), 2025-10-02 (30 min) |
| `ngrc_spot` | 45 | 2025-08-16 (127 min), 2025-06-12 (110 min) |
| `cms` | 47 | 2025-10-04 (63 min) |
| `som` | 63 | 2025-10-26 (282 min) |
| `hst` | 66 | 2024-11-13 (80 min) |
| `midas_r` | 71 | 2025-04-04 (69 min) |
| `rrcf` | 117 | 2025-10-26 (134 min) |
| `hawkes` | 164 | 2025-11-09 (241 min) |

- The four prediction detectors put all their alarm minutes on the
  2025-07-10 change of level. The other detectors find different events.
- The development period has no labels. Thus a small number of episodes
  shows only that the alarms are in a small number of long events. It does
  not show that a detector is better.
- In the full development period, the HyperLogLog fan-out had a bias of
  +0.77%. Its mean absolute error was 2.8%.

The detectors run on the full series in time order. The gate counts only
the minutes of the two test periods. Do not calculate a detector score in
a test period before the code freeze. At the code freeze, write the
SHA-256 of the detector file in this section.

**Events.**

| Event | Window (UTC) |
| --- | --- |
| E1: arrival burst | 2024-06-24 14:30 to 14:50 |
| E2: SSH campaign | 2026-04-27 00:00 to 2026-05-02 00:00 |
| E3: push from many campaigns | 2026-05-19 00:00 to 2026-05-20 00:00 |

**Gate.** Do these steps for each detector:

1. Find the threshold `θ*`. This is the largest threshold that gives one
   or more alarm minutes in each of E1, E2 and E3. It is the smallest of
   the three maximum scores in the event windows.
2. Make alarm episodes from the alarm minutes at `θ*`. Join two alarm
   minutes into one episode when the space between them is 30 minutes or
   less.
3. Count the episodes that do not touch an event window or the 6 hours
   before and after it. Divide by the number of test minutes with a score, and
   multiply by 525,600. The result is the incorrect alarms each year
   (FA/yr).

The gate passes if `ngrc_htm` has a lower FA/yr than each of `tail5x`,
`stl_z`, `untrained_htm` and `ar_htm`. The report also gives the FA/yr of
`ngrc_spot`, `hawkes`, `hst` and `midas_r`. These detectors do not change
the gate result.

Note: an episode that is not one of the three events is not always an
error. It can be an event that has no label. Thus the correct number of incorrect
alarms is equal to or less than the FA/yr.

**Full-span result (2026-10-24, `arrival_eval.py --mode full`).** The run
used all 1,090 calendar days of the new corpus (2023-07-07 to 2026-06-30,
899 days with packets). Each minute with a score is a test minute (1,126,069
minutes). The report is `output/reports/arrival_eval/arrival_eval_full.md`.

- No detector gives a score in E2. The sensor recorded no packets from
  2026-04-08 to 2026-04-26. After a long mask, a detector must have 3 fit
  days and 2 days of history. Thus the first scores come after E2.
- `θ*` uses only the events that have a score (E1 and E3). An alarm near
  E2 (6 h or less) is not an incorrect alarm.
- The `--from-scores` option makes the gate tables again from
  `arrival_scores_full.parquet`. It does not run the detectors again.

| Detector | `θ*` | FA/yr | E1 and E3 at 1 alarm minute each day |
| --- | ---: | ---: | --- |
| `ngrc_htm` (primary) | 25.4 | 97.6 | none |
| `ar_htm` | 27.0 | 98.5 | none |
| `untrained_htm` | 34.9 | 72.8 | none |
| `tail5x` | 6.50 | 0.9 | E1 and E3 |
| `stl_z` | 366 | 10.3 | E1 and E3 |
| `hawkes` | 103 | 17.3 | E1 and E3 |
| `ngrc_spot` | 25.5 | 1.9 | E3 only (no E1 score) |
| `bocpd` | 0.99 | 49.0 | E1 only |

**Gate: failure.** `ngrc_htm` has more incorrect alarms than all four
rivals. The NG-RC and AR readouts give almost the same result. Thus the
nonlinear terms add nothing.

`tail5x` comes from the same `new_src` rule
that found E1 and E3, so its low FA/yr does not come from a different method.
`stl_z` is the best detector that does not use the events.

The run with 24 BLAS threads took 13 s for each day on the loaded host.
With `OMP_NUM_THREADS=4`, `OPENBLAS_NUM_THREADS=4` and
`NUMBA_NUM_THREADS=4`, it took 0.7 s for each day. The full run took
24 minutes.

### 9.7 Phase 3 result: LIF and ALIF timing for each source

Code: `src/sg/lif.py` (numba kernels), `src/bench/lif_eval.py` (gate
harness), unit tests in `tests/test_lif.py`.

**Detector.** Each packet of a source is one input spike to a bank of 24
LIF neurons, with `tau` from 1 ms to 1 day. The membrane decays with the
accurate formula between spikes, so there is no time step. The state resets at each end of a
sensor mask. The bank gives two readouts:

1. Change (ALIF). Each neuron in the band from 1 to 16 times the median
   inter-arrival time (IAT) keeps two signals of `log v`: a fast mean (the
   last 32 spikes) and an adaptive threshold (the mean and variance since
   the reset). The score is the largest standardized distance between the
   two signals.
2. Regularity. This is `log(mean / std)` of the membrane value before each spike for
   the neurons from 0.5 to 2 times the median IAT. A metronome gives a high
   value.

The calibration uses the 28 recorded days before D. The score is
`-log10` of the exceedance rate in the fit-window source-days of the same
packet-count decile. Above the 90th percentile, an
exponential tail replaces the rate. `lif` is the larger of the two
calibrated readouts.

**Twins and rivals:**

- `untrained_lif`: 24 random `tau` values, all neurons, no adaptation, and no calibration.
- `hawkes`: the classical twin. It is an exponential Hawkes fit (the same
  kernel), with the time-rescaling KS score and the same calibration.
- `pacing`: `-log CV(IAT)` and the change of the median IAT between the
  two halves. These are the statistics of the `pacing` analyzer.
- `pacing_cal`: `pacing` with the calibration of `lif`.

**Test.** There were 43 test days, one each 21 recorded days from
2023-07-17 to 2026-06-24. Three other days (2023-10-15, 2024-09-15 and
2025-06-15) were used for the design work. Each test day has 10
`jittered_beacon` sources and 10 `rhythm_change` sources.

- `adversarysim --beacon-copies 10` makes the beacons. The first beacon
  is at 300 s ± 2 %. The other beacons have a period from 30 s to 1 h and
  a jitter from 1 % to 10 %.
- Each archetype is ranked in the recorded sources with 20 or more
  packets plus its own sources. Thus other injected sources cannot use
  the alert slots.

| Detector | Beacon k=10 | Beacon k=50 | Beacon k=100 | Rhythm k=10 | Rhythm k=50 | Rhythm k=100 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `lif` | 0.82 | 0.93 | 0.97 | 0.01 | 0.16 | 0.31 |
| `untrained_lif` | 0.61 | 0.90 | 0.95 | 0.00 | 0.03 | 0.05 |
| `pacing` | 0.04 | 0.88 | 0.98 | 0.01 | 0.03 | 0.08 |
| `pacing_cal` | 0.86 | 0.95 | 0.98 | 0.02 | 0.29 | 0.52 |
| `hawkes` | 0.50 | 0.65 | 0.77 | 0.00 | 0.01 | 0.05 |
| `lif_change` | 0.00 | 0.06 | 0.23 | 0.03 | 0.30 | 0.41 |
| `lif_nocal` | 0.02 | 0.88 | 0.96 | 0.04 | 0.38 | 0.63 |

There were 430 sources of each archetype. The chance level at k = 100 is
0.09. `control_replay` (215 sources) has a recall of 0.08 for `lif` at
k = 100, which is near the chance level.

**Gate: failure, by one point.** At k = 100, `lif` found 0.97 of the
beacons and `pacing` found 0.98. `lif` is better than `pacing` and
`untrained_lif` at all other points. At k = 10, `lif` found 0.82 of the
beacons and `pacing` found 0.04.

**Cause.** The calibration does the work, not the LIF. `pacing_cal` uses
the same calibration with the classical statistics. It is equal to or
better than `lif` at each point. For `rhythm_change`, the uncalibrated
readouts are better (`lif_nocal` 0.63 at k = 100). The packet-count decile
removes the part of the signal that comes from the packet rate.

Development changes before the test:

- The first change readout (an output neuron on the ALIF surprise) did not
  find `rhythm_change`. The slow/fast signal readout replaced it.
- The first bank (1 s to 1 day) had no neuron near the IAT of fast sources.
  At this time, the bank starts at 1 ms.
- The calibration gave the same top value to many sources (a tie at
  `-log10(1 / (1 + N))`). The exponential tail removes the tie.
- The regularity readout counted the increase from `v = 0`. At this time, it starts
  after 16 spikes.

SHA-256 of the files used for the 43-day test:

| File | SHA-256 |
| --- | --- |
| `src/sg/lif.py` | `5072aa05e56ac87721712b51afd6339cbcb26537afe921507cbfc87d7bef5213` |
| `src/bench/lif_eval.py` | `b20474dd019db67269db6376e22ef40ee5b97b5d7ccbe0b513d6b708db29f48a` |

After the test, the summary code changed: it keeps the `baselines.py` rows
apart with the prefix `bl_`. The per-set scores did not change.

### 9.8 Phase 4: the `neuro` step, feature columns and the risk term

Code: `src/neuro.py` (DAG step), `src/features/build_ip_features.py`,
`src/risk/compute_risk_score.py`.

- `neuro` runs the Phase 3 bank on each recorded day for each source with
  20 or more unmasked packets. It calibrates each day against the 28
  recorded days before it. A source-day is flagged when a calibrated
  readout is 4 or more (one in 10,000 source-days).
- The per-day readouts go into `output/.neuro_cache/`. This folder is not
  in the `STAGE_IO` outputs (rule 3 of §9.3). The cache key is the hash of
  `sg/lif.py`, the sensor mask and the packet limit.
- The step also calculates the HDC scores `hdc_proto` and `hdc_drift`
  (added 2026-10-27, §9.10 result 7). For each recorded day D, it makes
  the `chainfp` sessions of D and of the 7 recorded days before that day.
  Then it uses `bench/hdc_eval.score_set` with encoder seed 1, as in the
  gate. Each source with a session on D gets the two scores.
- The HDC calibration is the same as for LIF: the 28 recorded days before
  D are the reference. But the bins use the number of sessions on D, not
  the number of packets. A source-day is flagged when a calibrated score
  is 4 or more.
- The HDC cache is `output/.neuro_cache/dt=<day>/hdc_<key>.parquet`. Its key
  is the hash of `sg/hdc.py`, `bench/hdc_eval.py`, `chainfp.py`, the sensor
  mask, the number of fit days and the seed. One day takes approximately
  85 s with 4 workers (`--hdc-workers`), and each worker uses
  approximately 3.5 GB.
- When `arrival_scores_full.parquet` is available, the step also counts the
  alarm minutes in which each source sent packets. The alarms are the
  minutes at 1 alarm minute each day of `stl_z` (the Phase 2 result).
- Outputs: `output/reports/neuro/neuro.parquet` (one row for each source),
  `neuro_days.parquet` (LIF, one row for each source-day) and
  `neuro_hdc_days.parquet` (HDC, one row for each source-day).
- DAG: the parents of `neuro` are `analyzers`, `cluster`, `chainfp` and
  `sensormask`. `features` has `neuro` as a parent.
- Features: `neuro_days`, `neuro_change`, `neuro_reg`, `neuro_flag_days`,
  `neuro_arrival_min`, `neuro_hdc_days`, `neuro_hdc_proto` and
  `neuro_hdc_drift`. They are not in `NUMERIC_FEATURES` and not in
  `bootstrap_label` (rule 5 of §9.3).
- Risk: `neuro_signal` = the LIF term plus the HDC term plus the arrival
  term, with a cap of 8 points (`NEURO_CAP`).
  - The LIF term is `2 × (best calibrated readout − 4 − log10(days))`,
    with a cap of 6. The `log10(days)` part removes the increase that a
    source gets from many days of tests.
  - The HDC term uses the same rule with the larger of `neuro_hdc_proto`
    and `neuro_hdc_drift`, and with `neuro_hdc_days`. Its cap is 4
    (`NEURO_HDC_CAP`).
  - The arrival term is `log2(1 + alarm minutes)`, with a cap of 4 (0
    since 2026-10-25).
  - The rationale shows the labels `lif-metronome`, `lif-rate-shift`,
    `hdc-proto` and `hdc-drift`.

**Full-corpus result (2026-10-25, evolve).** The `neuro` step gave scores
to 1,584,161 source-days of 403,883 sources in 960 s. 4,210 sources have
one or more flagged days. 65,490 sources sent packets in one or more of the
782 `stl_z` alarm minutes.

The risk snapshot `output/risk/ip_risk/dt=2026-10-25` has 1,259,486 IPs.
68,752 IPs have a `neuro_signal` more than 0 (mean 1.9 points, maximum 8).
The tier "before" is the composite score without `neuro_signal`, with the
same clip to 0 to 100.

| Tier | Before | After | Change |
| --- | ---: | ---: | ---: |
| `critical` | 7,778 | 8,321 | +543 |
| `high` | 160,817 | 164,308 | +3,491 |
| `medium` | 491,726 | 488,016 | −3,710 |
| `low` | 267,311 | 267,427 | +116 |
| `info` | 331,854 | 331,414 | −440 |

5,342 IPs went up one tier. No IP went down. The cause of each move:

- The arrival term only: 5,119 IPs (96 %).
- The LIF term only: 209 IPs.
- Both terms: 13 IPs.

Of the 3,338 IPs with a LIF term, 2,998 have the label `lif-metronome` and
340 have the label `lif-rate-shift`. Their tiers after the term: 58
`critical`, 643 `high`, 2,537 `medium`, 41 `low` and 59 `info`.

**Problem: the arrival term.** The arrival term gives up to 4 points to each
source that sent packets in an alarm minute. But an alarm minute is a
property of all the traffic, not of one source. Of the 65,490 sources with
an arrival term, 2,248 are known benign scanners. Thus most of the tier
moves come from the time of the packets, not from the behavior of the
source.

Change the arrival term so that it gives each alarm only to the sources
that caused it. One method is the share of the source in the excess packets
of the alarm minute.

**Operator decision (2026-10-25).** The arrival cap is 0, and the 40-point
reduction for known scanners is 0. A known scanner keeps the flag
`known-scanner=<org>` in the rationale. The tiers after the new `risk` run:

| Tier | Before the decision | After the decision |
| --- | ---: | ---: |
| `critical` | 8,321 | 8,201 |
| `high` | 164,308 | 163,255 |
| `medium` | 488,016 | 498,190 |
| `low` | 267,427 | 269,227 |
| `info` | 331,414 | 320,613 |

395 known scanners are in the `critical` tier and 2,289 are in the `high`
tier.

**Second operator decision (2026-10-25).** The LIF points stay. An IP in a
published scanner CIDR (1,926 IPs, `benignfilter` evidence `cidr:`) gets a
reduction of 10 points (`SCANNER_CIDR_OFFSET`). A scanner that `benignfilter`
found only by user agent or ASN gets no reduction. After the new `risk` run,
the CIDR scanners are 2 `critical`, 19 `high`, 338 `medium`, 1,406 `low` and
161 `info`.

**Gate: not measured.** The Phase 4 gate is the operator precision on IPs
with an operator label. There is no file
`output/eval/label_queue_labeled.csv`.

### 9.9 Phase 5 result: WTA-STDP port-retina prototypes

Code: `src/sg/stdp.py`, `src/bench/stdp_eval.py`.

**Detector.** A source-day is a retina of 4,096 input neurons, one for
each destination-port hash bucket. The value of each input neuron is the
packet share of the source on that bucket. 256 output neurons compete.

- The winner learns by STDP: the inputs that fired move its weights up,
  and the other weights move down.
- Homeostasis increases the threshold of each winner, so no output neuron
  gets all inputs (Diehl and Cook, 2015).
- The network trains on the source-days of the 28 recorded days before D.
- The score is the novelty, `1 −` the best cosine to a prototype.

**Twins:** `kmeans` (spherical mini-batch k-means with the same K) and
`untrained_stdp` (the same network with no learning).

**Test:** the same 43 sets as Phase 3. Each archetype is ranked in the
recorded sources with 5 or more packets plus its own sources.

| Detector | `chain_mutation` k=100 | `jittered_beacon` k=100 | `fast_scanner` k=100 |
| --- | ---: | ---: | ---: |
| `stdp` | 0.00 | 0.22 | 0.00 |
| `kmeans` | 0.00 | 0.21 | 0.00 |
| `untrained_stdp` | 0.01 | 0.07 | 0.00 |
| `pkt_count` | 0.08 | 0.36 | 0.88 |
| `bl_new_port_24` (all sources of D) | 0.27 | 0.00 | — |

**Gate: failure.** No port-mix novelty score finds `chain_mutation`. Many
recorded sources hit port mixes that no prototype has, so a source with
one changed port is not unusual. STDP and k-means give the same result.

The Akida demonstration must have a BrainChip Akida device on a Raspberry Pi 5.
This hardware is not available, so that part of Phase 5 did not run.

### 9.10 Round 2 v0.1: harness v2 and the first round again

Plan: `docs/NEUROMORPHIC_ROUND2_PLAN.md`. Code: `src/bench/harness2.py`,
`src/bench/priority_labels.py`, `src/bench/phase4_gate.py`,
`src/bench/efficiency.py`, and the `--v2` archetypes of
`src/adversarysim.py`. The code freeze is
`output/reports/harness2/freeze_r2_v01_rerun.json`.

**Sets.** There are 215 sets: the 43 Phase 3 days with five seeds each.
Each set has 50 control sources and the round 2 archetypes. The 28 days
from 2024-08-01 are test days, with the held-out family `rotating_actor`
and lags of 30 to 60 s. The other 15 days are development days.

All values below are from the 125 test sets. Recall is for all injected
sources. The intervals are a bootstrap of the sets (95 %).

**Corrections before the run.**

- D12: the untrained LIF bank uses the tau range of the trained bank.
- D13: 50 control sources in each set.
- D14: `lif` and `lif_nocal` are co-primary.
- D15: `hdc.max_sim` uses bit-packed Hamming distance for int8 vectors.

**Result 1: `lif` finds beacons with a gap.** `beacon_gap` is a beacon
that stops for 1 to 6 h and starts again with a new phase. The `lif` code
was frozen in round 1, before this archetype was in the injector.

| Detector | `beacon_gap` k = 10 | `beacon_gap` k = 100 |
| --- | ---: | ---: |
| `lif` | 0.68 [0.63, 0.74] | 0.91 [0.87, 0.94] |
| `pacing_robust_cal` | 0.13 [0.10, 0.15] | 0.75 [0.69, 0.82] |
| `iforest` | 0.20 [0.16, 0.24] | 0.70 [0.63, 0.77] |
| `hawkes` | 0.20 [0.18, 0.23] | 0.50 [0.47, 0.54] |
| `pacing_cal` | 0.11 [0.10, 0.13] | 0.26 [0.22, 0.29] |
| `periodogram_cal` | 0.22 [0.19, 0.25] | 0.54 [0.50, 0.58] |
| `periodogram` | 0.17 [0.14, 0.19] | 0.49 [0.44, 0.54] |

The `pacing_robust` twins (median absolute deviation of the IATs) and the
`periodogram` twins (the spectral twin of part A) were added after this
result. They are the strongest classical twins. Gate rule 1 gives "pass" to `lif`
against each twin on `beacon_gap`, on the test sets and on the
development sets.

**Result 2: the untrained bank finds lockstep sources.** At k = 100,
`untrained_lif` found 0.52 [0.44, 0.59] of `lockstep_24` and 0.32
[0.27, 0.37] of `lagged_lockstep`. Every classical twin and baseline found
0.07 or less in round 1.

The spectral twin `periodogram_cal` found 0.42 [0.34, 0.50] of
`lockstep_24` and 0.24 [0.18, 0.30] of `lagged_lockstep`. The intervals
overlap with `untrained_lif`, thus gate rule 1 gives no difference. The
calibrated spectral twin does the same work as the untrained bank. The
burst twins (`burst_fano` and `burst_b`, on the 24 time scales of the LIF
bank) found 0.01 or less of the two lockstep archetypes.

**Result 3: the other timing archetypes have no difference.** On `jittered_beacon`,
`beacon_drift` and `multi_period`, `pacing_cal` is equal to or better than
`lif`. On `rhythm_change`, `lif_nocal` found 0.47 [0.42, 0.52] and
`pacing_cal` 0.41 [0.36, 0.46]. The intervals overlap.

**Result 4: STDP.** STDP is better than its untrained copy on the beacon
archetypes, but equal to k-means. No port-mix detector found
`chain_mutation`.

**Result 5: arrival detectors on recorded events.** The 1,853 payload
campaign waves give 29 launch clusters. With E1 and E3, 21 events have
minutes with a score (17 test, 4 development).

At 10 alarm minutes each day, a random score finds 0.42 of the test events. `ngrc_htm` found 0.06 and the
best detector, `hawkes`, 0.29. No arrival detector is better than chance
at this budget.

**Result 6: Phase 4 gate, failure.** On 70 score days, the sources with a
LIF risk term escalated at a rate of 0.0005 [0.0001, 0.0010]. Sources with
the same activity and no LIF term escalated at 0.0054 [0.0044, 0.0067].
The operator kept the LIF risk term (decision of 2026-10-25).

**Efficiency on this CPU** (`efficiency.py`, all data, one thread):

| Detector | Cost | Classical twin |
| --- | --- | --- |
| `lif` with `median_iat` | 371 ns for each packet | `pacing`, compiled: 12 ns |
| LIF state | 1,376 bytes for each source | `pacing`: 8 bytes for each packet |
| `ngrc_htm` | 46 µs for each minute | `stl_z`: 402 µs, `hawkes`: 1.7 µs |
| HDC lookup, bit-packed | 20 ns for each pair | float32: 80 ns |
| STDP scoring | 2.0 µs for each retina | k-means: 22.7 µs (scipy) |

**Result 7: HDC finds the `rotating_actor` archetype (2026-10-27).**
`hdc_eval` ran on all 215 sets. Summary:
`output/reports/harness2/harness2_hdc_eval_summary.md`.

Each HDC score has a matched RFF twin. The twin uses the same arithmetic
on random Fourier features of the same chains:

| HDC score | Matched twin | Difference in the twin |
| --- | --- | --- |
| `hdc_novelty`, `hdc_variant`, `hdc_align` | `rff_novelty`, `rff_variant`, `rff_align` | No noise floor |
| `hdc_proto` | `rff_proto` (added 2026-10-27) | Plain weighted spherical k-means (`prototypes(binarize=False)`), no noise floor |
| `hdc_drift` | `rff_drift` (added 2026-10-27) | No noise floor |

`hdc_eval.py --only DET ...` calculates only the given scores and adds them
to the ranks file of the set.

Gate rule 1 results against the matched twin:

| Archetype | HDC score | Matched twin | Test sets | Development sets |
| --- | --- | --- | --- | --- |
| `rotating_actor` | `hdc_proto` | `rff_proto` | `pass` | `pass` |
| `rotating_actor` | `hdc_drift` | `rff_drift` | `pass` | `pass` |
| `chain_mutation` | `hdc_novelty` | `rff_novelty` | `pass` | `pass` |
| `chain_mutation` | `hdc_align` | `rff_align` | no difference | no difference |
| `rhythm_change` | `hdc_align` | `rff_align` | no difference | twin better |
| beacon archetypes | `hdc_drift` | `rff_drift` | twin better | twin better |

Recall of `rotating_actor` at k = 100:

| Score | Test sets (125) | Development sets (90) |
| --- | ---: | ---: |
| `hdc_proto` | 0.35 [0.32, 0.38] | 0.38 [0.35, 0.41] |
| `hdc_drift` | 0.31 [0.29, 0.34] | 0.39 [0.36, 0.41] |
| `rff_novelty` | 0.19 [0.17, 0.20] | 0.26 [0.24, 0.28] |
| `rff_proto` | 0.09 [0.08, 0.10] | 0.17 [0.16, 0.19] |
| `rff_drift` | 0.01 [0.01, 0.01] | 0.09 [0.08, 0.11] |

The development days had no `rotating_actor` sources (it is a held-out
family). Thus `adversarysim --v2 --rotating-actor` made 90 more sets
`p3ra_<day>_s<k>`. This flag adds only `rotating_actor` and does not
change the `lagged_lockstep` lags. Each set has the same seed as its
`p3v2` set, thus its other archetypes are the same. Thus these sets have
their own summary (`harness2.py --summary ... --tag devra`, file
`harness2_hdc_eval_summary_devra.md`). A pooled summary would count those
sources two times.

`hdc_novelty` gets `pass` on `chain_mutation`, but its recall is only
0.14 at k = 100. `hdc_align` and `rff_align` each find 0.34.

The binary vectors are the cause of the difference. With the same
arithmetic on RFF vectors, prototypes and drift find almost no
`rotating_actor` sources. A `rotating_actor` source is a replay of a
recorded source from 4 new IPs. The result shows that HDC prototypes and
drift find this pattern. It does not show the precision of HDC on recorded
traffic that changes its IPs.

**HDC risk term (operator decision, 2026-10-27).** `hdc_proto` and
`hdc_drift` go into the risk score through the `neuro` step (§9.8), with
the LIF flag level of 4. The calibrated HDC scores have a limit, because
a cosine is between 0 and 1.

On a test of 36 days (2025-05-01 to 2025-06-05), 148,533 source-days had
a calibrated score. Only 2 had a score of 4 or more, and 1 of 33,665
sources got points (0.26). Thus the HDC term has a very small effect on
the tiers. In the gate, HDC found
`rotating_actor` sources near the top 100 of each day, approximately a
calibrated score of 1.7. A lower flag would give points to thousands of
sources each month, with a precision that is not known.

**HDC risk term, full corpus on the GPU (2026-10-28).** The `neuro` step
calculated `hdc_proto` and `hdc_drift` for all 899 days on the GPU path
(`sg.hdc_gpu`, §9.10 result 7). The run time was 7.7 hours with 2 workers.

- 1,059,981 sources had a calibrated score on 1 day or more (4,933,326
  source-days).
- 67 sources had a score of 4 or more (68 source-days). The highest score
  was 5.27.
- The flags occur in groups of related sources on a small number of days.
  On 2025-08-16 there were 17 sources. On 2026-04-28 there were 12 sources
  in 6 /24 networks (`85.217.149.0/24` and `104.243.35.0/24` with others).
  On 2026-05-19 there were 5 sources.
- 2,212 sources had a score of 3 or more, and 37,150 had a score of 2 or
  more.

The change to the tiers was very small. Before the HDC term, the tiers were
`critical` 7,279, `high` 164,088, `medium` 496,961, `low` 270,504 and `info`
320,654. With the HDC term, 2 sources moved from `medium` to `high`. The
other tiers did not change.

The GPU path is also a gate detector. On the 305 `hdc_eval` sets,
`hdc_proto_gpu` gets `pass` for gate rule 1 against `rff_proto` for
`rotating_actor` on the test sets and on the development sets. Its recall
at k = 100 is 0.36 [0.33, 0.39] (test) and 0.38 [0.35, 0.41]
(development). Against the CPU `hdc_proto` the result is "no
difference". At k = 100 the two detectors find 91% (test) and 94%
(development) of the same sources. The files are
`harness2_hdc_eval_summary_gpu.md` and
`harness2_hdc_eval_summary_devra_gpu.md`.
