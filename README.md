# SensorGrind_AI

SensorGrind_AI is a pipeline for the analysis of honeypot logs. It changes
itself and becomes better from run to run. The pipeline does these steps:

1. It puts the raw syslog files into one file and corrects the clock skew.
2. It parses the log into Parquet tables. This is the `parse` step, the
   first step of the DAG.
3. It runs 46 analysis steps on the tables. These include:
   - An ML threat classifier
   - HDBSCAN actor clusters
   - FP-Growth pattern mining
   - Leiden community detection
   - Change-point detection and drift detection
   - **A cross-analyzer correlator, with a verdict from fixed rules for each
     result**. It uses no LLM. The LLM narrative is an opt-in step.
   - A review by many AI providers
   - More than 20 analyzers that the project made for this data
4. It writes a full threat intelligence report for defenders, in markdown,
   HTML and PDF.

## What the pipeline sees

The pipeline runs on a recorded corpus, not on synthetic data. These are the
values from the last full run (snapshot of 2026-10-25). The input was the
`honeypi_logs.py` output `honeypi_sensor.log` (472 GB).

| Metric | Value |
| --- | --- |
| Total packets (after the removal of duplicates) | 1,232,067,956 |
| Different source IP addresses | 1,259,496 |
| Different payload blobs (SHA-256) | 106,414,804 |
| Events with an L7 protocol class | 34,777,746 (89,511,623 after the L7 backfills of 2026-10-30, refer to the note below) |
| IOCs found | 28,092,187 |
| Days with traffic in the corpus | 899 |
| Corpus range (UTC days) | 2023-07-07 to 2026-06-30 (8 sensor outages, refer to the table below) |
| Threats in the `critical` tier | 8,321 |
| Threats in the `high` tier | 164,308 |
| Actor communities (Leiden, 4 or more members) | 16 of 80 groups in the graph of the top 10,000 threat IPs |
| Behavior rules that the pipeline promoted (this run) | 20 |
| Cross-signal findings (correlator) | 86 (7 critical, 52 high, 27 medium). On 2026-10-30: 175 (7 critical, 48 high, 99 medium, 21 low) |
| Campaigns (10 or more IP addresses, burst of less than 60% of the corpus) | 1,853 of 2,000 payload waves |
| Full time (parser and evolve) | 8 h 9 min: parser 2 h 13 min, evolve steps 5 h 56 min |

The L7 event count is from the parser. Two runs of `src/l7_backfill.py`
added rows after the snapshot. The BitTorrent backfill added 54,261,465 rows,
and the Levin backfill added 472,412 rows. The total on 2026-10-30 is
89,511,623.

The full time does not include `honeypi_logs.py`. The evolve time is the sum
of the step times of two runs, because the memory limit stopped the first
run in `mining`.

The actor-community value is not comparable with the value of the run of
2026-05-31 (2,153). At this time, the `actorlink` graph has only the top
10,000 threat IPs.

Sensor outages (each run of UTC days with no packets):

| First day | Last day | Days |
| --- | --- | ---: |
| 2024-05-11 | 2024-05-20 | 10 |
| 2025-02-24 | 2025-02-24 | 1 |
| 2025-07-03 | 2025-07-03 | 1 |
| 2025-08-20 | 2025-09-22 | 34 |
| 2025-11-12 | 2026-02-04 | 85 |
| 2026-03-03 | 2026-04-06 | 35 |
| 2026-04-08 | 2026-04-26 | 19 |
| 2026-05-03 | 2026-05-08 | 6 |

The total is 191 days. The merged log of 2026-05-29 has packets from
2024-05-11 to 2024-05-20, but `honeypi_sensor.log` has none. The cause of
this difference is not known.

Earlier runs showed a history from 2019-02-14 to 2025-09-18. This history
was not correct. The hardware clock of honeypi00 had a defect, and its RTC
went back to 2019-02-14 many times. The consolidator of 2026-05-29 finds
this skew from the FortiGate and newsyslog anchors in the same syslog
stream. Then it writes the wall-clock time at which each sensor line got to
the log server. Refer to `output/reports/clock_skew/clock_skew.md` for the
skew dossier of each file.

The most important findings of the last run are:

- 1,789 different payload campaigns had their peak on the same day,
  **2026-05-19**. This was a coordinated botnet push with many vectors.
- **SIGTRAN, SS7 and SIP probes** of telco signaling planes came from 23
  sources (in CN, SC, TH, HK, US and AE), from 2023-08-22 to 2026-06-29.
  32 sources sent SCTP packets.
- An RDP credential spray used the same `hello` mstshash cookie from 1,820
  different IP addresses on 860 days, from 2023-07-06 to 2026-06-29.
- The 7 findings with the severity `critical` are:
  - 25 `critical`-tier botnet sources with a long persistence.
  - 5 synchronized pushes: 1,789 payloads on 2026-05-19, 18 on 2025-07-04,
    9 on 2025-07-06, 8 on 2026-04-29 and 6 on 2025-09-28.
  - The telco SS7, Diameter and SIGTRAN reconnaissance footprint.

The finding dates are in the local time of the sensor (PDT or PST).

## Quickstart

```bash
# 0. Consolidate the raw rotated syslog into a single sorted, deduped,
#    clock-skew-corrected merged.log.gz.  Inputs are .gz files under
#    ~/temp/sensor_logs/ and ~/temp/sensor_logs/<dated>/.  Filter is
#    "honeypi00 sensor:" + "PacketTime:"; clock skew is detected per
#    file by anchoring against FortiGate `date=time=tz=` and newsyslog
#    ISO-UTC prefix lines.  Outputs ~/temp/sensor_logs/consolidated/
#    merged.log.gz and the manifest, plus
#    output/reports/clock_skew/clock_skew.{md,parquet}.
#    Takes ~6h on the current corpus; safe to leave running unattended.
#    honeypi_logs.py output (honeypi_sensor.log) is an equivalent input.
venv/bin/python scripts/consolidate_logs.py

# 1. Parse the log and run the full evolve pipeline (DAG-ordered,
#    skip-if-fresh by default).  --input is a gzip file, a plain ASCII
#    file, or a folder.  The parse takes ~75-95 min on 1.1-1.2B events.
venv/bin/python src/evolve.py --input ~/temp/sensor_logs/consolidated/merged.log.gz

# 2. Run the pipeline again on the parsed tables (no --input: no parse).
#    A run with no step names does not run the opt-in steps (conclude).
venv/bin/python src/evolve.py

# 2a. Optional: LLM narratives for the findings (paid API calls)
venv/bin/python src/evolve.py conclude

# 3. Read the report
output/reports/COMPREHENSIVE.md
output/reports/COMPREHENSIVE.html   # browser, live Mermaid via CDN
output/reports/COMPREHENSIVE.pdf    # mermaid pre-rendered to SVG
```

### Input of the parse step

The `--input` argument of `evolve.py` gives the raw sensor log to two
steps: `parse` and `nonipproto`. The input can be one of these types:

- **A gzip file.** The tool finds the gzip format from the first two bytes
  of the file, not from the file name.
- **An ASCII file.** An example is `honeypi_sensor.log` from
  `honeypi_logs.py`.
- **A folder.** The tool reads each gzip file and each ASCII file in the
  folder. It does not read the subfolders.

Each line is a raw syslog line with a `PacketTime:` field. The lines of
`merged.log.gz` start with an ISO time and a tab. The tool removes this
prefix.

For a folder, the lines of each file must be in time sequence. The tool
merges the files in the sequence of their `PacketTime` values. It ignores binary files and files
with no sensor lines, and it writes a note for each one. It does not
remove duplicate lines that occur in more than one file.

Without `--input`, the orchestrator does not start `parse` or
`nonipproto`. The other steps use the Parquet tables that are on the disk.

You can also start the two tools directly:

```bash
venv/bin/python src/parser.py INPUT [--output DIR]
venv/bin/python src/nonipproto.py INPUT
```

The parser does not write into a Parquet root that has data in it. A
parse that starts on a full root does these steps:

1. It writes the new tables to `output/parquet.partial`.
2. When the parse completes, it moves the root of the last parse to
   `output/parquet.prev`. It deletes the `parquet.prev` of the run before.
3. It moves `parquet.partial` to `output/parquet`.

If the parse stops before the end, `output/parquet` does not change. The
parser gives the exit code 1, and the orchestrator does not start the
steps after it. The next parse deletes the remaining `parquet.partial`.

To run some steps again:

```bash
venv/bin/python src/evolve.py mining promote report
```

To run steps in parallel (the orchestrator obeys the DAG):

```bash
venv/bin/python src/evolve.py --parallel 4
```

To show the dependency graph:

```bash
venv/bin/python src/evolve.py --show-dag
```

To run a step again when its inputs did not change:

```bash
venv/bin/python src/evolve.py --force mining
```

To get the scores of the baseline detectors on injected archetypes:

- The operator runs these commands. They are not part of the DAG.
- The commands do not change the corpus on disk.

```bash
venv/bin/python src/sensormask.py                       # sensor-off mask
venv/bin/python src/adversarysim.py --inject phase0 --day 2026-05-10
venv/bin/python src/bench/baselines.py --eval phase0
# -> output/reports/baselines/baselines_phase0.md
```

## AI provider setup (optional)

Some steps (`originintel`, `aipayloaddecode`, `aireview`, and the opt-in
`conclude`) send prompts to hosted LLMs. Put one or more of these key files in the root of the
repository. Each of these steps uses the first provider that has a key that
works and an installed SDK.

```
claude.key.txt    # Anthropic
openai.key.txt    # OpenAI
xai.key.txt       # xAI
mistral.key.txt   # Mistral
gemini.key.txt    # Google
```

If no provider is available, the AI steps do not run, and they do not stop
the pipeline. The other steps do not use them.

## Layout

```
src/                                  # all working code lives here
  parser.py                           # raw log to 4 Parquet tables
  l7_backfill.py                      # apply a new L7 label to the stored
                                      #   tables (no full parse)
                                      #   (the `parse` step)
  evolve.py                           # DAG orchestrator + skip-if-fresh
  sgquery.py                          # meta-runner over base analyzers
  sg/                                 # shared library
    lib.py                            #   DuckDB factory, GeoIP, IOC enums
    sensorlog.py                      #   raw-log reader: gzip, ASCII, folder
    features.py                       #   feature snapshot registry
    models.py                         #   model registry (file-locked)
  25+ analyzer modules at src/*.py    # see ARCHITECTURE.md for the full list
  features/build_ip_features.py       # per-IP feature vector
  models/                             # ML training/scoring/drift
    train_threat_classifier.py        #   LightGBM + temporal split + SHAP
    train_actor_clusterer.py          #   HDBSCAN + persistence gating
    score_threats.py                  #   batch scoring with current model
    detect_drift.py                   #   Wasserstein + PSI + BH-FDR
  mining/                             # pattern discovery
    mine_itemsets.py                  #   FP-Growth + lift/conviction gates
    mine_sequences.py                 #   PrefixSpan over time-ordered events
    promote_patterns.py               #   Wilson-LCB pattern promotion
  longitudinal/                       # over-time analysis
    detect_changepoints.py            #   PELT with mBIC penalty
    cross_modal_lag.py                #   STL-detrended cross-correlation
    detect_coordination.py            #   campaign-onset detection (p5 launch
                                      #     -> p95 decay percentiles, peak day,
                                      #     density_score, always-on filter)
    attack_chains.py                  #   RPDBC stage transitions
    survival_analysis.py              #   Kaplan-Meier on actor cohorts
    infra_rotation.py                 #   infrastructure rotation tracking
  risk/                               # composite risk scoring
    compute_risk_score.py             #   ML x persistence x breadth x ...
    risk_dossier.py                   #   per-IP markdown dossiers
  conclusions/                        # cross-signal findings and verdicts
    correlate.py                      #   hand-coded cross-analyzer rules
                                      #     (telco SS7 recon, sync campaign
                                      #     burst, recent tight campaign, ...)
    graph.py                          #   KG-lite: findings -> storylines
    verdict.py                        #   fixed rules: facts -> one verdict
                                      #     per finding; findings -> problems
    synthesize.py                     #   opt-in (`conclude`): LLM narrative
                                      #     per finding (paid API calls)
  report/                             # output composition
    comprehensive_report.py           #   Sections 0 to 32 incl. Section 0 TL;DR,
                                      #     Section 0.5 Cross-Signal Problems
                                      #     and Section 32 neuromorphic scores
    render.py                         #   Mermaid + Matplotlib + PDF
                                      #     (svg_gantt_chart for campaigns)
  slowlow.py                          # slow-and-low scanners
  dnstlsintel.py                      # DNS qname + TLS SNI intel (DGA, mimic)
  selfmimic.py                        # sensor self-banner echo detection
  adversarysim.py                     # synthetic adversary coverage harness
                                      #   (--inject: full-schema eval overlay)
  sensormask.py                       # sensor-off gaps + clock-run boundaries
  neuro.py                            # LIF/ALIF and HDC scores per source (Phase 4)
  sg/lif.py, sg/stdp.py               # LIF/ALIF bank, Hawkes twin, WTA-STDP
  sg/hdc.py, sg/hdc_gpu.py            # HDC encoder and prototypes (CPU),
                                      #   GPU kernels (ROCm/CUDA PyTorch)
  sg/akd/                             # pybind11 binding to libakida (AKD1500)
  bench/lif_eval.py, bench/stdp_eval.py  # Phase 3 / Phase 5 gate harnesses
  bench/hdc_eval.py, bench/harness2.py   # HDC gate harness, round 2 summaries
  bench/hdc_gpu_check.py, bench/hdc_gpu_gate.py  # GPU path check and gate
  bench/akd_check.py, bench/akd_h1.py    # AKD1500 bit-exact check, H1 model
  bench/verdict_eval.py               # verdicts vs cached LLM cards
                                      #   (no API calls)
  bench/baselines.py                  # baseline detectors vs injected
                                      #   archetypes (recall@k, chance)
scripts/                              # source-data preprocessing (NOT analyzers)
  consolidate_logs.py                 # rotated syslog -> merged.log.gz with
                                      #   per-file clock-skew correction
                                      #   against FortiGate / newsyslog anchors
data/                                 # SOURCE data only -- do not write here
  merged.log.gz                       # honeypot log (optional: --input
                                      #   can point at any path)
output/                               # ALL pipeline output goes here
  parquet/                            # parser output (4 tables, daily-partitioned)
  features/                           # per-IP feature snapshots
  models/                             # registered model artifacts + registry.json
  reports/                            # analyzer + final report output
  patterns/                           # pattern-mining + change-point output
  risk/                               # risk scores
docs/
  ARCHITECTURE.md                     # data model, DAG, model contracts
reports/                              # research reports (neuromorphic plan)
research_notes/                       # source notes for those reports
VIBE_HISTORY.md                       # session log
.evolve/freshness.json                # skip-if-fresh cache
```

The `scripts/` directory has only the tools that prepare the raw input. The
analyzer code is in `src/`. `scripts/consolidate_logs.py` is the first step
of the pipeline:

- Input: the rotated honeypi00 syslog `.gz` files.
- Output: one sorted `merged.log.gz` file with the clock skew corrected.
  Give this file to `evolve.py --input`.
- It also writes a clock-skew dossier in `output/reports/clock_skew/`.

The `data/` directory is for the source input. All the outputs go to
`output/`.

## Pipeline summary

The pipeline has 48 steps in a DAG. The orchestrator (`evolve.py`) makes a
dependency graph from two sources:

- The explicit edges.
- The edges that it finds where the input globs of a step are the same as
  the output globs of a different step.

The top of the graph (text only, with no box-drawing characters):

| Step | Parent steps |
| --- | --- |
| `parse` | None (it starts only with `--input`) |
| `analyzers` | `parse` |
| `sensormask` | `parse` (it reads `packets` and `clock_runs`) |
| `neuro` | `analyzers`, `cluster`, `chainfp`, `sensormask` |
| `features` | `analyzers`, `cluster`, `neuro` |
| `model` | `features` |
| `score` | `features`, `model` |
| `risk` | `score` |
| `dossiers` | `risk` |
| `mining` | `features` |
| `promote` | `mining` |
| `actors` | `features` |
| `drift` | `features` |
| `chains`, `sequences`, `coordination`, `rotation`, `cross_modal`, `survival`, `pktanalysis`, `payloadanalysis`, `pacing`, `landscape`, `protocolanomaly`, `isc_compare`, `longitudinal`, `slowlow`, `dnstlsintel`, `selfmimic` | `analyzers` |
| `nonipproto`, `asnintel`, `cidrintel`, `tooling` | `analyzers` |
| `aipayloaddecode` | `nonipproto` |
| `actorlink` | `analyzers`, `tooling`, `risk` |
| `originintel` | `actorlink` |
| `correlate` | `risk`, `nonipproto`, `protocolanomaly`, `asnintel`, `cidrintel`, `tooling`, `slowlow`, `selfmimic`, `isc_compare`, `coordination`, `chains` |
| `verdict` | `correlate`, `analyzers`, `risk` (a verdict from fixed rules for each finding) |
| `conclude` | `correlate`, `kg` (opt-in: an LLM narrative for each finding) |
| `report` | All the steps before it (25 or more, with `verdict`) |
| `adversarysim` | `slowlow`, `dnstlsintel`, `selfmimic`, `risk`, `report` |
| `aireview` | `report` |

Note: `asnintel`, `chains`, `cidrintel`, `actorlink` and `promote` use
`features` and `risk`. They read the feature vector of each IP address with
a join to the risk-tier table. Earlier versions of the DAG had only
`analyzers` as their parent. On 2026-05-29 these steps stopped with the
error `no risk file` on a pipeline with no outputs, and the DAG got the
correction.

Each step with no other parent step has `parse` as its parent. Thus a new
parse completes before the analysis starts. Without `--input`, the
orchestrator does not start `parse`, and the other steps start.

`python src/evolve.py --show-dag` gives the full list of edges. The steps
with an I/O contract use the skip-if-fresh cache. The other steps run at
all times. For `parse`, the cache also compares the mtime of the
`--input` files with the Parquet tables. Thus, if the input and the
parser code did not change, the step does not parse again.

## Method notes

Many AI providers (Claude, OpenAI, xAI, Mistral, Gemini) did a review of the
pipeline. The project applied each recommendation that 2 or more of the 5
providers gave. The important changes are:

- **Drift**: Wasserstein-1, PSI and Benjamini-Hochberg FDR replaced the
  KS test (that had no FDR).
- **Actor clusters**: HDBSCAN gives the `cluster_persistence_` of each
  cluster and a global DBCV score. The code flags the clusters that are not
  stable, and it does not remove them.
- **Pattern mining**: an FP-Growth itemset must have a lift of 2 or more
  and a conviction of 1.5 or more. The code calculates these values for
  each item. It does not use `association_rules`, because that function
  had an OOM at 1 million itemsets.
- **Pattern promotion**: the code uses the Wilson lower confidence bound
  on purity, not a point estimate. Thus a pattern with small support does
  not get promotion by chance.
- **Change points**: PELT uses an mBIC penalty that changes with the length
  and the variance. It does not use a fixed value.
- **Community detection**: Leiden (Traag and others, 2019) replaced
  Louvain.
- **Cross-modal lag**: STL removes the weekly pattern and the trend before
  the correlation. This removes weekly lags that look causal but are not.
- **Threat classifier**:
  - The train and validation sets come from the `first_seen` time, not
    from a random selection.
  - The model gives the Brier calibration and the unlabeled positive rate
    with the AUC and AP.
  - The registry keeps the SHAP attribution with the model.
- **Originintel**: a new prompt asks for graded confidence, with explicit
  `alternative_classes` and `uncertainty_notes`. The default confidence is
  `low`, unless the evidence is very strong.
- **Model registry**: a cross-process `filelock` on `registry.json` covers
  each read, change and write. Thus two training steps that run at the same
  time cannot replace the entries of the other step.
- **BOGON filter**: the new code uses the `ipaddress` module.
  - It does correct CIDR tests for CGNAT (100.64/10) and for all of IPv6
    (`::`, `::1`, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32).
  - The previous test used string prefixes, and it flagged `1.1.1.10` as a
    bogon in error.
- **New analyzers**: `slowlow` (slow scanners that send a small number of
  packets), `dnstlsintel` (DGA and brand names), `selfmimic` (traffic that
  sends back the sensor banners), `adversarysim` (a synthetic coverage
  harness).
- **Clock-skew correction** (2026-05-29):
  - From 2025-09-23, the hardware clock of the honeypi00 sensor sometimes
    did not work. At each reboot, it went back to its 2019-02-14 epoch.
  - The consolidator uses the FortiGate `date=time=tz=` lines and the
    newsyslog ISO-UTC prefix lines in the same syslog stream as anchors.
    It finds the skew of each run.
  - It writes the corrected time into the first ISO column and into the
    `PacketTime:` field. Thus all the tools after it (the parser, grep)
    see the same timestamps.
  - The skew values for each file are in `output/reports/clock_skew/`.
- **Cross-signal findings, with a narrative from an LLM** (2026-05-29):
  - `src/conclusions/correlate.py` applies 18 cross-analyzer rules to all
    the analyzer parquet files and the risk snapshot. It writes
    `findings.parquet`.
  - Then `src/conclusions/synthesize.py` sends a prompt to the configured LLM. The LLM writes
    these fields for each finding: what, why it is important, threat model,
    risk, and the recommended action. The cache key is the sha256 of the
    prompt.
  - The rules include these patterns, and more:
    - The telco SS7 and SIGTRAN signature
    - Synchronized campaign bursts and recent short campaigns
    - The density of bulletproof ASNs
    - RDP credential spray, IPsec ESP probes and covert tunnels
  - Section 0.5 of the report shows each finding before the executive
    summary. Thus a defender can find them quickly.
  - Since 2026-10-30, `src/conclusions/verdict.py` gives the verdicts, and
    `synthesize.py` is an opt-in step. Refer to the next item.
- **Verdicts from fixed rules** (2026-10-30):
  - The LLM narratives had 3 problems. They were expensive (approximately
    $6 for each full run), they were long (883 KB of text for 175
    findings), and cards with the same facts got different verdicts.
  - `src/conclusions/verdict.py` measures facts for all the member sources
    of each finding:
    - the share of each L7 protocol
    - the share of known research scanners (`benignfilter`)
    - the share of botnet payloads and of bulletproof hosting (risk
      rationale)
    - the number of sources that sent HTTP credentials and that are not
      known scanners
    - the share of bulletproof ASNs in an ASN-level finding (`asnintel`)
  - An ordered rule table gives one verdict: `exploit_attempt`,
    `credential_attack`, `hostile_infrastructure`, `service_recon`,
    `protocol_anomaly`, `research_scanner`, `benign_p2p`, `context` or
    `unclassified`. When no rule fires, the verdict is `unclassified`.
  - Each verdict has the rule, the ATT&CK technique, a sentence that gives
    the numbers, an action and a basis (`members`, `sample`, `asns` or
    `pattern`).
  - The step merges the findings with the same verdict and target into
    problems (`output/conclusions/problems.parquet`).
  - The same corpus always gives the same output. The step runs in
    approximately 2 seconds, and it makes no API calls.
  - `src/bench/verdict_eval.py` compares the verdicts with the cached LLM
    cards. Refer to `docs/ARCHITECTURE.md` section 2 for the results.
- **Campaign start detection** (2026-05-30):
  - `detect_coordination.py` calculates the first-arrival percentiles of
    each payload (p5 start, p25, p50, p75, p95 end) and the day with the
    most traffic (the peak).
  - It sorts the campaigns by
    density_score = `ip_count * corpus_span_days / burst_window_days`.
  - The code removes the background payloads that occur at all times. These
    are the payloads with senders across more than 60% of the corpus.
  - Section 6 of the report shows a start histogram for each month, a
    top-20 SVG Gantt chart and a top-50 table. The chart has month-year
    labels on the axis and gray dashed grid lines.

Refer to `docs/ARCHITECTURE.md` for the full data and model contracts.
Refer to `VIBE_HISTORY.md` for the history of the pipeline.

## Neuromorphic detection plan (v3.4, all phases built and tested)

The research report `reports/Neuromorphic anomaly detection for honeypi.md`
examined SNN, HDC, reservoir, and HTM methods for the honeypi data. No
published result shows that these methods find network anomalies better than
`isolation forest` or ECOD. Thus the plan uses them for three new signals,
not for better detection numbers:

1. Graded similarity between session chains (HDC on `chainfp` tokens).
2. An adaptive baseline for the global arrival series (ESN or NG-RC with the
   HTM anomaly-likelihood layer).
3. A timing surprise for each event of a source (event-driven LIF).

Phase 0 gives the data and the yardstick that each subsequent phase must
have:

- `sensormask` (DAG stage) writes the sensor-off intervals. A `gap` interval
  is 30 or more minutes with no packets. NTP replies (UDP from port 123) to
  the sensor do not count as packets for this test. The 2025-11-11 to
  2026-02-05 outage is one `gap` interval. A `run_boundary` interval is 5 s before and after a
  clock-run start.
- `scripts/consolidate_logs.py` writes
  `output/reports/clock_skew/clock_runs.parquet`. Run the consolidator again
  to get this file.
- `adversarysim.py --inject NAME --day D` writes nine archetypes as full
  `packets` rows into `output/eval/inject/NAME/`. The corpus on disk does not
  change.
- `bench/baselines.py --eval NAME` scores random, count, z-score, STL,
  IForest, and ECOD detectors on those archetypes. It gives recall@k with the
  chance level, and no point adjustment.

Each phase has an exit gate. A new detector must be better than the
baselines and than an untrained copy of itself on the same injection set.

All phases ran on all the data on 2026-10-24: 899 days with packets, from
2023-07-07 to 2026-06-30. No neuromorphic detector was better than its
classical twin. `docs/ARCHITECTURE.md` §9.5 to §9.9 give the full results.
Round 2 (§9.10) found three detectors that are better than their matched
classical twins on the test sets and on the development sets: `lif` on
`beacon_gap`, and `hdc_proto` and `hdc_drift` on `rotating_actor`.

| Phase | Code | Gate result |
| --- | --- | --- |
| 1. HDC choreography novelty | `sg/hdc.py`, `bench/hdc_eval.py` | Round 1: failure. `hdc_align` found 22 of 70 `chain_mutation` sources, and its RFF twin found 24. Round 2 (2026-10-27): `hdc_proto` and `hdc_drift` get `pass` against their matched RFF twins on `rotating_actor`, on the test sets and on the development sets (recall at k = 100: 0.35 and 0.31 against 0.09 and 0.01 on the test sets). |
| 2. Global arrival detector | `bench/arrival_series.py`, `bench/arrival_eval.py` | Failure. `ngrc_htm` gave 97.6 incorrect alarms each year, and `stl_z` gave 10.3. |
| 3. LIF/ALIF timing for each source | `sg/lif.py`, `bench/lif_eval.py` | Failure by 0.01. On 43 days, `lif` found 0.82 of 430 beacons in the top 10, `pacing` 0.04. But `pacing` with the same calibration found 0.86. |
| 4. Feature and risk inputs | `neuro.py` (DAG step), 8 `neuro_*` feature columns, `neuro_signal` risk term (8 points or less) | Built and run on all data. The arrival term gave an alarm minute to all sources in that minute, so its cap is 0 (operator decision of 2026-10-25). The HDC term (`hdc_proto`, `hdc_drift`, cap 4 points) uses the LIF flag level of 4 (operator decision of 2026-10-27). Few sources get HDC points, because only a very small number of calibrated HDC scores are 4 or more. The gate uses the escalation labels of `docs/NEUROMORPHIC_ROUND2_PLAN.md` §3.4. |
| 5. WTA-STDP port prototypes | `sg/stdp.py`, `bench/stdp_eval.py` | Failure. No recall on `chain_mutation`. The AKD1500 card part is in the next section. |

To run the tests again:

```bash
./venv/bin/python src/bench/arrival_series.py
OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4 NUMBA_NUM_THREADS=4 \
    ./venv/bin/python src/bench/arrival_eval.py --mode full
./venv/bin/python src/adversarysim.py --inject p3t_20240606 --day 2024-06-06 \
    --replay-copies 10 --beacon-copies 10
./venv/bin/python src/bench/baselines.py --eval p3t_20240606
./venv/bin/python src/bench/lif_eval.py --eval p3t_20240606
./venv/bin/python src/bench/stdp_eval.py --eval p3t_20240606
./venv/bin/python src/bench/lif_eval.py --summary p3t_20240606 [more sets]
```

Use 4 threads for each numeric library. With 24 threads on a loaded host,
`arrival_eval.py` was 9 times slower.

`docs/NEUROMORPHIC_COMPANIONS.md` examines the companion methods (Hawkes,
SPOT, MIDAS, BOCPD, sketches and others).

The first test used a slice of 25 days (2024-01-13 to 2024-05-10). All
baselines missed `lockstep_24` at k = 100 or less, and `port_hour_z` found
nothing. Phases 1 to 3 must find this archetype.

See `docs/ARCHITECTURE.md` section 9 for the phase table, the data
contracts, and the rules for each stateful detector.

### GPU path for HDC (2026-10-27)

`sg/hdc_gpu.py` runs the HDC encoder and the prototype step on the GPU
with ROCm or CUDA PyTorch. The `neuro` step uses it when PyTorch finds a
GPU (`--hdc-device auto`, the default). On the GPU, the default is 2 workers
(`--hdc-workers`), because the integrated GPU uses host memory.

- The encoder output is bit-exact with the CPU encoder.
- The GPU path calculates the prototype dot values as integers, with no rounding. The
  CPU path rounds in float32. Thus `hdc_proto` is not fully the same on
  the two paths (Spearman 0.995 to 0.999).
- The GPU path is in the cache key. A change of device calculates the days
  again.
- Throughput on 8 days: CPU with 4 workers 55.4 s for each day, GPU with
  2 workers 16.8 s. The full run of 899 days took 7.7 hours.
- `bench/hdc_gpu_gate.py` calculated the GPU path as `hdc_proto_gpu` on
  all 305 gate sets. It gets `pass` against `rff_proto` on `rotating_actor`
  (test and development sets), with no difference from the CPU
  `hdc_proto`.

```bash
./venv/bin/python src/bench/hdc_gpu_check.py      # encode and score, CPU against GPU
./venv/bin/python src/neuro.py --hdc-device gpu   # or: evolve.py neuro
```

### AKD1500 card (2026-10-27)

The BrainChip AKD1500 PCIe card is in the host. It operates with
a driver that the operator built for kernel 7.0 (`/dev/akd1500_0`). The
vendor Python package must have TensorFlow and Python 3.12 or older. Thus
`src/sg/akd/` is a pybind11 binding to libakida 2.19.3 (C++), and the
models train in PyTorch.

- `bench/akd_check.py` compares the card, the libakida software and a
  NumPy reference. With 4-bit weights, the outputs are bit-exact.
- Fault: with 1-bit weights and 15 to 32 units, output unit 13 uses the
  `act_step` of unit 14 (742 mismatches of 2,171,664 outputs). Do not use
  1-bit weights on the card. The driver notes have the full report.
- Speed of model H1: the card uses 17.4 µs for each window (batches) and
  39 µs for one call. The libakida software uses 0.78 µs on the CPU. The
  PCIe cost is larger than the calculation. At this time, there is no
  energy value.

```bash
./venv/bin/python src/bench/akd_check.py
./venv/bin/python src/bench/akd_h1.py score --device auto   # card if found
```

## Performance changes (2026-05-30)

A read-only inspection (performance, security and AI-slop) gave the tier 1
corrections that follow. The full run time decreased from **9 h 53 min to
6 h 35 min** on the corpus of 1.1 billion events. This is approximately 33%
less time. Most of the decrease came from the consolidator change.

- **`*.key.txt` in `.gitignore`**: git ignores the five LLM API key
  files in the root of the repository. Thus `git add -A` does not add them.
- **`scripts/consolidate_logs.py`: gzip to zstd** for the temporary
  files of each input file and for the compression of the GNU sort spill.
  - The output `merged.log.gz` stays in gzip format, for the tools after it.
  - The consolidator time decreased from 6 h 16 min to 2 h 36 min
    (approximately 2.4 times faster).
  - The merge-spill part alone decreased from 5 h 50 min to 2 h 10 min.
- **`src/parser.py`**:
  - The base64 `Packetdata:` capture has a maximum of `{1,131072}`
    characters. Thus a very large blob cannot use all the memory of a
    worker process in `base64.b64decode`.
  - The `--workers` default changed from `min(6, cpu-2)` to
    `max(2, cpu-2)`, because the writer OOM had a correction before.
  - In `parse_text_fields`, one `finditer` with `lastgroup` dispatch
    replaced 11 different `.search()` calls for each line.
  - The total time did not change, because the writer controls the speed
    (pyarrow writes approximately 200k rows each second). But each worker
    uses approximately half of the CPU time that it used before. This helps
    if the writer becomes faster in the future.
- **`src/longitudinal/detect_coordination.py`**:
  - One `CREATE TEMP TABLE first_per_payload_ip` pass replaced 3 or 4 full
    scans of the `packets` view (1.1 billion rows).
  - The code gets the candidate shas, the percentiles, the peak day and the
    IP counts from this table.
  - The arrival-burst step reads `packets` one more time, because it must
    have the SYN scans that have no payload.
- **`src/asnintel.py`**:
  - The code writes `(src_ip, asn)` one time into
    `CREATE TEMP TABLE asn_ip`.
  - The four queries after it (top ports, top families, top probes,
    cooperation score) use this small table in memory. Before, each
    query read `packets` and the feature parquet one time.
  - The time did not change, because the DuckDB planner did this
    correctly before. The change stays as a second protection.
- **`src/sg/lib.py:load_report()` helper**:
  - One call replaces a pattern that occurred approximately 40 times in
    `comprehensive_report.py`:
    `path / if exists / con.execute(SELECT FROM read_parquet) / fetchall`.
  - Some of the call sites use the helper at this time. The other call
    sites can change in the future.
- **`src/conclusions/correlate.py`**:
  - The code of the `_table` wrapper, which had only one call, is in the
    caller at this time.
  - `TELCO_TCP_PORTS` is a `frozenset`, not a dict with descriptions
    that the code did not use.
  - 12 limits (`> 0.5`, `>= 50`, `< 7 days`, and others) have names as
    module constants at this time.

## Reporting

Each run makes the same full report in three formats at
`output/reports/COMPREHENSIVE.{md,html,pdf}`:

- Section 0 is a summary that a defender can read in 60 seconds.
- Section 0.5 gives the cross-signal problems.
- Sections 1 to 32 give the full analysis, with a caption for each table.

The report has these parts:

- Summary (Section 0): top-5 threats, top-5 actor communities, the drift
  warning, the number of problems that need action, and the recommended
  steps.
- **Cross-signal problems** (Section 0.5):
  - A problem table. Each row is one verdict and one target, with the
    number of findings, the number of different sources, the ports, the `detail` column and
    the dates.
  - A legend that gives one action for each verdict.
  - A finding index, with one line for each finding: the verdict, the rule
    and the facts that caused the verdict.
  - The report shows no LLM narrative.
- Sensor outages (Section 1): each run of UTC days with no packets, with
  its first day, last day and day count. The report finds these days from
  the `packets` day partitions. Rates and baselines have no data for these
  days.
- Risk tiers, with histograms of the composite score.
- Country, ASN and CIDR tables.
- L7 protocol mix, and the decoded non-IP protocols (from a local or a
  hosted AI).
- Attack chains for each IP address (RPDBC: recon, probe, drop, brute, C2,
  exfil).
- **Campaign start, Section 6**:
  - A start histogram for each month.
  - A top-20 SVG Gantt chart of the time length of each campaign (from the p5 start
    to the p95 end). Each bar has a label. The label is white in the bar,
    or black near a short bar with a gray line to the bar.
  - A top-50 table, sorted by density.
- Promoted rules from the pattern mining, and content-pattern candidates.
- ML feature drift (Wasserstein, PSI, BH-FDR).
- Survival analysis for each actor cohort.
- The types of attack that the detectors do not find, and recommended actions.
- Actor Atlas: Leiden communities, with an AI profile when you configure
  an AI provider.
- A catalog of the non-IP protocols, with sample payloads that an AI
  decoded (SCTP, GRE, ESP/AH, IP-in-IP, 6to4 and others).
- Neuromorphic scores, Section 32:
  - The count of sources that the LIF/ALIF bank and HDC gave a score to,
    and the count that they flagged.
  - The sources with a `neuro_signal` risk term, for each tier.
  - The top 25 sources by that term.
  - The HDC-flagged sources, in groups by day.
- A data-quality appendix for each analyzer.

## License and data

The corpus is the honeypot capture of the operator. Do not add it to git.
Do not add the `*.key.txt` files to git. Git ignores them, but this rule is
important.
