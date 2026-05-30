# SensorGrind_AI

A self-evolving honeypot-log analysis pipeline. Consolidates rotated raw
syslog (with clock-skew correction), parses into Parquet, runs ~36 analyzer
stages over them (ML threat classifier, HDBSCAN actor clustering, FP-Growth
pattern mining, Leiden community detection, change-point detection, drift
detection, **cross-analyzer correlator + LLM-written conclusions**,
multi-AI review, plus 20+ purpose-built analyzers), and emits a
comprehensive defender-facing threat intelligence report in
markdown / HTML / PDF.

## What it sees

This is a working pipeline against a real corpus, not a synthetic demo. As
of the latest run (2026-05-30 snapshot, post-clock-skew-correction):

| metric | value |
| --- | --- |
| total packets (post-dedup) | 1,108,150,395 |
| unique source IPs | 996,354 |
| distinct payload blobs (SHA-256) | 97,000,118 |
| L7-classified events | 32,520,828 |
| IOCs extracted | 22,687,221 |
| active days in corpus | 662 |
| corpus span | 2024-02-08 to 2026-05-29 (with sensor outage 2025-11-12 -> 2026-01-28) |
| critical-tier threats identified | 16,210 |
| high-tier threats identified | 179,989 |
| actor communities (Leiden) | 2,153 (>= 4 members) |
| auto-promoted behavioral rules (this run) | 20 |
| cross-signal findings (correlator + LLM) | 20 (8 critical, 6 high, 6 medium) |
| campaigns identified (>=10 IPs, burst < 60% of corpus) | 1,867 |

The 2019-02-14 → 2025-09-18 history seen in earlier runs was an artifact
of honeypi00's broken hardware clock - the sensor's RTC was repeatedly
resetting to Feb 14, 2019.  The 2026-05-29 consolidator detects that skew
via FortiGate / newsyslog anchors in the same syslog stream and rewrites
each sensor event's timestamp to the real wallclock time at which it
arrived at the log server.  See `output/reports/clock_skew/clock_skew.md`
for the per-file skew dossier.

Top findings in the latest run: 1,809 distinct payload campaigns peaking
simultaneously on **2026-05-19** (coordinated multi-vector botnet push);
**SIGTRAN / SS7 / SIP probing** of telco signaling planes from
CN-clustered infrastructure (16 sources, 2019-02-14 through 2025-08-15);
RDP credential spray reusing the `hello` mstshash cookie across 1,476
distinct IPs over six years.

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
venv/bin/python scripts/consolidate_logs.py
mv ~/temp/sensor_logs/consolidated/merged.log.gz data/merged.log.gz

# 1. Parse the merged honeypot log (one-time, ~95 min on 1.1B events)
venv/bin/python src/parser.py

# 2. Run the full evolve pipeline (DAG-ordered, skip-if-fresh by default)
venv/bin/python src/evolve.py

# 3. Read the report
output/reports/COMPREHENSIVE.md
output/reports/COMPREHENSIVE.html   # browser, live Mermaid via CDN
output/reports/COMPREHENSIVE.pdf    # mermaid pre-rendered to SVG
```

Re-run a specific stage:

```bash
venv/bin/python src/evolve.py mining promote report
```

Parallel execution (DAG-aware):

```bash
venv/bin/python src/evolve.py --parallel 4
```

See the dependency graph:

```bash
venv/bin/python src/evolve.py --show-dag
```

Force a stage to rerun even if its inputs are unchanged:

```bash
venv/bin/python src/evolve.py --force mining
```

## AI provider setup (optional)

Several stages (`originintel`, `aipayloaddecode`, `aireview`) call hosted
LLMs. Drop any of these key files in the repo root and the matching stage
will pick the first one that has both a valid key and an installed SDK:

```
claude.key.txt    # Anthropic
openai.key.txt    # OpenAI
xai.key.txt       # xAI
mistral.key.txt   # Mistral
gemini.key.txt    # Google
```

If no provider is available, the AI-driven stages skip gracefully -- the
rest of the pipeline does not depend on them.

## Layout

```
src/                                  # all working code lives here
  parser.py                           # raw log to 4 Parquet tables
  evolve.py                           # DAG orchestrator + skip-if-fresh
  sgquery.py                          # meta-runner over base analyzers
  sg/                                 # shared library
    lib.py                            #   DuckDB factory, GeoIP, IOC enums
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
  conclusions/                        # cross-signal findings + LLM narrative
    correlate.py                      #   18 hand-coded cross-analyzer rules
                                      #     (telco SS7 recon, sync campaign
                                      #     burst, recent tight campaign, ...)
    synthesize.py                     #   per-finding LLM conclusion:
                                      #     what / why-noteworthy / threat
                                      #     model / risk / recommended-action
  report/                             # output composition
    comprehensive_report.py           #   18+ sections incl. Section 0 TL;DR
                                      #     and Section 0.5 Cross-Signal
                                      #     Findings & Conclusions
    render.py                         #   Mermaid + Matplotlib + PDF
                                      #     (svg_gantt_chart for campaigns)
  slowlow.py                          # slow-and-low scanners
  dnstlsintel.py                      # DNS qname + TLS SNI intel (DGA, mimic)
  selfmimic.py                        # sensor self-banner echo detection
  adversarysim.py                     # synthetic adversary coverage harness
scripts/                              # source-data preprocessing (NOT analyzers)
  consolidate_logs.py                 # rotated syslog -> merged.log.gz with
                                      #   per-file clock-skew correction
                                      #   against FortiGate / newsyslog anchors
data/                                 # SOURCE data only -- do not write here
  merged.log.gz                       # honeypot log
output/                               # ALL pipeline output goes here
  parquet/                            # parser output (4 tables, daily-partitioned)
  features/                           # per-IP feature snapshots
  models/                             # registered model artifacts + registry.json
  reports/                            # analyzer + final report output
  patterns/                           # pattern-mining + change-point output
  risk/                               # risk scores
docs/
  ARCHITECTURE.md                     # data model, DAG, model contracts
VIBE_HISTORY.md                       # session log
.evolve/freshness.json                # skip-if-fresh cache
```

The `scripts/` folder holds raw-input preprocessors only -- analyzer code
lives in `src/`.  `scripts/consolidate_logs.py` is the pipeline's
front-door: rotated honeypi00 syslog `.gz` files in, single sorted
clock-skew-corrected `merged.log.gz` out, plus a clock-skew dossier
under `output/reports/clock_skew/`.  The `data/` folder is for source
input -- all output goes to `output/`.

## Pipeline at a glance

35 stages, DAG-scheduled. The orchestrator (`evolve.py`) computes a
dependency graph from explicit edges plus glob-overlap inference between
each stage's declared inputs and outputs.

Top of the graph (text-only, no box-drawing characters):

- analyzers (no parent)
- features  parent: analyzers
- model     parent: features
- score     parents: features, model
- risk      parent:  score
- dossiers  parent:  risk
- mining    parent:  features
- promote   parent:  mining
- actors    parent:  features
- drift     parent:  features
- chains, sequences, coordination, rotation, cross_modal, survival,
  pktanalysis, payloadanalysis, pacing, landscape, protocolanomaly,
  isc_compare, longitudinal, slowlow, dnstlsintel, selfmimic  parent: analyzers
- nonipproto, asnintel, cidrintel, tooling                    parent: analyzers
- aipayloaddecode                                             parent: nonipproto
- actorlink                                                   parents: analyzers, tooling, risk
- originintel                                                 parent:  actorlink
- correlate        parents: risk, nonipproto, protocolanomaly, asnintel,
                            cidrintel, tooling, slowlow, selfmimic,
                            isc_compare, coordination, chains
- conclude         parent:  correlate (LLM-narrated findings)
- report           parents: everything upstream (25+ stages incl. conclude)
- adversarysim     parents: slowlow, dnstlsintel, selfmimic, risk, report
- aireview         parent:  report

Note: `asnintel`, `chains`, `cidrintel`, `actorlink`, and `promote` all
depend on both `features` AND `risk` (they read per-IP feature vectors
joined against the risk-tier table).  Earlier versions of the DAG
declared only `analyzers` as their parent; this was fixed
2026-05-29 after stages failed with `no risk file` on a cold pipeline.

The full edge list is in `python src/evolve.py --show-dag`. Stages with a
registered I/O contract participate in the skip-if-fresh cache; the rest
always run.

## Methodology notes

The pipeline went through a multi-AI review pass (Claude, OpenAI, xAI,
Mistral, Gemini) and applied every recommendation that hit >= 2-of-5
consensus. The substantive ones:

- **Drift**: KS-test (no FDR) replaced with Wasserstein-1 + PSI +
  Benjamini-Hochberg FDR.
- **Actor clustering**: HDBSCAN now reports per-cluster `cluster_persistence_`
  and a global DBCV score; unstable clusters are flagged rather than dropped.
- **Pattern mining**: FP-Growth itemsets now gated on lift >= 2 + conviction
  >= 1.5 (per-item, not via `association_rules` -- that OOM'd at 1M itemsets).
- **Pattern promotion**: Wilson lower confidence bound on purity instead of
  point-estimate, so small-support patterns do not get promoted on luck.
- **Change-points**: PELT now uses length-and-variance-adaptive mBIC penalty
  instead of a fixed scalar.
- **Community detection**: Louvain replaced with Leiden (Traag et al. 2019).
- **Cross-modal lag**: STL detrending (weekly + trend) before correlation
  to remove spurious weekly "causal" lags.
- **Threat classifier**: temporal `first_seen` split instead of random;
  Brier calibration + unlabeled-positive-rate reported alongside AUC/AP;
  SHAP attribution persisted next to the model.
- **Originintel**: prompt rewritten for graded confidence with explicit
  `alternative_classes` + `uncertainty_notes`; default to `low` confidence
  unless evidence overwhelms.
- **Sensor model registry**: cross-process `filelock` around `registry.json`
  read-modify-write to stop concurrent training stages losing each other's
  entries.
- **BOGON filter**: rewrite using `ipaddress` module -- proper CIDR
  containment for CGNAT (100.64/10), full IPv6 (`::`, `::1`, fc00::/7,
  fe80::/10, ff00::/8, 2001:db8::/32). The previous string-prefix check was
  rejecting `1.1.1.10` as bogon.
- **New analyzers**: `slowlow` (low-and-slow scanners), `dnstlsintel`
  (DGA / brand-mimic), `selfmimic` (sensor banner echo), `adversarysim`
  (synthetic coverage harness).
- **Clock-skew correction** (2026-05-29): the honeypi00 sensor's hardware
  clock failed intermittently from 2025-09-23 onward, repeatedly
  resetting to its 2019-02-14 epoch on every reboot.  The consolidator
  now anchors against FortiGate `date=time=tz=` and newsyslog ISO-UTC
  prefix lines in the same syslog stream, detects per-run skew, and
  rewrites both the leading ISO column AND the body `PacketTime:` field
  so downstream tools (parser, ad-hoc grep) see consistent timestamps.
  Per-file skew stats land in `output/reports/clock_skew/`.
- **Cross-signal findings + LLM-written conclusions** (2026-05-29):
  `src/conclusions/correlate.py` runs 18 hand-coded cross-analyzer
  rules over every per-analyzer parquet + the risk snapshot, producing
  a `findings.parquet`.  `src/conclusions/synthesize.py` then asks the
  configured LLM to write what / why-noteworthy / threat-model / risk /
  recommended-action for each finding (cached by prompt sha256).  The
  rules cover the telco SS7/SIGTRAN signature, synchronized campaign
  bursts, recent tight campaigns, bulletproof ASN density, RDP
  credential spray, IPsec ESP probing, covert tunneling, and more.
  Report section 0.5 surfaces every finding above the executive
  summary so a defender does not have to dig.
- **Campaign-onset detection** (2026-05-30): `detect_coordination.py`
  now computes per-payload first-arrival percentiles (p5 launch, p25,
  p50, p75, p95 decay) and the single busiest day (peak), ranking by
  density_score = `ip_count * corpus_span_days / burst_window_days`.
  Always-on background payloads (whose senders span the whole corpus)
  are filtered out via a 60%-of-corpus cutoff.  Report section 6
  shows per-month launch histograms, a top-20 SVG Gantt with month-year
  axis labels and gray dashed gridlines, and a top-50 table.

See `docs/ARCHITECTURE.md` for the full data + model contracts and
`VIBE_HISTORY.md` for how the pipeline got here.

## Reporting

Every run produces three formats of the same comprehensive report at
`output/reports/COMPREHENSIVE.{md,html,pdf}`. Section 0 is the 60-second
defender read; Section 0.5 is the cross-signal findings layer; Sections
1-25 are the deep dive with per-table captions.

The report includes:

- TL;DR (Section 0) -- top-5 threats, top-5 actor communities, drift
  call-out, cross-signal finding counts, recommended next steps
- **Cross-signal findings & conclusions** (Section 0.5) -- one card per
  matched cross-analyzer rule, with LLM-written narrative (what /
  why-noteworthy / threat model / risk if realized / recommended
  action) and a links-back-to-evidence pointer to the supporting
  per-analyzer section
- Risk stratification with composite-score histograms
- Geographic / ASN / CIDR breakdown
- L7 protocol mix + non-IP-protocol decoding (via local or hosted AI)
- Per-IP attack chain reconstruction (RPDBC: recon, probe, drop, brute,
  C2, exfil)
- **Campaign-onset Section 6** -- per-month launch histogram, top-20
  SVG Gantt of campaign lifespans (p5 launch -> p95 decay) with
  on-bar labels (white inside, black outside with gray connector for
  short bars), and a top-50 density-ranked table
- Pattern-mining promoted rules + content-pattern candidates
- ML feature drift (Wasserstein / PSI / BH-FDR)
- Survival analysis by actor cohort
- Detection gaps + recommended actions
- Actor Atlas -- Leiden communities, AI-profiled (when an AI provider is
  configured)
- Non-IP-protocol catalog + AI-decoded sample payloads (SCTP, GRE,
  ESP/AH, IP-in-IP, 6to4 etc.)
- Per-analyzer data-quality appendix

## License & data

The corpus is the operator's own honeypot capture. Do not commit it. Do not
commit the `*.key.txt` files (they are git-ignored, but worth saying twice).
