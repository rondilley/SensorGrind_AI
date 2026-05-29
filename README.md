# SensorGrind_AI

A self-evolving honeypot-log analysis pipeline. Parses 6.6 years of honeypot
sensor logs into Parquet, runs ~35 analyzer stages over them (ML threat
classifier, HDBSCAN actor clustering, FP-Growth pattern mining, Leiden
community detection, change-point detection, drift detection, multi-AI
review, plus 20+ purpose-built analyzers), and emits a comprehensive
defender-facing threat intelligence report in markdown / HTML / PDF.

## What it sees

This is a working pipeline against a real corpus, not a synthetic demo. As of
the latest run (2026-05-29 snapshot):

| metric | value |
| --- | --- |
| total packets | 1,106,119,177 |
| unique source IPs | 992,533 |
| distinct payload blobs (SHA-256) | 97,069,527 |
| L7-classified events | 32,470,013 |
| IOCs extracted | 22,573,247 |
| active days in corpus | 600 |
| corpus span | 2019-02-14 to 2025-09-18 |
| critical-tier threats identified | 15,952 |
| high-tier threats identified | 167,383 |
| actor communities (Leiden) | 1,942 (21 with >= 4 members) |
| auto-promoted behavioral rules (this run) | 20 |

The top-5 threat IPs in the latest run all came back as **Mozi botnet** on
bulletproof or cloud infrastructure. The top-5 actor communities all
returned `commercial scanner` with `medium` confidence -- graded belief by
design, not over-claimed attribution.

## Quickstart

```bash
# 1. Parse the merged honeypot log (one-time, ~hours)
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
    detect_coordination.py            #   coordinated-wave detection
    attack_chains.py                  #   RPDBC stage transitions
    survival_analysis.py              #   Kaplan-Meier on actor cohorts
    infra_rotation.py                 #   infrastructure rotation tracking
  risk/                               # composite risk scoring
    compute_risk_score.py             #   ML x persistence x breadth x ...
    risk_dossier.py                   #   per-IP markdown dossiers
  report/                             # output composition
    comprehensive_report.py           #   17 sections + Section 0 TL;DR
    render.py                         #   Mermaid + Matplotlib + PDF
  slowlow.py                          # slow-and-low scanners
  dnstlsintel.py                      # DNS qname + TLS SNI intel (DGA, mimic)
  selfmimic.py                        # sensor self-banner echo detection
  adversarysim.py                     # synthetic adversary coverage harness
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

The `scripts/` folder is **legacy only** -- all working code lives in `src/`.
The `data/` folder is for source input -- all output goes to `output/`.

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
- actorlink                                                   parents: analyzers, tooling
- originintel                                                 parent:  actorlink
- report           parents: everything upstream (25+ stages)
- adversarysim     parents: slowlow, dnstlsintel, selfmimic, risk, report
- aireview         parent:  report

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

See `docs/ARCHITECTURE.md` for the full data + model contracts and
`VIBE_HISTORY.md` for how the pipeline got here.

## Reporting

Every run produces three formats of the same comprehensive report at
`output/reports/COMPREHENSIVE.{md,html,pdf}`. Section 0 is the 60-second
defender read; Sections 1-17 are the deep dive with per-table captions.

The report includes:

- TL;DR (Section 0) -- top-5 threats, top-5 actor communities, drift
  call-out, recommended next steps
- Risk stratification with composite-score histograms
- Geographic / ASN / CIDR breakdown
- L7 protocol mix + non-IP-protocol decoding (via local or hosted AI)
- Per-IP attack chain reconstruction (RPDBC: recon, probe, drop, brute,
  C2, exfil)
- Pattern-mining promoted rules + content-pattern candidates
- ML feature drift (Wasserstein / PSI / BH-FDR)
- Survival analysis by actor cohort
- Detection gaps + recommended actions
- Actor Atlas -- Leiden communities, AI-profiled (when an AI provider is
  configured)
- Per-analyzer data-quality appendix

## License & data

The corpus is the operator's own honeypot capture. Do not commit it. Do not
commit the `*.key.txt` files (they are git-ignored, but worth saying twice).
