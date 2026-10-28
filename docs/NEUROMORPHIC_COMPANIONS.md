# Companion methods for the neuromorphic plan

This note examines ten families of streaming methods that teams frequently put
next to spiking networks. For each family, it gives:

- The mathematical link to a neuromorphic primitive of the plan (LIF, HDC,
  ESN or NG-RC, HTM likelihood).
- The fit to the SensorGrind data.
- The phase of the plan where it goes, if it goes in.

The plan is in `docs/ARCHITECTURE.md` section 9.

## 1. Summary

1. Four methods go into Phase 2: EVT tail thresholds (SPOT), a discrete
   Hawkes model, MIDAS on edge streams, and change-point detection
   (BOCPD). Each of them has a direct use for the global arrival series.
2. Count-Min sketches and HyperLogLog give no value in the batch
   pipeline. DuckDB gives counts with no error, and `approx_count_distinct` is
   a HyperLogLog. They have value only for an online version on the
   sensor.
3. HDC was the subject of Phase 1. On this data, HDC was not better than a
   classical RFF encoder with the same steps (22 against 24 of 70).
4. The Hawkes model is the statistical twin of the Phase 3 LIF neuron. The
   two models use the same exponential kernel. Thus Phase 3 must compare
   the LIF with a Hawkes model.
5. A Markov model of the token sequence, Half-Space Trees and a self-organizing
   map are candidates for Phases 3 to 5.
6. Methods for lateral movement, user accounts and log keys do not apply.
   The sensor sees only inbound traffic to one address. It has no internal
   hosts, no users and no application logs.

## 2. The mathematical link: the exponential kernel

A LIF neuron with no reset has the membrane value
`v(t) = Σ w·e^(−(t − tᵢ)/τ)` for its input events `tᵢ`. Three of the
companion methods use the same kernel:

| Method | Quantity | Same as LIF when |
| --- | --- | --- |
| Count-Min sketch with decay | `c ← c·e^(−Δt/τ) + 1` for each counter | Each counter is a LIF neuron with no threshold |
| Hawkes process | `λ(t) = μ + Σ α·e^(−β(t − tᵢ))` | `β = 1/τ`, `α = w`, and the firing is a random function of `λ` |
| Leaky HTM likelihood window | Mean of the recent anomaly scores | The short window is an exponential average |

A LIF neuron with escape noise is a nonlinear Hawkes process [1, 2]. Thus
the Hawkes model gives the LIF a likelihood, and an analyst can examine
that number. This is the most important link in this note.

An exponential decay does not apply directly to HyperLogLog. Its registers
keep a maximum, not a sum. For a time window, keep one HyperLogLog for
each time bucket and merge the buckets of the window. A sliding-window
HyperLogLog is also possible.

## 3. The ten families

### 3.1 Streaming sketches (Count-Min, HyperLogLog)

- **Link:** each decayed counter is a leaky integrator. A signed sketch
  with one row is a sparse form of an HDC bundle [3].
- **Fit:** low for the batch pipeline. The pipeline runs in DuckDB on
  Parquet. It counts the sources, ports and new sources of each minute
  with no error, and the cost is small.
- **Use:** the Phase 2 minute vector puts the destination ports into 16
  hash buckets. This is one row of a Count-Min sketch. It keeps the vector
  at a fixed size.
- **Later:** an online detector on the Raspberry Pi sensor must use sketches,
  because the Pi cannot keep full sets of sources.
- **Use in Phase 2:** the operator added two sketch detectors to the
  development run.
  - `cms`: a Count-Min sketch of ports with two decayed copies (10 minutes
    and 1 day). The score is the largest rate ratio of a port in the minute.
  - `hll`: the HyperLogLog fan-out of each source (the port-scan signal).
    The score is the largest fan-out of a 10-minute block, as a robust z.

### 3.2 Hyperdimensional computing

- **Link:** this is a primitive of the plan, not a companion.
- **Result:** Phase 1 gave a gate failure. The alignment step found the
  mutated chains, but the HDC encoder did not do better than its RFF twin.
- **Use:** none for Phase 2. The encoder stays as a research tool.

### 3.3 Hawkes processes

- **Link:** the same kernel as LIF (section 2).
- **Fit:** high. Campaign traffic excites more traffic: when one source of
  a botnet starts, more sources follow in the next minutes.
- **Use in Phase 2:** a discrete Hawkes model on the counts of each minute,
  `λₜ = μₕ + Σₖ α·βᵏ·Nₜ₋ₖ`, with `μₕ` for each hour of the day. This model
  is a Poisson autoregression. The score is the Poisson tail probability of
  the count. The cost is one recursion step for each minute.
- **Use in Phase 3:** the classical twin of the LIF timing detector. A
  multivariate Hawkes model on port groups learns which port groups trigger
  other port groups. This does the same work as STDP, with numbers that an
  analyst can examine.

### 3.4 Markov chains for each entity

- **Link:** none to the spiking math. A Markov table models the sequence, and
  a LIF neuron models time.
- **Fit:** moderate. `chainfp` gives a token sequence for each session of a
  source. In Phase 1, the string twin `str_align` found 18 of 70
  `chain_mutation` sources with full chain strings only. A Markov table of token
  transitions is a smaller form of the same information.
- **Use:** a candidate for Phase 3 or 4, as a source score with an easy
  explanation: "this source sent RST after SYN-ACK, and no fit source did".
- **Use in Phase 2:** the operator added a global form to the development
  run as a reported detector. The chain uses the packet tokens of each
  source, and the minute score is the mean surprise of the transitions of
  the minute.

### 3.5 Streaming graph detection (MIDAS)

- **Link:** MIDAS keeps Count-Min sketches of edge counts and compares the
  count of the current time tick with the mean of all the ticks before it. Each
  sketch counter is a leaky integrator in the MIDAS-R form.
- **Fit:** high. An edge is (source /24, destination port), and the tick is
  one minute. A coordinated wave is a microcluster: many edges of the same type
  in a short time. MIDAS finds microclusters in constant time and
  memory for each edge [4].
- **Use in Phase 2:** a competitor detector. All the Phase 0 baselines
  missed the `lockstep_24` archetype at k = 100. That archetype is a
  microcluster of edges.
- **Not applicable:** lateral movement and service accounts. The sensor has
  no internal network.

### 3.6 Streaming tree methods (RRCF, Half-Space Trees)

- **Link:** none to the spiking math. These methods use the same features
  with no sequence. Thus they are a second opinion.
- **Fit:** moderate. The `river` library (0.26.1) has Half-Space Trees and a
  wheel for Python 3.14.
- **Use:** one more column in the Phase 2 report, with the agreement rate
  between Half-Space Trees and the primary detector. It does not go into
  the gate.
- **RRCF:** the operator also added RRCF to the development run. The
  `rrcf` package for Python is too slow for 680,000 minutes, so
  `arrival_eval.py` has a numba version. Each day builds a forest from the
  fit window, and each minute gets the mean CoDisp of its insertion.

### 3.7 Change-point detection (CUSUM, BOCPD)

- **Link:** BOCPD keeps a distribution of the run length since the last
  change [5]. Its hazard sets the prior of the segment length.
- **Fit:** high. One of the three known events of the Phase 2 gate is a
  five-day SSH campaign. A five-day campaign is a change of level, not a
  short peak.
- **Use in Phase 2:**
  - Run BOCPD on the residual of the primary detector.
  - When BOCPD shows a new segment, stop the readout refit for the first
    24 hours of the segment. Thus a slow increase from an adversary cannot
    teach the model a new usual level without a record of it.
  - The pipeline has PELT (`detect_changepoints`), but PELT works
    offline on the full series.

### 3.8 Extreme value theory (SPOT)

- **Link:** the HTM likelihood layer gives a Gaussian tail probability of
  the recent mean score. EVT fits a generalized Pareto distribution to the
  tail of each score. The tail of network counts is heavy, so the Gaussian
  tail is not correct there.
- **Fit:** high. The Phase 2 plan uses Benjamini-Hochberg across the
  series. Benjamini-Hochberg must have correct p-values for each series. SPOT
  gives a tail p-value with a set risk level, and DSPOT also follows drift
  [6].
- **Use in Phase 2:** a twin of the likelihood layer. The same NG-RC
  residual goes into the HTM likelihood in the primary detector, and into
  SPOT in the twin. EVT also puts the scores of different detectors on one
  scale. Phase 4 must have this scale for the risk term.

### 3.9 Self-organizing maps

- **Link:** a SOM is a neural network with competitive learning, like the
  WTA-STDP prototypes of Phase 5.
- **Fit:** moderate, for the view only. A SOM of the minute vectors (or of
  the source vectors) gives a stable 2-D map. A cell that gets no traffic
  in the fit period and then gets traffic is a new behavior.
- **Use:** Phase 4 or 5, for the report and for the Spoor view. It does not
  go into a gate.
- **Use in Phase 2:** the operator added the SOM to the development run as
  a reported detector. The score is the quantization error of each minute.
  In a trial on 20 days, the SOM did not flag the change of level on
  2025-07-10. After the change, the minutes were near cells that the map
  learned from the fit window.

### 3.10 Learned sequence models (DeepLog and others)

- **Link:** none.
- **Fit:** low. DeepLog must have log keys from an application. The nearest
  equivalent here is the `chainfp` token sequence. Phase 1 showed that a
  score for each session cannot show the difference between a mutated session from a scanner
  on a random port. A larger sequence model has the same limit.
- **Use:** the operator added the DeepLog parameter-value model to the
  Phase 2 development run as a reported detector. This part of DeepLog
  uses an LSTM to predict the next parameter vector, and the minute vector
  is such a vector. The log-key model stays a candidate for Phase 5, on
  the sources that the fast detectors flag.

## 4. Decisions for Phase 2

Phase 2 builds the global arrival detector. The design and the
pre-registered gate are in `docs/ARCHITECTURE.md` section 9.6. The
companion methods go in as follows:

| Method | Role in Phase 2 | In the gate |
| --- | --- | --- |
| NG-RC with the HTM likelihood | Primary detector | Yes |
| Linear AR with the HTM likelihood | Twin: the same steps with no nonlinear features | Yes |
| NG-RC with SPOT | Twin: EVT in place of the HTM likelihood | Yes (reported) |
| Untrained readout with the HTM likelihood | Untrained copy (rule 7 of section 9.3) | Yes |
| Discrete Hawkes | Competitor | Reported |
| MIDAS-R on (/24, port) edges | Competitor | Reported |
| Half-Space Trees | Second opinion | Reported |
| Robust Random Cut Forest | Second opinion | Reported |
| BOCPD | Refit control and level-change report | Reported |
| DeepLog parameter-value model (LSTM) | Competitor | Reported |
| Markov chain of packet tokens | Competitor | Reported |
| Self-organizing map | Competitor | Reported |
| Port hash buckets (one Count-Min row) | Part of the minute vector | Not a detector |
| Decayed Count-Min sketch of ports | Competitor | Reported |
| HyperLogLog fan-out of each source | Competitor | Reported |

The Phase 1 result gives one rule for all phases: each neuromorphic
detector must have a classical twin that uses the same steps. If the twin
gives the same result, the gain comes from the steps, not from the
neuromorphic part.

## 5. Sources

1. Brinkman, Rieke, Shea-Brown and Buice, "Predicting how and when hidden
   neurons skew measured synaptic interactions", the appendix
   maps a LIF network with noise to a nonlinear Hawkes model.
   <https://arxiv.org/pdf/1702.00865>
2. Mensi, Naud and Gerstner, "From Stochastic Nonlinear Integrate-and-Fire
   to Generalized Linear Models", NeurIPS 2011.
   <https://proceedings.neurips.cc/paper/2011/hash/82489c9737cc245530c7a6ebef3753ec-Abstract.html>
3. HyperCam (2025) uses a count sketch as an approximate HDC bundle.
   <https://arxiv.org/pdf/2501.10547>
4. Bhatia, Hooi, Yoon, Shin and Faloutsos, "MIDAS: Microcluster-Based
   Detector of Anomalies in Edge Streams", AAAI 2020.
   <https://arxiv.org/pdf/1911.04464>, code:
   <https://github.com/bhatiasiddharth/MIDAS>
5. Adams and MacKay, "Bayesian Online Changepoint Detection", 2007.
   <https://arxiv.org/abs/0710.3742>
6. Siffer, Fouque, Termier and Largouet, "Anomaly Detection in Streams with
   Extreme Value Theory", KDD 2017.
   <https://www.eecs.yorku.ca/course_archive/2017-18/F/6412/reading/kdd17p1067.pdf>
7. Gauthier, Bollt, Griffith and Barbosa, "Next Generation Reservoir
   Computing", Nature Communications 12, 5564 (2021).
   <https://arxiv.org/abs/2106.07688>
