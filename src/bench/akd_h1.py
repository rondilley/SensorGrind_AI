#!/usr/bin/env python3
"""
bench/akd_h1 — model H1 of the AKD1500 bench: a timing classifier for each
source window (docs/NEUROMORPHIC_ROUND2_PLAN.md §6, step 2).

Window: one source on one day of an injection set (real packets of the day
UNION the injected packets).  64 inputs, each a count n stored as
min(15, round(log2(1 + n))) (uint4):

   0..31  log10 inter-arrival time, 1 ms .. 100 000 s, 4 bins per decade
  32..47  dst_port class (PORT_CLASSES; 47 = no port / >= 49152)
  48..55  flag / protocol class (FLAG_CLASSES; SYN-ACK, i.e. backscatter,
          and odd flag mixes share slot 53)
  56..63  3-hour bucket of the UTC hour

Only packets.ts, dst_port, tcp_flags, proto and src_ip are read (FEATURES
of harness2).  Labels: the injected archetype of a source (truth level
"source"); real sources and control_replay sources are "background".  The
test-only family rotating_actor is never trained on.  Development sets
(day < harness2.DEV_END) train; the last DEV_VAL_FRAC of development days
validate (early stop); test sets only score.

Network: 64 -> 64 -> 32 -> K, Akida 1.0 FullyConnected layers with 4-bit
weights and 4-bit activations; the last layer has no activation and the
host turns its integer potentials into class logits (p * scale + bias).
Quantization-aware training runs the exact integer arithmetic of
sg.akd.fc_reference in the forward pass (straight-through gradients), so
the exported integers give the trained model bit for bit.

Detectors (score = 1 - P(background); harness2 ranks module "akd_h1"):
  h1_akida  the exported model run by libakida (sg.akd): mapped on the
            AKD1500 card when one is present (score --device auto|card),
            else the software backend; checked equal to h1_quant
  h1_quant  the same integers through sg.akd.fc_reference (CPU)
  h1_float  the float model before quantization (twin)
  h1_gbt    HistGradientBoostingClassifier on the same 64 inputs (twin)

    python src/bench/akd_h1.py windows        # extract every set (cached)
    python src/bench/akd_h1.py train          # GPU when available
    python src/bench/akd_h1.py score          # write harness2 ranks
    python src/bench/harness2.py --summary akd_h1 ALL \\
        --twins '{"h1_akida": ["h1_float", "h1_gbt"]}'

Output: output/reports/harness2/akd_h1/windows/<set>.parquet,
        output/models/akd_h1/{h1.pt,h1_akida.fbz,h1_gbt.pkl,train.json},
        output/reports/harness2/akd_h1/<set>_ranks.parquet
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import pickle
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib  # noqa: E402
from bench import harness2  # noqa: E402

OUT = harness2.OUT / "akd_h1"
WIN = OUT / "windows"
MODELS = lib.OUTPUT_DIR / "models" / "akd_h1"
N_IN = 64
HIDDEN = (64, 32)
BACKGROUND = "background"
TEST_ONLY = {"rotating_actor"}
DEV_VAL_FRAC = 0.2
BG_PER_DAY = 6000            # background windows kept per training day
SEED = 0

PORT_CLASSES = [
    ("ssh", "dst_port = 22"),
    ("telnet", "dst_port IN (23, 2323)"),
    ("http", "dst_port IN (80, 81, 8000, 8080, 8081, 8888)"),
    ("https", "dst_port IN (443, 8443)"),
    ("smb_rpc", "dst_port IN (135, 137, 138, 139, 445)"),
    ("rdp", "dst_port = 3389"),
    ("sql", "dst_port IN (1433, 1521, 3306, 5432)"),
    ("mail", "dst_port IN (25, 110, 143, 465, 587, 993, 995)"),
    ("dns", "dst_port = 53"),
    ("udp_amp", "dst_port IN (19, 123, 161, 389, 1900, 5353, 11211)"),
    ("sip", "dst_port IN (5060, 5061)"),
    ("infra", "dst_port IN (2375, 2376, 5984, 6379, 9000, 9200, 27017)"),
    ("low", "dst_port < 1024"),
    ("reg_lo", "dst_port < 10000"),
    ("reg_hi", "dst_port < 49152"),
]                            # class 15: no port, or ephemeral (>= 49152)
FLAG_CLASSES = [
    ("udp", "proto = 17"),
    ("other_proto", "proto <> 6"),
    ("rst", "tcp_flags & 4 <> 0"),
    ("fin", "tcp_flags & 1 <> 0"),
    ("syn", "tcp_flags & 63 = 2"),
    ("synack", "tcp_flags & 18 = 18"),
    ("psh", "tcp_flags & 8 <> 0"),
    ("ack", "tcp_flags & 16 <> 0"),
]                            # anything else (null, xmas ...) joins synack


def _case(classes: list[tuple[str, str]], default: int,
          slots: list[int] | None = None) -> str:
    whens = " ".join(f"WHEN {cond} THEN {slots[i] if slots else i}"
                     for i, (_, cond) in enumerate(classes))
    return f"CASE {whens} ELSE {default} END"


PORT_SQL = _case(PORT_CLASSES, 15)
# slots: syn 0, ack 1, psh 2, rst 3, fin 4, synack / other TCP 5, udp 6,
# other proto 7
FLAG_SQL = _case(FLAG_CLASSES, 5, slots=[6, 7, 3, 4, 0, 5, 2, 1])


def encode(counts: np.ndarray) -> np.ndarray:
    return np.minimum(15, np.round(np.log2(1 + counts))).astype(np.uint8)


# ------------------------------------------------------------ windows

def set_day(name: str) -> _dt.date:
    d = sorted((lib.eval_inject_dir(name) / "packets").glob("dt=*"))
    return _dt.date.fromisoformat(d[0].name[3:])


def all_sets() -> list[str]:
    return sorted(p.parent.name for p in (lib.EVAL_DIR / "inject").glob("*/truth.parquet")
                  if any((p.parent / "packets").glob("dt=*/*.parquet")))


def windows_of_set(name: str) -> Path:
    """Write the 64-input window of every source of the set day."""
    path = WIN / f"{name}.parquet"
    if path.exists():
        return path
    day = set_day(name)
    real = lib.PARQUET / "packets" / f"dt={day}"
    inj = lib.eval_inject_dir(name) / "packets" / f"dt={day}"
    con = lib.duck(threads=4)
    con.execute(f"""
        CREATE TEMP VIEW p AS
        SELECT src_ip, ts, dst_port, tcp_flags, proto
        FROM read_parquet(['{real}/*.parquet', '{inj}/*.parquet'], union_by_name=1)
        WHERE src_ip IS NOT NULL""")
    rows = con.execute(f"""
        WITH g AS (SELECT src_ip, ts, dst_port, tcp_flags, proto,
                          epoch(ts) - lag(epoch(ts)) OVER (PARTITION BY src_ip ORDER BY ts) iat
                   FROM p)
        SELECT src_ip, LEAST(31, GREATEST(0, floor((log10(GREATEST(iat, 1e-3)) + 3) * 4)))::INT f, count(*) n
          FROM g WHERE iat IS NOT NULL GROUP BY ALL
        UNION ALL
        SELECT src_ip, 32 + (CASE WHEN dst_port IS NULL OR dst_port >= 49152 THEN 15 ELSE {PORT_SQL} END), count(*)
          FROM p GROUP BY ALL
        UNION ALL
        SELECT src_ip, 48 + ({FLAG_SQL}), count(*) FROM p GROUP BY ALL
        UNION ALL
        SELECT src_ip, 56 + hour(ts AT TIME ZONE 'UTC') // 3, count(*) FROM p GROUP BY ALL
    """).fetchnumpy()
    truth = con.execute(f"""
        SELECT src_ip, archetype, is_control FROM read_parquet(
          '{lib.eval_inject_dir(name) / "truth.parquet"}') WHERE level = 'source'
    """).fetchall()
    con.close()
    ips, inv = np.unique(rows["src_ip"].astype(str), return_inverse=True)
    counts = np.zeros((len(ips), N_IN), np.int64)
    np.add.at(counts, (inv, rows["f"].astype(np.int64)), rows["n"].astype(np.int64))
    lab = {ip: (BACKGROUND if ctrl else arch) for ip, arch, ctrl in truth}
    x = encode(counts)
    WIN.mkdir(parents=True, exist_ok=True)
    t = pa.table({
        "src_ip": pa.array(ips.tolist()),
        "label": pa.array([lab.get(ip, BACKGROUND) for ip in ips]),
        "injected": pa.array([ip in lab for ip in ips]),
        "x": pa.FixedSizeBinaryArray.from_buffers(
            pa.binary(N_IN), len(ips), [None, pa.py_buffer(x.tobytes())]),
    })
    tmp = path.with_suffix(".tmp")
    pq.write_table(t, tmp, compression="zstd")
    tmp.replace(path)
    return path


def load_windows(name: str) -> tuple[list[str], np.ndarray, np.ndarray, np.ndarray]:
    t = pq.read_table(WIN / f"{name}.parquet")
    x = np.frombuffer(t.column("x").combine_chunks().buffers()[1], np.uint8)
    return (t.column("src_ip").to_pylist(), x.reshape(-1, N_IN).copy(),
            np.array(t.column("label").to_pylist()), t.column("injected").to_numpy())


def cmd_windows(args) -> None:
    sets = all_sets()
    todo = [s for s in sets if not (WIN / f"{s}.parquet").exists()]
    print(f"[akd_h1] {len(sets)} sets, {len(todo)} to extract", file=sys.stderr)
    t0 = time.time()
    with ProcessPoolExecutor(args.workers) as ex:
        for i, p in enumerate(ex.map(windows_of_set, todo), 1):
            if i % 20 == 0 or i == len(todo):
                print(f"[akd_h1] {i}/{len(todo)} ({time.time() - t0:.0f} s)", file=sys.stderr)


# ------------------------------------------------------------ training data

def split_sets() -> tuple[list[str], list[str]]:
    dev, test = [], []
    for s in all_sets():
        (dev if set_day(s) < harness2.DEV_END else test).append(s)
    return dev, test


def training_data() -> dict:
    """Dev windows: injected sources of every dev set, background sampled
    once per day (sets of one day share their real sources)."""
    dev, _ = split_sets()
    rng = np.random.default_rng(SEED)
    by_day: dict[_dt.date, list[str]] = {}
    for s in dev:
        by_day.setdefault(set_day(s), []).append(s)
    days = sorted(by_day)
    n_val = max(1, round(len(days) * DEV_VAL_FRAC))
    val_days = set(days[-n_val:])
    xs, ys, part = [], [], []
    for day in days:
        seen_bg = False
        for s in by_day[day]:
            _, x, y, inj = load_windows(s)
            keep = inj & ~np.isin(y, list(TEST_ONLY))
            if not seen_bg:
                bg = np.flatnonzero(~inj)
                keep[rng.choice(bg, min(len(bg), BG_PER_DAY), replace=False)] = True
                seen_bg = True
            xs.append(x[keep]); ys.append(y[keep])
            part.append(np.full(keep.sum(), day in val_days))
    x, y, val = np.concatenate(xs), np.concatenate(ys), np.concatenate(part)
    classes = [BACKGROUND] + sorted(set(y) - {BACKGROUND})
    yi = np.searchsorted(np.array(classes[1:]), y) + 1
    yi[y == BACKGROUND] = 0
    return {"x": x, "y": yi, "val": val, "classes": classes,
            "days": [str(d) for d in days], "val_days": sorted(str(d) for d in val_days)}


# ------------------------------------------------------------ models

def _torch():
    import torch
    return torch


def build_nets(n_classes: int):
    torch = _torch()
    nn = torch.nn

    class STE(torch.autograd.Function):
        @staticmethod
        def forward(ctx, x, fn):
            return fn(x)

        @staticmethod
        def backward(ctx, g):
            return g, None

    rnd = lambda x: STE.apply(x, torch.round)       # noqa: E731
    flr = lambda x: STE.apply(x, torch.floor)       # noqa: E731
    cil = lambda x: STE.apply(x, torch.ceil)        # noqa: E731

    class QFC(nn.Module):
        """Akida FullyConnected, 4-bit weights; integer forward, STE backward."""

        def __init__(self, n_in, n_out, activation):
            super().__init__()
            self.lin = nn.Linear(n_in, n_out)
            self.activation = activation
            self.log_step = nn.Parameter(torch.zeros(n_out))

        def scale(self):
            return (self.lin.weight.abs().amax(1).clamp_min(1e-8) / 7).detach()

        def ints(self):
            s = self.scale()
            w = rnd(self.lin.weight / s[:, None]).clamp(-7, 7)
            th = rnd(-self.lin.bias / s)
            q = (flr(torch.exp(self.log_step) / s * 16) / 16).clamp_min(1 / 16)
            return w, th, q, s

        def forward(self, a):
            w, th, q, s = self.ints()
            p = a @ w.T
            if not self.activation:
                return p * s + self.lin.bias       # host-side logits
            return cil((p - th) / q).clamp(0, 15)

    class QNet(nn.Module):
        def __init__(self):
            super().__init__()
            dims = (N_IN,) + HIDDEN
            self.layers = nn.ModuleList(
                [QFC(a, b, True) for a, b in zip(dims, dims[1:])]
                + [QFC(dims[-1], n_classes, False)])

        def forward(self, x):
            for layer in self.layers:
                x = layer(x)
            return x

    class FNet(nn.Module):
        def __init__(self):
            super().__init__()
            dims = (N_IN,) + HIDDEN
            mods = []
            for a, b in zip(dims, dims[1:]):
                mods += [nn.Linear(a, b), nn.ReLU()]
            self.net = nn.Sequential(*mods, nn.Linear(dims[-1], n_classes))

        def forward(self, x):
            return self.net(x / 15)

    return QNet, FNet


def _fit(model, x, y, val, weights, epochs, lr, device, label):
    torch = _torch()
    xt = torch.tensor(x, dtype=torch.float32, device=device)
    yt = torch.tensor(y, dtype=torch.long, device=device)
    tr, va = np.flatnonzero(~val), np.flatnonzero(val)
    loss_fn = torch.nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32, device=device))
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    gen = torch.Generator(device="cpu").manual_seed(SEED)
    best, best_state, bad = np.inf, None, 0
    for ep in range(epochs):
        model.train()
        perm = torch.tensor(tr)[torch.randperm(len(tr), generator=gen)].to(device)
        for i in range(0, len(perm), 4096):
            b = perm[i:i + 4096]
            opt.zero_grad()
            loss = loss_fn(model(xt[b]), yt[b])
            loss.backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            vl = float(loss_fn(model(xt[va]), yt[va]))
        print(f"[akd_h1] {label} epoch {ep + 1}: val loss {vl:.4f}", file=sys.stderr)
        if vl < best - 1e-4:
            best, bad = vl, 0
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= 4:
                break
    model.load_state_dict(best_state)
    return best


def export_ints(qnet) -> list[dict]:
    torch = _torch()
    out = []
    with torch.no_grad():
        for layer in qnet.layers:
            w, th, q, s = layer.ints()
            out.append({"w": w.cpu().numpy().astype(np.int8),
                        "th": th.cpu().numpy().astype(np.int32),
                        "step": (q * 1.0).cpu().numpy().astype(np.float32),
                        "scale": s.cpu().numpy().astype(np.float32),
                        "bias": layer.lin.bias.cpu().numpy().astype(np.float32),
                        "activation": layer.activation})
    return out


def quant_logits(layers: list[dict], x: np.ndarray) -> np.ndarray:
    """h1_quant: the exported integers through sg.akd.fc_reference."""
    from sg.akd import fc_reference
    a = x
    for L in layers:
        if L["activation"]:
            a = fc_reference(a, L["w"], L["th"], L["step"], 4)
        else:
            return fc_reference(a, L["w"], L["th"], L["step"], 4, activation=False) \
                * L["scale"] + L["bias"]
    raise ValueError("no output layer")


def akida_model(layers: list[dict]):
    from sg import akd
    m = akd.Model()
    m.add(akd.input_layer(N_IN, 4))
    for i, L in enumerate(layers):
        fc = akd.fully_connected(len(L["w"]), 4, 4, L["activation"], f"fc{i + 1}")
        m.add(fc)
        fc.set_variable("weights", L["w"].reshape(fc.get_variable("weights").shape))
        if L["activation"]:
            fc.set_variable("threshold", L["th"])
            fc.set_variable("act_step", L["step"])
    return m


def akida_logits(m, layers: list[dict], x: np.ndarray) -> np.ndarray:
    p = m.forward(x.reshape(-1, 1, 1, N_IN)).reshape(len(x), -1).astype(np.int64)
    return p * layers[-1]["scale"] + layers[-1]["bias"]


def score_of(logits: np.ndarray) -> np.ndarray:
    """1 - P(background), as a log-odds rank score (monotone, no overflow)."""
    z = logits - logits.max(1, keepdims=True)
    lse = lambda v: np.log(np.exp(v).sum(1))     # noqa: E731
    return lse(z[:, 1:]) - z[:, 0]


def cmd_train(args) -> None:
    torch = _torch()
    torch.manual_seed(SEED)
    device = "cuda" if torch.cuda.is_available() and not args.cpu else "cpu"
    d = training_data()
    x, y, val, classes = d["x"], d["y"], d["val"], d["classes"]
    freq = np.bincount(y[~val], minlength=len(classes)).astype(float)
    weights = 1 / np.sqrt(np.maximum(freq, 1))
    weights *= len(classes) / weights.sum()
    print(f"[akd_h1] train {int((~val).sum())} / val {int(val.sum())} windows, "
          f"{len(d['days'])} dev days, classes {dict(zip(classes, freq.astype(int)))}, "
          f"device {device}", file=sys.stderr)
    QNet, FNet = build_nets(len(classes))
    t0 = time.time()
    fnet = FNet().to(device)
    f_loss = _fit(fnet, x, y, val, weights, args.epochs, 1e-3, device, "float")
    t_float = time.time() - t0
    qnet = QNet().to(device)
    with torch.no_grad():                       # start from the float weights
        lins = [m for m in fnet.net if isinstance(m, torch.nn.Linear)]
        for ql, fl in zip(qnet.layers, lins):
            ql.lin.weight.copy_(fl.weight)
            ql.lin.bias.copy_(fl.bias)
        qnet.layers[0].lin.weight.div_(15)       # FNet sees x / 15
        a = torch.tensor(x[~val][:20000], dtype=torch.float32, device=device)
        for ql in qnet.layers[:-1]:              # step: 1/4 of the pre-activation spread
            z = a @ ql.lin.weight.T + ql.lin.bias
            ql.log_step.copy_(torch.log(z.std(0).clamp_min(1e-3) / 4))
            a = ql(a)
    t0 = time.time()
    q_loss = _fit(qnet, x, y, val, weights, args.epochs, 5e-4, device, "qat")
    t_qat = time.time() - t0
    layers = export_ints(qnet.cpu())

    from sklearn.ensemble import HistGradientBoostingClassifier
    t0 = time.time()
    sw = weights[y[~val]]
    gbt = HistGradientBoostingClassifier(max_iter=300, early_stopping=True,
                                         random_state=SEED)
    gbt.fit(x[~val], y[~val], sample_weight=sw)
    t_gbt = time.time() - t0

    # export check on the validation windows: libakida == fc_reference
    m = akida_model(layers)
    xv = x[val]
    eq = np.array_equal(akida_logits(m, layers, xv), quant_logits(layers, xv))
    acc = lambda lg: float(np.mean(lg.argmax(1) == y[val]))     # noqa: E731
    with torch.no_grad():
        f_lg = fnet.cpu()(torch.tensor(xv, dtype=torch.float32)).numpy()
    MODELS.mkdir(parents=True, exist_ok=True)
    torch.save({"float": fnet.state_dict(), "classes": classes, "layers": layers},
               MODELS / "h1.pt")
    (MODELS / "h1_akida.fbz").write_bytes(m.to_bytes())
    with open(MODELS / "h1_gbt.pkl", "wb") as f:
        pickle.dump(gbt, f)
    info = {"classes": classes, "dev_days": d["days"], "val_days": d["val_days"],
            "n_train": int((~val).sum()), "n_val": int(val.sum()),
            "val_loss": {"float": f_loss, "qat": q_loss},
            "val_acc": {"float": acc(f_lg), "quant": acc(quant_logits(layers, xv)),
                        "gbt": float(gbt.score(xv, y[val]))},
            "akida_equals_quant": eq, "device": device,
            "train_seconds": {"float": t_float, "qat": t_qat, "gbt": t_gbt}}
    (MODELS / "train.json").write_text(json.dumps(info, indent=2))
    print(json.dumps(info["val_acc"] | {"akida_equals_quant": eq}), file=sys.stderr)
    if not eq:
        raise SystemExit("[akd_h1] libakida output differs from fc_reference")


# ------------------------------------------------------------ scoring

def cmd_score(args) -> None:
    torch = _torch()
    ck = torch.load(MODELS / "h1.pt", weights_only=False)
    layers, classes = ck["layers"], ck["classes"]
    _, FNet = build_nets(len(classes))
    fnet = FNet()
    fnet.load_state_dict(ck["float"])
    fnet.eval()
    with open(MODELS / "h1_gbt.pkl", "rb") as f:
        gbt = pickle.load(f)
    m = akida_model(layers)
    from sg import akd
    cards = akd.devices()
    if args.device == "card" and not cards:
        raise SystemExit("[akd_h1] --device card: no AKD1500 found by the driver")
    on_card = args.device != "soft" and bool(cards)
    if on_card:
        m.map(cards[0])
        if [s.backend.name for s in m.sequences] != ["Hardware"]:
            raise SystemExit(f"[akd_h1] map on {cards[0].desc} is not all Hardware: "
                             f"{[(s.name, s.backend.name) for s in m.sequences]}")
    print(f"[akd_h1] h1_akida backend: {cards[0].desc if on_card else 'software'}",
          file=sys.stderr)
    sets = args.sets or all_sets()
    bad = n_win = 0
    t_ak = 0.0
    for i, name in enumerate(sets, 1):
        ips, x, _, _ = load_windows(name)
        q = quant_logits(layers, x)
        t0 = time.perf_counter()
        ak = akida_logits(m, layers, x)
        t_ak += time.perf_counter() - t0
        n_win += len(x)
        bad += int((ak != q).any())
        with torch.no_grad():
            f_lg = fnet(torch.tensor(x, dtype=torch.float32)).numpy()
        p = gbt.predict_proba(x)
        scores = {"h1_akida": score_of(ak), "h1_quant": score_of(q),
                  "h1_float": score_of(f_lg),
                  "h1_gbt": np.log(np.clip(1 - p[:, 0], 1e-12, None)) - np.log(np.clip(p[:, 0], 1e-12, None))}
        truth = [t for t in pq.read_table(lib.eval_inject_dir(name) / "truth.parquet").to_pylist()
                 if t["level"] == "source"]
        harness2.write_ranks("akd_h1", name, harness2.truth_ranks(
            name, set_day(name), ips, scores, truth, SEED))
        if i % 25 == 0 or i == len(sets):
            print(f"[akd_h1] scored {i}/{len(sets)}", file=sys.stderr)
    timing = {"backend": cards[0].desc if on_card else "software", "sets": len(sets),
              "windows": n_win, "akida_seconds": t_ak,
              "us_per_window": 1e6 * t_ak / max(n_win, 1), "sets_differing": bad}
    (MODELS / "score_timing.json").write_text(json.dumps(timing, indent=2))
    print(json.dumps(timing), file=sys.stderr)
    if bad:
        raise SystemExit(f"[akd_h1] {bad} sets where libakida differs from fc_reference")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("windows")
    w.add_argument("--workers", type=int, default=4)
    t = sub.add_parser("train")
    t.add_argument("--epochs", type=int, default=40)
    t.add_argument("--cpu", action="store_true")
    s = sub.add_parser("score")
    s.add_argument("--sets", nargs="*")
    s.add_argument("--device", choices=("auto", "card", "soft"), default="auto",
                   help="h1_akida backend: the AKD1500 card when found (auto), "
                        "the card or fail (card), or libakida software (soft)")
    args = ap.parse_args()
    {"windows": cmd_windows, "train": cmd_train, "score": cmd_score}[args.cmd](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
