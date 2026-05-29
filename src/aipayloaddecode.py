#!/usr/bin/env python3
"""
aipayloaddecode - use any available AI API to decode unidentified packet
payloads.

Reads the nonipproto output (non-TCP/UDP/ICMP IPv4 packets the parser
silently drops) and for each sample asks an LLM to identify the
protocol, decode the leading fields, and assess threat intent.

Provider selection
------------------
At startup we look for `{provider}.key.txt` files in the repo root and
match each one against an installed SDK.  We use the first available
combination from the preference order:

    1. claude   (anthropic SDK)         claude.key.txt
    2. openai   (openai SDK)            openai.key.txt
    3. xai      (openai SDK, x.ai URL)  xai.key.txt
    4. mistral  (mistralai SDK)         mistral.key.txt
    5. gemini   (google-generativeai)   gemini.key.txt

If no provider has both a key file AND an installed SDK, the stage
prints a one-line notice and exits 0 - the rest of the pipeline
continues unaffected.  Override the auto-pick with --provider.

Cache
-----
Every response is cached by (provider, model, sha256-of-input-bytes)
under `output/ai_cache/`.  Re-runs are free unless --force is passed.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib
import json
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


OUT_DIR = lib.REPORTS / "ai_decode"
CACHE = lib.OUTPUT_DIR / "ai_cache"


# ----------------------------------------------------------------------
# Provider registry
# ----------------------------------------------------------------------

# Each provider entry: name, key file, default model, sdk module to probe,
# and a call function with signature (api_key, model, prompt) -> dict|None.
PROVIDERS: list[dict] = []


def _register(name: str, key_file: str, default_model: str, sdk: str):
    """Decorator that wires a call function into the provider list."""
    def deco(fn):
        PROVIDERS.append({
            "name": name, "key_file": key_file,
            "default_model": default_model, "sdk": sdk, "call": fn,
        })
        return fn
    return deco


def _extract_json(text: str) -> dict | None:
    """Robustly pull a JSON object out of a model response."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip("` \n")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Last-ditch: find the first {...} block.
        s = text.find("{"); e = text.rfind("}")
        if s >= 0 and e > s:
            try:
                return json.loads(text[s:e + 1])
            except json.JSONDecodeError:
                return None
        return None


@_register("claude", "claude.key.txt", "claude-opus-4-7", "anthropic")
def _call_claude(api_key, model, prompt):
    import anthropic
    try:
        client = anthropic.Anthropic(api_key=api_key, timeout=300.0)
        resp = client.messages.create(
            model=model, max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if hasattr(b, "text"))
        return _extract_json(text)
    except Exception:
        raise


@_register("openai", "openai.key.txt", "gpt-4o", "openai")
def _call_openai(api_key, model, prompt):
    import openai
    try:
        client = openai.OpenAI(api_key=api_key, timeout=300.0)
        resp = client.chat.completions.create(
            model=model, max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        return _extract_json(resp.choices[0].message.content or "")
    except Exception:
        raise


@_register("xai", "xai.key.txt", "grok-4.3", "openai")
def _call_xai(api_key, model, prompt):
    import openai
    try:
        client = openai.OpenAI(api_key=api_key, base_url="https://api.x.ai/v1",
                               timeout=120.0)
        resp = client.chat.completions.create(
            model=model, max_tokens=1200,
            messages=[{"role": "user", "content": prompt}],
        )
        return _extract_json(resp.choices[0].message.content or "")
    except Exception:
        raise


@_register("mistral", "mistral.key.txt", "mistral-large-latest", "mistralai")
def _call_mistral(api_key, model, prompt):
    # mistralai 2.x split the SDK; the Mistral class lives under client.sdk
    from mistralai.client.sdk import Mistral
    try:
        client = Mistral(api_key=api_key, timeout_ms=120_000)
        resp = client.chat.complete(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        return _extract_json(resp.choices[0].message.content or "")
    except Exception:
        raise


@_register("gemini", "gemini.key.txt", "gemini-2.5-pro", "google.generativeai")
def _call_gemini(api_key, model, prompt):
    import google.generativeai as genai
    try:
        genai.configure(api_key=api_key)
        gm = genai.GenerativeModel(model)
        resp = gm.generate_content(prompt,
            generation_config={"response_mime_type": "application/json"})
        return _extract_json(resp.text or "")
    except Exception:
        raise


# ----------------------------------------------------------------------
# Provider discovery
# ----------------------------------------------------------------------

def discover_provider(prefer: str | None = None) -> tuple[dict, str] | None:
    """Return (provider, api_key) for the first usable provider, or None."""
    candidates = PROVIDERS
    if prefer:
        candidates = [p for p in PROVIDERS if p["name"] == prefer]
        if not candidates:
            print(f"[ai] unknown --provider '{prefer}'; "
                  f"known: {[p['name'] for p in PROVIDERS]}", file=sys.stderr)
            return None

    for p in candidates:
        key_file = lib.REPO_ROOT / p["key_file"]
        if not key_file.exists():
            continue
        try:
            importlib.import_module(p["sdk"])
        except ImportError:
            print(f"[ai] {p['name']}: key file present but {p['sdk']} SDK "
                  "not installed - skipping", file=sys.stderr)
            continue
        try:
            key = key_file.read_text().strip()
        except Exception as e:
            print(f"[ai] {p['name']}: failed to read {key_file}: {e}",
                  file=sys.stderr)
            continue
        if not key or key.startswith("#"):
            continue
        return p, key
    return None


# ----------------------------------------------------------------------
# Prompt + main loop
# ----------------------------------------------------------------------

PROMPT_TEMPLATE = """You are a packet-analysis assistant.  Below is the raw IP-payload of a single packet captured by a honeypot.  The packet's outer IPv4 protocol number is {proto_num}{proto_name_hint}.

The IP-payload was extracted by stripping the Ethernet (14 bytes) and IPv4 (>=20 bytes) headers from the captured frame.  Here are the first {n_bytes} bytes:

  hex:        {payload_hex}
  printable:  {payload_printable}

Please respond in strict JSON with the following keys (no markdown fences, no prose outside the JSON):

  identified_as     short label of the protocol/format (e.g. "SCTP INIT chunk", "GRE encapsulating IPv4", "6to4 IPv6/ICMPv6 echo")
  confidence        one of "high" | "medium" | "low"
  decoded_fields    object mapping field-name -> human-readable value (cover the most informative leading fields)
  threat_level      one of "benign" | "scanning" | "exploit_attempt" | "tunnel_setup" | "unknown"
  threat_summary    one short sentence: what is the sender trying to do?
  analysis          2-4 sentences of additional context: why this byte pattern matches that protocol, anything notable about the values (suspicious checksums, malformed lengths, atypical ports, etc.)

Return ONLY the JSON object."""


DECODE_SCHEMA = pa.schema([
    ("source",          pa.string()),
    ("provider",        pa.string()),
    ("proto_num",       pa.uint8()),
    ("proto_name",      pa.string()),
    ("payload_hex",     pa.string()),
    ("payload_sha256",  pa.string()),
    ("model",           pa.string()),
    ("identified_as",   pa.string()),
    ("confidence",      pa.string()),
    ("decoded_fields",  pa.string()),
    ("threat_level",    pa.string()),
    ("threat_summary",  pa.string()),
    ("analysis",        pa.string()),
    ("decoded_at",      pa.timestamp("us", tz="UTC")),
])


def _bytes_from_hex(h: str) -> bytes:
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""


def _printable(b: bytes) -> str:
    return "".join(chr(x) if 0x20 <= x < 0x7F else "." for x in b)


def _cache_key(provider: str, model: str, sha_hex: str) -> Path:
    safe_model = model.replace("/", "_").replace(":", "_")
    return CACHE / f"{provider}_{safe_model}_{sha_hex}.json"


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    found = discover_provider(prefer=args.provider)
    if found is None:
        print("[ai] no AI provider available (no '*.key.txt' file paired with "
              "an installed SDK).  Skipping AI payload decode stage.  "
              "This is fine - the rest of the pipeline does not depend on it.",
              file=sys.stderr)
        return 0
    provider, api_key = found
    model = args.model or provider["default_model"]
    print(f"[ai] provider={provider['name']} model={model}", file=sys.stderr)

    # ---- collect samples from nonipproto ----
    samples: list[dict] = []
    nonip_path = lib.REPORTS / "nonipproto" / "nonipproto.parquet"
    if nonip_path.exists():
        con = lib.duck()
        rows = con.execute(f"""
            SELECT proto_num, proto_name, sample_hex
            FROM read_parquet('{nonip_path}')
            WHERE sample_hex != ''
        """).fetchall()
        con.close()
        for n, name, hexs in rows:
            data = _bytes_from_hex(hexs)
            if not data:
                continue
            samples.append({
                "source":     f"nonipproto:proto{n}",
                "proto_num":  int(n),
                "proto_name": name,
                "payload":    data,
            })
        print(f"[ai] {len(samples)} nonipproto samples to analyze",
              file=sys.stderr)
    else:
        print("[ai] no nonipproto.parquet found - run that stage first",
              file=sys.stderr)
        return 0

    out_rows: list[dict] = []
    n_cached = n_called = n_failed = 0
    for i, s in enumerate(samples):
        if args.limit and i >= args.limit:
            break
        sha = hashlib.sha256(s["payload"]).hexdigest()
        cache_p = _cache_key(provider["name"], model, sha)
        if cache_p.exists() and not args.force:
            parsed = json.loads(cache_p.read_text())
            n_cached += 1
        else:
            proto_name_hint = (f" ({s['proto_name']})" if s["proto_name"]
                               and s["proto_name"] != f"proto-{s['proto_num']}" else "")
            prompt = PROMPT_TEMPLATE.format(
                proto_num=s["proto_num"],
                proto_name_hint=proto_name_hint,
                n_bytes=len(s["payload"]),
                payload_hex=s["payload"].hex(),
                payload_printable=_printable(s["payload"]),
            )
            print(f"[ai] {i+1}/{len(samples)} {s['source']} -> "
                  f"{provider['name']}/{model}...", file=sys.stderr)
            try:
                parsed = provider["call"](api_key, model, prompt)
            except Exception as e:
                print(f"[ai] call failed: {e}", file=sys.stderr)
                parsed = None
            if parsed is None:
                n_failed += 1
                continue
            cache_p.write_text(json.dumps(parsed, indent=2))
            n_called += 1
            time.sleep(args.sleep)

        out_rows.append({
            "source":         s["source"],
            "provider":       provider["name"],
            "proto_num":      s["proto_num"],
            "proto_name":     s["proto_name"],
            "payload_hex":    s["payload"].hex(),
            "payload_sha256": sha,
            "model":          model,
            "identified_as":  str(parsed.get("identified_as", "")),
            "confidence":     str(parsed.get("confidence", "")),
            "decoded_fields": json.dumps(parsed.get("decoded_fields", {}),
                                         separators=(",", ":"), default=str),
            "threat_level":   str(parsed.get("threat_level", "")),
            "threat_summary": str(parsed.get("threat_summary", "")),
            "analysis":       str(parsed.get("analysis", "")),
            "decoded_at":     _dt.datetime.now(_dt.timezone.utc),
        })

    pq.write_table(pa.Table.from_pylist(out_rows, schema=DECODE_SCHEMA),
                   OUT_DIR / "decodes.parquet",
                   compression="zstd", compression_level=3)

    md = ["# ai_decode - AI-assisted payload identification", "",
          f"_Provider: `{provider['name']}` / model: `{model}`.  "
          f"Cache hits: {n_cached}, fresh API calls: {n_called}, "
          f"failures: {n_failed}.  Cache under `output/ai_cache/`._", ""]
    for r in out_rows:
        md.append(f"## {r['source']} - {r['identified_as']}")
        md.append("")
        md.append(f"- **threat_level:** {r['threat_level']}")
        md.append(f"- **confidence:** {r['confidence']}")
        md.append(f"- **threat_summary:** {r['threat_summary']}")
        md.append(f"- **payload_hex (first 32B):** `{r['payload_hex'][:64]}`")
        md.append("")
        md.append("_decoded fields:_")
        md.append("")
        try:
            decoded = json.loads(r["decoded_fields"])
        except Exception:
            decoded = {}
        if decoded:
            md.append("| field | value |\n| --- | --- |")
            for k, v in decoded.items():
                v_str = str(v).replace("|", "\\|")[:200]
                md.append(f"| {k} | {v_str} |")
        else:
            md.append("_(none)_")
        md.append("")
        md.append(f"_analysis:_ {r['analysis']}")
        md.append("")

    (OUT_DIR / "ai_decode.md").write_text("\n".join(md) + "\n")
    print(f"[ai] wrote {OUT_DIR} (provider={provider['name']}, samples={len(out_rows)})",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", default=None,
                    help="Force a specific provider; otherwise auto-pick. "
                         f"Known: {[p['name'] for p in PROVIDERS]}")
    ap.add_argument("--model", default=None,
                    help="Model name; uses the provider's default if omitted.")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--sleep", type=float, default=0.3)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
