# echo_sonar.py — Drift Sonar (Embedding SNR + Merkle Fingerprints + Spicy Canary)
# ▶ Run: python echo_sonar.py
# Reads OPENAI_API_KEY from .env automatically (dotenv), and supports:
#   EMBED_MODEL               (default: text-embedding-3-small)
#   COMPLETIONS_MODEL         (optional; enables canary metrics)
#   ECHO_SONAR_LOG            (default: echo_sonar_log.json)
#   SNR_ALERT_THRESHOLD       (default: 0.03)
#   PROBES_PER_CLASS_LIMIT    (default: 4)
#   LOCAL_FALLBACK            ("1" to allow local hashing-embeddings if API fails)
#   HASH_DIM                  (dim for local fallback; default: 1024)

import os, json, hashlib, re, time
from datetime import datetime, timezone
from typing import List, Dict, Any

# ──────────────────────────────────────────────────────────────────────────────
# Load .env early (and allow it to override any machine/user env)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except Exception:
    # Minimal fallback parser (only KEY=VALUE lines)
    if os.path.exists(".env"):
        for line in open(".env", encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

# OpenAI client (lazy import instantiation so we can run even if not installed
# and LOCAL_FALLBACK=1 is set)
_openai_client = None
def _client():
    global _openai_client
    if _openai_client is None:
        from openai import OpenAI  # import here to avoid hard dependency w/ fallback
        _openai_client = OpenAI()
    return _openai_client

# ──────────────────────────────────────────────────────────────────────────────
# Config (with sensible, low-cost defaults)
EMBED_MODEL             = os.getenv("EMBED_MODEL", "text-embedding-3-small")
COMPLETIONS_MODEL       = os.getenv("COMPLETIONS_MODEL")  # None → canary disabled
LOG_PATH                = os.getenv("ECHO_SONAR_LOG", "echo_sonar_log.json")
PROBES_PER_CLASS_LIMIT  = int(os.getenv("PROBES_PER_CLASS_LIMIT", "4"))
SNR_ALERT_THRESHOLD     = float(os.getenv("SNR_ALERT_THRESHOLD", "0.03"))
LOCAL_FALLBACK          = os.getenv("LOCAL_FALLBACK", "0").lower() in ("1", "true", "yes")
HASH_DIM                = int(os.getenv("HASH_DIM", "1024"))

# Set at runtime by embed_texts()
EMBED_PROVIDER = None  # e.g., "openai:text-embedding-3-small" or "local:hashing-1024"

# ── Probe Sets: invariants (paraphrases / symbol permutations) ────────────────
PROBE_SETS: List[Dict[str, Any]] = [
    {"id":"binsearch.one","class":"paraphrase","variants":[
        "Explain binary search in one sentence.",
        "In a single line, describe how binary search works.",
        "Summarize the idea of binary search briefly.",
        "Binary search: give a one-sentence explanation."
    ]},
    {"id":"hash.def","class":"paraphrase","variants":[
        "Define a cryptographic hash function plainly.",
        "What is a cryptographic hash function? (simple definition)",
        "A simple definition of a cryptographic hash function.",
        "Explain cryptographic hash functions in plain terms."
    ]},
    {"id":"topos.ordering","class":"paraphrase","variants":[
        "What problem does topological sort solve?",
        "In one line: purpose of topological sorting.",
        "Why use topological orderings? One-sentence answer.",
        "Topological sort: what problem is it for?"
    ]},
    {"id":"json.permutation","class":"symbolperm","variants":[
        '{"a":1,"b":2,"c":3}', '{"b":2,"a":1,"c":3}',
        '{"c":3,"b":2,"a":1}', '{"c":3,"a":1,"b":2}'
    ]},
    {"id":"math.identity","class":"paraphrase","variants":[
        "State the Pythagorean theorem in one sentence.",
        "One-sentence statement of the Pythagorean theorem.",
        "Briefly state the Pythagorean theorem.",
        "Give a single-line description of the Pythagorean theorem."
    ]},
    {"id":"code.style","class":"paraphrase","variants":[
        "Why do linters matter? One line.",
        "Give one-sentence reasoning for using code linters.",
        "Explain in a single line the value of code linters.",
        "What is the point of code linters? Short answer."
    ]},
    {"id":"rl.policy","class":"paraphrase","variants":[
        "One-line definition of a policy in reinforcement learning.",
        "In one sentence, define 'policy' in RL.",
        "Explain 'policy' in reinforcement learning briefly.",
        "Policy (RL): one-sentence definition."
    ]},
]
for s in PROBE_SETS:
    s["variants"] = s["variants"][:PROBES_PER_CLASS_LIMIT]

# ──────────────────────────────────────────────────────────────────────────────
# Utils
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def cosine(a: List[float], b: List[float]) -> float:
    num = sum(x*y for x, y in zip(a, b))
    da = sum(x*x for x in a) ** 0.5
    db = sum(y*y for y in b) ** 0.5
    return num / (da*db + 1e-12)

def centroid(vectors: List[List[float]]) -> List[float]:
    if not vectors:
        return []
    d = len(vectors[0])
    out = [0.0] * d
    for v in vectors:
        for i, val in enumerate(v):
            out[i] += val
    return [x / len(vectors) for x in out]

def variance_to_centroid(vecs: List[List[float]]) -> float:
    c = centroid(vecs)
    if not c:
        return 0.0
    d = [(1.0 - cosine(v, c)) for v in vecs]
    return sum(d) / len(d)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def merkle_root_hex(chunks: List[bytes]) -> str:
    if not chunks:
        return sha256_hex(b"")
    nodes = [sha256_hex(c).encode() for c in chunks]
    while len(nodes) > 1:
        if len(nodes) & 1:
            nodes.append(nodes[-1])
        nodes = [sha256_hex(nodes[i] + nodes[i+1]).encode()
                 for i in range(0, len(nodes), 2)]
    return nodes[0].decode()

def load_log(path: str):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_log(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ──────────────────────────────────────────────────────────────────────────────
# Embeddings + optional fallback
def _local_hash_embeddings(texts: List[str], dim: int = HASH_DIM) -> List[List[float]]:
    # Local, deterministic embeddings using HashingVectorizer (no API / no cost)
    try:
        from sklearn.feature_extraction.text import HashingVectorizer
    except Exception as e:
        raise RuntimeError("Local fallback requested, but scikit-learn is not installed.") from e
    hv = HashingVectorizer(n_features=dim, alternate_sign=False, norm="l2")
    X = hv.transform(texts)  # sparse CSR
    return [row.toarray().ravel().tolist() for row in X]

def embed_texts(texts: List[str]) -> List[List[float]]:
    """
    Return embedding vectors for texts and sets global EMBED_PROVIDER.
    Uses OpenAI by default; falls back to local hashing if LOCAL_FALLBACK=1
    or if the API call fails and fallback is allowed.
    """
    global EMBED_PROVIDER
    try:
        r = _client().embeddings.create(model=EMBED_MODEL, input=texts)
        EMBED_PROVIDER = f"openai:{EMBED_MODEL}"
        return [d.embedding for d in r.data]
    except Exception as e:
        if LOCAL_FALLBACK:
            print(f"[⚠️] Embedding API failed ({type(e).__name__}): {e}")
            print("[⛳] Falling back to local hashing embeddings.")
            vecs = _local_hash_embeddings(texts, HASH_DIM)
            EMBED_PROVIDER = f"local:hashing-{HASH_DIM}"
            return vecs
        # Re-raise if fallback not allowed
        raise

# ──────────────────────────────────────────────────────────────────────────────
# Canary helpers
REFUSAL_PAT = re.compile(r"\b(can't|cannot|won't|not able|refuse|sorry)\b", re.I)

def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in freq.values())

def _complete_one(prompt: str) -> str:
    r = _client().chat.completions.create(
        model=COMPLETIONS_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=120
    )
    return (r.choices[0].message.content or "").strip()

def canary_metrics(prompts: List[str]) -> Dict[str, Any]:
    if not COMPREHENSIONS_MODEL := COMPLETIONS_MODEL:
        return {"enabled": False, "samples": []}
    samples = []
    for p in prompts:
        try:
            out = _complete_one(p)
        except Exception as e:
            out = f"[completion_error: {type(e).__name__}]"
        samples.append({
            "len_chars": len(out),
            "len_words": len(out.split()),
            "entropy": char_entropy(out),
            "refusal": bool(REFUSAL_PAT.search(out)),
        })
    def mean(xs): return sum(xs)/len(xs) if xs else 0.0
    return {
        "enabled": True,
        "samples": samples,
        "mean_len_chars": int(mean([s["len_chars"] for s in samples])),
        "mean_len_words": round(mean([s["len_words"] for s in samples]), 2),
        "mean_entropy": round(mean([s["entropy"] for s in samples]), 3),
        "refusal_rate": round(mean([1.0 if s["refusal"] else 0.0 for s in samples]), 2),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Core routine
def run_sonar() -> Dict[str, Any]:
    t0 = time.time()

    all_texts, index_map = [], []
    for s in PROBE_SETS:
        for i, t in enumerate(s["variants"]):
            all_texts.append(t)
            index_map.append((s["id"], i))

    print("[🔍] Probing embeddings…")
    vectors = embed_texts(all_texts)

    by_set: Dict[str, List[List[float]]] = {}
    for (sid, _), vec in zip(index_map, vectors):
        by_set.setdefault(sid, []).append(vec)

    centroids = {sid: centroid(vecs) for sid, vecs in by_set.items()}
    within    = {sid: variance_to_centroid(vecs) for sid, vecs in by_set.items()}

    # Merkle fingerprint over centroids (sorted order for determinism)
    chunks = []
    for sid in sorted(centroids.keys()):
        raw = json.dumps(centroids[sid], separators=(",", ":"), ensure_ascii=False).encode()
        chunks.append(raw)
    fingerprint = merkle_root_hex(chunks)

    # Canary: run optional completions on 1 variant per set
    canary_prompts = [s["variants"][0] for s in PROBE_SETS]
    canary = canary_metrics(canary_prompts)

    elapsed = round(time.time() - t0, 3)

    return {
        "timestamp": now_iso(),
        "embed_provider": EMBED_PROVIDER or f"openai:{EMBED_MODEL}",
        "model": EMBED_MODEL,
        "centroids": centroids,
        "within_var": within,
        "fingerprint": fingerprint,
        "canary": canary,
        "elapsed_sec": elapsed,
    }

def snr_against_prev(curr: Dict[str, Any], prev: Dict[str, Any]) -> Dict[str, Any]:
    terms, by = [], {}
    for sid, cnow in curr["centroids"].items():
        if sid not in prev["centroids"]:
            continue
        cprev = prev["centroids"][sid]
        # "Drift" term: cosine distance between current/prev centroids
        d = 1.0 - cosine(cnow, cprev)
        # "Noise" (variance) term: mean within-class variance across runs
        v = max(1e-9, (curr["within_var"].get(sid, 0.0) + prev["within_var"].get(sid, 0.0)) / 2.0)
        snr = d / v
        by[sid] = {"delta": d, "baseline_var": v, "snr": snr}
        terms.append(snr)
    mean_snr = sum(terms) / len(terms) if terms else 0.0
    return {"mean_snr": mean_snr, "by_set": by}

# ──────────────────────────────────────────────────────────────────────────────
def main():
    # Load existing log (if any)
    try:
        log = load_log(LOG_PATH)
    except Exception:
        log = []

    snap = run_sonar()
    result = {"snapshot": snap, "comparison": None, "alert": False}

    if log:
        prev = log[-1]["snapshot"]
        cmpres = snr_against_prev(snap, prev)
        result["comparison"] = cmpres
        if cmpres["mean_snr"] >= SNR_ALERT_THRESHOLD:
            result["alert"] = True

    log.append(result)
    save_log(LOG_PATH, log)

    # Console output
    print("\n[🧭] EchoFingerprint:", f"0x{snap['fingerprint']}")
    if result["comparison"]:
        ms = result["comparison"]["mean_snr"]
        flag = "💥 ALERT" if result["alert"] else "🟢 OK"
        print(f"[📈] Mean SNR vs previous: {ms:.6f}  [{flag}]  (threshold={SNR_ALERT_THRESHOLD})")
    if snap["canary"].get("enabled"):
        print(f"[🛎️] Canary — len(chars): ~{snap['canary']['mean_len_chars']}, "
              f"entropy: {snap['canary']['mean_entropy']}, "
              f"refusal_rate: {snap['canary']['refusal_rate']}")
    print(f"[💾] Log updated → {LOG_PATH}")
    print(f"[🧪] Embedding Provider: {snap.get('embed_provider')}")
    if COMPLETIONS_MODEL:
        print(f"[🧪] Completions Model: {COMPLETIONS_MODEL}")
    print(f"[⏱️] Elapsed: {snap['elapsed_sec']}s")
    print("[🦍] Drift Sonar complete.\n")

if __name__ == "__main__":
    main()
