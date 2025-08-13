# echo_sonar.py — Drift Sonar (embeddings SNR + Merkle fingerprints + Spicy Canary)
# ▶ Run: python echo_sonar.py   (reads OPENAI_API_KEY from .env automatically)
# Optional: set COMPLETIONS_MODEL in .env (e.g., gpt-4o-mini) to enable canary metrics.

import os, json, math, hashlib, re
from datetime import datetime, timezone
from typing import List, Dict, Any

# ── Load .env early (with graceful fallback) ───────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # <<< add override=True
except Exception:
    # Minimal fallback parser (only KEY=VALUE lines)
    if os.path.exists(".env"):
        for line in open(".env", encoding="utf-8"):
            line=line.strip()
            if line and not line.startswith("#") and "=" in line:
                k,v=line.split("=",1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

from openai import OpenAI

# ── Config ─────────────────────────────────────────────────────────────────────
EMBED_MODEL = os.getenv("EMBED_MODEL", "text-embedding-3-large")
COMPLETIONS_MODEL = os.getenv("COMPLETIONS_MODEL")  # None → skip canary completions
LOG_PATH    = os.getenv("ECHO_SONAR_LOG", "echo_sonar_log.json")
PROBES_PER_CLASS_LIMIT = 4
SNR_ALERT_THRESHOLD = float(os.getenv("SNR_ALERT_THRESHOLD", "0.015"))

# ── Probe Sets: invariants (paraphrases / symbol permutations) ─────────────────
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
for s in PROBE_SETS: s["variants"] = s["variants"][:PROBES_PER_CLASS_LIMIT]

# ── Utils ──────────────────────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def cosine(a: List[float], b: List[float]) -> float:
    num = sum(x*y for x,y in zip(a,b))
    da = sum(x*x for x in a) ** 0.5
    db = sum(y*y for y in b) ** 0.5
    return num / (da*db + 1e-12)

def centroid(vectors):
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
    if not c: return 0.0
    d = [(1.0 - cosine(v, c)) for v in vecs]
    return sum(d)/len(d)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def merkle_root_hex(chunks: List[bytes]) -> str:
    if not chunks: return sha256_hex(b"")
    nodes = [sha256_hex(c).encode() for c in chunks]
    while len(nodes) > 1:
        if len(nodes) & 1: nodes.append(nodes[-1])
        nodes = [sha256_hex(nodes[i]+nodes[i+1]).encode() for i in range(0,len(nodes),2)]
    return nodes[0].decode()

def load_log(path: str):
    if not os.path.exists(path): return []
    try:
        with open(path,"r",encoding="utf-8") as f: return json.load(f)
    except Exception:
        return []

def save_log(path: str, data):
    with open(path,"w",encoding="utf-8") as f: json.dump(data,f,indent=2)

# ── OpenAI client ──────────────────────────────────────────────────────────────
client = OpenAI()

def embed_texts(texts: List[str]) -> List[List[float]]:
    r = client.embeddings.create(model=EMBED_MODEL, input=texts)
    return [d.embedding for d in r.data]

def complete_one(prompt: str) -> str:
    if not COMPLETIONS_MODEL: return ""
    r = client.chat.completions.create(
        model=COMPLETIONS_MODEL,
        messages=[{"role":"user","content":prompt}],
        temperature=0,
        max_tokens=120
    )
    return (r.choices[0].message.content or "").strip()

# ── Canary helpers ─────────────────────────────────────────────────────────────
import math as _m
REFUSAL_PAT = re.compile(r"\b(can't|cannot|won't|not able|refuse|sorry)\b", re.I)

def char_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for ch in s: freq[ch]=freq.get(ch,0)+1
    n = len(s)
    return -sum((c/n)*_m.log2(c/n) for c in freq.values())

def canary_metrics(prompts: List[str]) -> Dict[str, Any]:
    if not COMPLETIONS_MODEL:
        return {"enabled": False, "samples": []}
    samples = []
    for p in prompts:
        out = complete_one(p)
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

# ── Core routine ───────────────────────────────────────────────────────────────
def run_sonar() -> Dict[str, Any]:
    all_texts, index_map = [], []
    for s in PROBE_SETS:
        for i,t in enumerate(s["variants"]):
            all_texts.append(t); index_map.append((s["id"], i))

    print("[🔍] Probing embeddings…")
    vectors = embed_texts(all_texts)

    by_set: Dict[str, List[List[float]]] = {}
    for (sid,_), vec in zip(index_map, vectors):
        by_set.setdefault(sid, []).append(vec)

    centroids = {sid: centroid(vecs) for sid,vecs in by_set.items()}
    within    = {sid: variance_to_centroid(vecs) for sid,vecs in by_set.items()}

    # Merkle fingerprint over centroids
    chunks = []
    for sid in sorted(centroids.keys()):
        raw = json.dumps(centroids[sid], separators=(",",":"), ensure_ascii=False).encode()
        chunks.append(raw)
    fingerprint = merkle_root_hex(chunks)

    # Canary: run optional completions on 1 variant per set
    canary_prompts = [s["variants"][0] for s in PROBE_SETS]
    canary = canary_metrics(canary_prompts)

    return {
        "timestamp": now_iso(),
        "model": EMBED_MODEL,
        "centroids": centroids,
        "within_var": within,
        "fingerprint": fingerprint,
        "canary": canary,
    }

def snr_against_prev(curr: Dict[str, Any], prev: Dict[str, Any]) -> Dict[str, Any]:
    terms, by = [], {}
    for sid, cnow in curr["centroids"].items():
        if sid not in prev["centroids"]: continue
        cprev = prev["centroids"][sid]
        d = 1.0 - cosine(cnow, cprev)                     # drift
        v = max(1e-9, (curr["within_var"].get(sid,0.0)+prev["within_var"].get(sid,0.0))/2.0)
        snr = d / v
        by[sid] = {"delta": d, "baseline_var": v, "snr": snr}
        terms.append(snr)
    mean_snr = sum(terms)/len(terms) if terms else 0.0
    return {"mean_snr": mean_snr, "by_set": by}

def main():
    log = []
    if os.path.exists(LOG_PATH):
        try:
            log = json.load(open(LOG_PATH, "r", encoding="utf-8"))
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
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)

    print("\n[🧭] EchoFingerprint:", f"0x{snap['fingerprint']}")
    if result["comparison"]:
        ms = result["comparison"]["mean_snr"]
        flag = "💥 ALERT" if result["alert"] else "🟢 OK"
        print(f"[📈] Mean SNR vs previous: {ms:.6f}  [{flag}]")
    if snap["canary"]["enabled"]:
        print(f"[🛎️] Canary — len(chars): ~{snap['canary']['mean_len_chars']}, "
              f"entropy: {snap['canary']['mean_entropy']}, "
              f"refusal_rate: {snap['canary']['refusal_rate']}")
    print(f"[💾] Log updated → {LOG_PATH}")
    print(f"[🧪] Embedding Model: {EMBED_MODEL}")
    if COMPLETIONS_MODEL:
        print(f"[🧪] Completions Model: {COMPLETIONS_MODEL}")
    print("[🦍] Drift Sonar complete.\n")

if __name__ == "__main__":
    main()
