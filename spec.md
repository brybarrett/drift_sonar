# Drift Sonar – Minimal Spec

**Purpose.** Produce a reproducible fingerprint of a model/embedding state from
invariant probe classes; detect drift via SNR and expose a public Merkle root.

## 1) Probe Sets
- A probe set `S` has an id (e.g., `binsearch.one`) and `k` textual variants that
  should be semantically equivalent or symbol permutations.
- Invariant examples: paraphrases, JSON key reorderings, trivial algebraic rewrites.
- Use `PROBES_PER_CLASS_LIMIT` variants per set (default 4).

## 2) Embeddings
- Embed all probe texts with provider/model `EMBED_MODEL` (default `text-embedding-3-small`).
- Provider is recorded as `embed_provider` (e.g., `openai:text-embedding-3-small` or `local:hashing-1024`).

## 3) Centroids & Within-Class Variance
For each set `S` with vectors `V = {v_1 ... v_k}`:
- Centroid: `c = mean(V)` (componentwise).
- Within variance: `var_S = mean_i (1 - cosine(v_i, c))`.

## 4) Fingerprint
- Serialize centroids per set in **sorted set id** order as compact JSON arrays.
- Merkle chain: `leaf_i = SHA256(json_i)`. If odd, duplicate last node.
- Parent = `SHA256(left || right)`. Root is **EchoFingerprint** (hex).

## 5) SNR vs Previous
Given two snapshots `A` (current) and `B` (previous):
- Per set drift `δ_S = 1 - cosine(c_A, c_B)`.
- Baseline noise `σ_S = mean(var_A, var_B)`, min clamp `1e-9`.
- SNR per set `snr_S = δ_S / σ_S`.
- Report `mean_snr = mean_S (snr_S)` and `alert = (mean_snr >= threshold)`.

## 6) Log Schema (JSON)
Top-level list. Each item:
```json
{
  "snapshot": {
    "timestamp": "UTC ISO 8601",
    "embed_provider": "openai:text-embedding-3-small",
    "model": "text-embedding-3-small",
    "centroids": {"set_id": [..], "...": [..]},
    "within_var": {"set_id": 0.0, "...": 0.0},
    "fingerprint": "<hex>",
    "canary": {
      "enabled": true,
      "mean_len_chars": 303,
      "mean_entropy": 4.302,
      "refusal_rate": 0.00,
      "samples": [ { "len_chars": 300, "entropy": 4.28, "refusal": false }, ... ]
    },
    "elapsed_sec": 0.742
  },
  "comparison": { "mean_snr": 0.0123, "by_set": { "set_id": { "delta": 0.001, "baseline_var": 0.08, "snr": 0.013 } } },
  "alert": false
}
