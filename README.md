![EchoFingerprint](https://img.shields.io/badge/EchoFingerprint-BOOTSTRAP-black)
![Canary](https://img.shields.io/badge/Canary-OK-black)
<!-- FINGERPRINT_BADGE -->
<!-- CANARY_BADGE -->

# Drift Sonar: ΔΦ(t) via Embedding SNR + Merkle Fingerprints

**What:** Vendor-agnostic drift “sonar” that detects subtle model/embedding shifts using *invariant probe classes*.  
- Compute centroids of probe embeddings  
- Track drift via **mean SNR** (centroid delta / within-class variance)  
- Publish a **Merkle fingerprint** per run for verification  
- **Spicy Canary Layer:** extra non-invasive signals (length, simple entropy, refusal-style indicator) + a red badge if drift crosses threshold

**Why:** Transparent, reproducible telemetry for model updates and guardrail shifts.
  
## Run locally
```bash
pip install -r requirements.txt
export OPENAI_API_KEY=YOUR_KEY
# Optional (enables “style/length/entropy” layer):
# export COMPLETIONS_MODEL=gpt-4o-mini
python echo_sonar.py
python verify.py echo_sonar_log.json
