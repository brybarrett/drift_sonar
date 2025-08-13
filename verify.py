# verify.py — recompute latest Merkle root from a stored log
import json, sys, hashlib

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def merkle_root_hex(chunks):
    if not chunks: return sha256_hex(b"")
    nodes = [sha256_hex(c).encode() for c in chunks]
    while len(nodes) > 1:
        if len(nodes) & 1: nodes.append(nodes[-1])
        nodes = [sha256_hex(nodes[i]+nodes[i+1]).encode() for i in range(0,len(nodes),2)]
    return nodes[0].decode()

def main(path):
    data = json.load(open(path, "r", encoding="utf-8"))
    if not data:
        print("Empty log."); return
    snap = data[-1]["snapshot"]
    chunks = []
    for sid in sorted(snap["centroids"].keys()):
        raw = json.dumps(snap["centroids"][sid], separators=(",", ":"), ensure_ascii=False).encode()
        chunks.append(raw)
    recomputed = merkle_root_hex(chunks)
    print("Logged fingerprint:     0x" + snap["fingerprint"])
    print("Recomputed fingerprint: 0x" + recomputed)
    print("MATCH:", recomputed == snap["fingerprint"])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python verify.py echo_sonar_log.json"); sys.exit(1)
    main(sys.argv[1])
