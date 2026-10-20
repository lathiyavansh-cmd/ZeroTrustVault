"""Primitive benchmark: RSA-3072 (OAEP/PSS) vs X25519/Ed25519, plus client protection time vs upload time.

Outputs CSV + PNG charts into eval/results/ so the numbers can go straight into the report.
Runs fully offline (no server) using the shared crypto core.

    python eval/bench_primitives.py --out eval/results [--iters 200] [--sizes 1 4 16 64 128] [--link-mbps 100]
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, x25519

from ztv_crypto import encrypt_bytes, merkle_root
from ztv_crypto.sign import build_manifest, sign_manifest
from ztv_crypto.wrap import generate_rsa_keypair, unwrap_dek, unwrap_dek_rsa, wrap_dek, wrap_dek_rsa

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def timeit(fn, iters: int) -> dict:
    # warmup
    for _ in range(max(1, iters // 20)):
        fn()
    samples = []
    for _ in range(iters):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000.0)
    samples.sort()
    return {
        "mean_ms": round(statistics.fmean(samples), 4),
        "median_ms": round(statistics.median(samples), 4),
        "p95_ms": round(samples[int(0.95 * (len(samples) - 1))], 4),
        "ops_per_s": round(1000.0 / statistics.fmean(samples), 1),
    }


def bench_primitives(iters: int) -> list[dict]:
    import uuid

    fid = str(uuid.uuid4())
    dek = os.urandom(32)
    rows: list[dict] = []

    # --- EC / modern ---
    rows.append({"family": "X25519", "operation": "keygen", **timeit(lambda: x25519.X25519PrivateKey.generate(), iters)})
    xsk = x25519.X25519PrivateKey.generate()
    xpk = xsk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    rec = wrap_dek(dek, xpk, fid, 1)
    rows.append({"family": "X25519+HKDF+AES-KW", "operation": "wrap", **timeit(lambda: wrap_dek(dek, xpk, fid, 1), iters)})
    rows.append({"family": "X25519+HKDF+AES-KW", "operation": "unwrap", **timeit(lambda: unwrap_dek(rec, xsk, fid, 1), iters)})

    rows.append({"family": "Ed25519", "operation": "keygen", **timeit(lambda: ed25519.Ed25519PrivateKey.generate(), iters)})
    esk = ed25519.Ed25519PrivateKey.generate()
    epk = esk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    man = build_manifest(file_id=fid, version=1, name="b", size=1, classification="INTERNAL", merkle_root=b"\x00" * 32, chunk_count=1, chunk_size=4194304, cipher="AES-256-GCM", nonce_prefix=b"\x00" * 8, owner_id="u1")
    signed = sign_manifest(man, esk)
    from ztv_crypto.sign import verify_manifest

    rows.append({"family": "Ed25519", "operation": "sign", **timeit(lambda: sign_manifest(man, esk), iters)})
    rows.append({"family": "Ed25519", "operation": "verify", **timeit(lambda: verify_manifest(signed, epk), iters)})

    # --- RSA-3072 baseline ---
    rows.append({"family": "RSA-3072", "operation": "keygen", **timeit(lambda: generate_rsa_keypair(3072), max(4, iters // 20))})
    rsa_sk = generate_rsa_keypair(3072)
    rsa_pk = rsa_sk.public_key()
    rrec = wrap_dek_rsa(dek, rsa_pk)
    rows.append({"family": "RSA-OAEP-3072", "operation": "wrap", **timeit(lambda: wrap_dek_rsa(dek, rsa_pk), iters)})
    rows.append({"family": "RSA-OAEP-3072", "operation": "unwrap", **timeit(lambda: unwrap_dek_rsa(rrec, rsa_sk), iters)})
    msg = b"benchmark message" * 4
    sig = rsa_sk.sign(msg, PSS, hashes.SHA256())
    rows.append({"family": "RSA-PSS-3072", "operation": "sign", **timeit(lambda: rsa_sk.sign(msg, PSS, hashes.SHA256()), iters)})
    rows.append({"family": "RSA-PSS-3072", "operation": "verify", **timeit(lambda: rsa_pk.verify(sig, msg, PSS, hashes.SHA256()), iters)})
    return rows


def bench_protection_vs_upload(sizes_mb: list[int], link_mbps: float) -> list[dict]:
    import uuid

    rows = []
    for mb in sizes_mb:
        data = os.urandom(mb * 1024 * 1024)
        fid = str(uuid.uuid4())
        t = time.perf_counter()
        cc, cts = encrypt_bytes(data, fid, 1)
        root = merkle_root(cts)
        esk = ed25519.Ed25519PrivateKey.generate()
        man = build_manifest(file_id=fid, version=1, name="f", size=len(data), classification="CONFIDENTIAL", merkle_root=root, chunk_count=len(cts), chunk_size=4194304, cipher="AES-256-GCM", nonce_prefix=cc.nonce_prefix, owner_id="u1")
        sign_manifest(man, esk)
        xsk = x25519.X25519PrivateKey.generate()
        wrap_dek(cc.dek, xsk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), fid, 1)
        protect_ms = (time.perf_counter() - t) * 1000.0
        upload_ms = (len(data) * 8 / (link_mbps * 1_000_000)) * 1000.0
        rows.append({
            "size_mb": mb,
            "protect_ms": round(protect_ms, 1),
            "upload_ms_at_link": round(upload_ms, 1),
            "overhead_pct": round(100.0 * protect_ms / (protect_ms + upload_ms), 2),
            "throughput_mbps": round(len(data) / 1024 / 1024 / (protect_ms / 1000.0), 1),
        })
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def charts(prim: list[dict], prot: list[dict], out: Path) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # noqa: BLE001
        print(f"(charts skipped: {e})")
        return

    # EC vs RSA per operation (log scale)
    ops = ["keygen", "wrap", "unwrap", "sign", "verify"]
    ec_map = {"keygen": "X25519", "wrap": "X25519+HKDF+AES-KW", "unwrap": "X25519+HKDF+AES-KW", "sign": "Ed25519", "verify": "Ed25519"}
    rsa_map = {"keygen": "RSA-3072", "wrap": "RSA-OAEP-3072", "unwrap": "RSA-OAEP-3072", "sign": "RSA-PSS-3072", "verify": "RSA-PSS-3072"}

    def get(fam, op):
        for r in prim:
            if r["family"] == fam and r["operation"] == op:
                return r["mean_ms"]
        return 0

    ec = [get(ec_map[o], o) for o in ops]
    rsa = [get(rsa_map[o], o) for o in ops]
    x = range(len(ops))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - 0.2 for i in x], ec, 0.4, label="X25519 / Ed25519", color="#2563eb")
    ax.bar([i + 0.2 for i in x], rsa, 0.4, label="RSA-3072", color="#dc2626")
    ax.set_yscale("log")
    ax.set_xticks(list(x))
    ax.set_xticklabels(ops)
    ax.set_ylabel("mean time per op (ms, log)")
    ax.set_title("Elliptic-curve vs RSA-3072 primitive cost")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "bench_ec_vs_rsa.png", dpi=130)
    plt.close(fig)

    if prot:
        sizes = [r["size_mb"] for r in prot]
        over = [r["overhead_pct"] for r in prot]
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.plot(sizes, over, "o-", color="#059669")
        ax.axhline(5, ls="--", color="#999", label="5% target")
        ax.set_xlabel("file size (MB)")
        ax.set_ylabel("client crypto as % of (crypto + upload)")
        ax.set_title("Cryptographic overhead vs upload time (100 Mbps link)")
        ax.legend()
        fig.tight_layout()
        fig.savefig(out / "bench_overhead.png", dpi=130)
        plt.close(fig)
    print(f"charts written to {out}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="eval/results")
    ap.add_argument("--iters", type=int, default=200)
    ap.add_argument("--sizes", type=int, nargs="+", default=[1, 4, 16, 64, 128])
    ap.add_argument("--link-mbps", type=float, default=100.0)
    ap.add_argument("--no-charts", action="store_true")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    print(f"benchmarking primitives ({a.iters} iters)...")
    prim = bench_primitives(a.iters)
    write_csv(out / "bench_primitives.csv", prim)
    for r in prim:
        print(f"  {r['family']:<22} {r['operation']:<7} mean {r['mean_ms']:>9.4f} ms  ({r['ops_per_s']} ops/s)")

    print(f"benchmarking client protection vs upload (link {a.link_mbps} Mbps)...")
    prot = bench_protection_vs_upload(a.sizes, a.link_mbps)
    write_csv(out / "bench_overhead.csv", prot)
    for r in prot:
        print(f"  {r['size_mb']:>4} MB  protect {r['protect_ms']:>8.1f} ms  upload {r['upload_ms_at_link']:>8.1f} ms  overhead {r['overhead_pct']:>5.2f}%  ({r['throughput_mbps']} MB/s)")

    if not a.no_charts:
        charts(prim, prot, out)
    print(f"\nCSV + charts in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
