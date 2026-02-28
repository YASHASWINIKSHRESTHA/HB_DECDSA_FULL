"""
HB-DECDSA: Benchmark Runner (v5 — FINAL)

Key methodology fixes:
  1. Global np.random.seed(42) before ALL SCA computation
  2. CPA attacker uses STANDARD XOR model for BOTH schemes
     (attacker does not know about Cantor layer)
  3. n=200 TVLA traces with fixed msg=0xFF
  4. n=1000 CPA traces for statistical significance
  5. n_hb=10 signing iterations minimum
  6. Percentile reporting (median, p5, p95, p99)
"""
import time
import json
import csv
import math
import statistics
import os
import numpy as np

from src.hybrid.hb_decdsa_scheme import HBDECDSAKey
from src.ecdsa_ref.keys import SigningKey
from src.sca.power_analysis import (
    simulate_traces, compute_snr, welch_ttest, cpa_attack,
    second_order_cpa, mutual_information_analysis,
    rfc6979_intermediate, cantor_intermediate
)


# ─────────────────────────────────────────────────────────────────────────────
# Timing with warmup + percentiles
# ─────────────────────────────────────────────────────────────────────────────
def measure_time(func, *args, n_warmup=10, n_measure=100):
    all_t = []
    for _ in range(n_warmup + n_measure):
        t0 = time.perf_counter()
        func(*args)
        t1 = time.perf_counter()
        all_t.append((t1 - t0) * 1000)

    measured = all_t[n_warmup:]
    mean = statistics.mean(measured)
    std  = statistics.stdev(measured) if len(measured) > 1 else 0.0
    med  = statistics.median(measured)
    p5   = float(np.percentile(measured, 5))
    p95  = float(np.percentile(measured, 95))
    p99  = float(np.percentile(measured, 99))
    se   = std / math.sqrt(len(measured))
    return mean, std, med, p5, p95, p99, mean - 1.96*se, mean + 1.96*se


def run_efficiency_benchmarks(n_rfc=1000, n_hb=10):
    print(f"\n[3/4] BENCHMARKS (RFC: n={n_rfc} w/warmup | HB: n={n_hb} w/warmup)")
    print("-" * 70)

    hb_key  = HBDECDSAKey.generate()
    rfc_key = SigningKey.generate()
    msg = b"HB-DECDSA benchmark message"

    print("  Key Generation (n=10)...")
    kg = measure_time(HBDECDSAKey.generate, n_warmup=5, n_measure=10)

    print(f"  HB-DECDSA Sign (n={n_hb})...")
    hbs = measure_time(hb_key.sign, msg, n_warmup=3, n_measure=n_hb)

    print(f"  RFC 6979 Sign (n={n_rfc})...")
    rfcs = measure_time(rfc_key.sign_deterministic, msg, n_warmup=50, n_measure=n_rfc)

    sig = hb_key.sign(msg)
    print(f"  Verification (n={n_rfc})...")
    ver = measure_time(hb_key.verify, msg, sig, n_warmup=50, n_measure=n_rfc)

    def pack(t, n):
        mean, std, med, p5, p95, p99, lo, hi = t
        return {"n": n, "mean": mean, "std": std, "median": med,
                "p5": p5, "p95": p95, "p99": p99, "ci95_lo": lo, "ci95_hi": hi}

    results = {
        "key_generation": pack(kg, 10),
        "hb_sign":        pack(hbs, n_hb),
        "rfc_sign":       pack(rfcs, n_rfc),
        "verification":   pack(ver, n_rfc),
    }

    hdr = f"  {'Op':<22} {'n':>5} {'Mean':>8} {'Std':>8} {'Median':>8} {'p5':>8} {'p95':>8} {'CI95':>18}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for k, m in results.items():
        nm = k.replace('_',' ').title().replace('Rfc','RFC').replace('Hb','HB-DECDSA')
        print(f"  {nm:<22} {m['n']:>5} {m['mean']:>8.2f} {m['std']:>8.2f} "
              f"{m['median']:>8.2f} {m['p5']:>8.2f} {m['p95']:>8.2f} "
              f"[{m['ci95_lo']:.2f}, {m['ci95_hi']:.2f}]")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# SCA Benchmarks
# ─────────────────────────────────────────────────────────────────────────────
def run_sca_benchmarks(n_sca=1000):
    # ═══ GLOBAL SEED — guarantees identical results every run ═══
    np.random.seed(42)

    NOISE       = 0.5      # 50% relative noise
    TRUE_KEY    = 0xAB
    FIXED_MSG   = 0xFF     # Standard TVLA fixed plaintext
    N_TVLA      = min(n_sca, 200)  # 200 traces for TVLA

    print(f"\n[4/4] SIDE-CHANNEL ANALYSIS")
    print(f"  Seed: 42 (deterministic)  |  Noise: {NOISE}")
    print(f"  CPA traces: {n_sca}  |  TVLA traces: {N_TVLA}")
    print(f"  CPA attacker model: STANDARD XOR (does not know Cantor)")
    print("-" * 65)

    messages = np.random.randint(0, 256, n_sca)

    # ── Generate traces using ACTUAL leakage model ──
    # RFC 6979: leakage = HW(msg XOR key)
    rfc_inter  = np.array([rfc6979_intermediate(int(m), TRUE_KEY) for m in messages])
    rfc_traces, rfc_hws = simulate_traces(rfc_inter, noise_std=NOISE)

    # HB-DECDSA: leakage = HW(cantor(msg, key))  ← this is what the chip ACTUALLY does
    hb_inter   = np.array([cantor_intermediate(int(m), TRUE_KEY) for m in messages])
    hb_traces, hb_hws  = simulate_traces(hb_inter, noise_std=NOISE)

    # ── TVLA (fixed-vs-random, single fixed msg) ──
    # Fixed traces: same message repeated N_TVLA times
    rfc_fixed_inter = np.array([rfc6979_intermediate(FIXED_MSG, TRUE_KEY)] * N_TVLA)
    hb_fixed_inter  = np.array([cantor_intermediate(FIXED_MSG, TRUE_KEY)]  * N_TVLA)
    rfc_fixed_traces, _ = simulate_traces(rfc_fixed_inter, noise_std=NOISE)
    hb_fixed_traces, _  = simulate_traces(hb_fixed_inter,  noise_std=NOISE)
    # Random traces: first N_TVLA of the already-generated traces
    rfc_tvla = welch_ttest(rfc_fixed_traces, rfc_traces[:N_TVLA])
    hb_tvla  = welch_ttest(hb_fixed_traces,  hb_traces[:N_TVLA])

    # ── SNR ──
    rfc_snr = compute_snr(rfc_traces, rfc_inter)
    hb_snr  = compute_snr(hb_traces,  hb_inter)

    # ── HW Variance (of raw HW values) ──
    rfc_hw_var = float(np.var(rfc_hws))
    hb_hw_var  = float(np.var(hb_hws))

    # ══════════════════════════════════════════════════════════════════════
    # CPA — THE KEY INSIGHT
    # The attacker uses a STANDARD XOR hypothesis for BOTH schemes
    # because they don't know about the Cantor layer.
    # Against RFC 6979: XOR hypothesis matches reality → HIGH correlation
    # Against HB-DECDSA: XOR hypothesis is WRONG → LOW correlation
    # ══════════════════════════════════════════════════════════════════════
    print("\n  Running CPA with standard XOR attacker hypothesis...")
    rfc_cpa, rfc_rank_idx = cpa_attack(rfc_traces, messages)  # default = XOR hypothesis
    hb_cpa,  hb_rank_idx  = cpa_attack(hb_traces,  messages)  # default = XOR hypothesis

    rfc_rank = int(list(rfc_rank_idx).index(TRUE_KEY)) + 1 if TRUE_KEY in rfc_rank_idx else 256
    hb_rank  = int(list(hb_rank_idx).index(TRUE_KEY))  + 1 if TRUE_KEY in hb_rank_idx  else 256

    # ── Second-Order CPA (XOR attacker) ──
    rfc_cpa2 = second_order_cpa(rfc_traces, messages)  # XOR hypothesis
    hb_cpa2  = second_order_cpa(hb_traces,  messages)  # XOR hypothesis

    # ── MIA (XOR attacker) ──
    rfc_mia = mutual_information_analysis(rfc_traces, messages)  # XOR hypothesis
    hb_mia  = mutual_information_analysis(hb_traces,  messages)  # XOR hypothesis

    results = {
        "rfc6979": {
            "cpa_max_corr": rfc_cpa, "cpa_key_rank": rfc_rank,
            "cpa2_max_corr": rfc_cpa2,
            "tvla_t": rfc_tvla, "snr": rfc_snr,
            "hw_variance": rfc_hw_var, "mia": rfc_mia,
        },
        "hb_decdsa": {
            "cpa_max_corr": hb_cpa, "cpa_key_rank": hb_rank,
            "cpa2_max_corr": hb_cpa2,
            "tvla_t": hb_tvla, "snr": hb_snr,
            "hw_variance": hb_hw_var, "mia": hb_mia,
        }
    }

    # Print results
    r, h = results["rfc6979"], results["hb_decdsa"]
    print(f"\n  {'Metric':<30} {'RFC 6979':>12} {'HB-DECDSA':>12} {'Delta':>10}")
    print("  " + "-" * 66)
    def row(name, rk, hk, lower_better=True):
        rv, hv = r[rk], h[hk]
        if isinstance(rv, float):
            d = (hv - rv) / rv * 100 if rv != 0 else 0
            tag = f"{d:+.1f}%"
            print(f"  {name:<30} {rv:>12.4f} {hv:>12.4f} {tag:>10}")
        else:
            print(f"  {name:<30} {rv:>12} {hv:>12}")

    row("CPA 1st-Order |r| (XOR hyp)",  "cpa_max_corr",  "cpa_max_corr")
    row("CPA 2nd-Order |r| (XOR hyp)",  "cpa2_max_corr", "cpa2_max_corr")
    row("MIA (bits, XOR hyp)",          "mia",           "mia")
    row("TVLA |t| (fixed=0xFF)",        "tvla_t",        "tvla_t")
    row("SNR",                          "snr",           "snr")
    row("HW Variance",                  "hw_variance",   "hw_variance")
    row("CPA Key Rank",                 "cpa_key_rank",  "cpa_key_rank")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────
def write_csv(filename, fieldnames, data):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(data)


def run_all(n_eff=1000, n_hb=10, n_sca=1000, throughput_sec=10):
    os.makedirs("results", exist_ok=True)

    eff = run_efficiency_benchmarks(n_rfc=n_eff, n_hb=n_hb)
    sca = run_sca_benchmarks(n_sca)

    print("\n[5/5] EXPORTING")
    all_res = {"efficiency": eff, "sca": sca}
    with open("results/benchmark_results.json", "w") as f:
        json.dump(all_res, f, indent=4)

    eff_rows = [{"Operation": k, **v} for k, v in eff.items()]
    write_csv("results/efficiency.csv",
              ["Operation","n","mean","std","median","p5","p95","p99","ci95_lo","ci95_hi"],
              eff_rows)

    s = sca
    sca_rows = [
        {"Metric": "CPA 1st-Order |r|", "RFC 6979": s["rfc6979"]["cpa_max_corr"], "HB-DECDSA": s["hb_decdsa"]["cpa_max_corr"]},
        {"Metric": "CPA 2nd-Order |r|", "RFC 6979": s["rfc6979"]["cpa2_max_corr"],"HB-DECDSA": s["hb_decdsa"]["cpa2_max_corr"]},
        {"Metric": "MIA (bits)",         "RFC 6979": s["rfc6979"]["mia"],           "HB-DECDSA": s["hb_decdsa"]["mia"]},
        {"Metric": "TVLA |t|",          "RFC 6979": s["rfc6979"]["tvla_t"],         "HB-DECDSA": s["hb_decdsa"]["tvla_t"]},
        {"Metric": "HW Variance",       "RFC 6979": s["rfc6979"]["hw_variance"],    "HB-DECDSA": s["hb_decdsa"]["hw_variance"]},
    ]
    write_csv("results/sca_results.csv", ["Metric", "RFC 6979", "HB-DECDSA"], sca_rows)
    print("Results written to results/ directory.")
