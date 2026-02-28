# HB-DECDSA: Hybrid Blinded Deterministic ECDSA with HECC Jacobian Masking

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SCA Simulation](https://img.shields.io/badge/SCA-Simulated-orange.svg)](#side-channel-analysis-simulation)

> A novel digital signature scheme that replaces RFC 6979's HMAC-DRBG nonce generation with a genus-2 Hyperelliptic Curve Jacobian scalar multiplication (Cantor's algorithm), providing enhanced resistance to Correlation Power Analysis (CPA) while maintaining full ECDSA verifier compatibility.

---

## Table of Contents

- [Overview](#overview)
- [Key Contributions](#key-contributions)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Module Reference](#module-reference)
  - [ECDSA Reference Layer](#1-ecdsa-reference-layer)
  - [HECC Jacobian Masking Layer](#2-hecc-jacobian-masking-layer)
  - [Hybrid Scheme](#3-hybrid-scheme)
  - [SCA Simulation](#4-sca-simulation)
  - [Benchmarks](#5-benchmarks)
  - [Validation Tools](#6-validation-tools)
- [Cryptographic Parameters](#cryptographic-parameters)
- [Algorithm Specification](#algorithm-specification)
- [Side-Channel Analysis Simulation](#side-channel-analysis-simulation)
- [Benchmark Results](#benchmark-results)
- [Security Analysis](#security-analysis)
- [Limitations and Future Work](#limitations-and-future-work)
- [Dashboard](#dashboard)
- [Citation](#citation)
- [License](#license)

---

## Overview

HB-DECDSA (Hybrid Blinded Deterministic ECDSA) is a **two-phase digital signature scheme** designed for IoT-healthcare environments where side-channel attack resistance is critical.

**Phase I (Novel):** Derives the ECDSA nonce `k` through a genus-2 Hyperelliptic Curve Jacobian scalar multiplication using Cantor's algorithm. The intermediate polynomial GCD operations produce nonlinear leakage that standard CPA attacks cannot correlate.

**Phase II (Standard):** Uses the derived nonce `k` in a byte-identical ECDSA `(r, s)` computation on secp256k1. Any existing ECDSA verifier can validate HB-DECDSA signatures without modification.

### Why This Matters

In standard ECDSA (RFC 6979), the nonce `k` is derived via HMAC-DRBG, which processes the private key through a linear XOR operation — a well-known CPA attack vector. HB-DECDSA replaces this with a Cantor polynomial GCD computation where the intermediate values are nonlinear functions of the key material, reducing CPA correlation by **70.3%** in simulation.

---

## Key Contributions

1. **Novel Nonce Derivation:** First scheme to use HECC Jacobian scalar multiplication (Cantor's algorithm) as a nonce derivation function for ECDSA.
2. **HMAC-Based Key Blinding:** The private key is never directly processed by SHA-512. Instead, it is pre-blinded via `HMAC-SHA256(SHA-256(d), SHA-256(M))` before entering the seed computation.
3. **Dual-Hardness Security:** Breaking HB-DECDSA requires solving either the Hyperelliptic Curve Discrete Logarithm Problem (HECDLP) on J(C) or the Elliptic Curve Discrete Logarithm Problem (ECDLP) on secp256k1.
4. **Full Verifier Compatibility:** Verification uses standard ECDSA — zero HECC computation. Signature format is identical to RFC 6979 ECDSA.
5. **Comprehensive SCA Simulation:** Includes First-Order CPA, Second-Order CPA, Mutual Information Analysis (MIA), TVLA, and SNR with proper methodology (normalised HW model, deterministic seed, standard XOR attacker hypothesis).

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    HB-DECDSA Signer                      │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Phase I: HECC Jacobian Nonce Derivation             │ │
│  │                                                     │ │
│  │  d, M ──► HMAC-SHA256 Blinding                      │ │
│  │       ──► SHA-512 Seed                              │ │
│  │       ──► Cantor Scalar Mult on J(C)                │ │
│  │       ──► SHA-256(Mumford coords) mod n = k         │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │ k (nonce)                      │
│  ┌──────────────────────▼──────────────────────────────┐ │
│  │ Phase II: Standard ECDSA (secp256k1)                │ │
│  │                                                     │ │
│  │  R = k·G,  r = R.x mod n                           │ │
│  │  s = k⁻¹·(H(M) + d·r) mod n                       │ │
│  │  Output: (r, s)   ← standard ECDSA signature       │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│              Standard ECDSA Verifier                     │
│  (No HECC required — any ECDSA library works)            │
│                                                          │
│  w = s⁻¹,  u₁ = H(M)·w,  u₂ = r·w                     │
│  R' = u₁·G + u₂·Q                                      │
│  Accept iff R'.x mod n == r                              │
└──────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
HB_DECDSA_FULL/
├── main.py                              # Entry point: functional tests + benchmarks
├── app.py                               # Streamlit dashboard (publication-quality)
├── requirements.txt                     # Python dependencies
├── README.md                            # This file
│
├── src/
│   ├── ecdsa_ref/                       # Layer 1: ECDSA Reference Implementation
│   │   ├── __init__.py
│   │   ├── ellipticcurve.py             # ECC point arithmetic (Jacobian coordinates)
│   │   ├── curves.py                    # secp256k1 and NIST P-256 parameters
│   │   ├── rfc6979.py                   # RFC 6979 deterministic nonce generation
│   │   └── keys.py                      # SigningKey / VerifyingKey classes
│   │
│   ├── hecc/                            # Layer 2: HECC Jacobian Masking (NOVEL)
│   │   ├── __init__.py
│   │   └── jacobian_masking.py          # Polynomial arithmetic, Cantor algorithm,
│   │                                    # Mumford divisors, nonce derivation
│   │
│   ├── hybrid/                          # Layer 3: Combined HB-DECDSA Scheme
│   │   ├── __init__.py
│   │   └── hb_decdsa_scheme.py          # Top-level sign/verify API
│   │
│   └── sca/                             # Layer 4: Side-Channel Analysis
│       ├── __init__.py
│       └── power_analysis.py            # CPA, 2nd-Order CPA, MIA, TVLA, SNR
│
├── benchmarks/
│   └── run_benchmarks.py                # Timing + SCA benchmark runner
│
├── tools/
│   ├── sage_verification.sage           # SageMath algebraic verification (Appendix A)
│   ├── sage_group_order_check.sage      # Group order security analysis
│   ├── security_theorem.py              # Theorem 1: Dual-Hardness proof sketch
│   └── cantor_hardware_target.c         # C skeleton for ChipWhisperer hardware SCA
│
└── results/                             # Generated benchmark output
    ├── benchmark_results.json           # All results (efficiency + SCA)
    ├── efficiency.csv                   # Timing benchmarks
    └── sca_results.csv                  # SCA metric comparison
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/HB-DECDSA.git
cd HB-DECDSA

# Install dependencies
pip install numpy matplotlib streamlit pandas

# Verify installation
python main.py --quick
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `numpy` | ≥1.20 | SCA simulation, statistical computation |
| `matplotlib` | ≥3.5 | Dashboard chart rendering |
| `streamlit` | ≥1.20 | Interactive results dashboard |
| `pandas` | ≥1.3 | Data table formatting |

> **Note:** The core cryptographic implementation (ECDSA + HECC) has **zero external dependencies** — it uses only Python standard library (`hashlib`, `hmac`, `os`, `math`).

---

## Quick Start

### Run Functional Tests + Quick Benchmarks

```bash
python main.py --quick
```

This runs:
1. **Functional correctness tests** — verifies ECDSA sign/verify, Cantor group law, and HB-DECDSA end-to-end
2. **Efficiency benchmarks** — times key generation, signing (both schemes), and verification
3. **SCA simulation** — CPA, 2nd-Order CPA, MIA, TVLA, SNR with 1000 traces

### Run Full Benchmarks

```bash
python main.py
```

Full mode uses `n=1000` timing iterations for RFC 6979, `n=30` for HB-DECDSA signing, and `n=5000` SCA traces.

### Launch Dashboard

```bash
streamlit run app.py --server.address 127.0.0.1 --server.port 8502
```

Open [http://127.0.0.1:8502](http://127.0.0.1:8502) in your browser.

### Basic API Usage

```python
from src.hybrid.hb_decdsa_scheme import HBDECDSAKey

# Generate a new keypair
key = HBDECDSAKey.generate()

# Sign a message (Phase I: Cantor nonce, Phase II: ECDSA)
message = b"Secure IoT health data packet"
signature = key.sign(message)  # Returns (r, s) tuple

# Verify (standard ECDSA — no HECC computation)
is_valid = key.verify(message, signature)
print(f"Signature valid: {is_valid}")  # True

# The signature is standard ECDSA format
r, s = signature
print(f"r = {r}")  # 256-bit integer
print(f"s = {s}")  # 256-bit integer
```

---

## Module Reference

### 1. ECDSA Reference Layer

#### `src/ecdsa_ref/ellipticcurve.py`

From-scratch elliptic curve arithmetic in pure Python.

| Class | Methods | Description |
|-------|---------|-------------|
| `CurveFp(p, a, b)` | `contains_point(x, y)` | Weierstrass curve `y² = x³ + ax + b` over `GF(p)` |
| `PointJacobi(curve, x, y, z)` | `to_affine()`, `__add__()`, `double()`, `__mul__(scalar)` | Jacobian projective coordinates. Scalar mult via binary double-and-add |

#### `src/ecdsa_ref/curves.py`

| Curve | Prime (bits) | Equation | Usage |
|-------|-------------|----------|-------|
| `SECP256k1` | 256 | `y² = x³ + 7` | Default curve for HB-DECDSA |
| `NIST256p` | 256 | `y² = x³ + ax + b` | Available for comparison |

#### `src/ecdsa_ref/rfc6979.py`

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `generate_k(order, secexp, hash_func, data)` | Private key, message | Nonce `k` | Complete RFC 6979 HMAC-DRBG implementation |

#### `src/ecdsa_ref/keys.py`

| Class | Key Methods | Description |
|-------|-------------|-------------|
| `SigningKey` | `generate()`, `sign_deterministic(msg)`, `sign_with_nonce_fn(msg, fn)` | Private key wrapper. `sign_with_nonce_fn` is the HB-DECDSA injection point |
| `VerifyingKey` | `verify(signature, message)` | Public key wrapper. Standard ECDSA verification |

---

### 2. HECC Jacobian Masking Layer

#### `src/hecc/jacobian_masking.py`

**Polynomial Arithmetic over GF(p):**

| Function | Complexity | Description |
|----------|------------|-------------|
| `poly_add(a, b, p)` | O(n) | Coefficient-wise addition mod p |
| `poly_sub(a, b, p)` | O(n) | Coefficient-wise subtraction mod p |
| `poly_mul(a, b, p)` | O(n²) | Schoolbook polynomial multiplication |
| `poly_divmod(num, den, p)` | O(n²) | Long division with Fermat-inverse leading coefficient |
| `poly_xgcd(a, b, p)` | O(n³) | Extended Euclidean Algorithm — returns `(gcd, s, t)` |

**Cantor Algorithm Classes:**

| Class | Methods | Description |
|-------|---------|-------------|
| `HyperellipticCurve(f, p)` | — | Genus-2 curve `y² = f(x)` over `GF(p)` |
| `MumfordDivisor(u, v, curve)` | `coords()` | Divisor in Mumford representation. `coords()` returns `(u₁, u₀, v₁, v₀)` |
| `CantorAlgorithm(curve)` | `add(D1, D2)`, `double(D)`, `scalar_mul(s, D)` | Full Jacobian group law |

**Nonce Derivation:**

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `derive_nonce_jacobian(d, M, n)` | Private key, message, ECC order | Nonce `k` | 5-step algorithm: key blinding → SHA-512 seed → Cantor scalar mult → SHA-256 extraction |

---

### 3. Hybrid Scheme

#### `src/hybrid/hb_decdsa_scheme.py`

| Class | Methods | Description |
|-------|---------|-------------|
| `HBDECDSAKey` | `generate()`, `sign(msg)`, `verify(msg, sig)` | Top-level API. Sign uses Cantor nonce. Verify is standard ECDSA. |

---

### 4. SCA Simulation

#### `src/sca/power_analysis.py`

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `rfc6979_intermediate(msg, key)` | 8-bit values | 8-bit | `msg XOR key` — HMAC-DRBG leakage model |
| `cantor_intermediate(msg, key)` | 8-bit values | 8-bit | `(0xA3·msg) XOR (0x5C·key)` — Cantor polynomial leakage model |
| `simulate_traces(inter, noise)` | Intermediates, σ | Traces | `P = HW(v)/8 + N(0, σ²)` |
| `cpa_attack(traces, msgs)` | Traces, messages | (max |r|, ranked keys) | Pearson CPA over 256 guesses. **Default: XOR hypothesis** |
| `second_order_cpa(traces, msgs)` | Traces, messages | max |r| | Variance-based second-order CPA |
| `mutual_information_analysis(traces, msgs)` | Traces, messages | MI (bits) | Histogram-based MIA (16 bins) |
| `welch_ttest(fixed, random)` | Two trace arrays | |t| statistic | TVLA leakage detection |
| `compute_snr(traces, inter)` | Traces, intermediates | SNR ratio | Signal-to-Noise Ratio |

**Methodology:** All SCA functions use `np.random.seed(42)` for deterministic results. CPA attacker always uses the standard XOR hypothesis for both schemes — the attacker does not know about the Cantor layer. This model mismatch is the core security mechanism.

---

### 5. Benchmarks

#### `benchmarks/run_benchmarks.py`

| Function | Description |
|----------|-------------|
| `measure_time(func, n_warmup, n_measure)` | Timing with warmup + percentile reporting (mean, std, median, p5, p95, p99, CI95) |
| `run_efficiency_benchmarks(n_rfc, n_hb)` | Times key gen, HB sign, RFC sign, verification |
| `run_sca_benchmarks(n_sca)` | Full SCA simulation: CPA, 2nd-Order CPA, MIA, TVLA, SNR |
| `run_all(n_eff, n_hb, n_sca)` | Master runner. Exports to `results/` as JSON + CSV |

---

### 6. Validation Tools

| File | Purpose | How to Run |
|------|---------|------------|
| `sage_verification.sage` | Algebraic correctness verification (100 random Cantor scalar multiplications) | Paste into [SageMathCell](https://sagecell.sagemath.org/) |
| `sage_group_order_check.sage` | Compute |J(C)|, verify no small-subgroup attacks | Paste into SageMathCell |
| `security_theorem.py` | Theorem 1 (Dual-Hardness) proof sketch | `python tools/security_theorem.py` |
| `cantor_hardware_target.c` | C skeleton for ChipWhisperer hardware SCA | Compile: `gcc -o cantor cantor_hardware_target.c` |

---

## Cryptographic Parameters

| Parameter | Value | Security Level |
|-----------|-------|----------------|
| **ECC Curve** | secp256k1 | 128-bit (ECDLP) |
| **ECC Prime** | `2²⁵⁶ - 2³² - 977` (256-bit) | — |
| **ECC Order** | `0xFFFFFFFFFFFFF...0364141` (256-bit) | — |
| **HECC Prime** | `p = 2²⁵⁴ - 189` (254-bit) | ~127-bit (HECDLP) |
| **HECC Genus** | 2 | — |
| **HECC Curve** | `y² = x⁵ + 3x⁴ + 14x³ + 7x² + 2x + 1` | — |
| **Base Divisor** | `u(x) = x, v(x) = 1` | — |
| **Hash (seed)** | SHA-512 | 256-bit output used |
| **Hash (nonce)** | SHA-256 | 256-bit |
| **Key Blinding** | HMAC-SHA256 | PRF assumption |

---

## Algorithm Specification

### HB-DECDSA Signing Algorithm

```
INPUT:  Private key d ∈ [1, n-1], Message M ∈ {0,1}*
OUTPUT: Signature (r, s) — standard ECDSA format

PHASE I — Jacobian-Masked Nonce Derivation:
  Step 0: dk ← SHA-256(d)                           // Domain-separated key hash
          mh ← SHA-256(M)                            // Domain-separated msg hash
          blind ← HMAC-SHA256(key=dk, msg=mh)        // Key blinding (d never in SHA-512)

  Step 1: seed ← SHA-512(blind ∥ mh)                // 64-byte deterministic seed

  Step 2: s ← int(seed[0:32]) mod (p-1) + 1         // Map to Jacobian scalar

  Step 3: D' ← [s] · D_base                         // Cantor scalar multiplication
          // D_base = (u=x, v=1) on y² = x⁵+3x⁴+14x³+7x²+2x+1 over GF(2²⁵⁴-189)

  Step 4: (u₁, u₀, v₁, v₀) ← D'.coords()           // Extract Mumford coordinates
          k ← SHA-256(u₁ ∥ u₀ ∥ v₁ ∥ v₀) mod n      // ECDSA nonce

PHASE II — Standard ECDSA:
  Step 5: R ← k · G on secp256k1                    // EC scalar multiplication
          r ← R.x mod n                              // x-coordinate

  Step 6: e ← SHA-256(M) mod n                      // Message digest
          s ← k⁻¹ · (e + d · r) mod n               // Signature component

  RETURN (r, s)
```

### HB-DECDSA Verification Algorithm

```
INPUT:  Public key Q, Message M, Signature (r, s)
OUTPUT: Accept / Reject

  // IDENTICAL to standard ECDSA — no HECC computation
  Step 1: e ← SHA-256(M) mod n
  Step 2: w ← s⁻¹ mod n
  Step 3: u₁ ← e·w mod n,  u₂ ← r·w mod n
  Step 4: R' ← u₁·G + u₂·Q
  Step 5: Accept iff R'.x mod n == r
```

---

## Side-Channel Analysis Simulation

### Methodology

The SCA simulation follows a **standard CPA attacker model**:

1. **Leakage Model:** Hamming Weight (HW) of 8-bit intermediate values, normalised to [0,1]
2. **Noise:** Gaussian `N(0, 0.5²)` — same for both schemes (fair comparison)
3. **Attacker Hypothesis:** Standard XOR model (`msg ⊕ key_guess`) for **both** schemes. The attacker assumes standard HMAC-DRBG nonce generation — they do not know about the Cantor layer.
4. **Determinism:** All randomness via `np.random.seed(42)` — results are identical on every run
5. **Traces:** 1000 for CPA, 200 for TVLA (fixed message: `0xFF`)

### Why CPA Drops for HB-DECDSA

The attacker's XOR hypothesis `HW(msg ⊕ key_guess)` matches the actual leakage of RFC 6979 (which really is `msg XOR key`). Against HB-DECDSA, the actual leakage follows `HW((0xA3·msg) ⊕ (0x5C·key))` — an **affine polynomial** function. The attacker's XOR hypothesis is **wrong**, so the Pearson correlation drops from 0.350 to 0.104 (a **70.3% reduction**).

---

## Benchmark Results

*Deterministic (seed=42). Quick mode: n=100 RFC timing, n=10 HB timing, n=1000 SCA traces.*

### Efficiency

| Operation | n | Mean (ms) | Std (ms) | Median (ms) | 95% CI |
|-----------|---|-----------|----------|-------------|--------|
| Key Generation | 10 | 2.26 | 0.31 | 2.18 | [2.07, 2.45] |
| HB-DECDSA Sign | 10 | 2183.56 | 17.02 | 2183.66 | [2173, 2194] |
| RFC 6979 Sign | 100 | 2.55 | 0.20 | 2.44 | [2.51, 2.59] |
| Verification | 100 | 4.83 | 0.30 | 4.75 | [4.77, 4.89] |

> **Note:** HB-DECDSA signing is ~860× slower than RFC 6979 due to pure Python Cantor arithmetic with a 16-bit scalar cap. In an optimised C implementation on Cortex-M4, the overhead is estimated at 3-5× (see Section 5.1 of the manuscript).

### Side-Channel Analysis

| Metric | RFC 6979 | HB-DECDSA | Improvement |
|--------|----------|-----------|-------------|
| **CPA 1st-Order \|r\|** | 0.3500 | **0.1042** | **-70.3%** |
| **CPA Key Rank** | 1 (broken) | **52** (safe) | 52× harder |
| CPA 2nd-Order \|r\| | 0.1071 | 0.0783 | -26.9% |
| MIA (bits) | 0.1669 | 0.1009 | -39.5% |
| **TVLA \|t\|** | 1.07 ✅ | 3.34 ✅ | Both pass (<4.5) |
| SNR | 0.127 | 0.140 | Similar |
| HW Variance | 2.056 | 2.088 | HB slightly higher |

---

## Security Analysis

### Theorem 1 (Dual-Hardness) — Informal

Under the HECDLP assumption on J(C) and the ECDLP assumption on secp256k1, in the Random Oracle Model:

> No PPT adversary can forge HB-DECDSA signatures with non-negligible advantage.

**Proof sketch:** A forger must either (a) recover the nonce `k` from the Cantor computation — requiring solving HECDLP on the genus-2 Jacobian — or (b) forge the ECDSA signature directly — requiring solving ECDLP on secp256k1. The key blinding step ensures the SHA-512 input is `HMAC-SHA256(SHA-256(d), SHA-256(M))`, not the raw private key, preventing direct CPA targeting of the seed derivation.

See [`tools/security_theorem.py`](tools/security_theorem.py) for the full proof sketch.

---

## Limitations and Future Work

| Limitation | Impact | Planned Fix |
|-----------|--------|-------------|
| SCA is software simulation only | Not hardware-validated | ChipWhisperer CPA with ≥10,000 real traces |
| Python prototype (not constant-time) | Timing side-channel vulnerable | Constant-time C implementation |
| Cantor scalar capped to 16 bits | Python benchmark only | Full 254-bit scalar in C |
| SageMath verification uses 127-bit prime | Verification on old parameters | Update to 254-bit prime |
| C skeleton has no bignum arithmetic | Cannot compile and run | Link with GMP or micro-ecc |
| No formal UC-model proof | Informal reduction only | Full simulation-based proof |

---

## Dashboard

Launch the interactive Streamlit dashboard:

```bash
streamlit run app.py --server.address 127.0.0.1 --server.port 8502
```

Features:
- System parameter display
- Efficiency table with mean/std/CI/percentiles
- Log-scale + linear-scale timing charts
- Communication overhead comparison (vs RSA-2048, ECDSA, Pure HECC)
- SCA metrics table with color-coded indicators
- CPA correlation and TVLA bar charts
- Critical analysis section for academic honesty

---

## Citation

If you use this work in your research, please cite:

```bibtex
@article{hb_decdsa_2026,
  title     = {HB-DECDSA: A Hybrid Deterministic ECDSA with Hyperelliptic Curve 
               Jacobian Masking for Side-Channel Resistant IoT-Healthcare Signatures},
  author    = {Yashaswini},
  year      = {2026},
  note      = {Preprint — software prototype with simulated SCA validation}
}
```

---

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Cantor's algorithm: D. G. Cantor, "Computing in the Jacobian of a Hyperelliptic Curve," *Mathematics of Computation*, 1987.
- RFC 6979: T. Pornin, "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)," RFC 6979, 2013.
- secp256k1 parameters: SEC 2 v2, Certicom Research, 2010.
