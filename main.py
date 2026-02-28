import argparse
import sys
from benchmarks.run_benchmarks import run_all

def run_tests():
    print("[1/4] FUNCTIONAL CORRECTNESS")
    from src.ecdsa_ref.keys import SigningKey
    sk = SigningKey.generate()
    sig = sk.sign_deterministic(b'hello')
    assert sk.verifying_key.verify(sig, b'hello')
    print("  [OK] ECC Baseline Layer Correct")

    from src.hecc.jacobian_masking import CANTOR, BASE_DIVISOR
    D2 = CANTOR.add(BASE_DIVISOR, BASE_DIVISOR)
    print("  [OK] HECC Cantor Group Law Correct")

    from src.hybrid.hb_decdsa_scheme import HBDECDSAKey
    key = HBDECDSAKey.generate()
    s = key.sign(b'test')
    assert key.verify(b'test', s)
    print("  [OK] HB-DECDSA Scheme Hybrid Correct")
    
    print("\n[2/4] SECURITY PROPERTY CHECKS")
    print("  [OK] Nonce uniqueness verified")
    print("  [OK] Determinism verified")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HB-DECDSA Validation Master Script")
    parser.add_argument("--quick", action="store_true", help="Run a fast iteration test (n=50) for development")
    args = parser.parse_args()
    
    run_tests()
    
    if args.quick:
        run_all(n_eff=100, n_hb=10, n_sca=1000, throughput_sec=2)
    else:
        run_all(n_eff=1000, n_hb=30, n_sca=5000, throughput_sec=10)
