# Appendix A-2: SageMath Group Order Security Verification
# 
# Run at: https://sagecell.sagemath.org/
# Purpose: Verify that the Jacobian J(C) has a cryptographically sound group order.
# A valid HECC parameter set requires |J(C)| to have a large prime factor 
# (ideally near-prime) to prevent small-subgroup attacks.
# 
# This addresses Reviewer Gap #4: "The curve choice is not cryptographically justified."

print("=" * 60)
print("HB-DECDSA: Group Order Security Verification (SageMath)")
print("=" * 60)

# 1. Define the prime field
p = 2^254 - 189
F = GF(p)
print(f"\n[+] Field prime p = 2^254 - 189  ({p.nbits()} bits)")
print(f"    p is prime: {p.is_prime()}")

# 2. Define the curve polynomial
R.<x> = PolynomialRing(F)
f = x^5 + 3*x^4 + 14*x^3 + 7*x^2 + 2*x + 1
print(f"\n[+] Curve: y^2 = {f}")

# 3. Verify f is squarefree (required for valid hyperelliptic curve)
squarefree = f.gcd(f.derivative()) == 1
print(f"[+] f(x) is squarefree: {squarefree}")
if not squarefree:
    print("[-] CRITICAL: f(x) has repeated roots — curve is INVALID.")
    sys.exit(1)

# 4. Construct curve and Jacobian
C = HyperellipticCurve(f)
print(f"[+] Curve genus: {C.genus()} (expected 2)")

J = C.jacobian()
print(f"[+] Constructed Jacobian J(C)")

# 5. Compute the group order (this may take 1-3 minutes for a 254-bit field)
# The group order determines the Discrete Logarithm security.
print(f"\n[+] Computing group order |J(C)| ... (may take ~60 seconds)")
try:
    order = J.order()
    print(f"\n[+] Group order |J(C)| = {order}")
    print(f"    Bit-length: {order.nbits()} bits")

    # Factorize to find the largest prime factor
    print(f"\n[+] Factorizing group order...")
    factors = factor(order)
    print(f"    {factors}")

    # Find the largest prime factor
    prime_factors = [(p, e) for (p, e) in factors]
    largest_prime = max(prime_factors, key=lambda pe: pe[0])[0]
    print(f"\n[+] Largest prime factor: {largest_prime}")
    print(f"    Bit-length of largest prime factor: {largest_prime.nbits()} bits")

    # Security assessment
    if largest_prime.nbits() >= 128:
        print(f"\n[PASS] Group order security: STRONG")
        print(f"       Largest prime factor >= 128 bits.")
        print(f"       Resistant to Pohlig-Hellman small-subgroup attacks.")
    elif largest_prime.nbits() >= 80:
        print(f"\n[WARN] Group order security: MARGINAL")
        print(f"       Largest prime factor < 128 bits.")
        print(f"       Consider choosing different curve parameters.")
    else:
        print(f"\n[FAIL] Group order security: WEAK")
        print(f"       Largest prime factor < 80 bits — scheme is insecure!")

    # Cofactor
    cofactor = order // largest_prime
    print(f"\n[+] Cofactor h = {cofactor}")
    if cofactor == 1:
        print("    Jacobian group is cyclic and prime order — ideal.")
    elif cofactor <= 8:
        print("    Small cofactor — group is near-prime order, acceptable.")
    else:
        print(f"    Cofactor {cofactor} — consider a twist-secure curve.")

except Exception as e:
    print(f"[-] Could not compute group order: {e}")
    print("    This may indicate the curve is singular or the computation timed out.")
    print("    If SageMathCell times out, run locally with sage installed.")

print("\n[+] Verification complete. Include this output as Appendix A-2.")
