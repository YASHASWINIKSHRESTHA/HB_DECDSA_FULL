import hashlib
import os
from .curves import SECP256k1
from .rfc6979 import generate_k
from .ellipticcurve import PointJacobi

class VerifyingKey:
    def __init__(self, curve, point):
        self._curve = curve
        self.pubkey = point
        
    def verify(self, signature, message, hash_func=hashlib.sha256):
        r, s = signature
        n = self._curve.order
        if not (1 <= r < n and 1 <= s < n):
            return False
            
        e = int.from_bytes(hash_func(message).digest(), "big") % n
        if e == 0:
            e = 1
            
        w = pow(s, n - 2, n)
        u1 = (e * w) % n
        u2 = (r * w) % n
        
        point = (self._curve.generator * u1) + (self.pubkey * u2)
        affine = point.to_affine()
        if affine is None:
            return False
            
        x, _ = affine
        return (x % n) == r

    @classmethod
    def from_string(cls, string, curve=SECP256k1):
        x = int.from_bytes(string[:32], 'big')
        y = int.from_bytes(string[32:], 'big')
        return cls(curve, PointJacobi(curve.curve, x, y, 1))


class SigningKey:
    def __init__(self, curve, privkey, verifying_key=None):
        self._curve = curve
        self._privkey = privkey
        if verifying_key is None:
            pub_point = curve.generator * privkey
            self.verifying_key = VerifyingKey(curve, pub_point)
        else:
            self.verifying_key = verifying_key

    @classmethod
    def generate(cls, curve=SECP256k1):
        privkey = int.from_bytes(os.urandom(32), 'big') % (curve.order - 1) + 1
        return cls(curve, privkey)

    def sign_digest(self, digest_val, k):
        n = self._curve.order
        point = self._curve.generator * k
        affine = point.to_affine()
        
        if affine is None:
            raise ValueError("K value leads to point at infinity (Extremely rare)")
            
        r = affine[0] % n
        if r == 0:
            raise ValueError("r = 0 (Extremely rare)")
            
        k_inv = pow(k, n - 2, n)
        s = (k_inv * (digest_val + self._privkey * r)) % n
        if s == 0:
            raise ValueError("s = 0 (Extremely rare)")
            
        return (r, s)

    def sign_deterministic(self, message, hash_func=hashlib.sha256):
        n = self._curve.order
        e = int.from_bytes(hash_func(message).digest(), "big") % n
        k = generate_k(n, self._privkey, hash_func, message)
        return self.sign_digest(e, k)

    def sign_with_nonce_fn(self, message, nonce_fn, hash_func=hashlib.sha256):
        """
        HB-DECDSA extension point.
        nonce_fn: callable(privkey_int, message_bytes, order_int) -> k_int
        Returns (r, s) — identical to standard ECDSA format.
        """
        n = self._curve.order
        h = int.from_bytes(hash_func(message).digest(), 'big') % n
        k = nonce_fn(self._privkey, message, n)  # HECC layer injected here
        return self.sign_digest(h, k)

    def to_string(self):
        return self._privkey.to_bytes(32, 'big')
