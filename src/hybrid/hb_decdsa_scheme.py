import hashlib
from ..ecdsa_ref.keys import SigningKey, VerifyingKey
from ..ecdsa_ref.curves import SECP256k1
from ..hecc.jacobian_masking import derive_nonce_jacobian

class HBDECDSAKey:
    """
    Top-level API for the Hybrid Deterministic ECDSA with HECC Jacobian Masking.
    Combines standard ECDSA SigningKey with the J(C) nonce derivation process.
    """
    def __init__(self, ecdsa_privkey=None, curve=SECP256k1):
        if ecdsa_privkey is None:
            self.sk = SigningKey.generate(curve)
        else:
            self.sk = SigningKey(curve, ecdsa_privkey)
            
        self.vk = self.sk.verifying_key
        
    @classmethod
    def generate(cls, curve=SECP256k1):
        return cls(curve=curve)
        
    @property
    def public_key_bytes(self):
        # Format: 0x04 || X || Y
        point = self.vk.pubkey
        affine = point.to_affine()
        if not affine:
            raise ValueError("Infinity point public key")
        x, y = affine
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        
    def sign(self, message, hash_func=hashlib.sha256):
        """
        Produce a deterministic HB-DECDSA signature for the message.
        """
        # Inject the HECC Jacobian nonce generation function here
        return self.sk.sign_with_nonce_fn(
            message=message,
            nonce_fn=derive_nonce_jacobian,
            hash_func=hash_func
        )
        
    def verify(self, message, signature, hash_func=hashlib.sha256):
        """
        Verify the HB-DECDSA signature using standard ECDSA verification rules.
        """
        return self.vk.verify(signature, message, hash_func=hash_func)
