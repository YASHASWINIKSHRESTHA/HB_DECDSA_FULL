import hmac

def generate_k(order, secexp, hash_func, data):
    """
    Generate the deterministic nonce k according to RFC 6979.
    """
    qlen = order.bit_length()
    holen = hash_func().digest_size
    holen_bits = holen * 8
    
    # 3.2 a. Process m through the hash function H
    h1 = hash_func(data).digest()
    
    # Ints to octet strings
    V = b'\x01' * holen
    K = b'\x00' * holen
    
    # Length of x and order in bytes
    rolen = (qlen + 7) // 8
    priv = secexp.to_bytes(rolen, "big")
    
    # Number of bits in hash output
    h1_int = int.from_bytes(h1, "big")
    
    if holen_bits > qlen:
        h1_int = h1_int >> (holen_bits - qlen)
    h1_int = h1_int % order # modulo order (rarely modifies, but safe)
    
    # Encode h1 to rolen bytes
    h1_bytes = h1_int.to_bytes(rolen, "big")
    
    # 3.2 d. K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    K = hmac.new(K, V + b'\x00' + priv + h1_bytes, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()
    
    # 3.2 f. K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    K = hmac.new(K, V + b'\x01' + priv + h1_bytes, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()
    
    # 3.2 h. generate k
    while True:
        t = b''
        while len(t) * 8 < qlen:
            V = hmac.new(K, V, hash_func).digest()
            t += V
            
        t_int = int.from_bytes(t, "big")
        if len(t) * 8 > qlen:
            t_int = t_int >> (len(t) * 8 - qlen)
            
        k = t_int
        if 1 <= k < order:
            return k
            
        # Update K and V if reject
        K = hmac.new(K, V + b'\x00', hash_func).digest()
        V = hmac.new(K, V, hash_func).digest()
