import utils
import AES_128 as AES128
import AES_256 as AES256

block_size = 16  # bytes

CIPHER_MAP = {
    'AES_128': AES128,
    'AES_256': AES256,
}


def get_cipher(cipher_name):
    if not cipher_name:
        raise ValueError('cipher_name is required')
    name = cipher_name.upper().replace('-', '_')
    if name in CIPHER_MAP:
        return CIPHER_MAP[name]
    raise ValueError(f'Unsupported cipher: {cipher_name}')


def encrypt_block(block, key, cipher_name='AES_128'):
    return get_cipher(cipher_name).encrypt(block, key)


def decrypt_block(block, key, cipher_name='AES_128'):
    return get_cipher(cipher_name).decrypt(block, key)


# XOR operation
def xor_blocks(block1, block2):
    return [b1 ^ b2 for b1, b2 in zip(block1, block2)]

# Multiply in GF(2^128)
def ghash_multiply(x, y):
    """
    Multiply two 128-bit values in GF(2^128) with the AES-GCM reduction polynomial.
    """
    z = [0] * 16
    v = list(y)
    
    for i in range(128):
        bit_index = i // 8
        bit_position = 7 - (i % 8)
        
        if (x[bit_index] >> bit_position) & 1:
            z = xor_blocks(z, v)
        
        # Check if MSB is set before shifting
        msb_set = (v[0] & 0x80) != 0
        
        # Shift v left by 1 bit
        for j in range(15):
            v[j] = ((v[j] << 1) | (v[j + 1] >> 7)) & 0xFF
        v[15] = (v[15] << 1) & 0xFF
        
        # Apply reduction polynomial if MSB was set
        if msb_set:
            v[0] ^= 0x87
    
    return z

# GHASH function
def ghash(h, plaintext, ciphertext, additional_data=None):
    """
    Compute GHASH authentication tag.
    """
    if additional_data is None:
        additional_data = []
    
    x = [0] * 16
    
    # Process additional data
    for i in range(0, len(additional_data), block_size):
        block = additional_data[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        block = xor_blocks(block, x)
        x = ghash_multiply(block, h)
    
    # Process ciphertext
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        block = xor_blocks(block, x)
        x = ghash_multiply(block, h)
    
    # Append lengths
    len_block = [0] * 16
    # Length of additional data in bits (64-bit big-endian)
    adata_len_bits = len(additional_data) * 8
    for j in range(8):
        len_block[7 - j] = (adata_len_bits >> (j * 8)) & 0xFF
    
    # Length of ciphertext in bits (64-bit big-endian)
    ctext_len_bits = len(ciphertext) * 8
    for j in range(8):
        len_block[15 - j] = (ctext_len_bits >> (j * 8)) & 0xFF
    
    x = xor_blocks(len_block, x)
    x = ghash_multiply(x, h)
    
    return x

# GCM mode encryption
def gcm_encrypt(plaintext, key, iv, additional_data=None, cipher_name='AES_128'):
    """
    GCM mode encryption with authentication.
    
    Args:
        plaintext: The plaintext bytes to encrypt
        key: The encryption key
        iv: The initialization vector (nonce)
        additional_data: Optional additional authenticated data
        cipher_name: Name of cipher (AES_128, AES_256)

    Returns:
        Tuple of (ciphertext, authentication_tag)
    """
    if additional_data is None:
        additional_data = []

    # Generate H = E(K, 0^128)
    h = encrypt_block([0] * 16, key, cipher_name)
    # Derive counter blocks
    if len(iv) == 12:
        # Standard 96-bit IV
        counter_block = iv + [0, 0, 0, 1]
    else:
        # Variable-length IV using GHASH
        iv_padded = iv + [0] * (16 - (len(iv) % 16))
        iv_len_block = [0] * 16
        iv_len_bits = len(iv) * 8
        for j in range(8):
            iv_len_block[15 - j] = (iv_len_bits >> (j * 8)) & 0xFF
        counter_block = ghash(h, [], iv_padded + iv_len_block)
    
    # Encrypt plaintext using CTR mode
    ciphertext = []
    counter = list(counter_block)
    counter_int = int.from_bytes(bytes(counter), byteorder="big")
    
    # CTR operations should use same cipher_name
    
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        
        # Encrypt counter
        counter_int += 1
        counter = list(counter_int.to_bytes(16, byteorder="big"))
        encrypted_counter = encrypt_block(counter, key, cipher_name)
        
        # XOR with plaintext
        xor_result = xor_blocks(block, encrypted_counter)
        ciphertext.extend(xor_result[:len(block)] if i + block_size > len(plaintext) else xor_result)
    
    # Compute authentication tag
    tag = ghash(h, plaintext, ciphertext, additional_data)
    
    # Encrypt first counter block for tag masking
    tag_mask = encrypt_block(list(counter_block), key, cipher_name)
    tag = xor_blocks(tag, tag_mask)
    
    return ciphertext, tag

# GCM mode decryption
def gcm_decrypt(ciphertext, key, iv, tag, additional_data=None, cipher_name='AES_128'):
    """
    GCM mode decryption with authentication verification.
    
    Args:
        ciphertext: The ciphertext bytes to decrypt
        key: The encryption key
        iv: The initialization vector (nonce)
        tag: The authentication tag
        additional_data: Optional additional authenticated data
        cipher_name: Name of cipher (AES_128, AES_256)
    
    Returns:
        Plaintext if authentication is valid, None otherwise
    """
    if additional_data is None:
        additional_data = []
    
    # Generate H = E(K, 0^128)
    h = encrypt_block([0] * 16, key, cipher_name)
    
    # Derive counter blocks (same as encryption)
    if len(iv) == 12:
        counter_block = iv + [0, 0, 0, 1]
    else:
        iv_padded = iv + [0] * (16 - (len(iv) % 16))
        iv_len_block = [0] * 16
        iv_len_bits = len(iv) * 8
        for j in range(8):
            iv_len_block[15 - j] = (iv_len_bits >> (j * 8)) & 0xFF
        counter_block = ghash(h, [], iv_padded + iv_len_block)
    
    # Verify authentication tag first
    computed_tag = ghash(h, [], ciphertext, additional_data)
    tag_mask = encrypt_block(list(counter_block), key, cipher_name)
    computed_tag = xor_blocks(computed_tag, tag_mask)
    
    if computed_tag != tag:
        print("Authentication tag verification failed!")
        return None
    
    # Decrypt ciphertext using CTR mode
    plaintext = []
    counter = list(counter_block)
    counter_int = int.from_bytes(bytes(counter), byteorder="big")
    
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        
        # Encrypt counter
        counter_int += 1
        counter = list(counter_int.to_bytes(16, byteorder="big"))
        encrypted_counter = encrypt_block(counter, key, cipher_name)
        
        # XOR with ciphertext
        xor_result = xor_blocks(block, encrypted_counter)
        plaintext.extend(xor_result[:len(block)] if i + block_size > len(ciphertext) else xor_result)
    
    return plaintext

if __name__ == "__main__":
    # Test Vector
    key = utils.str_to_int_array("0xF6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884")
    iv = utils.str_to_int_array("0x00FAAC24C1585EF15A43D875")  # 96-bit IV
    plaintext = utils.str_to_int_array("0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    
    print("Plaintext:", utils.int_to_hex(plaintext))
    print("Key:", utils.int_to_hex(key))
    print("IV:", utils.int_to_hex(iv))

    ciphertext, tag = gcm_encrypt(plaintext, key, iv)
    print("Ciphertext:", utils.int_to_hex(ciphertext))
    print("Authentication Tag:", utils.int_to_hex(tag))

    print("\n--- Testing GCM Decryption ---")
    decrypted_plaintext = gcm_decrypt(ciphertext, key, iv, tag)
    if decrypted_plaintext is not None:
        print("Decrypted Plaintext:", utils.int_to_hex(decrypted_plaintext))
        print("Match Original:", plaintext == decrypted_plaintext)
    
    print("\n--- Testing Authentication with Tampered Ciphertext ---")
    tampered_ciphertext = list(ciphertext)
    tampered_ciphertext[0] ^= 0x01  # Flip one bit
    decrypted_tampered = gcm_decrypt(tampered_ciphertext, key, iv, tag)
    print("Result of tampering detection:", "Detected ✓" if decrypted_tampered is None else "Not detected (ERROR)")
