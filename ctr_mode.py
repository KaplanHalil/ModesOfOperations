import utils
import AES_128 as AES128
import AES_256 as AES256
import PRESENT80 as PRESENT


CIPHER_MAP = {
    'AES_128': AES128,
    'AES_256': AES256,
    'PRESENT80': PRESENT,
}


def get_cipher(cipher_name):
    if not cipher_name:
        raise ValueError('cipher_name is required')
    name = cipher_name.upper().replace('-', '_')
    if name in CIPHER_MAP:
        return CIPHER_MAP[name]
    raise ValueError(f'Unsupported cipher: {cipher_name}')


def get_block_size(cipher_name):
    cipher = get_cipher(cipher_name)
    return getattr(cipher, 'block_size', 16)


def encrypt_block(block, key, cipher_name):
    return get_cipher(cipher_name).encrypt(block, key)


def decrypt_block(block, key, cipher_name):
    return get_cipher(cipher_name).decrypt(block, key)

max_counter_value = 0xFFFFFFFF  # Maximum value for a 4-byte counter

# XOR operation
def xor_blocks(block1, block2):
    return [b1 ^ b2 for b1, b2 in zip(block1, block2)]

# Construct counter block as per RFC 3686
def construct_counter_block(nonce, iv, block_counter):
    # Nonce (4 bytes) || IV (8 bytes) || Block Counter (4 bytes)
    nonce_iv = nonce + iv
    counter = list(block_counter.to_bytes(4, byteorder="big"))
    return nonce_iv + counter

# CTR mode encryption (RFC 3686 compliant)
def ctr_encrypt(plaintext, key, nonce, iv, initial_counter, cipher_name='AES_128'):
    ciphertext = []
    block_counter = initial_counter
    block_size = get_block_size(cipher_name)

    # Process each block
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        # Construct the counter block
        counter_block = construct_counter_block(nonce, iv, block_counter)
        # Encrypt the counter block
        encrypted_counter = encrypt_block(list(counter_block), key, cipher_name)
        # XOR plaintext block with encrypted counter
        xor_result = xor_blocks(block, encrypted_counter)
        # Append to ciphertext
        ciphertext.extend(xor_result)
        # Increment and wrap block counter
        block_counter = (block_counter + 1) & max_counter_value

    return ciphertext

# CTR mode encryption with external counter block
def ctr_encrypt_with_counter_block(plaintext, key, counter_block, cipher_name='AES_128'):
    """
    CTR mode encryption that takes counter block from outside and increments it.
    
    Args:
        plaintext: The plaintext bytes to encrypt
        key: The encryption key
        counter_block: The initial 16-byte counter block (passed by reference and incremented)
        cipher_name: Name of cipher (AES_128, AES_256, PRESENT80)
    
    Returns:
        The ciphertext bytes
    """
    ciphertext = []
    block_size = get_block_size(cipher_name)

    # Process each block
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        # Encrypt the counter block
        encrypted_counter = encrypt_block(list(counter_block), key, cipher_name)
        # XOR plaintext block with encrypted counter
        xor_result = xor_blocks(block, encrypted_counter)
        # Append to ciphertext
        ciphertext.extend(xor_result)
        # Increment counter block (treat as 128-bit big-endian integer)
        counter_int = int.from_bytes(bytes(counter_block), byteorder="big")
        counter_int = (counter_int + 1) & ((1 << 128) - 1)  # Wrap at 128-bit
        counter_block[:] = list(counter_int.to_bytes(16, byteorder="big"))

    return ciphertext

# CTR mode decryption (same as encryption for stream ciphers)
def ctr_decrypt(ciphertext, key, nonce, iv, initial_counter, cipher_name='AES_128'):
    """
    CTR mode decryption - identical to encryption for stream cipher mode.
    
    Args:
        ciphertext: The ciphertext bytes to decrypt
        key: The encryption key
        nonce: The nonce (4 bytes)
        iv: The initialization vector (8 bytes)
        initial_counter: The initial block counter value
        cipher_name: Name of cipher (AES_128, AES_256, PRESENT80)
    
    Returns:
        The plaintext bytes
    """
    return ctr_encrypt(ciphertext, key, nonce, iv, initial_counter, cipher_name)

# CTR mode decryption with external counter block
def ctr_decrypt_with_counter_block(ciphertext, key, counter_block, cipher_name='AES_128'):
    """
    CTR mode decryption that takes counter block from outside and increments it.
    Since CTR is a stream cipher, decryption is identical to encryption.
    
    Args:
        ciphertext: The ciphertext bytes to decrypt
        key: The encryption key
        counter_block: The initial 16-byte counter block (passed by reference and incremented)
    
    Returns:
        The plaintext bytes
    """
    return ctr_encrypt_with_counter_block(ciphertext, key, counter_block)

if __name__ == "__main__":
    # Test Vector #1
    key = utils.str_to_int_array("0xF6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884")
    nonce = utils.str_to_int_array("0x00FAAC24")  # 4 bytes
    iv = utils.str_to_int_array("0xC1585EF15A43D875")  # 8 bytes
    plaintext = utils.str_to_int_array("0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    initial_counter = 1  # Start from block counter 1

    print("Plaintext:", utils.int_to_hex(plaintext))
    print("Key:", utils.int_to_hex(key))
    print("Nonce:", utils.int_to_hex(nonce))
    print("IV:", utils.int_to_hex(iv))
    print("Initial Counter:", initial_counter)

    ciphertext = ctr_encrypt(plaintext, key, nonce, iv, initial_counter)
    print("Ciphertext:", utils.int_to_hex(ciphertext))

    ##############################################################

    print("\n--- Testing ctr_encrypt_with_counter_block ---")
    # Create a counter block from nonce + iv + initial counter value
    external_counter_block = nonce + iv + list(initial_counter.to_bytes(4, byteorder="big"))
    print("Initial Counter Block:", utils.int_to_hex(external_counter_block))
    
    ciphertext2 = ctr_encrypt_with_counter_block(plaintext, key, external_counter_block)
    print("Ciphertext:", utils.int_to_hex(ciphertext2))
    print("Counter Block After Encryption:", utils.int_to_hex(external_counter_block))

    print("\n--- Testing CTR Decryption ---")
    # Reset counter for decryption
    decrypted = ctr_decrypt(ciphertext, key, nonce, iv, initial_counter)
    print("Decrypted Plaintext:", utils.int_to_hex(decrypted))
    print("Match Original:", plaintext == decrypted)

    print("\n--- Testing CTR Decryption with External Counter Block ---")
    # Reset counter block for decryption
    external_counter_block = nonce + iv + list(initial_counter.to_bytes(4, byteorder="big"))
    decrypted2 = ctr_decrypt_with_counter_block(ciphertext2, key, external_counter_block)
    print("Decrypted Plaintext:", utils.int_to_hex(decrypted2))
    print("Match Original:", plaintext == decrypted2)
