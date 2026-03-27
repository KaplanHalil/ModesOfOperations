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


# ECB mode encryption (Electronic Codebook)
def ecb_encrypt(plaintext, key, cipher_name='AES_128'):
    """
    ECB mode encryption - encrypts each block independently.
    
    Args:
        plaintext: The plaintext bytes to encrypt
        key: The encryption key
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
        # Encrypt the block
        encrypted_block = encrypt_block(block, key, cipher_name)
        # Append to ciphertext
        ciphertext.extend(encrypted_block)

    return ciphertext

# ECB mode decryption (Electronic Codebook)
def ecb_decrypt(ciphertext, key, cipher_name='AES_128'):
    """
    ECB mode decryption - decrypts each block independently.
    
    Args:
        ciphertext: The ciphertext bytes to decrypt
        key: The encryption key
    
    Returns:
        The plaintext bytes
    """
    plaintext = []

    block_size = get_block_size(cipher_name)
    # Process each block
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        # Decrypt the block
        decrypted_block = decrypt_block(block, key, cipher_name)
        # Append to plaintext
        plaintext.extend(decrypted_block)

    return plaintext

if __name__ == "__main__":
    # Test Vector #1
    key = utils.str_to_int_array("0xF6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884")
    plaintext = utils.str_to_int_array("0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")

    print("Plaintext:", utils.int_to_hex(plaintext))
    print("Key:", utils.int_to_hex(key))

    ciphertext = ecb_encrypt(plaintext, key)
    print("Ciphertext:", utils.int_to_hex(ciphertext))

    print("\n--- Testing ECB Decryption ---")
    decrypted_plaintext = ecb_decrypt(ciphertext, key)
    print("Decrypted Plaintext:", utils.int_to_hex(decrypted_plaintext))
    print("Match Original:", plaintext == decrypted_plaintext)
