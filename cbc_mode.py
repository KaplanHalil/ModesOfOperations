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


# XOR operation
def xor_blocks(block1, block2):
    return [b1 ^ b2 for b1, b2 in zip(block1, block2)]

# CBC mode encryption
def cbc_encrypt(plaintext, key, iv, cipher_name='AES_128'):
    ciphertext = []
    previous_block = iv

    block_size = get_block_size(cipher_name)
    # Process each block
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        if len(block) < block_size:
            # Padding if block is smaller than block size
            block += [0] * (block_size - len(block))
        # XOR with previous block or IV
        xor_result = xor_blocks(block, previous_block)
        # Encrypt the XOR result
        encrypted_block = encrypt_block(xor_result, key, cipher_name)
        # Append to ciphertext
        ciphertext.extend(encrypted_block)
        # Update the previous block for the next iteration
        previous_block = encrypted_block

    return ciphertext

# CBC mode decryption
def cbc_decrypt(ciphertext, key, iv, cipher_name='AES_128'):
    """
    CBC mode decryption.
    
    Args:
        ciphertext: The ciphertext bytes to decrypt
        key: The encryption key
        iv: The initialization vector (same as used in encryption)
        cipher_name: Name of cipher (AES_128, AES_256, PRESENT80)
    
    Returns:
        The plaintext bytes
    """
    plaintext = []
    previous_block = iv

    block_size = get_block_size(cipher_name)
    # Process each block
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        # Decrypt the block
        decrypted_block = decrypt_block(block, key, cipher_name)
        # XOR with previous ciphertext block or IV
        xor_result = xor_blocks(decrypted_block, previous_block)
        # Append to plaintext
        plaintext.extend(xor_result)
        # Update the previous block for the next iteration
        previous_block = block

    return plaintext

if __name__ == "__main__":

    key = utils.str_to_int_array("0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv  = utils.str_to_int_array("0x000102030405060708090A0B0C0D0E0F")
    plaintext = utils.str_to_int_array("0x6bc1bee22e409f96e93d7e117393172a")
    print("Plaintext:", plaintext)
    print("Key:", key)
    print("IV:", iv)

    ciphertext = cbc_encrypt(plaintext, key, iv)
    print("Ciphertext:", utils.int_to_hex(ciphertext))

    print("\n--- Testing CBC Decryption ---")
    decrypted_plaintext = cbc_decrypt(ciphertext, key, iv)
    print("Decrypted Plaintext:", utils.int_to_hex(decrypted_plaintext))
    print("Match Original:", plaintext == decrypted_plaintext)