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

# CFB (Cipher Feedback) encryption
def cfb_encrypt(plaintext, key, iv, cipher_name='AES_128'):
    ciphertext = []
    feedback = iv

    block_size = get_block_size(cipher_name)
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))

        encrypted_feedback = encrypt_block(feedback, key, cipher_name)
        encrypted_block = xor_blocks(block, encrypted_feedback)

        ciphertext.extend(encrypted_block[:len(plaintext[i:i + block_size])])
        feedback = encrypted_block

    return ciphertext

# CFB decryption
def cfb_decrypt(ciphertext, key, iv, cipher_name='AES_128'):
    plaintext = []
    feedback = iv

    block_size = get_block_size(cipher_name)
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))

        encrypted_feedback = encrypt_block(feedback, key, cipher_name)
        decrypted_block = xor_blocks(block, encrypted_feedback)

        plaintext.extend(decrypted_block[:len(ciphertext[i:i + block_size])])
        feedback = block

    return plaintext

if __name__ == "__main__":
    key = utils.str_to_int_array("0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = utils.str_to_int_array("0x000102030405060708090A0B0C0D0E0F")
    plaintext = utils.str_to_int_array("0x6bc1bee22e409f96e93d7e117393172a")

    ciphertext = cfb_encrypt(plaintext, key, iv)
    print("CFB Ciphertext:", utils.int_to_hex(ciphertext))
    decrypted = cfb_decrypt(ciphertext, key, iv)
    print("CFB Decrypted:", utils.int_to_hex(decrypted))
    print("Match", plaintext == decrypted)
