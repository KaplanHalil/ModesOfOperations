import utils
import AES_128 as cipher  # Assuming AES_128 implements AES encryption

block_size = 16  # bytes
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
def ctr_encrypt(plaintext, key, nonce, iv, initial_counter):
    ciphertext = []
    block_counter = initial_counter

    # Process each block
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        # Construct the counter block
        counter_block = construct_counter_block(nonce, iv, block_counter)
        # Encrypt the counter block
        encrypted_counter = cipher.encrypt(list(counter_block), key)
        # XOR plaintext block with encrypted counter
        xor_result = xor_blocks(block, encrypted_counter)
        # Append to ciphertext
        ciphertext.extend(xor_result)
        # Increment and wrap block counter
        block_counter = (block_counter + 1) & max_counter_value

    return ciphertext

if __name__ == "__main__":
    # Test Vector #1
    key = utils.str_to_int_array("0x7E24067817FAE0D743D6CE1F32539163")
    nonce = utils.str_to_int_array("0x006CB6DB")  # 4 bytes
    iv = utils.str_to_int_array("0xC0543B59DA48D90B")  # 8 bytes
    plaintext = utils.str_to_int_array("0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    initial_counter = 1  # Start from block counter 1

    print("Plaintext:", utils.int_to_hex(plaintext))
    print("Key:", utils.int_to_hex(key))
    print("Nonce:", utils.int_to_hex(nonce))
    print("IV:", utils.int_to_hex(iv))
    print("Initial Counter:", initial_counter)

    ciphertext = ctr_encrypt(plaintext, key, nonce, iv, initial_counter)
    print("Ciphertext:", utils.int_to_hex(ciphertext))

    # Expected Ciphertext: E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8
