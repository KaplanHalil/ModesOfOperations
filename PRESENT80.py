import utils

plaintext_size = 8  # bytes
ciphertext_size = 8  # bytes
mkey_size = 10  # bytes
round_key_size = 8  # bytes
num_rounds = 31
block_size = 8

SBOX = [
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
]

INV_SBOX = [0] * 16
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

PERM = [0, 16, 32, 48, 1, 17, 33, 49,
        2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53,
        6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57,
        10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61,
        14, 30, 46, 62, 15, 31, 47, 63]

INV_PERM = [0] * 64
for i, p in enumerate(PERM):
    INV_PERM[p] = i


def sub_bytes(state):
    nibble_state = utils.convert_to_nibble_array(state)
    for i in range(len(nibble_state)):
        nibble_state[i] = SBOX[nibble_state[i]]
    return utils.nibbles_to_int_array(nibble_state)


def inv_sub_bytes(state):
    nibble_state = utils.convert_to_nibble_array(state)
    for i in range(len(nibble_state)):
        nibble_state[i] = INV_SBOX[nibble_state[i]]
    return utils.nibbles_to_int_array(nibble_state)


def permute(state):
    bit_state = utils.int_list_to_bit_list(state)
    new_bit_state = [0] * 64
    for i in range(64):
        new_bit_state[PERM[i]] = bit_state[i]
    return utils.bit_list_to_int_list(new_bit_state)


def inv_permute(state):
    bit_state = utils.int_list_to_bit_list(state)
    new_bit_state = [0] * 64
    for i in range(64):
        new_bit_state[INV_PERM[i]] = bit_state[i]
    return utils.bit_list_to_int_list(new_bit_state)


def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


def key_schedule(key):
    keybits = utils.int_list_to_bit_list(key)
    round_keys = []

    for i in range(num_rounds + 1):
        round_key_bits = keybits[:64]
        round_keys.append(utils.bit_list_to_int_list(round_key_bits))

        # Rotate 80-bit key left by 61 bits
        keybits = utils.rotate_left(keybits, 61)

        # S-box on leftmost 4 bits
        sbox_input = utils.bit_list_to_int(keybits[:4])
        sbox_output = SBOX[sbox_input]
        keybits[:4] = utils.int_to_bit_list(sbox_output, 4)

        # XOR round counter
        rc_segment = keybits[60:65]
        rc_value = utils.bit_list_to_int(rc_segment)
        rc_value = (rc_value ^ (i + 1)) & 0x1F
        keybits[60:65] = utils.int_to_bit_list(rc_value, 5)

    return round_keys


def encrypt(block, key):
    if len(block) != block_size:
        raise ValueError('PRESENT80 block must be 8 bytes')
    if len(key) != mkey_size:
        raise ValueError('PRESENT80 key must be 10 bytes')

    round_keys = key_schedule(key)
    state = add_round_key(block, round_keys[0])

    for round in range(1, num_rounds + 1):
        state = sub_bytes(state)
        state = permute(state)
        state = add_round_key(state, round_keys[round])

    return state


def decrypt(block, key):
    if len(block) != block_size:
        raise ValueError('PRESENT80 block must be 8 bytes')
    if len(key) != mkey_size:
        raise ValueError('PRESENT80 key must be 10 bytes')

    round_keys = key_schedule(key)
    state = add_round_key(block, round_keys[num_rounds])

    for round in range(num_rounds - 1, -1, -1):
        state = inv_permute(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round])

    return state


if __name__ == '__main__':
    plaintext = utils.str_to_int_array('0x0000000000000000')
    key = utils.str_to_int_array('0x00000000000000000000')

    print('PRESENT plaintext:', utils.int_to_hex(plaintext))
    print('PRESENT key:', utils.int_to_hex(key))

    ciphertext = encrypt(plaintext, key)
    print('PRESENT ciphertext:', utils.int_to_hex(ciphertext))

    decrypted = decrypt(ciphertext, key)
    print('PRESENT decrypted:', utils.int_to_hex(decrypted))
    print('match:', decrypted == plaintext)
