# Takes string of form "0x0001..." converts int list of form [0,1]
def str_to_int_array(hex_str):
    # Remove the '0x' prefix if it exists
    hex_str = hex_str[2:] if hex_str.startswith("0x") else hex_str
    
    # Ensure the length of the string is even for grouping into bytes
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str  # Add leading zero if necessary
    
    # Convert each pair of characters into a byte (integer)
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]



# Takes int array converts hex array
def int_to_hex(int_list):
    ciphertext_hex_array = [f"0x{byte:02x}" for byte in int_list]
    formatted_ciphertext = "[" + ", ".join(ciphertext_hex_array) + "]"
    return formatted_ciphertext

# Galois Field multiplication
def gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = (a << 1) ^ (0x1B if a & 0x80 else 0)
        b >>= 1
    return p & 0xFF  # Ensure the result is a byte

# XOR operation
def xor_blocks(block1, block2):
    return [b1 ^ b2 for b1, b2 in zip(block1, block2)]


def int_list_to_bit_list(int_list):
    return [bit for num in int_list for bit in map(int, f"{num:08b}")]


def bit_list_to_int_list(bit_list):
    if len(bit_list) % 8 != 0:
        raise ValueError("The length of the bit list must be a multiple of 8.")
    return [int(''.join(map(str, bit_list[i:i + 8])), 2) for i in range(0, len(bit_list), 8)]


def int_to_bit_list(n, width):
    if n < 0:
        raise ValueError("Input must be a non-negative integer")
    if n >= (1 << width):
        raise ValueError(f"Integer too large to fit in {width} bits")
    return [int(b) for b in f"{n:0{width}b}"]


def bit_list_to_int(bits):
    return int(''.join(map(str, bits)), 2)


def rotate_left(lst, nekadar):
    n = len(lst)
    return lst[nekadar % n:] + lst[:nekadar % n]


# int array alıp 4 bitlik nipple array veren fonk.
def convert_to_nibble_array(int_array):
    nibble_array = []
    for val in int_array:
        bits = int_to_bit_list(val, 8)
        left_nibble = bit_list_to_int(bits[:4])
        right_nibble = bit_list_to_int(bits[4:])
        nibble_array.append(left_nibble)
        nibble_array.append(right_nibble)
    return nibble_array


# 4 bitlik nipple array alıp int array veren fonksiyon
def nibbles_to_int_array(nibble_array):
    if len(nibble_array) % 2 != 0:
        raise ValueError("Nibble array length must be even.")
    int_array = []
    for i in range(0, len(nibble_array), 2):
        left = nibble_array[i]
        right = nibble_array[i+1]
        combined = (left << 4) | right
        int_array.append(combined)
    return int_array


if __name__ == "__main__":
    #key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9b, 0x6d, 0x8f, 0x6c, 0x7e]
    print(str_to_int_array("0x0001c2"))