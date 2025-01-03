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

if __name__ == "__main__":

    #key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9b, 0x6d, 0x8f, 0x6c, 0x7e]
    print(str_to_int_array("0x0001c2"))