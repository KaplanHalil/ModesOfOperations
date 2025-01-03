import utils
#import AES_128 as cipher
import AES_256 as cipher

block_size = 16  #bytes
ciphertext_size= 8 # Mb


# makes CBC mode encryption and writes ciphertext to the file
def cbc_encrypt_write(plaintext, key, iv):

    # Encrypt and write the plaintext in chunks
    with open("ciphertext.hex", "wb") as f:
        previous_block = iv
        for i in range(0, len(plaintext), block_size):
            block = plaintext[i:i + block_size]
            if len(block) < block_size:
                block += [0] * (block_size - len(block))
            xor_result = utils.xor_blocks(block, previous_block)
            encrypted_block = cipher.encrypt(xor_result, key)
            f.write(bytes(encrypted_block))
            previous_block = encrypted_block
            # Print progress
            progress = (i + block_size) / len(plaintext) * 100
            print(f"Ciphertext progress: {progress:.2f}%", end='\r')

    

if __name__ == "__main__":

    key = utils.str_to_int_array("0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv  = utils.str_to_int_array("0x000102030405060708090A0B0C0D0E0F")
    
    # Generate plaintext
    plaintext = [(i % 256) for i in range(ciphertext_size * 1024 * 1024)]

    print("---Plaintext is ready---")

    cbc_encrypt_write(plaintext,key,iv)
