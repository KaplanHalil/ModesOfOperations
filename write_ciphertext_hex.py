#!/usr/bin/env python3
"""Generate plaintext, encrypt with chosen cipher/mode, and write ciphertext as hex."""
import argparse
import secrets
import sys

import utils
import cbc_mode
import cfb_mode
import ctr_mode
import ecb_mode
import gcm_mode
import ofb_mode


CIPHER_KEY_SIZES = {
    'AES_128': 16,
    'AES_256': 32,
    'PRESENT80': 10,
}

SUPPORTED_MODES = ['ECB', 'CBC', 'CFB', 'CTR', 'OFB', 'GCM']
SUPPORTED_CIPHERS = list(CIPHER_KEY_SIZES.keys())


def parse_bytes(value, expected_len=None):
    """Parse hex string or comma-separated ints into byte list."""
    if value is None:
        return None
    value = value.strip()
    if value.startswith('0x') or value.startswith('0X'):
        result = utils.str_to_int_array(value)
    elif ',' in value:
        result = [int(x.strip(), 0) & 0xFF for x in value.split(',') if x.strip()]
    else:
        # raw hex without prefix
        try:
            result = utils.str_to_int_array('0x' + value)
        except Exception:
            raise argparse.ArgumentTypeError('Invalid byte input: %s' % value)

    if expected_len is not None and len(result) != expected_len:
        raise argparse.ArgumentTypeError(
            f'Expected {expected_len} bytes, got {len(result)}')
    return result


def fixed_bytes(length, start=0):
    return [(start + i) & 0xFF for i in range(length)]


def make_plaintext(size):
    return [(i & 0xFF) for i in range(size)]


def encrypt_plaintext(plaintext, key, cipher, mode, iv=None, nonce=None, initial_counter=1):
    mode = mode.upper()

    if mode == 'ECB':
        return ecb_mode.ecb_encrypt(plaintext, key, cipher)
    if mode == 'CBC':
        if iv is None:
            raise ValueError('IV is required for CBC mode')
        return cbc_mode.cbc_encrypt(plaintext, key, iv, cipher)
    if mode == 'CFB':
        if iv is None:
            raise ValueError('IV is required for CFB mode')
        return cfb_mode.cfb_encrypt(plaintext, key, iv, cipher)
    if mode == 'OFB':
        if iv is None:
            raise ValueError('IV is required for OFB mode')
        return ofb_mode.ofb_process(plaintext, key, iv, cipher)
    if mode == 'CTR':
        if iv is None or nonce is None:
            raise ValueError('nonce and iv are required for CTR mode')
        return ctr_mode.ctr_encrypt(plaintext, key, nonce, iv, initial_counter, cipher)
    if mode == 'GCM':
        if iv is None:
            raise ValueError('IV (nonce) is required for GCM mode')
        ciphertext, tag = gcm_mode.gcm_encrypt(plaintext, key, iv, additional_data=[], cipher_name=cipher)
        return ciphertext, tag

    raise ValueError(f'Unsupported mode: {mode}')


def write_hex_file(path, data_bytes):
    with open(path, 'w') as f:
        f.write(''.join(f'{b:02x}' for b in data_bytes))


def main():
    parser = argparse.ArgumentParser(description='Encrypt plaintext and save ciphertext as hex.')
    parser.add_argument('--size', type=int, required=True, help='Plaintext size in bytes (>=1)')
    parser.add_argument('--algorithm', choices=SUPPORTED_CIPHERS, required=True,
                        help='Cipher algorithm')
    parser.add_argument('--mode', choices=SUPPORTED_MODES, required=True, help='Cipher mode')
    parser.add_argument('--output', default='ciphertext.hex', help='Output path for ciphertext hex')
    parser.add_argument('--output-tag', default=None,
                        help='Optional path to write GCM authentication tag as hex')

    args = parser.parse_args()

    if args.size <= 0:
        raise SystemExit('size must be a positive integer')

    cipher = args.algorithm
    mode = args.mode.upper()
    key_len = CIPHER_KEY_SIZES[cipher]

    key = list(secrets.token_bytes(key_len))

    iv = None
    nonce = None

    if mode in ['CBC', 'CFB', 'OFB']:
        iv = list(secrets.token_bytes(16))

    if mode == 'GCM':
        # Standard 96-bit nonce for GCM.
        iv = list(secrets.token_bytes(12))

    if mode == 'CTR':
        nonce = list(secrets.token_bytes(4))
        iv = list(secrets.token_bytes(8))

    plaintext = list(secrets.token_bytes(args.size))

    try:
        result = encrypt_plaintext(plaintext, key, cipher, mode, iv=iv, nonce=nonce, initial_counter=1)
    except Exception as e:
        raise SystemExit(f'Encryption failed: {e}')

    if mode == 'GCM':
        ciphertext, tag = result
    else:
        ciphertext = result
        tag = None

    write_hex_file(args.output, ciphertext)

    print(f'Wrote ciphertext ({len(ciphertext)} bytes) to {args.output}')
    if tag is not None:
        if args.output_tag:
            write_hex_file(args.output_tag, tag)
            print(f'Wrote GCM tag ({len(tag)} bytes) to {args.output_tag}')
        else:
            print('GCM tag:', ''.join(f'{b:02x}' for b in tag))


if __name__ == '__main__':
    main()
