import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from common import extract_and_decode_payload


def aes_key_unwrap(wrapping_key, wrapped_key, backend, aiv=b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6"):
    if len(wrapped_key) < 24:
        raise InvalidUnwrap("Must be at least 24 bytes")

    if len(wrapped_key) % 8 != 0:
        raise InvalidUnwrap("The wrapped key must be a multiple of 8 bytes")

    if len(wrapping_key) not in [16, 24, 32]:
        raise ValueError("The wrapping key must be a valid AES key length")

    r = [wrapped_key[i:i + 8] for i in range(0, len(wrapped_key), 8)]
    a = r.pop(0)
    a, r = _unwrap_core(wrapping_key, a, r, backend)
    if not bytes_eq(a, aiv):
        raise InvalidUnwrap()

    return b"".join(r)


def _unwrap_core(wrapping_key, a, r, backend):
    # Implement RFC 3394 Key Unwrap - 2.2.2 (index method)
    decryptor = Cipher(AES(wrapping_key), ECB(), backend).decryptor()
    n = len(r)
    for j in reversed(range(6)):
        for i in reversed(range(n)):
            # pack/unpack are safe as these are always 64-bit chunks
            atr = struct.pack(
                ">Q", struct.unpack(">Q", a)[0] ^ ((n * j) + i + 1)
            ) + r[i]
            # every decryption operation is a discrete 16 byte chunk so
            # it is safe to reuse the decryptor for the entire operation
            b = decryptor.update(atr)
            a = b[:8]
            r[i] = b[-8:]

    assert decryptor.finalize() == b""
    return a, r


def extract_consecutive_byte_ranges(payload_bytes, *lengths):
    offset = 0
    results = []

    for lengths in lengths:
        result = payload_bytes[offset:offset+lengths]
        offset += lengths
        results.append(result)
    
    return tuple(results)


def extract(input_lines):
    payload_bytes = extract_and_decode_payload(input_lines)
    
    key_encrypting_key, wrapped_key_iv, key, iv = \
        extract_consecutive_byte_ranges(payload_bytes, 32, 8, 40, 16)

    ciphertext = payload_bytes[(32+8+40+16):]

    backend = default_backend()
    unwrapped_key = aes_key_unwrap(key_encrypting_key, key, backend, wrapped_key_iv)

    cipher = Cipher(algorithms.AES(unwrapped_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    output = decryptor.update(ciphertext)
    
    decryptor.finalize()

    return output.decode('utf-8')
