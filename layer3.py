from itertools import cycle
from common import extract_and_decode_payload


def extract(input_lines):
    payload_bytes = extract_and_decode_payload(input_lines)

    # # As the first line always contains a lot of '=' characters, the following produces
    # # a key that will allow us to locate the '==[ Payload ]==...' line, which has 32
    # # consecutive '=' characters to extract the full, correct key with.
    # a = payload_bytes[32:64]
    # b = b'================================'
    # c = bytes(x ^ y for x,y in zip(a,b))

    target_offset = 109*32

    a = payload_bytes[target_offset:target_offset+32]
    b = b'================================'
    c = bytes(x ^ y for x,y in zip(a,b))

    decrypted_bytes = bytes(x ^ y for x, y in zip(payload_bytes, cycle(c)))
    return decrypted_bytes.decode("utf-8")
