from common import extract_and_decode_payload


def flip_alternate_bytes(b):
    return b ^ 0b01010101


def rotate_right(b):
    left_bit = (b & 0b1) * 128
    return (b >> 1) | left_bit


def extract(input_lines):
    payload_bytes = extract_and_decode_payload(input_lines)

    extracted_bytes = bytes(rotate_right(flip_alternate_bytes(b)) for b in payload_bytes)

    return extracted_bytes.decode("utf-8")
