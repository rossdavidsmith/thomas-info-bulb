from common import extract_and_decode_payload


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def check_parity(input):
    parity = 0
    b = input

    for _ in range(7):
        b >>= 1
        parity += b & 0x1

    return (parity % 2) == (input & 0b1)


def compress_parity_bytes(g):
    acc = 0

    for b in g:
        acc <<= 7
        acc |= (b >> 1)

    return (acc & 0xFFFFFFFFFFFFFF).to_bytes(7, 'big')


def extract(input_lines):
    payload_bytes = extract_and_decode_payload(input_lines)
    parity_checked_bytes = list(filter(check_parity, payload_bytes))
    compressed_bytes = b''.join(map(compress_parity_bytes, chunks(parity_checked_bytes, 8)))

    return compressed_bytes.decode("utf-8")
