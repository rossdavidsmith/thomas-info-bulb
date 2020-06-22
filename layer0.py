from common import extract_and_decode_payload

def extract(input_lines):
    payload_bytes = extract_and_decode_payload(input_lines)
    
    return payload_bytes.decode('utf-8')