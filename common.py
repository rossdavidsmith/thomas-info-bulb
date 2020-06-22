from base64 import a85decode
from re import search, DOTALL


def extract_and_decode_payload(onion_layer_string):
    result = search('<~.*~>', onion_layer_string, DOTALL)
    encoded_payload = result.group()
    return a85decode(encoded_payload, adobe=True)


def write_string_to_file(filename, output_string):
    with open(filename, 'w') as inner_payload_file:
        inner_payload_file.write(output_string)
        inner_payload_file.close()
