from common import extract_and_decode_payload, write_string_to_file

import layer0
import layer1
import layer2
import layer3
import layer4
import layer5


if __name__ == "__main__":
    with open('onion.txt') as onion_file:
        onion_text = onion_file.read()

    layer_extractors = [
        layer0.extract,
        layer1.extract,
        layer2.extract,
        layer3.extract,
        layer4.extract,
        layer5.extract
    ]

    text = onion_text

    for i, extract_method in enumerate(layer_extractors):
        text = extract_method(text)

        write_string_to_file(f'payload{i+1}.txt', text)
