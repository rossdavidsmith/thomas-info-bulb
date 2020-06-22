from struct import unpack
from typing import NamedTuple
from functools import reduce
from operator import add

from common import extract_and_decode_payload


class InternetHeader(NamedTuple):
    version: int
    header_length: int
    type_of_service: int
    total_length: int
    identification: int
    fragmentation_permitted: bool
    is_last_fragment: bool
    fragment_offset: int
    time_to_live: int
    protocol: int # Enum?
    header_checksum: int
    source_address: int
    destination_address: int
    # options?
    

    def validate_checksum(self):
        '''
        The checksum algorithm is:

            The checksum field is the 16 bit one's complement of the one's
            complement sum of all 16 bit words in the header.  For purposes of
            computing the checksum, the value of the checksum field is zero.

        This is a simple to compute checksum and experimental evidence
        indicates it is adequate, but it is provisional and may be replaced
        by a CRC procedure, depending on further experience.
        '''
        c16 = Checksum16()
        c16.add(self.version << 12)
        c16.add(self.header_length << 8)
        c16.add(self.type_of_service)
        c16.add(self.total_length)
        c16.add(self.identification)
        c16.add(0 if self.fragmentation_permitted else 0b0100000000000000)
        c16.add(0 if self.is_last_fragment else 0b0010000000000000)
        c16.add(self.fragment_offset)
        c16.add(self.time_to_live << 8)
        c16.add(self.protocol)
        c16.add(self.fragment_offset)
        c16.add(self.source_address >> 16)
        c16.add(self.source_address & 0xFFFF)
        c16.add(self.destination_address >> 16)
        c16.add(self.destination_address & 0xFFFF)

        ip_checksum = c16.checksum()
        
        return ip_checksum == self.header_checksum


class UserDatagram(NamedTuple):
    internet_header: InternetHeader
    source_port: int
    destination_port: int
    length: int
    checksum: int
    content: bytes

    def verify_checksum(self):
        '''
        Checksum is the 16-bit one's complement of the one's complement sum of:
            - a pseudo header of information from the IP header,
            - the UDP header
            - the data, padded with zero octets at the end (if necessary) to make
            a multiple of two octets.
                
        The pseudo header conceptually prefixed to the UDP header contains:
            - the source address
            - the destination address
            - the protocol
            - the UDP length.
        
        This information gives protection against misrouted datagrams. This checksum
        procedure is the same as is used in TCP.

                        0      7 8     15 16    23 24    31
                        +--------+--------+--------+--------+
                        |          source address           |
                        +--------+--------+--------+--------+
                        |        destination address        |
                        +--------+--------+--------+--------+
                        |  zero  |protocol|   UDP length    |
                        +--------+--------+--------+--------+
        '''
        c16 = Checksum16()

        ip_content_length_octets = self.internet_header.total_length - (self.internet_header.header_length * 4)

        c16.add((self.internet_header.source_address >> 16) & 0xFFFF)
        c16.add(self.internet_header.source_address & 0xFFFF)
        c16.add((self.internet_header.destination_address >> 16) & 0xFFFF)
        c16.add(self.internet_header.destination_address & 0xFFFF)
        c16.add(self.internet_header.protocol)
        c16.add(ip_content_length_octets)

        c16.add(self.source_port)
        c16.add(self.destination_port)
        c16.add(self.length)

        for i, b in enumerate(self.content):
            if i%2 == 0:
                c16.add(b << 8)
            else:
                c16.add(b)
        
        computed_udp_checksum = c16.checksum()

        return self.checksum == computed_udp_checksum








class Checksum16():
    def __init__(self):
        self.sum = 0

    def add(self, short):
        checksum = self.sum + short
        self.sum = (checksum & 0xFFFF) + (checksum >> 16)
        
    def add_range(self, shorts):
        for short in shorts:
            self.add(short)
    
    def checksum(self):
        return self.sum ^ 0xFFFF


def consume_header(bytestream, index):
    (version_ihl,
        type_of_service,
        total_length,
        identification,
        flags_fragment_offset,
        ttl, protocol,
        header_checksum,
        source_address,
        destination_address) \
            = unpack('!BBHHHBBHII', bytestream[index:index+20])

    header_length = version_ihl & 0xF

    assert(protocol == 17)     #  17: User Datagram Protocol
    assert(header_length == 5) #  Assume that there are no options in the provided data until
                               #  proven otherwise.
    
    header = InternetHeader(
        version = (version_ihl >> 1) & 0xF,
        header_length = header_length,
        type_of_service = type_of_service,
        total_length = total_length,
        identification = identification,
        fragmentation_permitted = not (flags_fragment_offset & 0x5FFFF),
        is_last_fragment = not (flags_fragment_offset & 0x3FFFF),
        fragment_offset = flags_fragment_offset & 0x1FFF,
        time_to_live = ttl,
        protocol = protocol,
        header_checksum = header_checksum,
        source_address = source_address,
        destination_address = destination_address)

    index += 20

    return (index, header)


def consume_user_datagram(bytestream, index, header):
    source_port, destination_port, length, udp_checksum \
        = unpack('!HHHH', bytestream[index:index+8])

    content_length = length - 8
    index += 8

    content = bytestream[index:index+content_length]
    index += content_length

    user_datagram = UserDatagram(
        internet_header = header,
        source_port = source_port,
        destination_port = destination_port,
        length = length,
        checksum = udp_checksum,
        content = content
    )

    return (index, user_datagram)


def ip_address_string_to_int(s):
    parts = list(map(int, s.split('.')))

    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def ip_address_int_to_string(i):
    return '.'.join(str((i >> (x*8)) & 0xFF) for x in [3,2,1,0])


def extract(input_lines):
    payload_bytes = extract_and_decode_payload(input_lines)

    required_source = ip_address_string_to_int('10.1.1.10')
    required_destination = ip_address_string_to_int('10.1.1.200')
    required_destination_port = 42069

    bytestream = payload_bytes

    index = 0

    result_bytes = bytes(b'')
    
    while index < len(bytestream):
        index, header = consume_header(bytestream, index)
        index, user_datagram = consume_user_datagram(bytestream, index, header)

        header_valid = header.validate_checksum()
        udp_valid = user_datagram.verify_checksum()

        # header_checksum_string = '✔' if header_valid else '✘'
        # udp_checksum_string = '✔' if udp_valid else '✘'

        # print(
        #     f'[{header_checksum_string}-{udp_checksum_string}] ' +
        #     f'{ip_address_int_to_string(header.source_address)}:{user_datagram.source_port} => ' +
        #     f'{ip_address_int_to_string(header.destination_address)}:{user_datagram.destination_port}'
        # )

        if (header_valid and
           udp_valid and
           header.source_address == required_source and
           header.destination_address == required_destination and
           user_datagram.destination_port == required_destination_port):
            result_bytes += user_datagram.content
        # else:
        #     print(user_datagram.content.decode('utf-8'))

    return result_bytes.decode('utf-8')