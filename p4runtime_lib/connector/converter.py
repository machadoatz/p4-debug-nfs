#!/usr/bin/env python3

import codecs
import math
import re
import socket


class Converter(object):
    """
    This class contains several helper functions for encoding to and decoding from byte strings:
        - Integers;
        - IPv4 and IPv6 addresses;
        - Ethernet addresses.
    """

    """
    patterns
    """

    __mac_pattern = re.compile(
        '^[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$')

    """
    auxiliary functions
    """

    @staticmethod
    def bitwidth_to_bytes(bitwidth):
        return int(math.ceil(bitwidth / 8.0))

    """
    matchers
    """

    def matches_mac(self, mac_addr_string):
        return self.__mac_pattern.match(mac_addr_string) is not None

    @staticmethod
    def matches_ipv4(ip_addr_string):
        try:
            socket.inet_pton(socket.AF_INET, ip_addr_string)
            return True

        except socket.error:
            return False

    @staticmethod
    def matches_ipv6(ip_addr_string):
        try:
            socket.inet_pton(socket.AF_INET6, ip_addr_string)
            return True

        except socket.error:
            return False

    """
    encoders
    """

    @staticmethod
    def encode_mac(mac_addr_string):
        return codecs.decode(mac_addr_string.replace(':', ''), 'hex')

    @staticmethod
    def encode_ipv4(ip_addr_string):
        return socket.inet_aton(ip_addr_string)

    @staticmethod
    def encode_ipv6(ip_addr_string):
        return socket.inet_pton(socket.AF_INET6, ip_addr_string)

    def encode_num(self, number: int, bitwidth: int):
        return number.to_bytes(self.bitwidth_to_bytes(bitwidth), byteorder='big')

    def encode(self, x, bitwidth):
        """
        Tries to infer the type of `x` and encode it.
        """

        byte_len = self.bitwidth_to_bytes(bitwidth)
        if (type(x) == list or type(x) == tuple) and len(x) == 1:
            x = x[0]

        if type(x) == str:
            if self.matches_mac(x):
                encoded_bytes = self.encode_mac(x)

            elif self.matches_ipv4(x):
                encoded_bytes = self.encode_ipv4(x)

            elif self.matches_ipv6(x):
                encoded_bytes = self.encode_ipv6(x)

            else:
                raise Exception(
                    'The provided string does not mach any known address.')

        elif type(x) == int:
            encoded_bytes = self.encode_num(x, bitwidth)

        elif type(x) == bytes:
            encoded_bytes = x

        else:
            raise Exception(
                'Encoding objects of `{}` is not supported.'.format(type(x)))

        assert len(encoded_bytes) == byte_len
        return encoded_bytes

    """
    decoders
    """

    @staticmethod
    def decode_mac(encoded_mac_addr):
        return ':'.join(['00'] * (6 - len(encoded_mac_addr)) + [format(byte, '02x') for byte in encoded_mac_addr])

    @staticmethod
    def decode_ipv4(encoded_ip_addr):
        return socket.inet_ntoa(encoded_ip_addr)

    @staticmethod
    def decode_ipv6(encoded_ip_addr):
        return socket.inet_ntop(socket.AF_INET6, encoded_ip_addr)

    @staticmethod
    def decode_num(encoded_number):
        return int.from_bytes(encoded_number, byteorder='big')

    def decode(self, encoded_bytes: bytes, bitwidth):
        """
        Tries to infer the type of `encoded_bytes` and decode it.
        """

        # if len(encoded_bytes) and bitwidth are not equal, prepend 0s
        truncated_bytes = math.ceil((bitwidth - len(encoded_bytes) * 8) / 8)
        if truncated_bytes != 0:
            encoded_bytes = (truncated_bytes * b'\0') + encoded_bytes

        # fixme this is still a work in progress
        # right now, the bitwidth is being used as a hint to "guess" the original type of the value
        # however, this approach fails under obvious conditions
        # in the near future, more hints should be provided to the decoder, such as param_name (or param_alias)

        if bitwidth == 48:
            # mac address?
            return self.decode_mac(encoded_bytes)

        elif bitwidth == 32:
            # ipv4 address?
            return self.decode_ipv4(encoded_bytes)

        elif bitwidth == 128:
            # ipv6 address?
            return self.decode_ipv6(encoded_bytes)

        # number?
        return self.decode_num(encoded_bytes)
