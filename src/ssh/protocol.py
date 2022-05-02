import hmac
import secrets
import socket
from base64 import b64decode, b64encode
from typing import Tuple

from Crypto.Cipher import AES


class SshTLPProtocol:
    #  https://datatracker.ietf.org/doc/html/rfc4253#page-4
    packet_length_header = 4
    padding_length_header = 1
    min_padding_size = 4
    encryption_algorithm = 'aes128-cbc'
    # For MAC
    # hmac-sha1-96 RECOMMENDED first 96 bits of HMAC-SHA1 (digest length = 12, key length = 20)
    hash_algorithm = 'sha1-96'
    mac_length = 12

    def __init__(self, cipher_block_length=0):
        self.package_multiple = max(cipher_block_length, 8)
        self.min_packet_size = max(cipher_block_length, 16)

    def _recv_size(self, socket: socket.socket, msg_size: int) -> bytes:
        contents = b''

        while len(contents) != msg_size:
            contents += socket.recv(msg_size - len(contents))

        return contents

    def receive_message(self, socket: socket.socket, shared_key: str = None) -> Tuple[bytes, bytes]:
        packet_length_header = self._recv_size(socket, self.packet_length_header)
        padding_length_header = self._recv_size(socket, self.padding_length_header)
        packet_length = int.from_bytes(packet_length_header, 'little', signed=False)
        padding_length = int.from_bytes(padding_length_header, 'little', signed=False)
        payload_size = packet_length - padding_length - self.padding_length_header
        payload = self._recv_size(socket, payload_size)
        socket.recv(padding_length)
        if shared_key is not None:
            payload = self.decrypt(payload, shared_key)
            mac = self._recv_size(socket, self.mac_length)
        return payload, mac

    def send_message(self, socket: socket.socket, payload: bytes, sequence_number: int, shared_key=None):
        packet = self.create_padded_payload(payload)
        if shared_key is not None:
            data = self.encrypt(packet, shared_key)
        else:
            data = payload

        if shared_key is not None:
            mac = self.mac(shared_key, sequence_number, payload)
            msg = packet + mac
        else:
            msg = packet

        socket.send(msg)

    def create_padded_payload(self, data: bytes):
        payload_size = len(data)
        fixed_header_size = self.packet_length_header + self.padding_length_header
        remainder = (fixed_header_size + payload_size) % self.package_multiple
        padding_size = self.package_multiple - remainder

        while padding_size + payload_size < self.min_padding_size:
            padding_size += self.package_multiple

        if padding_size > 255:
            raise ValueError("padding too large")

        padded_packet = payload_size.to_bytes(self.packet_length_header, 'little', signed=False)
        padded_packet += padding_size.to_bytes(self.padding_length_header, 'little', signed=False)
        padded_packet += data
        padded_packet += secrets.token_bytes(padding_size)
        return padded_packet

    def mac(self, shared_key, sequence_number: int, unencrypted_packet: bytes) -> bytes:
        if shared_key is None:
            raise ValueError("Key not set.")

        sequence_number_bytes = sequence_number.to_bytes(4, 'little', signed=False)
        return hmac.new(
            key=shared_key,
            msg=sequence_number_bytes + unencrypted_packet,
            digestmod=self.hash_algorithm
        ).digest()

    def encrypt(self, packet: bytes, shared_key: str) -> bytes:
        cipher = AES.new(shared_key.encode('utf-8'), AES.MODE_CBC)
        encrypted_packet = cipher.encrypt(packet)
        new_cipher = AES.new(shared_key.encode('utf-8'), AES.MODE_CBC)
        plaintext = new_cipher.decrypt(encrypted_packet)
        return encrypted_packet

    def decrypt(self, encrypted_packet: bytes, shared_key: str) -> bytes:
        cipher = AES.new(shared_key.encode('utf-8'), AES.MODE_CBC)
        plaintext_packet = cipher.decrypt(encrypted_packet)
        return plaintext_packet
