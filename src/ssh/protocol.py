import hmac
import secrets
import socket


class SshTLPProtocol:
    #  https://datatracker.ietf.org/doc/html/rfc4253#page-4
    packet_length_header = 4
    padding_length_header = 1
    min_padding_size = 4
    encryption_algorithm = 'aes128-cbc'
    hash_algorithm = 'sha1-96'

    def __init__(self, cipher_block_length=0, mac_length=0):
        self.package_multiple = max(cipher_block_length, 8)
        self.min_packet_size = max(cipher_block_length, 16)
        self.mac_length = mac_length

    def _recv_size(self, socket: socket.socket, msg_size: int) -> bytes:
        contents = b''

        while len(contents) != msg_size:
            contents += socket.recv(msg_size - len(contents))

        return contents

    def receive_message(self, socket: socket.socket) -> bytes:
        packet_length_header = self._recv_size(socket, self.packet_length_header)
        padding_length_header = self._recv_size(socket, self.padding_length_header)
        packet_length = int.from_bytes(packet_length_header, 'little', signed=False)
        padding_length = int.from_bytes(padding_length_header, 'little', signed=False)
        payload_size = packet_length
        payload = self._recv_size(socket, payload_size)
        socket.recv(padding_length)
        return payload

    def send_message(self, socket: socket.socket, payload: bytes, sequence_number: int, shared_key=None):
        msg_size = len(payload)
        packet_length = msg_size.to_bytes(self.packet_length_header, 'little', signed=False)

        # 4 < padding length < 255
        padding_size = self.packet_length_header + self.padding_length_header + len(payload) % self.package_multiple
        # bytes to add because of minimum package size > 16
        bytes_to_add = max(0, self.min_packet_size - (self.packet_length_header + self.padding_length_header + len(payload)) - padding_size)
        padding_size += bytes_to_add
        if padding_size == 0:
            padding_size = self.package_multiple
        elif padding_size <= self.min_padding_size:
            padding_size = self.package_multiple - padding_size + 1

        unencrypted_packet = packet_length
        unencrypted_packet += padding_size.to_bytes(self.padding_length_header, 'little', signed=False)
        unencrypted_packet += payload
        unencrypted_packet += secrets.token_bytes(padding_size)
        if shared_key is not None:
            encrypted_packet = self.encrypt(unencrypted_packet, shared_key)
            mac = self.mac(shared_key, sequence_number, unencrypted_packet)
            msg = encrypted_packet + mac
        else:
            msg = unencrypted_packet

        socket.send(msg)

    def mac(self, shared_key, sequence_number: int, unencrypted_packet: bytes) -> bytes:
        if shared_key is None:
            raise ValueError("Key not set.")

        sequence_number_bytes = sequence_number.to_bytes(4, 'little', signed=False)
        return hmac.new(
            key=shared_key,
            msg=sequence_number_bytes + unencrypted_packet,
            digestmod=self.hash_algorithm
        ).digest()

    def encrypt(self, packet, shared_key):
        return packet
