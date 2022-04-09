import secrets
import socket


class SshTLPProtocol:
    #  https://datatracker.ietf.org/doc/html/rfc4253#page-4
    packet_length_header = 4
    padding_length_header = 1

    def __init__(self, cipher_block_length):
        self.package_multiple = max(cipher_block_length, 8)

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
        payload_size = packet_length - padding_length - 1
        payload = self._recv_size(socket, payload_size)
        return payload

    def send_message(self, socket: socket.socket, payload: bytes):
        msg_size = len(payload)
        try:
            packet_length = msg_size.to_bytes(self.packet_length_header, 'little', signed=False)
        except OverflowError:
            raise ValueError(f'The message is too long. Max size is {2**self.packet_length_header}')

        # 4 < padding length <255
        padding_size = self.packet_length_header + self.padding_length_header + len(payload) % self.package_multiple
        if padding_size == 0:
            padding_size = self.package_multiple
        elif padding_size <= 4:
            padding_size = self.package_multiple - padding_size + 1

        msg = packet_length
        msg += padding_size.to_bytes(self.padding_length_header, 'little', signed=False)
        msg += payload
        msg += secrets.token_bytes(padding_size)

        assert len(msg) % self.package_multiple == 0
        socket.send(msg)
