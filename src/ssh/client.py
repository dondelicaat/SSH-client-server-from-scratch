import logging
import socket
import time

from ssh.key_exchange import StartKeyExchange
from ssh.protocol import SshTLPProtocol


class SshClient:
    def __init__(self, host, port, protocol: SshTLPProtocol):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.socket = None
        self.sequence_number = 0

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))

    def handshake(self):
        msg = StartKeyExchange(
            kex_algorithms='diffie-hellman-group1-sha1',
            server_host_key_algorithms='ssh-ecdsa',
            encryption_algorithms_client_to_server='aes128-cbc',
            encryption_algorithms_server_to_client='aes128-cbc',
            mac_algorithms_client_to_server='sha1-96',
            mac_algorithms_server_to_client='sha1-96',
            first_kex_packet_follows=False,
        )
        self.protocol.send_message(self.socket, bytes(msg), self.sequence_number)
        print(f"Sent handshake message {msg}")
        msg = self.protocol.receive_message(self.socket)
        reply = StartKeyExchange.from_bytes(msg)
        print(reply)

    def close(self):
        # msg = Message(Close())
        # self.protocol.send_message(self.socket, bytes(msg))
        self.socket.close()


if __name__ == "__main__":
    protocol = SshTLPProtocol()
    client = SshClient(
        host='localhost', port=8000,
        protocol=protocol
    )
    client.connect()
    while True:
        client.handshake()
        time.sleep(5)
    # client.close()
