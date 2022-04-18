import logging
import socket
import time

from ssh.key_exchange import StartKeyExchange, DiffieHellmanKeyExchange, StartKeyExchangeDH, \
    KeyExchangeDHReply
from ssh.protocol import SshTLPProtocol

logger = logging.getLogger(__name__)


class SshClient:
    def __init__(self, host, port, protocol: SshTLPProtocol):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.socket = None
        self.sequence_number = 0
        self.key_exchange_protocol = DiffieHellmanKeyExchange()
        self.shared_secret = None

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((self.host, self.port))

    def send(self, msg):
        # Sequence number is incremented on each packet and is used to create a MAC (hash) of each
        # message send which can be validated by the ssh server. This is not included in the message
        # and the server implementation must increment the seq number as well. See also:
        # https://crypto.stackexchange.com/questions/59750/ssh-sequence-number-validity
        # todo: check if > int32 then 0
        self.sequence_number += 1
        self.protocol.send_message(self.socket, bytes(msg), self.sequence_number)

    def receive(self):
        msg = self.protocol.receive_message(self.socket)
        self.sequence_number += 1
        return msg

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
        self.send(msg)
        logger.info("Started key exchange")
        msg = self.receive()
        reply = StartKeyExchange.from_bytes(msg)
        logger.info("agreed on using DH")
        partial_key = self.key_exchange_protocol.generate_partial_shared_key()
        logger.info("Sending generated partial secret")
        kex_init_msg = StartKeyExchangeDH(partial_key)
        self.send(kex_init_msg)
        kex_reply_msg = self.receive()
        kex_reply = KeyExchangeDHReply.from_bytes(kex_reply_msg)
        logger.info("Got servers partial secret")
        self.shared_secret = self.key_exchange_protocol.calculate_shared_key(kex_reply.f)
        logger.info("Generated a shared key. Key exchange done.")

    def close(self):
        # msg = Message(Close())
        # self.protocol.send_message(self.socket, bytes(msg))
        self.sequence_number = 0
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
