import socket
import logging
import uuid
from dataclasses import dataclass
from threading import Thread
from queue import Queue

from ssh.key_exchange import MessageCodes, StartKeyExchange, StartKeyExchangeDH, KeyExchangeDHReply, \
    DiffieHellmanKeyExchange
from ssh.protocol import SshTLPProtocol

logging.basicConfig(level=logging.INFO)


@dataclass
class Client:
    socket_connection: socket.socket
    sequence_number: int
    shared_secret: int


class SshServer:
    def __init__(
            self, host, port, protocol: SshTLPProtocol,
            inbox: Queue, concurrent_clients=16
    ):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.concurrent_clients = concurrent_clients
        self.inbox = inbox
        self.clients = {}
        self.key_exchange_protocol = DiffieHellmanKeyExchange()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(self.concurrent_clients)

            while True:
                logging.info("waiting for client")
                client, client_address = s.accept()
                logging.info(f'got client at {client_address}')

                client_connection = Thread(target=self.handle_client, args=(client, client_address))
                client_connection.start()

    def handle_client(self, client_connection, client_address):
        logging.info("started a new connection")
        client_id = str(uuid.uuid4())
        self.clients[client_id] = Client(
            socket_connection=client_connection,
            sequence_number=0,
            shared_secret=None,
        )

        with client_connection:
            while True:
                msg_bytes = self.protocol.receive_message(client_connection)
                logging.info(f"Message received")
                self.clients[client_id].sequence_number += 1
                reply = self.handle_msg(self.clients[client_id], msg_bytes)
                self.send(client_id, reply)

    def send(self, client_id, message):
        self.clients[client_id].sequence_number += 1
        client = self.clients[client_id]
        self.protocol.send_message(
            socket=client.socket_connection,
            payload=bytes(message),
            sequence_number=client.sequence_number
        )

    def handle_msg(self, client, msg: bytes):
        logging.info(f"Handling msg for client {client}")

        msg_code = int.from_bytes(msg[0:1], 'little')
        logging.info(f"Received msg code: {msg_code}")
        reply = None
        if msg_code == MessageCodes.SSH_MSG_KEXINIT.value:
            reply = StartKeyExchange.from_bytes(msg)
        elif msg_code == MessageCodes.SSH_MSG_KEXDH_INIT.value:
            logging.info("received kexdh init msg")
            msg = StartKeyExchangeDH.from_bytes(msg)
            client_shared_secret = msg.e
            server_partial_secret = self.key_exchange_protocol.generate_partial_shared_key()
            client.shared_secret = self.key_exchange_protocol.calculate_shared_key(client_shared_secret)
            reply = KeyExchangeDHReply(
                f=server_partial_secret,
                server_host_key_certificates="https://some-verification-url",
                signature_h="SOME SIGNATURE"
            )
        # else:

            # self.inbox.put((client_id, msg_bytes)) or
            # reply = ...# Not ok todo

        return reply
