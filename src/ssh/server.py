import socket
import logging
import uuid
from threading import Thread
from queue import Queue

from ssh.key_exchange import MessageCodes, StartKeyExchange
from ssh.protocol import SshTLPProtocol

logging.basicConfig(level=logging.INFO)


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

    def handle_client(self, client, client_address):
        logging.info("started a new connection")
        client_id = str(uuid.uuid4())
        sequence_number = 0

        with client:
            while True:
                msg_bytes = self.protocol.receive_message(client)
                msg_code = int.from_bytes(msg_bytes[0:1], 'little')
                logging.info(f"Received msg code: {msg_code}")
                msg = None
                if msg_code == MessageCodes.SSH_MSG_KEXINIT.value:
                    msg = StartKeyExchange.from_bytes(msg_bytes)
                logging.info(f"Message received: {msg}")


                self.clients[client_id] = client
                sequence_number += 1
                self.inbox.put((client_id, msg, sequence_number))

    def send(self, client_id, message, sequence_number: int):
        client = self.clients[client_id]
        self.protocol.send_message(socket=client, payload=bytes(message), sequence_number=sequence_number)

