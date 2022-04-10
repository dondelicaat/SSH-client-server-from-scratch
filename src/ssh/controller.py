import logging
from queue import Queue
from threading import Thread

from ssh.protocol import SshTLPProtocol
from ssh.server import SshServer
from ssh.ssh_model import Ssh

logger = logging.getLogger(__name__)


class ServerController:
    def __init__(
        self,
        protocol: SshTLPProtocol,
        port: int, host: str,
    ):
        self.inbox = Queue()
        self.outbox = Queue()

        self.server = SshServer(
            host=host, port=port,
            inbox=self.inbox,
            protocol=protocol
        )

        self.ssh = Ssh(
            outbox=self.outbox
        )

    def handle_inbox(self):
        while True:
            client_id, message, sequence_number = self.inbox.get(block=True)
            self.ssh.handle_msg(client_id, message, sequence_number)

    def handle_outbox(self):
        while True:
            client_id, message, sequence_number = self.outbox.get()
            self.server.send(client_id, message, sequence_number)

    def run(self):
        raft_server_thread = Thread(target=self.server.run)
        handle_outbox_thread = Thread(target=self.handle_outbox)
        handle_input_thread = Thread(target=self.handle_inbox)
        raft_server_thread.start()
        handle_outbox_thread.start()
        handle_input_thread.start()


if __name__ == "__main__":
    ssh_protocol = SshTLPProtocol()

    server_controller = ServerController(
        protocol=ssh_protocol,
        port=8000,
        host='localhost'
    )

    server_controller.run()
