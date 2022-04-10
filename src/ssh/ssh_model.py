from queue import Queue

from ssh.key_exchange import StartKeyExchange


class Ssh:
    def __init__(self, outbox: Queue):
        self.outbox = outbox

    def handle_msg(self, client_id, msg, sequence_number):
        if isinstance(msg, StartKeyExchange):
            self.outbox.put((client_id, msg, sequence_number))
