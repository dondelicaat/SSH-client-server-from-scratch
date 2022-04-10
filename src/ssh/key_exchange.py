import secrets
from dataclasses import dataclass


@dataclass
class StartKeyExchangeMessage:
    """
    To be send by on connection established on server and first message send by client.
    (Actually first msg should be protocol version exchange but not implementing that)
    :return:
    """
    kex_algorithms: str
    server_host_key_algorithms: str
    encryption_algorithms_client_to_server: str
    encryption_algorithms_server_to_client: str
    mac_algorithms_client_to_server: str
    mac_algorithms_server_to_client: str
    first_kex_packet_follows: bool

    def __bytes__(self):
        SSH_MSG_KEXINIT = 20
        # name lists according to https://datatracker.ietf.org/doc/html/rfc4251
        # Set list of key exchange algo's
        cookie = secrets.token_bytes(16)
        kex_algorithms = self.name_list(self.kex_algorithms)
        server_host_key_algorithms = self.name_list(self.server_host_key_algorithms)
        encryption_algorithms_client_to_server = self.name_list(self.encryption_algorithms_client_to_server)
        encryption_algorithms_server_to_client = self.name_list(self.encryption_algorithms_server_to_client)
        mac_algorithms_client_to_server = self.name_list(self.mac_algorithms_client_to_server)
        mac_algorithms_server_to_client = self.name_list(self.mac_algorithms_server_to_client)
        # If first_kex_packet_follows is False since not guessing initial kex so no msg following
        first_kex_packet_follows = bytes(int(self.first_kex_packet_follows))

        msg = SSH_MSG_KEXINIT.to_bytes(1, 'little', signed=False)
        msg += cookie
        msg += kex_algorithms
        msg += server_host_key_algorithms
        msg += encryption_algorithms_client_to_server
        msg += encryption_algorithms_server_to_client
        msg += mac_algorithms_client_to_server
        msg += mac_algorithms_server_to_client
        msg += first_kex_packet_follows

        return msg

    @classmethod
    def from_bytes(cls, payload: bytes):
        index = 16 + 1
        index, kex_algorithms = cls.parse_name_list(index, payload)
        index, server_host_key_algorithms = cls.parse_name_list(index, payload)
        index, encryption_algorithms_client_to_server = cls.parse_name_list(index, payload)
        index, encryption_algorithms_server_to_client = cls.parse_name_list(index, payload)
        index, mac_algorithms_client_to_server = cls.parse_name_list(index, payload)
        index, mac_algorithms_server_to_client = cls.parse_name_list(index, payload)
        first_kex_packet_follows = bool(int.from_bytes(payload[index: index + 1], 'little', signed=False))
        return cls(
            kex_algorithms=kex_algorithms, server_host_key_algorithms=server_host_key_algorithms,
            encryption_algorithms_server_to_client=encryption_algorithms_server_to_client,
            encryption_algorithms_client_to_server=encryption_algorithms_client_to_server,
            mac_algorithms_server_to_client=mac_algorithms_server_to_client,
            mac_algorithms_client_to_server=mac_algorithms_client_to_server,
            first_kex_packet_follows=first_kex_packet_follows
        )

    @staticmethod
    def parse_name_list(index, payload) -> (int, str):
        """ format of nameslist: `("<comma separated list of names>"),`
            but simplify to `(<name>),`
        """
        length = int.from_bytes(payload[index:index + 4], 'little', signed=False)
        name_list_start_index = index + 4 + 1
        index += 4 + 1 + length + 2
        return index, payload[name_list_start_index: name_list_start_index + length].decode('utf-8')

    def name_list(self, names: str) -> bytes:
        name_list = f"({names}),"
        name_list_size_bytes = len(names.encode('utf-8')).to_bytes(4, 'little', signed=False)
        return name_list_size_bytes + name_list.encode()


msg = StartKeyExchangeMessage(
    kex_algorithms='diffie-hellman-group1-sha1',
    server_host_key_algorithms='ssh-ecdsa',
    encryption_algorithms_client_to_server='aes128-cbc',
    encryption_algorithms_server_to_client='aes128-cbc',
    mac_algorithms_client_to_server='sha1-96',
    mac_algorithms_server_to_client='sha1-96',
    first_kex_packet_follows=False,
)

byte_msg = bytes(msg)



