import hashlib
import random
import secrets
from dataclasses import dataclass
from enum import Enum


class MessageCodes(Enum):
    SSH_MSG_KEXINIT = 20
    SSH_MSG_KEXDH_INIT = 200
    SSH_MSG_KEXDH_REPLY = 201


@dataclass
class Message:
    @staticmethod
    def to_two_complement_bytestring(value: int) -> bytes:
        two_complement = '0' + format(value, 'b')
        return KeyExchangeDHReply.to_bytestring(two_complement)

    @staticmethod
    def from_two_complement_bytestring(index: int, payload: bytes) -> (int, int):
        index, binary_value_string = KeyExchangeDHReply.from_bytestring(index, payload)
        return index, int(binary_value_string, 2)

    @staticmethod
    def to_bytestring(value: str) -> bytes:
        name_list_size_bytes = len(value.encode('utf-8')).to_bytes(4, 'little', signed=False)
        return name_list_size_bytes + value.encode()

    @staticmethod
    def from_bytestring(index: int, payload: bytes) -> (int, str):
        length = int.from_bytes(payload[index:index + 4], 'little', signed=False)
        return index + 4 + length, payload[index + 4:index + 4 + length].decode()

    @staticmethod
    def from_name_list(index, payload) -> (int, str):
        """ format of nameslist: `("<comma separated list of names>"),`
            but simplify to `(<name>),`
        """
        length = int.from_bytes(payload[index:index + 4], 'little', signed=False)
        name_list_start_index = index + 4 + 1
        index += 4 + 1 + length + 2
        return index, payload[name_list_start_index: name_list_start_index + length].decode('utf-8')

    @staticmethod
    def to_name_list(names: str) -> bytes:
        name_list = f"({names}),"
        name_list_size_bytes = len(names.encode('utf-8')).to_bytes(4, 'little', signed=False)
        return name_list_size_bytes + name_list.encode()


@dataclass
class StartKeyExchange(Message):
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
        msg_code = MessageCodes.SSH_MSG_KEXINIT.value
        # name lists according to https://datatracker.ietf.org/doc/html/rfc4251
        # Set list of key exchange algo's
        cookie = secrets.token_bytes(16)
        kex_algorithms = self.to_name_list(self.kex_algorithms)
        server_host_key_algorithms = self.to_name_list(self.server_host_key_algorithms)
        encryption_algorithms_client_to_server = self.to_name_list(self.encryption_algorithms_client_to_server)
        encryption_algorithms_server_to_client = self.to_name_list(self.encryption_algorithms_server_to_client)
        mac_algorithms_client_to_server = self.to_name_list(self.mac_algorithms_client_to_server)
        mac_algorithms_server_to_client = self.to_name_list(self.mac_algorithms_server_to_client)
        # If first_kex_packet_follows is False since not guessing initial kex so no msg following
        first_kex_packet_follows = bytes(int(self.first_kex_packet_follows))

        msg = msg_code.to_bytes(1, 'little', signed=False)
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
        index, kex_algorithms = cls.from_name_list(index, payload)
        index, server_host_key_algorithms = cls.from_name_list(index, payload)
        index, encryption_algorithms_client_to_server = cls.from_name_list(index, payload)
        index, encryption_algorithms_server_to_client = cls.from_name_list(index, payload)
        index, mac_algorithms_client_to_server = cls.from_name_list(index, payload)
        index, mac_algorithms_server_to_client = cls.from_name_list(index, payload)
        first_kex_packet_follows = bool(int.from_bytes(payload[index: index + 1], 'little', signed=False))
        return cls(
            kex_algorithms=kex_algorithms, server_host_key_algorithms=server_host_key_algorithms,
            encryption_algorithms_server_to_client=encryption_algorithms_server_to_client,
            encryption_algorithms_client_to_server=encryption_algorithms_client_to_server,
            mac_algorithms_server_to_client=mac_algorithms_server_to_client,
            mac_algorithms_client_to_server=mac_algorithms_client_to_server,
            first_kex_packet_follows=first_kex_packet_follows
        )


@dataclass
class StartKeyExchangeDH(Message):
    """ Used to start DH kex """
    e: int

    def __bytes__(self):
        msg_code = MessageCodes.SSH_MSG_KEXDH_INIT.value
        msg = msg_code.to_bytes(1, 'little', signed=False)
        two_complement_e = '0' + format(self.e, 'b')
        msg += two_complement_e.encode('utf-8')
        return msg

    @classmethod
    def from_bytes(cls, payload: bytes):
        binary_value = payload[2:].decode()
        e = int(binary_value, 2)
        return cls(e=e)

@dataclass
class KeyExchangeDHReply(Message):
    """ Used to start DH kex """
    server_host_key_certificates: str
    f: int
    signature_h: str

    def __bytes__(self):
        msg_code = MessageCodes.SSH_MSG_KEXDH_REPLY.value
        msg = msg_code.to_bytes(1, 'little', signed=False)
        msg += self.to_bytestring(self.server_host_key_certificates)
        msg += self.to_two_complement_bytestring(self.f)
        msg += self.to_bytestring(self.signature_h)
        return msg

    @classmethod
    def from_bytes(cls, payload: bytes):
        index = 1
        index, server_host_key_certificates = cls.from_bytestring(index, payload)
        index, f = cls.from_two_complement_bytestring(index, payload)
        index, signature_h = cls.from_bytestring(index, payload)
        return cls(
            server_host_key_certificates=server_host_key_certificates, f=f,
            signature_h=signature_h
        )


class DiffieHellmanKeyExchange:
    # Todo: Replace with proper Oakley gp 2 params.
    p = 23
    g = 5
    q = 100000

    def __init__(self):
        self.x = random.randint(1, self.q)

    def generate_partial_shared_key(self):
        return (self.g ** self.x) % self.p

    def calculate_shared_key(self, received_partial_shared_key):
        return (received_partial_shared_key ** self.x) % self.p

    def calculate_hash(self, v_c: str, v_s: str, i_c: str, i_s: str, k_s: str, e: str, f: str, k: str) -> str:
        # Todo: Replace with proper sha-1 hash
        to_hash = v_c + v_s + i_c + i_s + k_s + e + f + k
        return hashlib.sha1(to_hash).hexdigest()

