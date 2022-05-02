from unittest.mock import MagicMock
import pytest

from src.ssh.protocol import SshTLPProtocol
#
# @pytest.mark.parametrize("payload,expected",
#     [
#         ("", b'\x00\x00\x00\x00'),
#     ]
# )
# def test_protocol(payload, expected):
#     protocol = SshTLPProtocol()
#     payload = payload.encode()
#     mock_socket = MagicMock()
#     protocol.send_message(mock_socket, payload, sequence_number=0)
#     mock_socket.send.assert_called_with(expected)


@pytest.mark.parametrize("payload,key",
    [
        (b'supersecretwohoo', "My1234Secretkkey"),
    ]
)
def test_encryption(payload, key):
    protocol = SshTLPProtocol(16)
    encrypted_msg = protocol.encrypt(packet=payload, shared_key=key)
    plaintext_msg = protocol.decrypt(encrypted_packet=encrypted_msg, shared_key=key)
    assert plaintext_msg == payload

@pytest.mark.parametrize("payload,cipher_block_size",
    [
        (b"this is a supersecret message", 16),
    ]
)
def test_create_padded_msg(payload, cipher_block_size):
    min_packet_size = 16
    protocol = SshTLPProtocol(cipher_block_length=cipher_block_size)
    fixed_header_size = protocol.packet_length_header + protocol.padding_length_header
    padded_payload = protocol.create_padded_payload(payload)
    total_length = len(padded_payload)
    assert total_length >= min_packet_size
    assert (total_length % cipher_block_size) == 0
