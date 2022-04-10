from ssh.key_exchange import StartKeyExchangeMessage


def test_start_kex_msg():
    msg = StartKeyExchangeMessage(
        kex_algorithms='diffie-hellman-group1-sha1',
        server_host_key_algorithms='ssh-ecdsa',
        encryption_algorithms_client_to_server='aes128-cbc',
        encryption_algorithms_server_to_client='aes128-cbc',
        mac_algorithms_client_to_server='sha1-96',
        mac_algorithms_server_to_client='sha1-96',
        first_kex_packet_follows=False,
    )

    msg_from_bytes = StartKeyExchangeMessage.from_bytes(bytes(msg))

    assert msg == msg_from_bytes
