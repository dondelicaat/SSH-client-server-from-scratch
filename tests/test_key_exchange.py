from ssh.key_exchange import StartKeyExchange, StartKeyExchangeDH, KeyExchangeDHReply, \
    DiffieHellmanKeyExchange


def test_start_kex_msg():
    msg = StartKeyExchange(
        kex_algorithms='diffie-hellman-group1-sha1',
        server_host_key_algorithms='ssh-ecdsa',
        encryption_algorithms_client_to_server='aes128-cbc',
        encryption_algorithms_server_to_client='aes128-cbc',
        mac_algorithms_client_to_server='sha1-96',
        mac_algorithms_server_to_client='sha1-96',
        first_kex_packet_follows=False,
    )

    msg_from_bytes = StartKeyExchange.from_bytes(bytes(msg))

    assert msg == msg_from_bytes


def test_start_kex_dh_msg():
    msg = StartKeyExchangeDH(1255521414)
    msg_from_bytes = StartKeyExchangeDH.from_bytes(bytes(msg))
    assert msg == msg_from_bytes


def test_kex_dh_reply_msg():
    msg = KeyExchangeDHReply(
        server_host_key_certificates="TEST",
        f=12412436346,
        signature_h="sometestsignature"
    )
    msg_from_bytes = KeyExchangeDHReply.from_bytes(bytes(msg))
    assert msg == msg_from_bytes


def test_kex_dh():
    client = DiffieHellmanKeyExchange()
    client_partial = client.generate_partial_shared_key()
    server = DiffieHellmanKeyExchange()
    server_partial = server.generate_partial_shared_key()

    assert client.calculate_shared_key(server_partial) == server.calculate_shared_key(client_partial)