from discovery import EndPoint, PingNode, PingServer
# from crypto import keccak256
# from secp256k1 import PrivateKey, PublicKey
# import rlp
# import binascii

my_endpoint = EndPoint(u'52.4.20.183', 30303, 30303)
their_endpoint = EndPoint(u'127.0.0.1', 30303, 30303)

# ping = PingNode(my_endpoint, their_endpoint)

server = PingServer(my_endpoint)

# msg = server.wrap_packet(ping)
# mdc = msg[:32]
# if mdc != keccak256(msg[32:]):
#     print "bad mdc"

# signature = msg[32:97]
# assert len(signature) == 65
# signed_data = msg[97:]
# deserialized_sig = server.priv_key.ecdsa_recoverable_deserialize(signature[:64],
#                                                                  ord(signature[64]))

# pub = PublicKey()
# remote_pubkey = server.priv_key.ecdsa_recover(keccak256(signed_data),
#                                               deserialized_sig,
#                                               raw = True
#                                           )
# pub.public_key = remote_pubkey

# verified = pub.ecdsa_verify(keccak256(signed_data),
#                             pub.ecdsa_recoverable_convert(deserialized_sig),
#                             raw = True)

# if not verified:
#     print "Bad verification"

# cmd_id = msg[97] 
# print binascii.b2a_hex(cmd_id)
# payload = msg[98:]
# print rlp.decode(payload)
listen_thread = server.udp_listen()
listen_thread.start()

server.ping(their_endpoint)


