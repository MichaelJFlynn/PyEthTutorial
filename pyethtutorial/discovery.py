import socket
import threading
import time
import struct
import rlp
from crypto import keccak256
from secp256k1 import PrivateKey
from ipaddress import ip_address

class EndPoint(object):
    def __init__(self, address, udpPort, tcpPort):
        self.address = ip_address(address)
        self.udpPort = udpPort
        self.tcpPort = tcpPort

    def pack(self):
        return [self.address.packed,
                struct.pack(">i", self.udpPort), 
                struct.pack(">i", self.tcpPort)]

                        
class PingNode(object):
    packet_type = '\x01';
    h256_version = '\x03';
    def __init__(self, endpoint_from, endpoint_to):
        self.endpoint_from = endpoint_from
        self.endpoint_to = endpoint_to

    def pack(self):
        return [self.h256_version,
                self.endpoint_from.pack(),
                self.endpoint_to.pack(),
                struct.pack(">i", time.time() + 60)]    

                                        
class PingServer(object):
    def __init__(self, my_endpoint):
        self.UDP_PORT = 30303
        self.UDP_IP = "127.0.0.1"
        self.endpoint = my_endpoint


        ## get private key
        priv_key_file = open('priv_key', 'r')
        priv_key_serialized = priv_key_file.read()
        priv_key_file.close()
        self.priv_key = PrivateKey(priv_key_serialized, raw = False)

    def wrap_packet(self, packet):        
        payload = packet.packet_type + rlp.encode(packet.pack())
        sig = self.priv_key.ecdsa_sign_recoverable(keccak256(payload), raw = True)
        sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
        payload = sig_serialized[0] + chr(sig_serialized[1]) + payload

        payload_hash = keccak256(payload)
        return payload_hash + payload

    def udp_listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.endpoint.udpPort))

        def receive_pong():
            print "listening..."
            data, addr = sock.recvfrom(1024)
            print "received message[", addr, "]: ", data

        return threading.Thread(target = receive_pong)

    def ping(self, endpoint):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ping = PingNode(self.endpoint, endpoint)
        message = self.wrap_packet(ping)
        print "sending ping: ", message
        sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))
