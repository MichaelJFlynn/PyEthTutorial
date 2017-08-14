import socket
import threading
import time
import struct
import rlp
import binascii
from crypto import keccak256
from secp256k1 import PrivateKey, PublicKey
from ipaddress import ip_address

class EndPoint(object):
    def __init__(self, address, udpPort, tcpPort):
        self.address = ip_address(address)
        self.udpPort = udpPort
        self.tcpPort = tcpPort

    def __str__(self): 
        return "(EP " + self.address.exploded + " " + str(self.udpPort) + " " + str(self.tcpPort)  + ")"

    def pack(self):
        return [self.address.packed,
                struct.pack(">H", self.udpPort), 
                struct.pack(">H", self.tcpPort)]
    @classmethod
    def unpack(cls, packed):
        udpPort = struct.unpack(">H", packed[1])[0]
        tcpPort = struct.unpack(">H", packed[2])[0]
        return cls(packed[0], udpPort, tcpPort)
                        
class PingNode(object):
    packet_type = '\x01';
    version = '\x03';
    def __init__(self, endpoint_from, endpoint_to, timestamp):
        self.endpoint_from = endpoint_from
        self.endpoint_to = endpoint_to
        self.timestamp = timestamp

    def __str__(self):
        return "(Ping " + str(ord(self.version)) + " " + str(self.endpoint_from) + " " + str(self.endpoint_to) + " " +  str(self.timestamp) + ")"
        

    def pack(self):
        return [self.version,
                self.endpoint_from.pack(),
                self.endpoint_to.pack(),
                struct.pack(">I", self.timestamp)]    
        
    @classmethod
    def unpack(cls, packed):
        assert(packed[0] == cls.version)
        endpoint_from = EndPoint.unpack(packed[1])
        endpoint_to = EndPoint.unpack(packed[2])
        return cls(endpoint_from, endpoint_to)


class Pong(object): 
    packet_type = '\x02'
    
    def __init__(self, to, echo, timestamp):
        self.to = to
        self.echo = echo
        self.timestamp = timestamp

    def __str__(self):
        return "(Pong " + str(self.to) + " <echo hash> " + str(self.timestamp) + ")"

    def pack(self):
        return [
            self.to.pack(),
            self.echo,
            struct.pack(">I", timestamp)]

    @classmethod
    def unpack(cls, packed):
        to = EndPoint.unpack(packed[0])
        echo = packed[1]
        timestamp = struct.unpack(">I", packed[2])[0]
        return cls(to, echo, timestamp)
    
                                        
class PingServer(object):
    def __init__(self, my_endpoint):
        self.endpoint = my_endpoint

        ## get private key
        priv_key_file = open('priv_key', 'r')
        priv_key_serialized = priv_key_file.read()
        priv_key_file.close()
        self.priv_key = PrivateKey()
        self.priv_key.deserialize(priv_key_serialized)

        ## init socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', self.endpoint.udpPort))

    def wrap_packet(self, packet):        
        payload = packet.packet_type + rlp.encode(packet.pack())
        sig = self.priv_key.ecdsa_sign_recoverable(keccak256(payload), raw = True)
        sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
        payload = sig_serialized[0] + chr(sig_serialized[1]) + payload

        payload_hash = keccak256(payload)
        return payload_hash + payload

    def receive_pong(self, payload):
        print " received Pong"
        print "", Pong.unpack(rlp.decode(payload))

    def receive_ping(self, payload):
        print " received Ping"
        print "", PingNode.unpack(rlp.decode(payload))

    def receive(self):
        print "listening..."
        data, addr = self.sock.recvfrom(1024)
        print "received message[", addr, "]:"

        ## decode response

        ## verify hash
        msg_hash = data[:32]
        if msg_hash != keccak256(data[32:]):
            print " First 32 bytes are not keccak256 hash of the rest."
            return
        else:
            print " Verified message hash."

        ## verify signature
        signature = data[32:97]
        signed_data = data[97:]
        deserialized_sig = self.priv_key.ecdsa_recoverable_deserialize(signature[:64],
                                                                       ord(signature[64]))
            

        remote_pubkey = self.priv_key.ecdsa_recover(keccak256(signed_data),
                                                      deserialized_sig,
                                                      raw = True)
        pub = PublicKey()
        pub.public_key = remote_pubkey
        
        verified = pub.ecdsa_verify(keccak256(signed_data),
                                    pub.ecdsa_recoverable_convert(deserialized_sig),
                                    raw = True)
            
        if not verified:
            print " Signature invalid"
            return
        else:
            print " Verified signature."
            
        response_types = { 
            PingNode.packet_type : self.receive_ping,
            Pong.packet_type : self.receive_pong        
        }

        try:
            dispatch = response_types[data[97]]
        except KeyError: 
            print " Unknown message type: " + data[97]
            return

        payload = data[98:]
        dispatch(payload)

    def udp_listen(self):
        return threading.Thread(target = self.receive)

    def ping(self, endpoint):
        ping = PingNode(self.endpoint, endpoint, time.time() + 60)
        message = self.wrap_packet(ping)
        print "sending " + str(ping)
        self.sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))
