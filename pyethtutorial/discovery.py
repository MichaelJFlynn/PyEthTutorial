import socket
import threading
import time
import struct
import rlp
import binascii
import select
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
        if packed[2] == "":
            tcpPort = udpPort
        else:
            tcpPort = struct.unpack(">H", packed[2])[0]
        return cls(packed[0], udpPort, tcpPort)

class FindNeighbors(object):
    packet_type = '\x03'

    def __init__(self, target, timestamp):
        self.target = target
        self.timestamp = timestamp

    def __str__(self):
        return "(FN " + binascii.b2a_hex(self.target)[:7] + "... " + str(self.timestamp) + ")"
        
    def pack(self):
        return [
            self.target,
            struct.pack(">I", self.timestamp)
        ]
    
    @classmethod
    def unpack(cls, packed):
        timestamp = struct.unpack(">I", packed[1])[0]
        return cls(packed[0], timestamp)
                        

class Neighbors(object):
    packet_type = '\x04'
    
    def __init__(self, nodes, timestamp):
        self.nodes = nodes
        self.timestamp = timestamp

    def __str__(self):
        return "(Ns [" + ", ".join(map(str, self.nodes)) + "] " + str(self.timestamp) + ")"
        
    def pack(self):
        return [
            map(lambda x: x.pack(), self.nodes),
            struct.pack(">I", self.timestamp)
        ]

    @classmethod 
    def unpack(cls, packed):
        nodes = map(lambda x: Node.unpack(x), packed[0])
        timestamp = struct.unpack(">I", packed[1])[0]
        return cls(nodes, timestamp)

class Node(object): 
    
    def __init__(self, endpoint, node): 
        self.endpoint = endpoint
        self.node = node

    def __str__(self):
        return "(N " + binascii.b2a_hex(self.node)[:7] + "...)"
        
    def pack(self):
        packed = self.endpoint.pack()
        packed.append(node)
        return packed

    @classmethod 
    def unpack(cls, packed):
        endpoint = EndPoint.unpack(packed[0:3])
        return cls(endpoint, packed[3])


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
        ## assert(packed[0] == cls.version)
        endpoint_from = EndPoint.unpack(packed[1])
        endpoint_to = EndPoint.unpack(packed[2])
        timestamp = struct.unpack(">I", packed[3])[0]
        return cls(endpoint_from, endpoint_to, timestamp)


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
            struct.pack(">I", self.timestamp)]

    @classmethod
    def unpack(cls, packed):
        to = EndPoint.unpack(packed[0])
        echo = packed[1]
        timestamp = struct.unpack(">I", packed[2])[0]
        return cls(to, echo, timestamp)
    
                                        
class Server(object):
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

        ## set socket non-blocking mode
        self.sock.setblocking(0)

    def wrap_packet(self, packet):        
        payload = packet.packet_type + rlp.encode(packet.pack())
        sig = self.priv_key.ecdsa_sign_recoverable(keccak256(payload), raw = True)
        sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
        payload = sig_serialized[0] + chr(sig_serialized[1]) + payload

        payload_hash = keccak256(payload)
        return payload_hash + payload

    def receive_pong(self, payload, msg_hash):
        print " received Pong"
        print "", Pong.unpack(rlp.decode(payload))

    def receive_ping(self, payload, msg_hash):
        print " received Ping"
        ping = PingNode.unpack(rlp.decode(payload))
        pong = Pong(ping.endpoint_from, msg_hash, time.time() + 60)
        print " sending Pong Response: " + str(pong) 
        self.send(pong, pong.to)


    def receive_find_neighbors(self, payload, msg_hash):
        print " received FindNeighbors"
        print "", FindNeighbors.unpack(rlp.decode(payload))

    def receive_neighbors(self, payload, msg_hash):
        print " received Neighbors"
        print "", Neighbors.unpack(rlp.decode(payload))

    def receive(self, data):
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
            Pong.packet_type : self.receive_pong,
            FindNeighbors.packet_type : self.receive_find_neighbors,
            Neighbors.packet_type : self.receive_neighbors
        }

        try:
            dispatch = response_types[data[97]]
        except KeyError: 
            print " Unknown message type: " + data[97]
            return

        payload = data[98:]
        dispatch(payload, msg_hash)


    def listen(self): 
        print "listening..."
        while True:
            ready = select.select([self.sock], [], [], 1.0)
            if ready[0]:
                data, addr = self.sock.recvfrom(2048)
                print "received message[", addr, "]:"
                self.receive(data)

    def listen_thread(self):
        thread = threading.Thread(target = self.listen)
        thread.daemon = True
        return thread

    def send(self, packet, endpoint):
        message = self.wrap_packet(packet)
        print "sending " + str(packet)
        self.sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))
