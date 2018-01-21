import socket
import threading
import time
import struct
import rlp
import binascii
import select
import random
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
        if packed[2] == '': 
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

                       
class PingNode(object):
    packet_type = '\x01'
    version = '\x03'
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

    ## amount of time to sleep before refreshing
    discovery_rest_time = 5

    ## time to wait for peer response
    timeout_time = 3

    ## min peers
    min_peers = 25

    def __init__(self, my_endpoint, bootnode):
        self.endpoint = my_endpoint
        self.bootnode = bootnode

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

        ## discovery protocol variables
        self.expecting_pong = {}
        self.expecting_neighbors = {}
        self.peers = []

    def wrap_packet(self, packet):        
        payload = packet.packet_type + rlp.encode(packet.pack())
        sig = self.priv_key.ecdsa_sign_recoverable(keccak256(payload), raw = True)
        sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
        payload = sig_serialized[0] + chr(sig_serialized[1]) + payload

        payload_hash = keccak256(payload)
        return payload_hash + payload

    def receive_pong(self, payload, msg_hash, node):
        print " received Pong"
        print "", Pong.unpack(rlp.decode(payload))

        if self.expecting_pong.pop(node.node, None):
            if not node.node in map(lambda x: x.node, self.peers):
                self.peers.append(node) 

    def receive_ping(self, payload, msg_hash, node):
        print " received Ping"
        ping = PingNode.unpack(rlp.decode(payload))        
        pong = Pong(node.endpoint, msg_hash, time.time() + 60)
        print "  sending Pong response: " + str(pong)
        self.send(pong, pong.to)
        self.add_peer(node)
            
        
    def receive_find_neighbors(self, payload, msg_hash, node):
        print " received FindNeighbors"
        print "", FindNeighbors.unpack(rlp.decode(payload))

    def receive_neighbors(self, payload, msg_hash, node):
        print " received Neighbors"
        neighbors = Neighbors.unpack(rlp.decode(payload))
        print "", neighbors

        if node.node in self.expecting_neighbors:
            for neighbor in neighbors.nodes:
                self.add_peer(neighbor)

    def listen(self):
        print "listening..."
        while True:
            ready = select.select([self.sock], [], [], 1.0) 
            if ready[0]:
                data, addr = self.sock.recvfrom(2048)
                print "received message[", addr, "]:"        
                self.receive(data, addr[0], addr[1])

    def receive(self, data, ip, port):
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
        
        from_endpoint = EndPoint(ip.decode('utf-8'), port, port)
        from_node = Node(from_endpoint, pub.serialize(compressed = False)[1:])

        payload = data[98:]
        dispatch(payload, msg_hash, from_node)

    def listen_thread(self):
        thread = threading.Thread(target = self.listen)
        thread.daemon = True
        return thread

    def discover_thread(self):
        thread = threading.Thread(target = self.discover)
        thread.daemon = True
        return thread

    def send(self, packet, endpoint):
        message = self.wrap_packet(packet)
        print "sending " + str(packet)
        self.sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))

    def connecting_to(self, node):
        return node in self.expecting_pong

    def add_peer(self, node):
        if node.node in map(lambda x: x.node, self.peers):
            return
        
        if self.connecting_to(node):
            return
            
        if node.node == self.priv_key.pubkey.serialize(compressed = False)[1:]:
            return

        packet = PingNode(self.endpoint, node.endpoint, time.time() + 2)
        self.send(packet, node.endpoint)
        self.expecting_pong[node.node] = time.time()

    def query_neighbors(self, node):        
        my_key = self.priv_key.pubkey.serialize(compressed = False)[1:]
        if not node.node in self.expecting_neighbors:            
            packet = FindNeighbors(my_key, time.time() + 2)
            self.send(packet, node.endpoint)
            self.expecting_neighbors[node.node] = time.time()


    def discover(self):

        while True:
            ## remove timeout requests
            now = time.time()
            self.expecting_neighbors = {k:t for k,t in self.expecting_neighbors.iteritems() if (now-t) < self.timeout_time}
            self.expecting_pong = {k:t for k,t in self.expecting_pong.iteritems() if (now-t) < self.timeout_time}

            ## print the current discovery status
            print "Discovery status: %d peers / %d min peers / %d connecting" % (
                len(self.peers),
                self.min_peers,
                len(self.expecting_pong)
            )

            ## add peer if not enough peers
            if len(self.peers) < self.min_peers:
                if len(self.peers) == 0:
                    self.add_peer(self.bootnode)
                else:
                    node = random.choice(self.peers)
                    self.query_neighbors(node)
             
            time.sleep(self.discovery_rest_time)
        
