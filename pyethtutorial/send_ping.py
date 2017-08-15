from discovery import EndPoint, PingNode, PingServer, FindNeighbors, bootnode
import time

my_endpoint = EndPoint(u'52.4.20.183', 30303, 30303)
their_endpoint = EndPoint(u'13.93.211.84', 30303, 30303)

server = PingServer(my_endpoint)

fb = FindNeighbors(bootnode.key, time.time() + 60)
ping = PingNode(my_endpoint, their_endpoint, time.time() + 60)

listen_thread = server.udp_listen()
listen_thread.start()

server.send(fb, bootnode.to_endpoint())

