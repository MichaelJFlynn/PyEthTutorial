from discovery import EndPoint, PingNode, Server, FindNeighbors, Node
import binascii
import time

# my_endpoint = EndPoint(u'52.4.20.183', 30302, 30302)
# their_endpoint = EndPoint(u'0.0.0.0', 30303, 30303)

# my_endpoint = EndPoint(u'52.4.20.183', 30303, 30303)
# their_endpoint = EndPoint(u'24.62.221.188', 30303, 30303)

bootnode_key = "3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99"
bootnode_endpoint = EndPoint(u'13.93.211.84',
                    30303,
                    30303)
bootnode = Node(bootnode_endpoint,
                    binascii.a2b_hex(bootnode_key))

my_endpoint = EndPoint(u'52.4.20.183', 30303, 30303)
server = Server(my_endpoint)

fn = FindNeighbors(bootnode.node, time.time() + 60)
ping = PingNode(my_endpoint, bootnode.endpoint, time.time() + 60)

listen_thread = server.listen_thread()
listen_thread.start()

server.send(ping, bootnode.endpoint)
time.sleep(5)
server.send(fn, bootnode.endpoint)
time.sleep(3)
