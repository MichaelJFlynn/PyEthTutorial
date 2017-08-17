from discovery import EndPoint, PingNode, Server, FindNeighbors, Node
import time
import binascii

bootnode_key = "3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99"

bootnode_endpoint = EndPoint(u'13.93.211.84', 30303, 30303)

bootnode = Node(bootnode_endpoint, 
                binascii.a2b_hex(bootnode_key))

my_endpoint = EndPoint(u'52.4.20.183', 30303, 30303)
server = Server(my_endpoint)

listen_thread = server.listen_thread()
listen_thread.start()

fn = FindNeighbors(bootnode.node, time.time() + 60)
ping = PingNode(my_endpoint, bootnode.endpoint, time.time() + 60)

## introduce self
server.send(ping, bootnode.endpoint)
## wait for pong-ping-pong
time.sleep(3)
## ask for neighbors
server.send(fn, bootnode.endpoint)
## wait for response
time.sleep(3)



