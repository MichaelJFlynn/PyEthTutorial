from discovery import EndPoint, PingNode, PingServer

my_endpoint = EndPoint(u'52.4.20.183', 30303, 30303)
their_endpoint = EndPoint(u'52.16.188.185', 30303, 30303)

server = PingServer(my_endpoint)

listen_thread = server.udp_listen()
listen_thread.start()

server.ping(their_endpoint)
