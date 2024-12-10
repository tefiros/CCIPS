import socket


s = socket.socket()
s.bind(('192.168.200.153', 0))
s.connect(('192.168.100.1', 8888))