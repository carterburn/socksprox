import socket
import logging

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 8888))
s.listen(1)
logging.info('Waiting for a client...')
client, addr = s.accept()

data = client.recv(4096)
client.sendall(data)
client.close()
s.close()
