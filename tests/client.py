import socket
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

s = socket.socket()
logging.info('Connecting to SOCKS server')
s.connect(('127.0.0.1', 4444))

handshake = b'\x05\x01\x00'

logging.info('Sending initial handshake packet (no auth)')
s.send(handshake)

resp = s.recv(2)

req = bytes([0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x22, 0xB8])
logging.info('Sending SOCKS client request')
s.send(req)

resp = s.recv(10)

# send some data to be proxied, expect a response
teststr = b'Test String'
s.send(teststr)
verify = s.recv(len(teststr))
if verify == teststr:
    logging.critical('PASSED')
else:
    logging.critical('FAILED')

s.close()
