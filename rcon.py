#!/usr/bin/env python


import socket
import argparse
import struct
import sys

RCON_DEFAULT_IP="52.62.86.177"
#RCON_DEFAULT_PORT="28015"
RCON_DEFAULT_PORT="28016"
RCON_DEFAULT_PASSWORD="subseven"

### Stolen constants
ID_MAX              = 255
ID_CHAT             = 65535
ID_PLAYERS          = 65534
ID_PASSWORD         = 1
RESPONSE            = 0
COMMAND             = 2
PASSWORD            = 3
###########


class RCON:
	MAX_PACKET_SIZE=4096*1024
	MAX_INT=0xffffffff
	def __init__(self, ip, port, password, logfile=sys.stdout):
		self.ip = ip
		self.address = (ip, port)
		self.password = password
		self.logfile=logfile
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.buf = ''

	def connect(self):
		print "Connecting to %s %d"%(self.address[0], self.address[1])
		return self.socket.connect(self.address)

	def disconnect(self):
		return self.socket.close()

	def send(self, message):
		self.socket.send(message)

	def recv(self):
		if self.buf is '':
			self.buf = self.socket.recv(self.MAX_PACKET_SIZE)
		# Pop the message length from the buffer
		msg_len = struct.unpack('I', self.buf[:4])[0]
		self.buf = self.buf[4:]
		# Pop the message from the buffer
		ret_buf, self.buf = self.buf[:msg_len - 2], self.buf[msg_len:]
		return ret_buf

	def recv_data(self):
		data = self.recv()
		(a, b), msg = struct.unpack('II', data[:8]), data[8:]
		if msg == '':
			msg = None
		# Is the data a log message
		if (a, b) == (0, 4):
			if self.logfile is not None:
				self.logfile.write("%d %d"%(a, b))
				self.logfile.write(msg)
			return self.recv_data()
		elif (a, b) == (self.MAX_INT, 0):
			return self.recv_data() 
		else:
			return a, b, msg

	def send_data(self, type, payload='', id=404):
		if payload is None:
			payload = ''
		pkt = struct.pack('II', id, type) + payload + "\0\0"
		pkt = struct.pack('I', len(pkt)) + pkt
		self.send(pkt)

	def get_chat(self):
		self.send_data(COMMAND, 'getchat', ID_CHAT)

	def get_player_list(self):
		self.send_data(COMMAND, 'listplayers', ID_PLAYERS)

	def send_auth(self):
		self.send_data(PASSWORD, self.password, ID_PASSWORD)
		print "Send auth. Waiting for response"
		# expect (1, 0). This seems to be an ACK
		a, resp, _ = self.recv_data()
		# Authentication response now comes through
		a, resp, _ = self.recv_data()
		if a == self.MAX_INT:
			print "Authentication failed (%d)"%(resp)
			return -1
		elif a == 1:
			print "Authentication successful"
			return 0
		else:
			print "Authentication failed: Unknown response (%x %x)"%(a, resp)
			return -1

	def send_command(self, msg):
		# Send the command
		self.send_data(0x02, msg, 0xa7);
		# Receive connection status
		a, b, msg = self.recv_data()
		if (a, b) != (167, 0):
			print "(%d %d)"%(a, b)
		print msg

	def get_config(self):
		# Send the command
		self.send_data(0x05, None, 0x3e35)
		# Receive connection status
		a, b, msg = self.recv_data()
		print "a=%d b=%d"%(a, b)
		print msg
		a, b, msg = self.recv_data()
		print "a=%d b=%d"%(a, b)
		print msg
		a, b, msg = self.recv_data()
		print "a=%d b=%d"%(a, b)
		print msg




def parse_args():
	parser = argparse.ArgumentParser(description="RCON client software")
	parser.add_argument('-i', '--ip'      , dest='ip'      , default=RCON_DEFAULT_IP,       help="The IP address of the server to connect to."    )
	parser.add_argument('-p', '--port'    , dest='port'    , default=RCON_DEFAULT_PORT,     help="The port on which the RCON server is listening.")
	parser.add_argument('-w', '--password', dest='password', default=RCON_DEFAULT_PASSWORD, help="The password that the RCON server expects."     )
	options = parser.parse_args()
	return options

if __name__ == '__main__':
	options = parse_args()
	rcon = RCON(options.ip, int(options.port), options.password, None);
	rcon.connect()
	if rcon.send_auth():
		print "Failed to send auth"
	else:
		print "Auth successful"
	rcon.send_command("status")
	rcon.send_command("users")
	while True:
		try: 
			sys.stdout.write("$ ")
			line = sys.stdin.readline().strip()
			if line == '':
				break;
			else:
				rcon.send_command(line)
		except KeyboardInterrupt:
			break;
	print
	rcon.disconnect()
	print "Disconnected from RCON"






