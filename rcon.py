#!/usr/bin/env python


import socket
import argparse
import struct
import sys
import readline
import rlcompleter

RCON_DEFAULT_IP="localhost"
RCON_DEFAULT_PORT="28016"
RCON_DEFAULT_PASSWORD="CHANGE_ME"
HISTORY_FILENAME=".history"
LOGFILE=sys.stdout
LOGFILE=None

### Stolen constants
ID_CHAT             = 65535
ID_PLAYERS          = 65534
###########

#Threading:
#import time,readline,thread,sys
#
#def noisy_thread():
#    while True:
#        time.sleep(3)
#        sys.stdout.write('\r'+' '*(len(readline.get_line_buffer())+2)+'\r')
#        print 'Interrupting text!'
#        sys.stdout.write('> ' + readline.get_line_buffer())
#        sys.stdout.flush()
#
#thread.start_new_thread(noisy_thread, ())
#while True:
#    s = raw_input('> ')

class RCON:
	MAX_PACKET_SIZE=4096*1024
	MAX_INT=0xffffffff
	TYPE_RESPONSE=0
	TYPE_COMMAND=2
	TYPE_PASSWORD=3
	ID_PASSWORD=1
	ID_RCON_COMMAND=0xa7
	def __init__(self, ip, port, password, logfile=None):
		self.ip = ip
		self.address = (ip, port)
		self.password = password
		if logfile is not None:
			self.logfile=open(logfile, "a")
		else:
			self.logfile=sys.stdout
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
		while len(self.buf) < msg_len:
			self.buf = self.buf + self.socket.recv(self.MAX_PACKET_SIZE)
		# Pop the message from the buffer
		ret_buf, self.buf = self.buf[:msg_len - 2], self.buf[msg_len:]
		return ret_buf

	def recv_data(self):
		data = self.recv()
		(id, type), msg = struct.unpack('II', data[:8]), data[8:]
		if msg == '':
			msg = None
		# Is the data a log message
		if (id, type) == (0, 4):
			self.logfile.write(msg+"\n")
			return self.recv_data()
		elif (id, type) == (self.MAX_INT, 0):
			return self.recv_data() 
		else:
			return id, type, msg

	def send_data(self, id, type, payload=None):
		if payload is None:
			payload = ''
		pkt = struct.pack('II', id, type) + payload + "\0\0"
		pkt = struct.pack('I', len(pkt)) + pkt
		self.send(pkt)

	def send_auth(self):
		self.send_data(self.ID_PASSWORD, self.TYPE_PASSWORD, self.password)
		# expect (1, 0). This seems to be an ACK
		id, type, _ = self.recv_data()
		# Authentication response now comes through
		id, type, _ = self.recv_data()
		if id == self.MAX_INT:
			print "Authentication failed (%d)"%(type)
			return -1
		elif id == self.ID_PASSWORD:
			return 0
		else:
			print "Authentication failed: Unknown response (%x %x)"%(id, type)
			return -1

	def send_command(self, msg):
		# Send the command
		self.send_data(self.ID_RCON_COMMAND, self.TYPE_COMMAND, msg);
		# Receive connection status
		id, type, msg = self.recv_data()
		if (id, type) != (self.ID_RCON_COMMAND, self.TYPE_RESPONSE):
			print "(%d %d)"%(id, type)
		print msg

	def give(self, username="DarkSchine", item="apple", qty="1"):
		self.send_data(0x4c40, self.TYPE_COMMAND, "inventory.giveto \"%s\" \"%s\" \"%s\""%(username, item, qty))

class MyCompleter(object):
	def __init__(self, options):
		self.options = sorted(options)
	def complete(self, text, state):
		if state == 0:  # on first trigger, build possible matches
			if text:  # cache matches (entries that start with entered text)
				self.matches = [s for s in self.options if s and s.startswith(text)]
			else:  # no text entered, all matches possible
				self.matches = self.options[:]
		# return match indexed by state
		try: 
			return self.matches[state]
		except IndexError:
			return None

def parse_args():
	parser = argparse.ArgumentParser(description="RCON client software")
	parser.add_argument('-i', '--ip'      , dest='ip'      , default=RCON_DEFAULT_IP,       help="The IP address of the server to connect to."    )
	parser.add_argument('-p', '--port'    , dest='port'    , default=RCON_DEFAULT_PORT,     help="The port on which the RCON server is listening.")
	parser.add_argument('-w', '--password', dest='password', default=RCON_DEFAULT_PASSWORD, help="The password that the RCON server expects."     )
	parser.add_argument('-l', '--logfile' , dest='logfile' , default=None,                  help="Specify a file for logging RCON output"         )
	options = parser.parse_args()
	return options


class Console:
	def __init__(self, history_filename):
		completer = MyCompleter(["status", "stats", "users", "players", "say", "inventory.giveto"])
		readline.set_completer(completer.complete)
		readline.parse_and_bind('tab: complete')
		open(history_filename, 'a').close()
		readline.read_history_file(history_filename)
	def input(self,prompt):
		return raw_input(prompt)
	def close(self):
		readline.write_history_file(HISTORY_FILENAME)

if __name__ == '__main__':
	options = parse_args()
	rcon = RCON(options.ip, int(options.port), options.password, options.logfile);
	rcon.connect()
	if rcon.send_auth():
		print "Authentication failed"
	else:
		print "Authentication successful"
		print
		rcon.send_command("status")
		rcon.send_command("users")
		con = Console(HISTORY_FILENAME);
		while True:
			try: 
				input = con.input("$ ")
				if input == "test3":
					rcon.give()
				else:
					rcon.send_command(input)
			except KeyboardInterrupt:
				break;
			except EOFError:
				break;
		con.close();
		print
	rcon.disconnect()

	print "Disconnected from RCON"





