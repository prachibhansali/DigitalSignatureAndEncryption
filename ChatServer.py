from optparse import OptionParser
import sys
import socket

active_clients = [] # stores addresses of connected clients

def main():
	# Read options and arguments from command line
	parser = OptionParser()
	parser.add_option("-p", "--sp", dest = "port", help = "port where server is running")

	(options, _) = parser.parse_args()
	
	if options.port is None :
		print 'usage: python ChatServer.py --sp <port>'
		return

	try:
		# Create a UDP server socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		server_address = ('localhost', int(options.port))

		# Bind socket to server address
		sock.bind(server_address)
		print 'Server Initialized...'
	except socket.error, exc:
		print "Caught exception while creating server socket: %s" % exc

	while True:
		data, address = sock.recvfrom(1024);
		if data=='GREETING':
			if address not in active_clients:
				active_clients.append(address)
		else:
			format_message = '<From ' + str(address[0]) + ':' + str(address[1]) + '>: ' + data
			# Broadcast message to all active clients
			for client_address in active_clients:
				sock.sendto(format_message, client_address)

if __name__ == "__main__":
	main()