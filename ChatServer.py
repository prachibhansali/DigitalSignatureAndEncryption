from optparse import OptionParser
import sys
import socket

connected_clients = []

def main():
	parser = OptionParser()
	parser.add_option("-p", "--sp", dest = "port", help = "port where server is running")

	(options, _) = parser.parse_args()
	
	if options.port is None :
		print 'usage: python ChatServer.py --sp <port>'
		return

	server_port = options.port

	# Create a UDP server socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_address = ('localhost', int(server_port))
	sock.bind(server_address)
	print 'Server Initialized...'

	while True:
		data, address = sock.recvfrom(4096)
		if data=='GREETING':
			print 'Client Connected : %s' % str(address) 
			connected_clients.append(address)
			data, address = sock.recvfrom(4096)
		format_message = '<From ' + str(address) + '>: ' + data
		for client in connected_clients:
			sock.sendto(format_message, client)

if __name__ == "__main__":
	main()