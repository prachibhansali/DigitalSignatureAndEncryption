from optparse import OptionParser
import sys
import socket

def main():
	parser = OptionParser()
	parser.add_option("-p", "--sp", dest = "port", help = "port where server is running")

	(options, _) = parser.parse_args()
	
	if(len(args) != 1) :
		print 'python ChatServer.py --sp <port>'

	server_port = options.port

	# Create a UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_address = ('localhost', int(server_port))
	
	print 'starting up on address', server_address
	sock.bind(server_address)

	while True:
		data, address = sock.recvfrom(4096)
		if data=='GREETING':
			print >>sys.stderr, 'received from client %s' % str(address)

if __name__ == "__main__":
	main()