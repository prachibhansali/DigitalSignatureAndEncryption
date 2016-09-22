import sys
import socket
from optparse import OptionParser

def main():
	parser = OptionParser()
	parser.add_option("-i", "--sip", dest = "server_ip", help = "ip address of the server")
	parser.add_option("-p", "--sp", dest = "server_port", help = "port where server is running")

	(options, _) = parser.parse_args()
	server_address = (options.server_ip, int(options.server_port))

	# Create a UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	try:
		send_message = sock.sendto('GREETING', server_address)
		print "sent message" + str(send_message)
	finally:
		print >>sys.stderr, 'closing socket'
    	sock.close()

if __name__ == "__main__":
	main()