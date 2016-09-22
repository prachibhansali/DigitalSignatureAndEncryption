import sys
import socket
from threading import Thread
from optparse import OptionParser

def main():
	parser = OptionParser()
	parser.add_option("-i", "--sip", dest = "server_ip", help = "ip address of the server")
	parser.add_option("-p", "--sp", dest = "server_port", help = "port where server is running")

	(options, _) = parser.parse_args()
	if options.server_port is None or options.server_ip is None:
		print 'usage: python ChatClient.py --sip <server ip> --sp <server port>'
		return

	server_address = (options.server_ip, int(options.server_port))

	# Create a UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# Send Greeting message to server
	send_message = sock.sendto('GREETING', server_address)

	# Send and receive messages simultaneously to and from server
	Thread(target=send_msg, args=(sock,server_address)).start()
	Thread(target=rec_msg, args=(sock,)).start()

def send_msg(sock, server_address):
	try:
		while True:
			client_message = raw_input();
			print 'sending ' + client_message
			send_message = sock.sendto(client_message, server_address)
	except socket.error, exc:
		print "Caught exception while sending client message: %s" % exc

def rec_msg(sock):
	try:
		while True:
			incoming_message,_ = sock.recvfrom(4096)
			print incoming_message
	except socket.error, exc:
		print "Caught exception while receiving message from server: %s" % exc

if __name__ == "__main__":
	main()