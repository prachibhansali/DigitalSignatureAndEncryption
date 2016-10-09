#!/bin/usr/python
import sys, getopt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import base64
import binascii
import struct
import os

# AES block size is 16 bytes
AES_BLOCK_SIZE = 16
# Use AES-256 encryption
AES_KEY_SIZE = 32
# Size of initialization vector is 16 bytes
AES_IV_SIZE = 16

def sign(private_key, digest):
	signer = private_key.signer(
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
			),
		hashes.SHA256()
		)
	signer.update(digest)
	signature = signer.finalize()
	return signature

def verify_signature(public_key, signature, message):
	verifier = public_key.verifier(
		signature,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
			),
		hashes.SHA256()
		)
	verifier.update(message)
	verifier.verify()

def rsa_encrypt(public_key, aes_key):
	aes_key_encrypted = public_key.encrypt(
		aes_key,
		padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None)
		)
	return aes_key_encrypted

def rsa_decrypt(private_key, aes_key_encrypted):
	aes_key = private_key.decrypt(
		aes_key_encrypted,
		padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None)
		)
	return aes_key

def generate_hmac(key, message):
	h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
	h.update(message)
	return h.finalize()

def encrypt_and_sign(destination_public_key, sender_private_key, plaintext, ciphertext_file):
	print 'starting encryption'
	out = open(ciphertext_file, 'wb+')
	try:
		key = os.urandom(AES_KEY_SIZE)
		iv = os.urandom(AES_IV_SIZE)

		# Generate an HMAC of plaintext and sign it using sender's private key.
		digest = generate_hmac(key, plaintext)
		signed_digest = sign(sender_private_key, digest)

		print 'encrypting...'
		# Encrypt signed digest and plaintext using AES-CTR mode.
		cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		ciphertext = encryptor.update(signed_digest) + encryptor.update(plaintext)  + encryptor.finalize()

		# Encrypt the generated AES key using RSA
		encrypted_key = rsa_encrypt(destination_public_key, key)

		print 'writing encrypted text to file...'
		# Write ciphertext to output file
		output = encrypted_key + iv + ciphertext
		out.write(output)
		print 'successfully stored the ciphertext at location: ', ciphertext_file
	except Exception, e:
		print 'Error while encrypting the message %s' % e 
		exit()


def decrypt_and_verify(destination_private_key, sender_public_key, ciphertext, output_plaintext_file):
	print 'starting decryption'
	out = open(output_plaintext_file, 'w+')
	try:
		destination_key_length = (destination_private_key.key_size)/8

		# Ciphertext format: encrypted_key + iv + ciphertext
		encrypted_key = ciphertext[:destination_key_length]
		iv = ciphertext[destination_key_length:destination_key_length+AES_IV_SIZE]
		cipher_text = ciphertext[destination_key_length+AES_IV_SIZE:]

		# Fetch AES key by decrypting using RSA
		aes_key = rsa_decrypt(destination_private_key, encrypted_key)

		print 'decrypting...'
		# Decrypt ciphertext using AES to obtain digest and plaintext
		cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()

		sender_key_length = (sender_public_key.key_size)/8
		signed_digest = decrypted_text[:sender_key_length]
		decrypted_text = decrypted_text[sender_key_length:]

		# Generate an HMAC of decrypted text and verify it using sender's public key.
		# Throw an exception if verification fails.
		digest = generate_hmac(aes_key, decrypted_text)
		verify_signature(sender_public_key, signed_digest, digest)

		print 'writing decrypted text to file...'
		# Write decrypted text to output file.
		out.write(decrypted_text)
		print 'successfully stored decrypted text at location: ', output_plaintext_file
		
	except InvalidSignature, e:
		print 'Invalid signature %s' % e
		exit()
	except Exception, e:
		print 'Error while decrypting the message %s' % e 
		exit()

def read_private_key(filename):
	try:
		with open(filename, "rb") as key_file:
			key = serialization.load_der_private_key(
				key_file.read(), 
				password=None, 
				backend=default_backend())	    
		return key
	except Exception, e:
		print 'Error in reading key: %s' % e
		exit()
	
def read_public_key(filename):
	try:
		with open(filename, "rb") as key_file:
			key = serialization.load_der_public_key(
	      		key_file.read(),
	      		backend=default_backend())	    
			return key
	except Exception, e:
		print 'Error in reading key: %s' % e
		exit()
	
def read_file_contents(filename):
	try:
		with open(filename, 'rb') as f:
			return f.read()
	except Exception, e:
		print 'Error in reading file: %s' % e
		exit()

def main(argv):
	try:
		opts, args = getopt.getopt(argv, "ed")
		if len(opts) != 1 or len(args) != 4:
			print 'usage: fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file'
			print 'or'
			print 'usage: fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file'
			return
		for opt, _ in opts:
			if opt == '-e':
				# Perform encryption
				destination_public_key = read_public_key(args[0])
				sender_private_key = read_private_key(args[1])
				input_plaintext = read_file_contents(args[2])
				ciphertext_file = args[3]
				encrypt_and_sign(destination_public_key, sender_private_key, input_plaintext, ciphertext_file)
			elif opt == '-d':
				# Perform decryption
				destination_private_key = read_private_key(args[0])
				sender_public_key = read_public_key(args[1])
				ciphertext = read_file_contents(args[2])
				output_plaintext = args[3]
				decrypt_and_verify(destination_private_key, sender_public_key, ciphertext, output_plaintext)
			else:
			 	return
	except getopt.GetoptError, e:
		print 'Error in fetching arguments %s' % e
		return

if __name__ == "__main__":
	main(sys.argv[1:])