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

AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 16
AES_IV_SIZE = 16
SALT = 16

def pad(message):
	if len(message) % AES_BLOCK_SIZE == 0:
		return message
	padding_needed = AES_BLOCK_SIZE - (len(message)%AES_BLOCK_SIZE)
	#PKCS#7
	message = message+chr(padding_needed)*padding_needed
	return message

def unpad(message):
	val = int(binascii.hexlify(message[-1]), 16)
	orig_length = len(message) - val
	return message[:orig_length]

def sign(private_key, digest):
	signer = private_key.signer(
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA384()),
			salt_length=padding.PSS.MAX_LENGTH
			),
		hashes.SHA384()
		)
	signer.update(digest)
	signature = signer.finalize()
	return signature

def verify(public_key, signature, message):
	verifier = public_key.verifier(
		signature,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA384()),
			salt_length=padding.PSS.MAX_LENGTH
			),
		hashes.SHA384()
		)
	verifier.update(message)
	try:
		verifier.verify()
		return True
	except InvalidSignature, e:
		print 'Invalid signature due to exception %s' % e 
		return False


def rsa_encrypt(public_key, aes_key):
	aes_key_encrypted = public_key.encrypt(
		aes_key,
		padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA384()),
		algorithm=hashes.SHA384(),
		label=None)
		)
	return aes_key_encrypted

def rsa_decrypt(private_key, aes_key_encrypted):
	aes_key = private_key.decrypt(
		aes_key_encrypted,
		padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA384()),
		algorithm=hashes.SHA384(),
		label=None)
		)
	return aes_key

def generate_hmac(key, message):
	h = hmac.HMAC(key, hashes.SHA384(), backend=default_backend())
	h.update(message)
	return h.finalize()

def encrypt_and_sign(destination_public_key, sender_private_key, input_plaintext, ciphertext_file):
	key = os.urandom(AES_KEY_SIZE)
	iv = os.urandom(AES_IV_SIZE)

	digest = generate_hmac(key, input_plaintext)
	signed_digest = sign(sender_private_key, digest)

	plaintext = pad(input_plaintext)
	
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(plaintext) + encryptor.finalize()

	encrypted_key = rsa_encrypt(destination_public_key, key)
	output = signed_digest + encrypted_key + iv + ciphertext
	out = open(ciphertext_file, 'wb+')
	out.write(output)
	return output


def decrypt_and_verify(destination_private_key, sender_public_key, ciphertext, output_plaintext):
	key_length = (sender_public_key.key_size)/8
	signed_digest = ciphertext[:key_length]
	remainder = ciphertext[key_length:]
	encrypted_key = remainder[:key_length]
	remainder = remainder[key_length:]
	iv = remainder[:AES_IV_SIZE]
	cipher_text = remainder[AES_IV_SIZE:]

	aes_key = rsa_decrypt(destination_private_key, encrypted_key)
	cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()

	decrypted_text = unpad(decrypted_text)
	digest = generate_hmac(aes_key, decrypted_text)

	if verify(sender_public_key, signed_digest, digest):
		out = open(output_plaintext, 'w+')
		out.write(decrypted_text)

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
				destination_public_key = read_public_key(args[0])
				sender_private_key = read_private_key(args[1])
				input_plaintext = read_file_contents(args[2])
				ciphertext_file = args[3]
				encrypt_and_sign(destination_public_key, sender_private_key, input_plaintext, ciphertext_file)
			elif opt == '-d':
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