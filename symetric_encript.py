import os
import getpass
import base64
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes,hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat,PrivateFormat,ParameterFormat, load_pem_public_key, load_pem_parameters

def deriveKey(password):
	backend=default_backend()
	salt = os.urandom(16)
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=backend
	)
	key = kdf.derive(password)
	return salt,key

def dh_derive(key):
	# Change "length" based on algorithm
	return HKDF(algorithm=hashes.SHA256(),
				length=32,
				salt=None,
				info=b'dh handshake',
				backend=default_backend()
	).derive(key)

def encriptText(key, text, algorithm = 'AES'):
	backend = default_backend()
	if algorithm == "AES":
		algo=algorithms.AES(key)
	else:
		raise(Exception("Invalid Algorithm"))
	bs = int(algo.block_size / 8)
	missing_bytes= bs - len(text) % bs
	if missing_bytes == 0:
		missing_bytes = bs
	padding = bytes([missing_bytes]*missing_bytes)
	text+=padding
	cipher = Cipher(algo, modes.ECB(), backend=backend)
	encryptor = cipher.encryptor()
	ct = encryptor.update(text) + encryptor.finalize()
	return ct

def decriptText(key, cryptogram, algorithm = 'AES'):
	backend = default_backend()
	if algorithm == "AES":
		algo=algorithms.AES(key)
	else:
		raise(Exception("Invalid Algorithm"))

	cipher = Cipher(algo, modes.ECB(), backend=backend)
	decryptor = cipher.decryptor()
	text = decryptor.update(cryptogram) + decryptor.finalize()
	p = text[-1]
	if len(text) < p:
		raise(Exception("Invalid padding: Larger than text"))
	if p > algo.block_size / 8:
		raise(Exception("Invalid padding: Larger than block size"))
	for x in text[-p:-1]:
		if x != p:
			raise(Exception("Invalid padding value"))
	return text[:-p]

def encriptFile(key,algorithm,fileIn,fileOut):
	fout=open(fileOut,"wb")
	with open(fileIn, "rb") as f:
		bts = f.read(256)
		while bts:
			fout.write(encriptText(key,algorithm,bts))
			bts = f.read(256)
	fout.close()
	f.close()

def decriptFile(key,algorithm,fileIn,fileOut):
	fout=open(fileOut,"wb")
	with open(fileIn, "rb") as f:
		bts = f.read(256)
		while bts:
			fout.write(decriptText(key,algorithm,bts))
			bts = f.read(256)
	fout.close()
	f.close()

def generateKey(pass_len = 16):
	password = randomPassword(pass_len)
	salt, key = deriveKey(bytes(password,"utf-8"))
	return key

def randomPassword(pass_len):
	letters = string.ascii_letters + string.digits + string.punctuation
	return ''.join(random.choice(letters) for letter in range(pass_len)) 

def dh_parameters():
	print("Generating Parameters")
	parameters = dh.generate_parameters(generator=2, key_size=512,
		backend=default_backend())
	return parameters

def dh_private(parameters):
	print("Generating Private Key")
	return parameters.generate_private_key()

def load_pem(bmessage):
	return load_pem_public_key(bmessage,backend=default_backend())

def load_params(bmessage):
	return load_pem_parameters(bmessage,backend=default_backend())

def get_mac(key,message,algorithm):
	backend = default_backend()
	if algorithm == "SHA256":
		algo=hashes.SHA256()
	elif algorithm == "SHA512":
		algo=hashes.SHA512()
	else:
		raise(Exception("Invalid Algorithm"))
	mac=hmac.HMAC(key,algo,backend)
	mac.update(message)
	return mac.finalize()