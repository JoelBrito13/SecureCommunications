import os
import getpass
import base64
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat,PrivateFormat,ParameterFormat, load_pem_public_key, load_pem_parameters

from Crypto.Cipher import Salsa20

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
	return HKDF(algorithm=hashes.SHA256(),
				length=32,
				salt=None,
				info=b'dh handshake',
				backend=default_backend()
	).derive(key)

	"""
    										AES Session 
    """
									
def encriptText(key, text, algorithm, iv):
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
	cipher = Cipher(algo, modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	ct = encryptor.update(text) + encryptor.finalize()
	return ct

def decriptText(key, cryptogram, algorithm, iv):
	backend = default_backend()
	if algorithm == "AES":
		algo=algorithms.AES(key)
	else:
		raise(Exception("Invalid Algorithm"))

	cipher = Cipher(algo, modes.CBC(iv), backend=backend)
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


	"""
    										Salsa20 Session 
    """
									
def encryptTextSalsa20(key, text):
	cipher = Salsa20.new(key=key)
	ciphertext = cipher.nonce + cipher.encrypt(text)
	return ciphertext

def decryptTextSalsa20(key, ciphertext):
	msg_end = ciphertext[:8]
	msg_start = ciphertext[8:]
	cipher = Salsa20.new(key=key, nonce=msg_end)
	plaintext = cipher.decrypt(msg_start)
	return plaintext

	"""
    										Algorithms Combination Session 
    """
									
def encryptAesSalsa20(key_aes, keysalsa, text, iv):
	aes_cipher = encriptText(key = key_aes, text=text, algorithm="AES", iv=iv)
	salsa_cipher = encryptTextSalsa20(key=keysalsa, text=aes_cipher)
	return salsa_cipher

def decryptAesSalsa20(key_aes, keysalsa, cipher, iv):
	sansa_text = decryptTextSalsa20(key=keysalsa, ciphertext=cipher)
	aes_text = decriptText(key=key_aes, cryptogram=sansa_text, algorithm="AES", iv=iv)
	return aes_text


def generateKey(pass_len = 16):
	password = randomPassword(pass_len)
	salt, key = deriveKey(bytes(password,"utf-8"))
	return key

def randomPassword(pass_len):
	letters = string.ascii_letters + string.digits + string.punctuation
	return ''.join(random.choice(letters) for letter in range(pass_len)) 

def dh_parameters():
	parameters = dh.generate_parameters(generator=2, key_size=1024,
		backend=default_backend())
	return parameters

def dh_private(parameters):
	return parameters.generate_private_key()

def load_pem(bmessage):
	return load_pem_public_key(bmessage,backend=default_backend())

def load_params(bmessage):
	return load_pem_parameters(bmessage,backend=default_backend())