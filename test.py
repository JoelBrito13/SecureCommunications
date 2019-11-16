import os
import json
import pickle
import getpass
import base64
import string
import random

from Crypto.Cipher import Salsa20
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from asymetric_encript import rsa_key, rsa_encrypt, rsa_decrypt
from symetric_encript import generateKey, encryptAesSalsa20, decryptAesSalsa20

while False:
	priv,pub = rsa_key()
	print("priv: ",priv)
	print("pub: ",pub)
	text =b"ffaas"
	cipher=rsa_encrypt(pub,text)
	print("cipher: ",cipher)
	p_text=rsa_decrypt(priv, cipher)
	print("p_text: ",p_text)
	print(priv.public_key())

	mesage={'key':'AAS','key':pub.__str__()}
	print(mesage)
	pp=pickle.dumps(mesage)

	print()
	print()
	import inspect
	[print(x) for x in inspect.getmembers(priv)]
	x = RSAPublicNumbers()
	print(x)	

text = "Python random text to encryptor".encode('ascii'	)

key1 = generateKey(32)
key2 = generateKey(32)

message={'AES':key1, 'Salsa20':key2}
print(message)
#pickle_msg = pickle.dump(message)
#print(pickle_msg)

text = "Python random text to encryptor".encode('ascii'	)
print(text)

iv = os.urandom(16)
crypto = encryptAesSalsa20(key1, key2,text, iv)


print("Cryptogram: {}\niv: {}".format(crypto, iv))

text_d =decryptAesSalsa20(key1, key2, crypto, iv=iv)
print(text_d==text)
print("Decrypt: {}".format(text_d))

try:
	print("key1",base64.b64encode(key1).decode())
except:
	print("Could not encode key1")

try:
	msg=base64.b64encode(crypto).decode()
	print("msg",msg)
	message = {"type":"DATA","data":msg}
	print("message", message)
	message_b=(json.dumps(message) + '\r\n').encode()
	print("message_b", message_b)
	print(base64.b64encode(message_b).decode())

except:
	print("Could not encode message")

#try:
#	print(base64.b64encode(pickle_msg).decode())
#except:
#	print("Could not encode pickle_msg")
        
try:
	print("crypto",base64.b64encode(crypto).decode())
except:
	print("Could not encode crypto")
