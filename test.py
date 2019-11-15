import os
import json
import pickle
import getpass
import base64
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from asymetric_encript import rsa_key, rsa_encrypt, rsa_decrypt
from symetric_encript import deriveKey, encriptText, decriptText

priv,pub = rsa_key()
print("priv: ",priv)
print("pub: ",pub)
text =b"ffaas"
cipher=rsa_encrypt(pub,text)
print("cipher: ",cipher)
p_text=rsa_decrypt(priv, cipher)
print("p_text: ",p_text)
print(priv.public_key())
print()
print()

mesage={'key':'AAS','key':pub.__str__()}
print(mesage)
pp=pickle.dumps(mesage)

import inspect
[print(x) for x in inspect.getmembers(pub)]

print(pub.__class__())


#print(deriveKey(b'1234'))
#key = randomPassword(16)
#print(key)
#message={'KEY':key}
#print(type(message['KEY']))
#
#message_b = (json.dumps(message) + '\r\n').encode()
#print(message_b)
#json_msg = json.loads(message_b)
#print(json_msg['KEY'])
#
#
#text = "Python random text to encryptor".encode('utf-8')
#print(text)
#crypto=encriptText(key.encode('ascii'), text)
#print("Cryptogram: {}".format(crypto))
#text_d=decriptText(key.encode('ascii'),crypto)
#print("Decrypt: {}".format(text_d))
#

        