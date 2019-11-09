from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from siocript import *

def rsa_key(size,file1,file2):
	private_key = rsa.generate_private_key(public_exponent=65537,key_size=size,backend=default_backend())
	public_key = private_key.public_key()
	pem_private = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.BestAvailableEncryption(b'topsecret'))
	pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)
	fi=open(file1,"wb")
	fi2=open(file2,"wb")
	fi.write(pem_private)
	fi2.write(pem_public)

def rsa_file_encrypt(filein,publickey,fileout):
	fin= open(filein,"rb")
	with open(publickey, "rb") as key_file:
			public_key = serialization.load_pem_public_key(
				key_file.read(),
				backend=default_backend())
	message= fin.read(256)
	while message:
		ciphertext = public_key.encrypt(
			message,
			padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None))
		fout= open(fileout,"wb")
		fout.write(ciphertext)
		message= fin.read(256)
	fout.close()

def rsa_encrypt(publickey,text):
	with open(publickey, "rb") as key_file:
			public_key = serialization.load_pem_public_key(
				key_file.read(),
				backend=default_backend())
	ciphertext = public_key.encrypt(
			text,
			padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None))
	return ciphertext

def rsa_file_decrypt(filein,privatekey,fileout):
	fin= open(filein,"rb")
	message= fin.read()
	fin.close()
	with open(privatekey, "rb") as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=b'topsecret',
			backend=default_backend())
	plaintext = private_key.decrypt(
		message,
		padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None))
	fout= open(fileout,"wb")
	fout.write(plaintext)
	fout.close()


rsa_key(1024,"private","public")
newf = open("rsatest","wb")
messg=b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.Suspendisse malesuada libero arcu, id semper dolor dictum eu. Donec accumsan vitae ipsum sit amet maximus. Nullam ut turpis vitae elit posuere." 
newf.write(messg)
newf.close()
salt,key=deriveKey(b"abcdefghijk")
encriptFile(key,"AES","rsatest","encripted")
rsa_encrypt("public",key)
decriptFile(key,"AES","encripted","decripted")