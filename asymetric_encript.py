from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
	)

def rsa_key(size=2048):
	private_key = rsa.generate_private_key(public_exponent=65537,key_size=size,backend=default_backend())
	public_key = private_key.public_key()
	pem_private = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.BestAvailableEncryption(b'topsecret'))
	pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)
	return private_key,public_key


def rsa_encrypt(public_key,text):
	ciphertext = public_key.encrypt(
	    text,
	    padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA256()),
	        algorithm=hashes.SHA256(),
	        label=None
	    )
	)

	return ciphertext
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

def rsa_decrypt(private_key, ciphertext):
	plaintext = private_key.decrypt(
	    ciphertext,
	    padding.OAEP(
	        mgf=padding.MGF1(algorithm=hashes.SHA256()),
	        algorithm=hashes.SHA256(),
	        label=None
	    )
	)
	return plaintext

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

