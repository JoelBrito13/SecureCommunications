from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def rsa_pk_file(fname):
	with open(fname,"rb") as f:
		data=f.read()
	return serialization.load_pem_public_key(data,default_backend())