import os
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, ParameterFormat, \
    load_pem_public_key, load_pem_parameters
from Crypto.Cipher import Salsa20


class CriptoAlgorithm:
    def __init__(self, algorithm, key=None, initial_vector=None):
        self.key = key
        self.algorithm = algorithm
        self.initial_vector = initial_vector

    def EncriptText(self, text):
        if self.algorithm == "Salsa20":
            return self.encryptTextSalsa20(text)
        else:
            return self.cryptographyEncriptText(text)

    def DecriptText(self, ciphertext):
        if self.algorithm == "Salsa20":
            return self.decryptTextSalsa20(ciphertext)
        else:
            return self.cryptographyDecriptText(ciphertext)

    """
                                            AES Session 
    """

    def cryptographyEncriptText(self, text):
        backend = default_backend()
        algo = algorithms.AES(self.key)

        bs = int(algo.block_size / 8)
        missing_bytes = bs - len(text) % bs
        if missing_bytes == 0:
            missing_bytes = bs
        padding = bytes([missing_bytes] * missing_bytes)
        text += padding
        cipher = Cipher(algo, modes.CBC(self.initial_vector), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(text) + encryptor.finalize()
        return ct

    def cryptographyDecriptText(self, ciphertext):
        backend = default_backend()
        algo = algorithms.AES(self.key)

        cipher = Cipher(algo, modes.CBC(self.initial_vector), backend=backend)
        decryptor = cipher.decryptor()
        text = decryptor.update(ciphertext) + decryptor.finalize()
        p = text[-1]
        if len(text) < p:
            raise (Exception("Invalid padding: Larger than text"))
        if p > algo.block_size / 8:
            raise (Exception("Invalid padding: Larger than block size"))
        for x in text[-p:-1]:
            if x != p:
                raise (Exception("Invalid padding value"))
        return text[:-p]

        """
                                                Salsa20 Session 
        """

    def encryptTextSalsa20(self, text):
        cipher = Salsa20.new(key=self.key)
        ciphertext = cipher.nonce + cipher.encrypt(text)
        return ciphertext

    def decryptTextSalsa20(self, ciphertext):
        msg_end = ciphertext[:8]
        msg_start = ciphertext[8:]
        cipher = Salsa20.new(key=self.key, nonce=msg_end)
        plaintext = cipher.decrypt(msg_start)
        return plaintext

        """
                                                MAC Session 
        """

    def get_mac(self, cipher, algorithm):
        backend = default_backend()
        if algorithm == "SHA256":
            algo = hashes.SHA256()
        elif algorithm == "SHA512":
            algo = hashes.SHA512()
        else:
            raise (Exception("Invalid Algorithm"))
        mac = hmac.HMAC(self.key, algo, backend)
        mac.update(cipher)

        return mac.finalize()

        """
                                                    Generate Key            
        """

    def generate_key(self, pass_len=64):
        password = self.random_password(pass_len)
        self.key = self.derive_key(bytes(password, "utf-8"))
        return self.key

    @staticmethod
    def random_password(pass_len):
        letters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(letters) for letter in range(pass_len))

    @staticmethod
    def derive_key(password):
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
            backend=backend
        )
        return kdf.derive(password)



def dh_derive(key):
    return HKDF(algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'dh handshake',
                backend=default_backend()
                ).derive(key)


def dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=512,
                                        backend=default_backend())
    return parameters


def dh_private(parameters):
    return parameters.generate_private_key()


def load_pem(bmessage):
    return load_pem_public_key(bmessage, backend=default_backend())

def load_params(bmessage):
    return load_pem_parameters(bmessage, backend=default_backend())


def get_mac(key, message, algorithm):
    backend = default_backend()
    if algorithm == "SHA256":
        algo = hashes.SHA256()
    elif algorithm == "SHA512":
        algo = hashes.SHA512()
    else:
        raise (Exception("Invalid Algorithm"))
    mac = hmac.HMAC(key, algo, backend)
    mac.update(message)
    return mac.finalize()
