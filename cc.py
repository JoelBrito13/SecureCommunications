import PyKCS11
from PyKCS11.LowLevel import CKA_ID, CKA_LABEL, CKA_CLASS, CKO_PRIVATE_KEY, CKO_CERTIFICATE, CKK_RSA, CKA_KEY_TYPE, CKA_VALUE
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend

lib = '/usr/local/lib/libpteidpkcs11.so'

class SmartCardAuthenticator:

    def __init__(self):
        self.pkcs11=PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

    def get_user_certificate(self):
        slot = self.pkcs11.getSlotList()[0]
        session = self.pkcs11.openSession(slot)

        cert_obj = session.findObjects([(PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
        cert_value=session.getAttributeValue(cert_obj,[CKA_VALUE])[0]
        
        return x509.load_der_x509_certificate(bytes(cert_value),default_backend())

    def sign(self,message):
        slot = self.pkcs11.getSlotList()[0]
        session = self.pkcs11.openSession(slot)

        private_key = session.findObjects([(PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_PRIVATE_KEY),
        (PyKCS11.LowLevel.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0]

        mechanism = PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_SHA1_RSA_PKCS, None)
        return bytes(session.sign(private_key, message, mechanism))