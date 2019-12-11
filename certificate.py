from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os
import datetime
import sys



class Validator:
    
    def __init__(self):
        self.resource_dir=os.path.join(os.getcwd(),"resources")
        self.today=datetime.datetime.now()
        self.roots=self.load_roots()
        self.intermediates=self.load_intermediates()

    def build_issuers(self,chain,cert):
        chain.append(cert)
        issuer=cert.issuer
        subject=cert.subject

        if issuer == subject and subject in self.roots:
            return True
        if issuer in self.roots:
            return self.build_issuers(chain,self.roots[issuer])
        if issuer in self.intermediates:
            return self.build_issuers(chain,self.intermediates[issuer])
        return False

    def load_cert_file(self,fname):
        cert=None
        with open(fname,"rb") as f:
            data=f.read()
            cert=x509.load_pem_x509_certificate(data, default_backend())
        return cert
    
    def load_cert(self,cert):
        return x509.load_pem_x509_certificate(cert, default_backend())

    def load_roots(self):
        print("Loading roots")
        roots={}
        roots_dir=os.path.join(self.resource_dir,"roots")
        for f in os.scandir(roots_dir):
            try:
                cert=self.load_cert_file(f.path)
                if cert != None and self.today < cert.not_valid_after:
                    roots[cert.subject]=cert
            except:
                print("Failed to load {}".format(f.path))
        return roots

    def load_intermediates(self):
        print("Loading intermediates")
        intermediates={}
        intermediate_dir=os.path.join(self.resource_dir,"intermediates")
        for f in os.scandir(intermediate_dir):
            try:
                cert=self.load_cert_file(f.path)
                if cert != None and self.today < cert.not_valid_after:
                    intermediates[cert.subject]=cert
            except:
                print("Failed to load {}".format(f.path))
        return intermediates

