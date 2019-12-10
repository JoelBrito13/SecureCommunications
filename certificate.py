from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os
import datetime
import sys

roots={}
intermediates={}
today=datetime.datetime.now()

def build_issuers(chain,cert):
    chain.append(cert)

    issuer=cert.issuer
    subject=cert.subject

    if issuer == subject and subject in roots:
        return True
    if subject in roots:
        return build_issuers(chain,roots[issuer])

    if subject in intermediates:
        return build_issuers(chain,intermediates[issuer])
    return False

def load_cert(fname):
    cert=None
    with open(fname,"rb") as f:
        data=f.read()
        cert=x509.load_pem_x509_certificate(data, default_backend())
    return cert

print("Loading roots")
for f in os.scandir("/etc/ssl/certs"):
    try:
        cert=load_cert(f.path)
        if cert != None and today < cert.not_valid_after:
            roots[cert.subject]=cert
    except:
        print("Failed to load {}".format(f.path))

print("Loading user cert")
user_cert=load_cert(sys.argv[1])
subject = cert.subject

print("Loading intermediates")
for c in sys.argv[2:]:
    cert=load_cert(c)
    subject=cert.subject
    intermediates[subject]=cert