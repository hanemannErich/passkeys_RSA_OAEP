from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import PublicFormat
import datetime


# Gerar uma chave RSA para Alice
alice_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Gerar o certificado X.509 para Alice
alice_cert = x509.CertificateBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Alice"),
    ])
).issuer_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Alice"),
    ])
).public_key(
    alice_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).sign(alice_key, hashes.SHA256())

# Gerar uma chave RSA para Bob
bob_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Gerar o certificado X.509 para Bob
bob_cert = x509.CertificateBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Bob"),
    ])
).issuer_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Bob"),
    ])
).public_key(
    bob_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).sign(bob_key, hashes.SHA256())

# Gerar uma chave RSA para Server
server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
# Gerar o certificado X.509 para Server
server_cert = x509.CertificateBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Server"),
    ])
).issuer_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Server"),
    ])
).public_key(
    server_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).sign(server_key, hashes.SHA256())


#salvar certificados e chaves
with open('alice_cert.pem', 'wb') as f:
    f.write(alice_cert.public_bytes(Encoding.PEM))

with open('alice_key.pem', 'wb') as f:
    f.write(alice_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ))

with open('bob_cert.pem', 'wb') as f:
    f.write(bob_cert.public_bytes(Encoding.PEM))

with open('bob_key.pem', 'wb') as f:
    f.write(bob_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ))


with open('server-api/server_cert.pem', 'wb') as f:
    f.write(server_cert.public_bytes(Encoding.PEM))

with open('server-api/server_key.pem', 'wb') as f:
    f.write(server_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ))