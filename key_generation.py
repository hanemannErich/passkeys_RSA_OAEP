from cryptography import x509
import cryptography.hazmat.backends as backends
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.asymmetric as asymmetric
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import datetime

# Gera um par de chaves RSA
alice_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=backends.default_backend()
)

# Extrai a chave pública
alice_public_key = alice_key.public_key()

# Serializa as chaves em formato PEM
alice_private_key_pem = alice_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

alice_public_key_pem = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
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

# Salva as chaves em arquivos PEM
with open('alice_private_key.pem', 'wb') as f:
    f.write(alice_private_key_pem)

with open('alice_public_key.pem', 'wb') as f:
    f.write(alice_public_key_pem)

with open('alice_cert.pem', 'wb') as f:
    f.write(alice_cert.public_bytes(Encoding.PEM))



# Gera um par de chaves RSA
server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=backends.default_backend()
)

# Extrai a chave pública
server_public_key = server_key.public_key()

# Serializa as chaves em formato PEM
server_private_key_pem = server_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

server_public_key_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# Gerar o certificado X.509 para Server
server_cert = x509.CertificateBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Alice"),
    ])
).issuer_name(
    x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Alice"),
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

# Salva as chaves em arquivos PEM
with open('server-api/alice_cert.pem', 'wb') as f:
    f.write(alice_cert.public_bytes(Encoding.PEM))

with open('server-api/server_private_key.pem', 'wb') as f:
    f.write(server_private_key_pem)

with open('server-api/server_public_key.pem', 'wb') as f:
    f.write(server_public_key_pem)

with open('server-api/server_cert.pem', 'wb') as f:
    f.write(server_cert.public_bytes(Encoding.PEM))