import cryptography.hazmat.backends as backends
import cryptography.hazmat.primitives.asymmetric as asymmetric
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.x509 import load_pem_x509_certificate
import cryptography.exceptions
import hashlib

def verify_signature(challenge, signature, public_key_pem):
    # Carrega o certificado digital do servidor
    with open('server_cert.pem', 'rb') as f:
        certificate_pem = f.read()

    certificate = load_pem_x509_certificate(
        certificate_pem,
        backend=backends.default_backend()
    )

    # Extrai a chave pública do servidor do certificado
    public_key = certificate.public_key()

    # Recebe a assinatura e a chave pública do cliente
    data = {
        'signature': signature,
        'public_key': public_key_pem
    }

    # Carrega a chave pública do cliente
    client_public_key = serialization.load_pem_public_key(
        data['public_key'].encode('utf-8'),
        backend=backends.default_backend()
    )

    # Verifica a assinatura do cliente
    try:
        client_public_key.verify(
            data['signature'],
            challenge.encode('utf-8'),
            algorithm=asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=asymmetric.hashes.SHA256()),
                hash_alg=asymmetric.hashes.SHA256()
            )
        )
        return('Assinatura do cliente verificada com sucesso!')
    except Exception as e:
        return('Assinatura do cliente inválida!')