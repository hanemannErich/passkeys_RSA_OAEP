import cryptography.hazmat.backends as backends
from cryptography.hazmat.primitives import hashes
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

    try:
        client_public_key.verify(
            signature,
            challenge.encode('utf-8'),
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return 'Assinatura do cliente verificada com sucesso!'
    except cryptography.exceptions.InvalidSignature:
        return 'Assinatura do cliente inválida!'
    except Exception as e:
        return f'Erro ao verificar a assinatura do cliente: {e}'