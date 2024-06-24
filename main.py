import requests
import cryptography.hazmat.backends as backends
import cryptography.hazmat.primitives.asymmetric as asymmetric
from cryptography.hazmat.primitives.asymmetric import padding as assymetric_padding
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes  # Import the hashes module
import hashlib
import json

# Carrega as chaves privadas e públicas do cliente
with open('alice_private_key.pem', 'rb') as f:
    private_key_pem = f.read()

private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=None,
    backend=backends.default_backend()
)

with open('alice_public_key.pem', 'rb') as f:
    public_key_pem = f.read()

public_key = serialization.load_pem_public_key(
    public_key_pem,
    backend=backends.default_backend()
)


def send_login_request(username, password):
    # Envia uma requisição POST para o servidor
    headers = {
    'accept': 'application/json',
    'content-type': 'application/x-www-form-urlencoded',
    }

    params = {
        'username': 'alice@email.com',
        'password': '1234',
    }
    response = requests.post('http://localhost:8000/api/login', params=params, headers=headers)
    return response.json()

def send_authentication_request(data: dict):
    # Envia uma requisição POST para o servidor
    headers = {
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
    }

    params = {
        'username': data.get('username'),
        'signature': data.get('signature'),
        'public_key': data.get('public_key'),
        'challenge': data.get('challenge'),
    }

    response = requests.post('http://localhost:8000/api/authenticate', params=params, headers=headers)
    return response.json()

def main():
    username = 'alice@email.com'
    print('Cliente iniciado!')
    print('para este teste, o servidor deve estar rodando em localhost:8000')
    print('o nome de usuario e senha sao: alice@email.com, 1234')
    print('enviando login request')
    response = send_login_request(username, '1234')
    # Recebe o desafio do servidor
    print(response)

    challenge = input('Digite o desafio do servidor: ')

    # Specify the hash algorithm and optional label for OAEP padding
    padding = assymetric_padding.OAEP(
        mgf=assymetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None  # Optional label (can be omitted)
    )

    # Sign the challenge with the private key using OAEP padding
    signature = private_key.sign(
        challenge.encode('utf-8'),
        padding=padding
    )

    # Envia a assinatura e a chave pública do cliente para o servidor
    data = {
        'username': username,
        'signature': signature,
        'public_key': public_key_pem.decode('utf-8'),
        'challenge': challenge
    }

    # Envia os dados para o servidor
    print('Enviando dados para o servidor:', data)

    response = send_authentication_request(data)
    print(response)


if __name__ == '__main__':
    main()