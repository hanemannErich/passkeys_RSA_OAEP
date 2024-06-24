from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from utils import verify_signature
import cryptography.hazmat.primitives.serialization as serialization
import os
import cryptography.hazmat.backends as backends
import cryptography.hazmat.primitives.asymmetric as asymmetric
import cryptography.hazmat.primitives.serialization as serialization
import hashlib
import random
import string

app = FastAPI()

class User:
    def __init__(self, username, password, challenge=None):
        self.username = username
        self.password = password
        self.challenge = challenge
        self.public_key = None

    def set_challenge(self, challenge):
        self.challenge = challenge

    def set_public_key(self, public_key):
        self.public_key = public_key

    def __str__(self):
        return f"Pessoa(username={self.username}, challenge={self.challenge})"

class Users:
    def __init__(self):
        self.users = []

    def add_user(self, user):
        self.users.append(user)

# create example user
users = Users()
alice = users.add_user(User('alice@email.com', '1234'))


@app.post('/api/login')
def send_message(username: str, password: str):
    user = check_username(username)
    if user and check_password(username, password):
        challenge = generate_random_string(64)
        user.set_challenge(challenge)

        return {'message': 'user found',
                'challenge': challenge}

    elif not user:
        return {'message': 'user not found'}
    elif not check_password(username, password):
        return {'message': 'wrong password'}
    else:
        raise HTTPException(status_code=401, detail="Não autorizado")


@app.post('/api/authenticate')
def authenticate(username: str, signature: str, public_key: str, challenge: str):
    user = check_username(username)
    if user and user.challenge == challenge:
        user.set_public_key(public_key)
        signature = base64.b64decode(signature)
        verification_result = verify_signature(challenge, signature, user.public_key)
        if verification_result == 'Assinatura do cliente verificada com sucesso!':
            return {'message': 'user authenticated'}
        else:
            return {'message': 'authentication failed', 'detail': verification_result}
    else:
        return {'message': 'user not authenticated'}


def generate_random_string(length):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def check_username(username: str):
    for user in users.users:
        if user.username == username:
            return user
    return False

def check_password(username: str, password: str):
    for user in users.users:
        if user.username == username and user.password == password:
            return True
    return False
