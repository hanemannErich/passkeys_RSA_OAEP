# Projeto de Autenticação com Passkeys

Este projeto implementa a autenticação entre um cliente e vários servidores usando passkeys (chaves RSA). O cliente gera uma chave privada para acessar um servidor e pode se autenticar no servidor escolhido. As chaves privadas são armazenadas de forma segura, e a comunicação é criptografada usando RSA com padding OAEP.

## Requisitos

- Python 3.10.14
- `cffi==1.16.0`
- `cryptography==42.0.7`
- `pip==24.0`
- `pycparser==2.22`
- `pycryptodome==3.20.0`
- `pyotp==2.9.0`
- `setuptools==69.5.1`
- `wheel==0.43.0`

## Instalação

1. Clone o repositório:

   ```sh
   git clone https://github.com/hanemannErich/passkeys_RSA_OAEP
   cd passkeys_RSA_OAEP
   ```

2. Execute `pip install -r requirements.txt`

## Execução

1. Crie as chaves e certificados rodando `python3 key_generation.py`

2. Entre no diretório da api `cd server-api`

3. Execute `uvicorn main:app`

4. Execute o código `main.py` da raiz do projeto e siga as instruções.
