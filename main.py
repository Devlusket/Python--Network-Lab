import os

import paramiko
from dotenv import load_dotenv

# Carrega as variáveis existentes no arquivo .env
load_dotenv()

HOST = os.getenv("MIKROTIK_HOST", "")
PORT = int(os.getenv("MIKROTIK_PORT", "22"))
USERNAME = os.getenv("MIKROTIK_USER")
PASSWORD = os.getenv("MIKROTIK_PASSWORD")


def main():
    print("Conectando ao MikroTik...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
    )

    print("Conectado ao MikroTik com sucesso!\n")

    stdin, stdout, stderr = client.exec_command("/system identity print")

    output = stdout.read().decode("utf-8")
    error = stderr.read().decode("utf-8")

    if error:
        print(f"Erro retornado pelo MikroTik:\n{error}")
    else:
        print("Resposta do RouterOS:")
        print(output)

    client.close()


if __name__ == "__main__":
    main()