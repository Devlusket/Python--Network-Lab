import os

import paramiko
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("MIKROTIK_HOST", "")
PORT = int(os.getenv("MIKROTIK_PORT", "22"))
USERNAME = os.getenv("MIKROTIK_USER", "")
PASSWORD = os.getenv("MIKROTIK_PASSWORD", "")

COMANDOS = [
    ("IDENTIDADE", "/system identity print"),
    ("RECURSOS E UPTIME", "/system resource print"),
    ("INTERFACES", "/interface print"),
    ("ENDEREÇOS IP", "/ip address print"),
    ("ROTAS", "/ip route print"),
    ("VIZINHOS OSPF", "/routing ospf neighbor print"),
    ("SESSÕES BGP", "/routing bgp session print"),
    ("CLIENTES PPPOE ATIVOS", "/ppp active print"),
]


def executar_comando(
    client: paramiko.SSHClient,
    titulo: str,
    comando: str,
) -> None:
    print(f"\n===== {titulo} =====")

    _, stdout, stderr = client.exec_command(comando)

    resultado = stdout.read().decode("utf-8")
    erro = stderr.read().decode("utf-8")

    if erro.strip():
        print(f"Erro retornado pelo MikroTik:\n{erro}")
    elif resultado.strip():
        print(resultado)
    else:
        print("Nenhum dado retornado.")


def main() -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Conectando ao MikroTik {HOST}...")

        client.connect(
            hostname=HOST,
            port=PORT,
            username=USERNAME,
            password=PASSWORD,
            timeout=10,
        )

        print("Conectado com sucesso!")

        for titulo, comando in COMANDOS:
            executar_comando(client, titulo, comando)

    except paramiko.AuthenticationException:
        print("Falha na autenticação. Verifique o usuário e a senha.")

    except paramiko.SSHException as erro:
        print(f"Erro na conexão SSH: {erro}")

    except TimeoutError:
        print("A conexão excedeu o tempo limite.")

    except Exception as erro:
        print(f"Falha durante a execução: {erro}")

    finally:
        client.close()
        print("\nConexão encerrada.")


if __name__ == "__main__":
    main()