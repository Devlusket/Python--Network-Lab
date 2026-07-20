import os

import paramiko
from dotenv import load_dotenv


load_dotenv()


USER = os.getenv("MIKROTIK_USER", "")
PASSWORD = os.getenv("MIKROTIK_PASSWORD", "")
PORT = int(os.getenv("MIKROTIK_PORT", "22"))


MIKROTIKS = [
    ("MT1", os.getenv("MT1_HOST", "")),
    ("MT2", os.getenv("MT2_HOST", "")),
    ("MT3", os.getenv("MT3_HOST", "")),
    ("MT4", os.getenv("MT4_HOST", "")),
    ("MT5", os.getenv("MT5_HOST", "")),
]


COMANDOS = [
    ("IDENTIDADE", "/system identity print"),
    ("RECURSOS E UPTIME", "/system resource print"),
    ("INTERFACES", "/interface print"),
    ("ENDEREÇOS IP", "/ip address print"),
    ("ROTAS", "/ip route print"),
    ("VIZINHOS OSPF", "/routing ospf neighbor print"),
    ("SESSÕES BGP", "/routing bgp session print"),
    ("CLIENTES PPPOE ATIVOS", "/ppp active print"),
    ("TABELA ARP", "/ip arp print"),
]


def conectar(host: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    client.connect(
        hostname=host,
        port=PORT,
        username=USER,
        password=PASSWORD,
        timeout=10,
    )

    return client


def executar_comando(
    client: paramiko.SSHClient,
    titulo: str,
    comando: str,
) -> None:
    print(f"\n===== {titulo} =====")

    _, stdout, stderr = client.exec_command(comando)

    saida = stdout.read().decode("utf-8").strip()
    erro = stderr.read().decode("utf-8").strip()

    if saida:
        print(saida)

    if erro:
        print(f"ERRO: {erro}")

    if not saida and not erro:
        print("Nenhuma informação retornada.")


def validar_configuracao() -> None:
    if not USER:
        raise ValueError(
            "MIKROTIK_USER não foi definido no arquivo .env."
        )

    if not PASSWORD:
        raise ValueError(
            "MIKROTIK_PASSWORD não foi definido no arquivo .env."
        )

    equipamentos_sem_host = [
        nome
        for nome, host in MIKROTIKS
        if not host
    ]

    if equipamentos_sem_host:
        nomes = ", ".join(equipamentos_sem_host)

        raise ValueError(
            f"Host não definido para: {nomes}."
        )


def main() -> None:
    validar_configuracao()

    for nome, host in MIKROTIKS:
        print("\n")
        print("=" * 60)
        print(f"Conectando ao {nome} - {host}")
        print("=" * 60)

        client = None

        try:
            client = conectar(host)

            print(f"Conexão SSH com {nome} realizada com sucesso.")

            for titulo, comando in COMANDOS:
                executar_comando(
                    client,
                    titulo,
                    comando,
                )

        except paramiko.AuthenticationException:
            print(
                f"Falha de autenticação no {nome}. "
                "Verifique usuário e senha."
            )

        except paramiko.SSHException as erro:
            print(
                f"Erro de SSH no {nome}: {erro}"
            )

        except TimeoutError:
            print(
                f"Tempo de conexão esgotado no {nome}."
            )

        except OSError as erro:
            print(
                f"Não foi possível conectar ao {nome}: {erro}"
            )

        finally:
            if client is not None:
                client.close()
                print(f"\nConexão com {nome} encerrada.")


if __name__ == "__main__":
    main()