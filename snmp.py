import asyncio
import getpass
from dataclasses import dataclass

import paramiko
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
    walk_cmd,
)


# ============================================================
# CONFIGURAÇÃO
# ============================================================

SNMP_COMMUNITY = "public"
SNMP_PORT = 161
SSH_PORT = 22


@dataclass
class Router:
    nome: str
    ip: str


ROTEADORES = [
    Router("MT1", "192.168.56.10"),
    Router("MT2", "192.168.56.20"),
    Router("MT3", "192.168.56.30"),
    Router("MT4", "192.168.56.40"),
    Router("MT5", "192.168.56.50"),
]


# ============================================================
# OIDs SNMP
# ============================================================

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# Tabela padrão de interfaces
OID_IF_NAME = "1.3.6.1.2.1.2.2.1.2"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

# Contadores de 64 bits
OID_IF_BYTES_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_BYTES_OUT = "1.3.6.1.2.1.31.1.1.1.10"

# Erros e descartes
OID_IF_DISCARDS_IN = "1.3.6.1.2.1.2.2.1.13"
OID_IF_ERRORS_IN = "1.3.6.1.2.1.2.2.1.14"
OID_IF_DISCARDS_OUT = "1.3.6.1.2.1.2.2.1.19"
OID_IF_ERRORS_OUT = "1.3.6.1.2.1.2.2.1.20"


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def limpar_tela() -> None:
    print("\033[2J\033[H", end="")


def pausar() -> None:
    input("\nPressione Enter para continuar...")


def formatar_bytes(valor: int) -> str:
    unidades = ["B", "KB", "MB", "GB", "TB", "PB"]
    numero = float(valor)

    for unidade in unidades:
        if numero < 1024:
            return f"{numero:.2f} {unidade}"

        numero /= 1024

    return f"{numero:.2f} EB"


def formatar_uptime(timeticks: int) -> str:
    # SNMP TimeTicks utiliza centésimos de segundo
    segundos_totais = timeticks // 100

    dias, resto = divmod(segundos_totais, 86400)
    horas, resto = divmod(resto, 3600)
    minutos, segundos = divmod(resto, 60)

    partes = []

    if dias:
        partes.append(f"{dias}d")

    if horas or dias:
        partes.append(f"{horas}h")

    if minutos or horas or dias:
        partes.append(f"{minutos}min")

    partes.append(f"{segundos}s")

    return " ".join(partes)


def extrair_indice_oid(oid: str) -> int:
    return int(oid.rsplit(".", 1)[-1])


def status_admin(valor: str) -> str:
    estados = {
        "1": "habilitada",
        "2": "desabilitada",
        "3": "testing",
    }

    return estados.get(valor, f"desconhecido ({valor})")


def status_operacional(valor: str) -> str:
    estados = {
        "1": "UP",
        "2": "DOWN",
        "3": "TESTING",
        "4": "UNKNOWN",
        "5": "DORMANT",
        "6": "NOT PRESENT",
        "7": "LOWER LAYER DOWN",
    }

    return estados.get(valor, f"DESCONHECIDO ({valor})")


# ============================================================
# SNMP
# ============================================================

async def criar_transporte(ip: str) -> UdpTransportTarget:
    return await UdpTransportTarget.create(
        (ip, SNMP_PORT),
        timeout=2,
        retries=1,
    )


async def snmp_get(ip: str, oid: str) -> str | None:
    engine = SnmpEngine()

    try:
        transporte = await criar_transporte(ip)

        resultado = await get_cmd(
            engine,
            CommunityData(SNMP_COMMUNITY, mpModel=1),
            transporte,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        error_indication, error_status, error_index, var_binds = resultado

        if error_indication:
            print(f"Erro SNMP: {error_indication}")
            return None

        if error_status:
            print(f"Erro retornado pelo agente: {error_status}")
            return None

        if not var_binds:
            return None

        return str(var_binds[0][1])

    except Exception as erro:
        print(f"Falha na consulta SNMP: {erro}")
        return None

    finally:
        engine.close_dispatcher()


async def snmp_walk(ip: str, oid_base: str) -> dict[int, str]:
    engine = SnmpEngine()
    resultados: dict[int, str] = {}

    try:
        transporte = await criar_transporte(ip)

        iterator = walk_cmd(
            engine,
            CommunityData(SNMP_COMMUNITY, mpModel=1),
            transporte,
            ContextData(),
            ObjectType(ObjectIdentity(oid_base)),
            lexicographicMode=False,
        )

        async for (
            error_indication,
            error_status,
            error_index,
            var_binds,
        ) in iterator:

            if error_indication:
                print(f"Erro SNMP: {error_indication}")
                break

            if error_status:
                print(f"Erro retornado pelo agente: {error_status}")
                break

            for oid, valor in var_binds:
                indice = extrair_indice_oid(str(oid))
                resultados[indice] = str(valor)

    except Exception as erro:
        print(f"Falha no SNMP walk: {erro}")

    finally:
        engine.close_dispatcher()

    return resultados


async def mostrar_informacoes_gerais(router: Router) -> None:
    print(f"\nInformações gerais — {router.nome}")
    print("=" * 50)

    nome = await snmp_get(router.ip, OID_SYS_NAME)
    descricao = await snmp_get(router.ip, OID_SYS_DESCR)
    uptime_bruto = await snmp_get(router.ip, OID_SYS_UPTIME)

    print(f"IP:          {router.ip}")
    print(f"Hostname:    {nome or 'indisponível'}")
    print(f"Sistema:     {descricao or 'indisponível'}")

    if uptime_bruto and uptime_bruto.isdigit():
        print(f"Uptime:      {formatar_uptime(int(uptime_bruto))}")
    else:
        print("Uptime:      indisponível")


async def coletar_interfaces(router: Router) -> dict[int, dict[str, str]]:
    consultas = {
        "nome": OID_IF_NAME,
        "admin": OID_IF_ADMIN_STATUS,
        "oper": OID_IF_OPER_STATUS,
        "bytes_in": OID_IF_BYTES_IN,
        "bytes_out": OID_IF_BYTES_OUT,
        "discards_in": OID_IF_DISCARDS_IN,
        "errors_in": OID_IF_ERRORS_IN,
        "discards_out": OID_IF_DISCARDS_OUT,
        "errors_out": OID_IF_ERRORS_OUT,
    }

    interfaces: dict[int, dict[str, str]] = {}

    for campo, oid in consultas.items():
        dados = await snmp_walk(router.ip, oid)

        for indice, valor in dados.items():
            interfaces.setdefault(indice, {})
            interfaces[indice][campo] = valor

    return interfaces


async def mostrar_interfaces(router: Router) -> None:
    print(f"\nInterfaces — {router.nome}")
    print("=" * 80)

    interfaces = await coletar_interfaces(router)

    if not interfaces:
        print("Nenhuma interface encontrada ou SNMP indisponível.")
        return

    for indice in sorted(interfaces):
        interface = interfaces[indice]

        nome = interface.get("nome", f"ifIndex-{indice}")
        admin = status_admin(interface.get("admin", "?"))
        oper = status_operacional(interface.get("oper", "?"))

        try:
            bytes_in = formatar_bytes(int(interface.get("bytes_in", "0")))
            bytes_out = formatar_bytes(int(interface.get("bytes_out", "0")))
        except ValueError:
            bytes_in = interface.get("bytes_in", "indisponível")
            bytes_out = interface.get("bytes_out", "indisponível")

        print(f"\n[{indice}] {nome}")
        print(f"  Administrativo: {admin}")
        print(f"  Operacional:    {oper}")
        print(f"  Recebido:       {bytes_in}")
        print(f"  Enviado:        {bytes_out}")
        print(f"  Erros RX:       {interface.get('errors_in', '0')}")
        print(f"  Erros TX:       {interface.get('errors_out', '0')}")
        print(f"  Descartes RX:   {interface.get('discards_in', '0')}")
        print(f"  Descartes TX:   {interface.get('discards_out', '0')}")


# ============================================================
# SSH
# ============================================================

def executar_ssh(
    router: Router,
    usuario: str,
    senha: str,
    comando: str,
) -> None:
    cliente = paramiko.SSHClient()

    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        cliente.connect(
            hostname=router.ip,
            port=SSH_PORT,
            username=usuario,
            password=senha,
            timeout=5,
            look_for_keys=False,
            allow_agent=False,
        )

        stdin, stdout, stderr = cliente.exec_command(
            comando,
            timeout=15,
        )

        saida = stdout.read().decode("utf-8", errors="replace").strip()
        erro = stderr.read().decode("utf-8", errors="replace").strip()

        if saida:
            print(saida)
        elif erro:
            print(f"Erro retornado pelo MikroTik:\n{erro}")
        else:
            print("O comando não retornou dados.")

    except paramiko.AuthenticationException:
        print("Falha de autenticação SSH.")

    except paramiko.SSHException as erro:
        print(f"Erro SSH: {erro}")

    except TimeoutError:
        print("Tempo limite da conexão SSH excedido.")

    except Exception as erro:
        print(f"Falha ao conectar via SSH: {erro}")

    finally:
        cliente.close()


def menu_ssh(
    router: Router,
    usuario: str,
    senha: str,
) -> None:
    while True:
        limpar_tela()

        print("=" * 58)
        print(f" CONSULTAS SSH — {router.nome} ({router.ip})")
        print("=" * 58)
        print("1 - Sessões PPPoE/PPP ativas")
        print("2 - Sessões BGP")
        print("3 - Vizinhos OSPF")
        print("4 - Tabela ARP")
        print("5 - Rotas")
        print("6 - Comando manual")
        print("0 - Voltar")

        opcao = input("\nEscolha: ").strip()

        limpar_tela()

        if opcao == "1":
            print(f"PPP ativos — {router.nome}\n")
            executar_ssh(
                router,
                usuario,
                senha,
                "/ppp active print detail without-paging",
            )

        elif opcao == "2":
            print(f"BGP — {router.nome}\n")
            executar_ssh(
                router,
                usuario,
                senha,
                "/routing bgp session print detail without-paging",
            )

        elif opcao == "3":
            print(f"OSPF — {router.nome}\n")
            executar_ssh(
                router,
                usuario,
                senha,
                "/routing ospf neighbor print detail without-paging",
            )

        elif opcao == "4":
            print(f"ARP — {router.nome}\n")
            executar_ssh(
                router,
                usuario,
                senha,
                "/ip arp print detail without-paging",
            )

        elif opcao == "5":
            print(f"Rotas — {router.nome}\n")
            executar_ssh(
                router,
                usuario,
                senha,
                "/ip route print detail without-paging",
            )

        elif opcao == "6":
            comando = input("Digite o comando RouterOS: ").strip()

            if comando:
                print()
                executar_ssh(router, usuario, senha, comando)

        elif opcao == "0":
            return

        else:
            print("Opção inválida.")

        pausar()


# ============================================================
# MENUS
# ============================================================

def escolher_roteador() -> Router | None:
    while True:
        limpar_tela()

        print("=" * 58)
        print(" MIKROTIK MONITOR HÍBRIDO")
        print("=" * 58)

        for numero, router in enumerate(ROTEADORES, start=1):
            print(f"{numero} - {router.nome:<4} {router.ip}")

        print("0 - Sair")

        escolha = input("\nEscolha o equipamento: ").strip()

        if escolha == "0":
            return None

        try:
            indice = int(escolha) - 1

            if 0 <= indice < len(ROTEADORES):
                return ROTEADORES[indice]

        except ValueError:
            pass

        print("\nOpção inválida.")
        pausar()


async def menu_principal(
    router: Router,
    usuario: str,
    senha: str,
) -> None:
    while True:
        limpar_tela()

        print("=" * 58)
        print(f" {router.nome} — {router.ip}")
        print("=" * 58)
        print("1 - Informações gerais via SNMP")
        print("2 - Interfaces via SNMP")
        print("3 - Consultas específicas via SSH")
        print("4 - Consultar OID manualmente")
        print("0 - Trocar equipamento")

        opcao = input("\nEscolha: ").strip()

        limpar_tela()

        if opcao == "1":
            await mostrar_informacoes_gerais(router)

        elif opcao == "2":
            await mostrar_interfaces(router)

        elif opcao == "3":
            menu_ssh(router, usuario, senha)
            continue

        elif opcao == "4":
            oid = input("Digite o OID: ").strip()

            if oid:
                print()
                valor = await snmp_get(router.ip, oid)

                if valor is not None:
                    print(f"{oid} = {valor}")

        elif opcao == "0":
            return

        else:
            print("Opção inválida.")

        pausar()


async def main() -> None:
    limpar_tela()

    print("Credenciais SSH")
    print("=" * 30)

    usuario = input("Usuário SSH [automacao]: ").strip() or "automacao"
    senha = getpass.getpass("Senha SSH: ")

    while True:
        router = escolher_roteador()

        if router is None:
            limpar_tela()
            print("Monitor encerrado.")
            return

        await menu_principal(router, usuario, senha)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nPrograma encerrado.")