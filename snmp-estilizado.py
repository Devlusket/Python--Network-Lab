from __future__ import annotations

import asyncio
import getpass
import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import paramiko
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
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

console = Console()

SNMP_COMMUNITY = "public"
SNMP_PORT = 161
SNMP_TIMEOUT = 2
SNMP_RETRIES = 1

SSH_PORT = 22
SSH_TIMEOUT = 5
SSH_PRIVATE_KEY = Path("~/.ssh/id_ed25519_mikrotik").expanduser()

# Intervalo usado para calcular tráfego atual.
TRAFFIC_SAMPLE_SECONDS = 2.0

CPU_WARNING = 70
CPU_CRITICAL = 90
MEMORY_WARNING = 75
MEMORY_CRITICAL = 90


@dataclass(frozen=True)
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
# OIDs
# ============================================================

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

OID_IF_NAME = "1.3.6.1.2.1.2.2.1.2"
OID_IF_MTU = "1.3.6.1.2.1.2.2.1.4"
OID_IF_MAC = "1.3.6.1.2.1.2.2.1.6"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

OID_IF_BYTES_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_PACKETS_IN = "1.3.6.1.2.1.31.1.1.1.7"
OID_IF_BYTES_OUT = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_PACKETS_OUT = "1.3.6.1.2.1.31.1.1.1.11"

OID_IF_DISCARDS_IN = "1.3.6.1.2.1.2.2.1.13"
OID_IF_ERRORS_IN = "1.3.6.1.2.1.2.2.1.14"
OID_IF_DISCARDS_OUT = "1.3.6.1.2.1.2.2.1.19"
OID_IF_ERRORS_OUT = "1.3.6.1.2.1.2.2.1.20"


# ============================================================
# MODELOS
# ============================================================

@dataclass
class SSHResult:
    ok: bool
    output: str = ""
    error: str = ""


@dataclass
class RouterReport:
    router: Router
    ssh_online: bool = False
    snmp_online: bool = False

    routeros: str = "indisponível"
    uptime: str = "indisponível"
    cpu: int | None = None
    memoria_pct: int | None = None

    interfaces_up: int = 0
    interfaces_down: int = 0
    interfaces_total: int = 0

    ospf_total: int = 0
    ospf_full: int = 0
    ospf_configurado: bool = False

    bgp_total: int = 0
    bgp_established: int = 0
    bgp_configurado: bool = False

    ldp_total: int = 0
    ldp_operational: int = 0
    ldp_configurado: bool = False
    mpls_forwarding_entries: int = 0
    ldp_local_mappings: int = 0
    ldp_remote_mappings: int = 0
    ldp_neighbors: list[dict[str, str]] = field(default_factory=list)

    pppoe: list[dict[str, str]] = field(default_factory=list)
    dhcp_leases: list[dict[str, str]] = field(default_factory=list)

    falhas: list[str] = field(default_factory=list)


# ============================================================
# FORMATAÇÃO E UTILITÁRIOS
# ============================================================

def limpar_tela() -> None:
    console.clear()


def pausar() -> None:
    console.input("\n[dim]Pressione Enter para continuar...[/dim]")


def valor_inteiro(valor: Any, padrao: int = 0) -> int:
    try:
        return int(str(valor))
    except (TypeError, ValueError):
        return padrao


def formatar_bytes(valor: int) -> str:
    unidades = ("B", "KiB", "MiB", "GiB", "TiB")
    numero = float(max(valor, 0))

    for unidade in unidades:
        if numero < 1024 or unidade == unidades[-1]:
            return f"{numero:.2f} {unidade}"
        numero /= 1024

    return f"{numero:.2f} TiB"


def formatar_taxa(bits_por_segundo: float) -> str:
    unidades = ("bps", "Kbps", "Mbps", "Gbps", "Tbps")
    numero = max(bits_por_segundo, 0.0)

    for unidade in unidades:
        if numero < 1000 or unidade == unidades[-1]:
            if numero >= 100:
                return f"{numero:.0f} {unidade}"
            if numero >= 10:
                return f"{numero:.1f} {unidade}"
            return f"{numero:.2f} {unidade}"
        numero /= 1000

    return f"{numero:.2f} Tbps"


def formatar_timeticks(valor: str | int) -> str:
    # PySNMP normalmente devolve TimeTicks como número de centésimos.
    ticks = valor_inteiro(valor)
    segundos_totais = ticks // 100

    dias, resto = divmod(segundos_totais, 86400)
    horas, resto = divmod(resto, 3600)
    minutos, segundos = divmod(resto, 60)

    partes: list[str] = []
    if dias:
        partes.append(f"{dias}d")
    if horas or dias:
        partes.append(f"{horas}h")
    if minutos or horas or dias:
        partes.append(f"{minutos}m")
    partes.append(f"{segundos}s")
    return "".join(partes)


def formatar_percentual(valor: int | None, warning: int, critical: int) -> Text:
    if valor is None:
        return Text("— indisponível", style="dim")

    if valor >= critical:
        return Text(f"✗ {valor}%", style="bold red")
    if valor >= warning:
        return Text(f"⚠ {valor}%", style="bold yellow")
    return Text(f"✓ {valor}%", style="bold green")


def status_texto(ok: bool, sucesso: str, falha: str) -> Text:
    return Text(f"✓ {sucesso}", style="bold green") if ok else Text(f"✗ {falha}", style="bold red")


def extrair_indice_oid(oid: str) -> int:
    return int(oid.rsplit(".", 1)[-1])


def interface_ethernet(nome: str) -> bool:
    return nome.lower().startswith("ether")


def status_operacional(valor: str) -> str:
    return {
        "1": "UP",
        "2": "DOWN",
        "3": "TESTING",
        "4": "UNKNOWN",
        "5": "DORMANT",
        "6": "NOT PRESENT",
        "7": "LOWER LAYER DOWN",
    }.get(str(valor), f"DESCONHECIDO({valor})")


def status_administrativo(valor: str) -> str:
    return {
        "1": "habilitada",
        "2": "desabilitada",
        "3": "testing",
    }.get(str(valor), f"desconhecido({valor})")


def parse_routeros_size(valor: str) -> int:
    """
    Converte valores como 1024KiB, 256MiB e 1GiB para bytes.
    """
    match = re.fullmatch(r"\s*([\d.]+)\s*([KMGT]?i?B)?\s*", valor, flags=re.I)
    if not match:
        return 0

    numero = float(match.group(1))
    unidade = (match.group(2) or "B").upper()

    fatores = {
        "B": 1,
        "KB": 1000,
        "KIB": 1024,
        "MB": 1000**2,
        "MIB": 1024**2,
        "GB": 1000**3,
        "GIB": 1024**3,
        "TB": 1000**4,
        "TIB": 1024**4,
    }

    return int(numero * fatores.get(unidade, 1))


def parse_key_values(texto: str) -> dict[str, str]:
    """
    Extrai pares chave=valor de uma saída curta do RouterOS.
    """
    resultado: dict[str, str] = {}

    for linha in texto.splitlines():
        linha = linha.strip()
        if not linha:
            continue

        # /system resource print usa "chave: valor"
        if ":" in linha and "=" not in linha:
            chave, valor = linha.split(":", 1)
            resultado[chave.strip()] = valor.strip()
            continue

        try:
            tokens = shlex.split(linha)
        except ValueError:
            tokens = linha.split()

        for token in tokens:
            if "=" not in token:
                continue
            chave, valor = token.split("=", 1)
            resultado[chave.lstrip(".")] = valor.strip('"')

    return resultado


def parse_terse_records(texto: str) -> list[dict[str, str]]:
    """
    Converte linhas de 'print terse' em uma lista de dicionários.

    O RouterOS pode iniciar cada linha com índice e flags. Esses tokens são
    preservados nos campos internos '_index' e '_flags'.
    """
    registros: list[dict[str, str]] = []

    for linha in texto.splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("Flags:") or linha.startswith("Columns:"):
            continue

        try:
            tokens = shlex.split(linha)
        except ValueError:
            tokens = linha.split()

        registro: dict[str, str] = {}
        flags: list[str] = []

        for token in tokens:
            if "=" in token:
                chave, valor = token.split("=", 1)
                registro[chave.lstrip(".")] = valor.strip('"')
            elif token.isdigit() and "_index" not in registro:
                registro["_index"] = token
            else:
                flags.append(token)

        if flags:
            registro["_flags"] = "".join(flags)

        if any(not chave.startswith("_") for chave in registro):
            registros.append(registro)

    return registros


# ============================================================
# SNMP
# ============================================================

async def criar_transporte(ip: str) -> UdpTransportTarget:
    return await UdpTransportTarget.create(
        (ip, SNMP_PORT),
        timeout=SNMP_TIMEOUT,
        retries=SNMP_RETRIES,
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

        if error_indication or error_status or not var_binds:
            return None

        return str(var_binds[0][1])

    except Exception:
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

        async for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication or error_status:
                break

            for oid, valor in var_binds:
                resultados[extrair_indice_oid(str(oid))] = str(valor)

    except Exception:
        pass

    finally:
        engine.close_dispatcher()

    return resultados


async def snmp_walks(ip: str, consultas: dict[str, str]) -> dict[str, dict[int, str]]:
    tarefas = {
        nome: asyncio.create_task(snmp_walk(ip, oid))
        for nome, oid in consultas.items()
    }

    return {
        nome: await tarefa
        for nome, tarefa in tarefas.items()
    }


async def coletar_interfaces_resumo(router: Router) -> tuple[bool, int, int, int]:
    dados = await snmp_walks(
        router.ip,
        {
            "nome": OID_IF_NAME,
            "admin": OID_IF_ADMIN_STATUS,
            "oper": OID_IF_OPER_STATUS,
        },
    )

    nomes = dados["nome"]
    if not nomes:
        return False, 0, 0, 0

    up = 0
    down = 0

    for indice, nome in nomes.items():
        if not interface_ethernet(nome):
            continue

        admin = dados["admin"].get(indice)
        oper = dados["oper"].get(indice)

        # Interface desabilitada é contabilizada como DOWN no relatório.
        if admin == "1" and oper == "1":
            up += 1
        else:
            down += 1

    return True, up, down, up + down


async def coletar_interfaces_completas(router: Router) -> dict[int, dict[str, str]]:
    consultas = {
        "nome": OID_IF_NAME,
        "mtu": OID_IF_MTU,
        "mac": OID_IF_MAC,
        "admin": OID_IF_ADMIN_STATUS,
        "oper": OID_IF_OPER_STATUS,
        "bytes_in": OID_IF_BYTES_IN,
        "packets_in": OID_IF_PACKETS_IN,
        "bytes_out": OID_IF_BYTES_OUT,
        "packets_out": OID_IF_PACKETS_OUT,
        "discards_in": OID_IF_DISCARDS_IN,
        "errors_in": OID_IF_ERRORS_IN,
        "discards_out": OID_IF_DISCARDS_OUT,
        "errors_out": OID_IF_ERRORS_OUT,
    }

    dados = await snmp_walks(router.ip, consultas)
    interfaces: dict[int, dict[str, str]] = {}

    for campo, valores in dados.items():
        for indice, valor in valores.items():
            interfaces.setdefault(indice, {})[campo] = valor

    return interfaces


async def medir_trafego(router: Router) -> dict[int, dict[str, float]]:
    primeira = await snmp_walks(
        router.ip,
        {
            "in": OID_IF_BYTES_IN,
            "out": OID_IF_BYTES_OUT,
        },
    )

    inicio = time.monotonic()
    await asyncio.sleep(TRAFFIC_SAMPLE_SECONDS)

    segunda = await snmp_walks(
        router.ip,
        {
            "in": OID_IF_BYTES_IN,
            "out": OID_IF_BYTES_OUT,
        },
    )
    intervalo = max(time.monotonic() - inicio, 0.001)

    taxas: dict[int, dict[str, float]] = {}
    indices = set(primeira["in"]) | set(primeira["out"]) | set(segunda["in"]) | set(segunda["out"])

    for indice in indices:
        in_1 = valor_inteiro(primeira["in"].get(indice))
        in_2 = valor_inteiro(segunda["in"].get(indice))
        out_1 = valor_inteiro(primeira["out"].get(indice))
        out_2 = valor_inteiro(segunda["out"].get(indice))

        # Counter64 pode voltar a zero após reboot/recriação da interface.
        delta_in = max(in_2 - in_1, 0)
        delta_out = max(out_2 - out_1, 0)

        taxas[indice] = {
            "rx_bps": delta_in * 8 / intervalo,
            "tx_bps": delta_out * 8 / intervalo,
        }

    return taxas


# ============================================================
# SSH
# ============================================================

def criar_cliente_ssh() -> paramiko.SSHClient:
    """Cria um cliente Paramiko com a política usada pelo laboratório."""
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return cliente


def conectar_ssh_sync(
    router: Router,
    usuario: str,
    senha: str,
) -> tuple[paramiko.SSHClient | None, str, str]:
    """
    Tenta autenticar primeiro com a chave privada e depois com senha.

    Retorna (cliente, metodo, erro). Quando a conexão falha, cliente é None.
    Um cliente novo é criado para cada tentativa porque uma falha de
    autenticação pode deixar o transporte anterior inutilizável.
    """
    erros: list[str] = []

    if SSH_PRIVATE_KEY.is_file():
        cliente = criar_cliente_ssh()
        try:
            cliente.connect(
                hostname=router.ip,
                port=SSH_PORT,
                username=usuario,
                key_filename=str(SSH_PRIVATE_KEY),
                timeout=SSH_TIMEOUT,
                auth_timeout=SSH_TIMEOUT,
                banner_timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            return cliente, "chave SSH", ""
        except paramiko.AuthenticationException:
            erros.append("chave SSH rejeitada")
            cliente.close()
        except Exception as exc:
            erros.append(f"chave SSH: {exc}")
            cliente.close()
    else:
        erros.append(f"chave não encontrada em {SSH_PRIVATE_KEY}")

    if senha:
        cliente = criar_cliente_ssh()
        try:
            cliente.connect(
                hostname=router.ip,
                port=SSH_PORT,
                username=usuario,
                password=senha,
                timeout=SSH_TIMEOUT,
                auth_timeout=SSH_TIMEOUT,
                banner_timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            return cliente, "senha", ""
        except paramiko.AuthenticationException:
            erros.append("senha rejeitada")
            cliente.close()
        except Exception as exc:
            erros.append(f"senha: {exc}")
            cliente.close()
    else:
        erros.append("senha não informada")

    return None, "", "; ".join(erros)


def executar_comando_no_cliente(
    cliente: paramiko.SSHClient,
    comando: str,
) -> SSHResult:
    """Executa um comando usando uma sessão SSH já autenticada."""
    try:
        _, stdout, stderr = cliente.exec_command(comando, timeout=15)
        saida = stdout.read().decode("utf-8", errors="replace").strip()
        erro = stderr.read().decode("utf-8", errors="replace").strip()

        if erro and not saida:
            return SSHResult(False, error=erro)

        return SSHResult(True, output=saida, error=erro)
    except Exception as exc:
        return SSHResult(False, error=str(exc))


def executar_ssh_sync(
    router: Router,
    usuario: str,
    senha: str,
    comando: str,
) -> SSHResult:
    cliente, _, erro = conectar_ssh_sync(router, usuario, senha)
    if cliente is None:
        return SSHResult(False, error=f"falha de autenticação ({erro})")

    try:
        return executar_comando_no_cliente(cliente, comando)
    finally:
        cliente.close()


async def executar_ssh(
    router: Router,
    usuario: str,
    senha: str,
    comando: str,
) -> SSHResult:
    return await asyncio.to_thread(
        executar_ssh_sync,
        router,
        usuario,
        senha,
        comando,
    )


def coletar_dados_ssh_sync(
    router: Router,
    usuario: str,
    senha: str,
) -> dict[str, SSHResult]:
    """
    Abre uma única sessão SSH por roteador e executa todas as consultas
    sequencialmente nela. Isso evita cinco handshakes simultâneos por CHR.
    """
    comandos = {
        "resource": "/system resource print",
        "ospf": "/routing ospf neighbor print terse without-paging",
        "bgp": "/routing bgp session print terse without-paging",
        "ldp_neighbors": "/mpls ldp neighbor print terse without-paging",
        "mpls_forwarding": "/mpls forwarding-table print terse without-paging",
        "ldp_local": "/mpls ldp local-mapping print terse without-paging",
        "ldp_remote": "/mpls ldp remote-mapping print terse without-paging",
        "pppoe": "/ppp active print terse without-paging",
        "dhcp": "/ip dhcp-server lease print terse without-paging",
    }

    cliente, _, erro = conectar_ssh_sync(router, usuario, senha)
    if cliente is None:
        falha = SSHResult(False, error=f"falha de autenticação ({erro})")
        return {nome: falha for nome in comandos}

    try:
        return {
            nome: executar_comando_no_cliente(cliente, comando)
            for nome, comando in comandos.items()
        }
    finally:
        cliente.close()


async def coletar_dados_ssh(
    router: Router,
    usuario: str,
    senha: str,
) -> dict[str, SSHResult]:
    return await asyncio.to_thread(
        coletar_dados_ssh_sync,
        router,
        usuario,
        senha,
    )


# ============================================================
# COLETA E INTERPRETAÇÃO
# ============================================================

def interpretar_resource(saida: str, report: RouterReport) -> None:
    dados = parse_key_values(saida)

    versao = dados.get("version")
    canal = dados.get("channel")
    if versao:
        report.routeros = f"{versao} ({canal})" if canal else versao

    if dados.get("uptime"):
        report.uptime = dados["uptime"]

    cpu = dados.get("cpu-load", "").rstrip("%")
    if cpu.isdigit():
        report.cpu = int(cpu)

    total = parse_routeros_size(dados.get("total-memory", ""))
    livre = parse_routeros_size(dados.get("free-memory", ""))

    if total > 0:
        report.memoria_pct = round((total - livre) / total * 100)


def interpretar_ospf(saida: str, report: RouterReport) -> None:
    registros = parse_terse_records(saida)
    report.ospf_total = len(registros)
    report.ospf_full = sum(
        1 for registro in registros
        if registro.get("state", "").lower() == "full"
    )
    report.ospf_configurado = report.ospf_total > 0


def interpretar_bgp(saida: str, report: RouterReport) -> None:
    registros = parse_terse_records(saida)
    report.bgp_total = len(registros)

    estabelecidas = 0
    for registro in registros:
        estado = registro.get("state", "").lower()
        flags = registro.get("_flags", "").upper()

        if estado == "established" or "E" in flags:
            estabelecidas += 1

    report.bgp_established = estabelecidas
    report.bgp_configurado = report.bgp_total > 0


def interpretar_ldp_neighbors(saida: str, report: RouterReport) -> None:
    """Interpreta vizinhos LDP e identifica sessões operacionais."""
    registros = parse_terse_records(saida)
    report.ldp_total = len(registros)
    report.ldp_neighbors = []

    operacionais = 0
    for registro in registros:
        flags = registro.get("_flags", "").upper()
        estado = registro.get("state", "").lower()
        operacional = (
            "O" in flags
            or estado == "operational"
            or registro.get("operational", "").lower() in {"yes", "true"}
        )

        if operacional:
            operacionais += 1

        report.ldp_neighbors.append({
            "transport": registro.get("transport", "—"),
            "local_transport": registro.get("local-transport", "—"),
            "peer": registro.get("peer", "—"),
            "addresses": registro.get("addresses", "—"),
            "status": "OPERATIONAL" if operacional else (estado.upper() or "INATIVO"),
            "flags": flags or "—",
        })

    report.ldp_operational = operacionais
    report.ldp_configurado = report.ldp_total > 0


def interpretar_mpls_forwarding(saida: str, report: RouterReport) -> None:
    report.mpls_forwarding_entries = len(parse_terse_records(saida))
    if report.mpls_forwarding_entries > 0:
        report.ldp_configurado = True


def interpretar_ldp_mappings(
    local_saida: str,
    remote_saida: str,
    report: RouterReport,
) -> None:
    report.ldp_local_mappings = len(parse_terse_records(local_saida))
    report.ldp_remote_mappings = len(parse_terse_records(remote_saida))

    if report.ldp_local_mappings > 0 or report.ldp_remote_mappings > 0:
        report.ldp_configurado = True


def interpretar_pppoe(saida: str, report: RouterReport) -> None:
    registros = parse_terse_records(saida)

    for registro in registros:
        if registro.get("service", "").lower() != "pppoe":
            continue

        report.pppoe.append({
            "nome": registro.get("name", "desconhecido"),
            "ip": registro.get("address", "sem IP"),
            "uptime": registro.get("uptime", "—"),
            "caller_id": registro.get("caller-id", "—"),
        })


def interpretar_dhcp_leases(saida: str, report: RouterReport) -> None:
    """Registra apenas leases DHCP atualmente ativas (status=bound)."""
    registros = parse_terse_records(saida)

    for registro in registros:
        if registro.get("status", "").lower() != "bound":
            continue

        report.dhcp_leases.append({
            "ip": registro.get("address", "sem IP"),
            "mac": registro.get("mac-address", "—"),
            "hostname": registro.get("host-name", "—"),
            "servidor": registro.get("server", "—"),
            "expira_em": registro.get("expires-after", "—"),
            "ultima_vez": registro.get("last-seen", "—"),
            "status": registro.get("status", "—"),
        })


async def coletar_relatorio_router(
    router: Router,
    usuario: str,
    senha: str,
) -> RouterReport:
    report = RouterReport(router=router)

    tarefa_snmp = asyncio.create_task(coletar_interfaces_resumo(router))
    tarefa_ssh = asyncio.create_task(coletar_dados_ssh(router, usuario, senha))

    snmp_ok, up, down, total = await tarefa_snmp
    report.snmp_online = snmp_ok
    report.interfaces_up = up
    report.interfaces_down = down
    report.interfaces_total = total

    dados_ssh = await tarefa_ssh
    resource = dados_ssh["resource"]

    report.ssh_online = resource.ok

    if resource.ok:
        interpretar_resource(resource.output, report)
    else:
        report.falhas.append(f"SSH: {resource.error}")

    if dados_ssh["ospf"].ok:
        interpretar_ospf(dados_ssh["ospf"].output, report)
    elif report.ssh_online:
        report.falhas.append("falha ao consultar OSPF")

    if dados_ssh["bgp"].ok:
        interpretar_bgp(dados_ssh["bgp"].output, report)
    elif report.ssh_online:
        report.falhas.append("falha ao consultar BGP")

    if dados_ssh["ldp_neighbors"].ok:
        interpretar_ldp_neighbors(dados_ssh["ldp_neighbors"].output, report)
    elif report.ssh_online:
        report.falhas.append("falha ao consultar vizinhos LDP")

    if dados_ssh["mpls_forwarding"].ok:
        interpretar_mpls_forwarding(dados_ssh["mpls_forwarding"].output, report)
    elif report.ssh_online:
        report.falhas.append("falha ao consultar forwarding MPLS")

    if dados_ssh["ldp_local"].ok and dados_ssh["ldp_remote"].ok:
        interpretar_ldp_mappings(
            dados_ssh["ldp_local"].output,
            dados_ssh["ldp_remote"].output,
            report,
        )
    elif report.ssh_online:
        report.falhas.append("falha ao consultar mappings LDP")

    if dados_ssh["pppoe"].ok:
        interpretar_pppoe(dados_ssh["pppoe"].output, report)
    elif report.ssh_online:
        report.falhas.append("falha ao consultar PPPoE")

    if dados_ssh["dhcp"].ok:
        interpretar_dhcp_leases(dados_ssh["dhcp"].output, report)
    elif report.ssh_online:
        report.falhas.append("falha ao consultar leases DHCP")

    if not report.snmp_online:
        report.falhas.append("SNMP indisponível")

    return report


# ============================================================
# EXIBIÇÃO DO DASHBOARD
# ============================================================

def linha_tabela(tabela: Table, rotulo: str, valor: Text | str) -> None:
    tabela.add_row(Text(rotulo, style="cyan"), valor)


def exibir_router_card(report: RouterReport) -> None:
    tabela = Table.grid(padding=(0, 2))
    tabela.add_column(width=23)
    tabela.add_column()

    linha_tabela(
        tabela,
        "Status SSH",
        status_texto(report.ssh_online, "conectado", "indisponível"),
    )
    linha_tabela(
        tabela,
        "Status SNMP",
        status_texto(report.snmp_online, "respondendo", "indisponível"),
    )
    linha_tabela(tabela, "RouterOS", report.routeros)
    linha_tabela(tabela, "Uptime", report.uptime)
    linha_tabela(tabela, "CPU", formatar_percentual(report.cpu, CPU_WARNING, CPU_CRITICAL))
    linha_tabela(
        tabela,
        "Memória utilizada",
        formatar_percentual(report.memoria_pct, MEMORY_WARNING, MEMORY_CRITICAL),
    )

    if report.snmp_online:
        estilo_iface = "bold green" if report.interfaces_down == 0 else "bold yellow"
        linha_tabela(
            tabela,
            "Interfaces Ethernet",
            Text(
                f"{'✓' if report.interfaces_down == 0 else '⚠'} "
                f"{report.interfaces_up} UP / {report.interfaces_down} DOWN",
                style=estilo_iface,
            ),
        )
    else:
        linha_tabela(tabela, "Interfaces Ethernet", Text("— indisponível", style="dim"))

    if report.ospf_configurado:
        ospf_ok = report.ospf_full == report.ospf_total
        linha_tabela(
            tabela,
            "Vizinhos OSPF Full",
            Text(
                f"{'✓' if ospf_ok else '⚠'} {report.ospf_full}/{report.ospf_total}",
                style="bold green" if ospf_ok else "bold yellow",
            ),
        )
    else:
        linha_tabela(tabela, "OSPF", Text("— não configurado", style="dim"))

    if report.bgp_configurado:
        bgp_ok = report.bgp_established == report.bgp_total
        linha_tabela(
            tabela,
            "Sessões BGP",
            Text(
                f"{'✓' if bgp_ok else '⚠'} {report.bgp_established}/{report.bgp_total}",
                style="bold green" if bgp_ok else "bold yellow",
            ),
        )
    else:
        linha_tabela(tabela, "BGP", Text("— não configurado", style="dim"))

    if report.ldp_configurado:
        ldp_ok = report.ldp_total > 0 and report.ldp_operational == report.ldp_total
        linha_tabela(
            tabela,
            "Vizinhos LDP",
            Text(
                f"{'✓' if ldp_ok else '⚠'} "
                f"{report.ldp_operational}/{report.ldp_total} operacionais",
                style="bold green" if ldp_ok else "bold yellow",
            ),
        )
        linha_tabela(
            tabela,
            "Forwarding MPLS",
            Text(
                f"✓ {report.mpls_forwarding_entries} entrada(s)",
                style="bold green",
            ),
        )
    else:
        linha_tabela(tabela, "MPLS / LDP", Text("— não configurado", style="dim"))

    linha_tabela(
        tabela,
        "Clientes PPPoE",
        Text(f"✓ {len(report.pppoe)} ativo(s)", style="bold green"),
    )

    for cliente in report.pppoe:
        linha_tabela(
            tabela,
            f"  ↳ {cliente['nome']}",
            f"{cliente['ip']} | {cliente['uptime']}",
        )

    linha_tabela(
        tabela,
        "Leases DHCP ativas",
        Text(f"✓ {len(report.dhcp_leases)} bound", style="bold green"),
    )

    for lease in report.dhcp_leases:
        identificacao = lease["hostname"] if lease["hostname"] != "—" else lease["mac"]
        linha_tabela(
            tabela,
            f"  ↳ {identificacao}",
            f"{lease['ip']} | expira em {lease['expira_em']}",
        )

    if report.falhas:
        linha_tabela(
            tabela,
            "Avisos",
            Text("; ".join(report.falhas), style="bold yellow"),
        )

    console.print(
        Panel(
            tabela,
            title=f"[bold]{report.router.nome} — {report.router.ip}[/bold]",
            border_style="bright_blue" if (report.ssh_online or report.snmp_online) else "red",
            box=box.ROUNDED,
            expand=False,
            width=72,
        )
    )


def exibir_resumo(reports: list[RouterReport], inicio: float) -> None:
    online = sum(1 for r in reports if r.ssh_online or r.snmp_online)
    total_interfaces = sum(r.interfaces_total for r in reports)
    total_up = sum(r.interfaces_up for r in reports)
    ospf_total = sum(r.ospf_total for r in reports)
    ospf_full = sum(r.ospf_full for r in reports)
    bgp_total = sum(r.bgp_total for r in reports)
    bgp_established = sum(r.bgp_established for r in reports)
    ldp_total = sum(r.ldp_total for r in reports)
    ldp_operational = sum(r.ldp_operational for r in reports)
    mpls_forwarding = sum(r.mpls_forwarding_entries for r in reports)
    pppoe = sum(len(r.pppoe) for r in reports)
    dhcp = sum(len(r.dhcp_leases) for r in reports)

    alertas_cpu = [r for r in reports if r.cpu is not None and r.cpu >= CPU_WARNING]
    alertas_memoria = [
        r for r in reports
        if r.memoria_pct is not None and r.memoria_pct >= MEMORY_WARNING
    ]
    falhas = [r for r in reports if r.falhas]

    tabela = Table.grid(padding=(0, 2))
    tabela.add_column(width=23)
    tabela.add_column()

    linha_tabela(
        tabela,
        "Equipamentos",
        Text(
            f"{'✓' if online == len(reports) else '⚠'} {online}/{len(reports)} online",
            style="bold green" if online == len(reports) else "bold yellow",
        ),
    )
    linha_tabela(
        tabela,
        "Interfaces Ethernet",
        Text(
            f"{'✓' if total_up == total_interfaces else '⚠'} {total_up}/{total_interfaces} UP",
            style="bold green" if total_up == total_interfaces else "bold yellow",
        ),
    )
    linha_tabela(
        tabela,
        "Vizinhos OSPF Full",
        Text(
            f"{'✓' if ospf_full == ospf_total else '⚠'} {ospf_full}/{ospf_total}",
            style="bold green" if ospf_full == ospf_total else "bold yellow",
        ),
    )
    linha_tabela(
        tabela,
        "Sessões BGP",
        Text(
            f"{'✓' if bgp_established == bgp_total else '⚠'} "
            f"{bgp_established}/{bgp_total}",
            style="bold green" if bgp_established == bgp_total else "bold yellow",
        ),
    )
    if ldp_total > 0:
        linha_tabela(
            tabela,
            "Vizinhos LDP",
            Text(
                f"{'✓' if ldp_operational == ldp_total else '⚠'} "
                f"{ldp_operational}/{ldp_total} operacionais",
                style="bold green" if ldp_operational == ldp_total else "bold yellow",
            ),
        )
        linha_tabela(
            tabela,
            "Forwarding MPLS",
            Text(f"✓ {mpls_forwarding} entrada(s)", style="bold green"),
        )
    else:
        linha_tabela(tabela, "MPLS / LDP", Text("— não configurado", style="dim"))

    linha_tabela(tabela, "Clientes PPPoE", Text(f"✓ {pppoe} ativo(s)", style="bold green"))
    linha_tabela(
        tabela,
        "Leases DHCP ativas",
        Text(f"✓ {dhcp} bound", style="bold green"),
    )
    linha_tabela(
        tabela,
        "CPU",
        Text(
            "✓ sem alertas" if not alertas_cpu
            else "⚠ " + ", ".join(f"{r.router.nome}={r.cpu}%" for r in alertas_cpu),
            style="bold green" if not alertas_cpu else "bold yellow",
        ),
    )
    linha_tabela(
        tabela,
        "Memória",
        Text(
            "✓ sem alertas" if not alertas_memoria
            else "⚠ " + ", ".join(
                f"{r.router.nome}={r.memoria_pct}%" for r in alertas_memoria
            ),
            style="bold green" if not alertas_memoria else "bold yellow",
        ),
    )
    linha_tabela(
        tabela,
        "Falhas de coleta",
        Text(
            "✓ nenhuma" if not falhas
            else "⚠ " + ", ".join(r.router.nome for r in falhas),
            style="bold green" if not falhas else "bold yellow",
        ),
    )

    tabela.add_section()
    linha_tabela(tabela, "Data da coleta", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    linha_tabela(tabela, "Tempo total", f"{time.monotonic() - inicio:.2f} segundos")

    console.print(
        Panel(
            tabela,
            title="[bold]RESUMO DO LABORATÓRIO[/bold]",
            border_style="magenta",
            box=box.ROUNDED,
            expand=False,
            width=72,
        )
    )


async def mostrar_dashboard(usuario: str, senha: str) -> None:
    limpar_tela()
    console.print(Align.center("[bold cyan]MIKROTIK LAB MONITOR[/bold cyan]"))
    console.print(Align.center("[dim]Coletando informações dos equipamentos...[/dim]\n"))

    inicio = time.monotonic()

    tarefas = [
        asyncio.create_task(coletar_relatorio_router(router, usuario, senha))
        for router in ROTEADORES
    ]
    reports = await asyncio.gather(*tarefas)

    for report in reports:
        exibir_router_card(report)

    exibir_resumo(reports, inicio)


# ============================================================
# TELAS DE DETALHES
# ============================================================

async def mostrar_informacoes_gerais(router: Router, usuario: str, senha: str) -> None:
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — INFORMAÇÕES GERAIS[/bold cyan]")

    nome_task = asyncio.create_task(snmp_get(router.ip, OID_SYS_NAME))
    descr_task = asyncio.create_task(snmp_get(router.ip, OID_SYS_DESCR))
    uptime_task = asyncio.create_task(snmp_get(router.ip, OID_SYS_UPTIME))
    resource_task = asyncio.create_task(
        executar_ssh(router, usuario, senha, "/system resource print")
    )

    nome, descricao, uptime_snmp, resource = await asyncio.gather(
        nome_task, descr_task, uptime_task, resource_task
    )

    tabela = Table(box=box.ROUNDED, show_header=False)
    tabela.add_column("Campo", style="cyan", width=22)
    tabela.add_column("Valor")

    tabela.add_row("Equipamento", router.nome)
    tabela.add_row("IP de gerenciamento", router.ip)
    tabela.add_row("Hostname SNMP", nome or "indisponível")
    tabela.add_row("Descrição SNMP", descricao or "indisponível")
    tabela.add_row(
        "Uptime SNMP",
        formatar_timeticks(uptime_snmp) if uptime_snmp else "indisponível",
    )

    if resource.ok:
        dados = parse_key_values(resource.output)
        campos = [
            ("RouterOS", dados.get("version")),
            ("Canal", dados.get("channel")),
            ("Arquitetura", dados.get("architecture-name")),
            ("Plataforma", dados.get("platform")),
            ("CPU", dados.get("cpu")),
            ("Núcleos", dados.get("cpu-count")),
            ("Frequência", dados.get("cpu-frequency")),
            ("Carga de CPU", dados.get("cpu-load")),
            ("Memória livre", dados.get("free-memory")),
            ("Memória total", dados.get("total-memory")),
            ("Disco livre", dados.get("free-hdd-space")),
            ("Disco total", dados.get("total-hdd-space")),
        ]

        for rotulo, valor in campos:
            if valor:
                tabela.add_row(rotulo, valor)
    else:
        tabela.add_row("SSH", Text(resource.error or "indisponível", style="red"))

    console.print(tabela)


async def mostrar_interfaces(router: Router) -> None:
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — INTERFACES[/bold cyan]")
    console.print("[dim]Coletando interfaces e medindo tráfego por 2 segundos...[/dim]\n")

    interfaces_task = asyncio.create_task(coletar_interfaces_completas(router))
    taxas_task = asyncio.create_task(medir_trafego(router))
    interfaces, taxas = await asyncio.gather(interfaces_task, taxas_task)

    if not interfaces:
        console.print("[bold red]Não foi possível consultar as interfaces via SNMP.[/bold red]")
        return

    tabela = Table(box=box.ROUNDED, header_style="bold cyan", row_styles=["", "dim"])
    tabela.add_column("Índice", justify="right")
    tabela.add_column("Interface")
    tabela.add_column("Admin")
    tabela.add_column("Estado")
    tabela.add_column("RX atual", justify="right")
    tabela.add_column("TX atual", justify="right")
    tabela.add_column("RX total", justify="right")
    tabela.add_column("TX total", justify="right")
    tabela.add_column("Erros", justify="right")
    tabela.add_column("Descartes", justify="right")

    for indice in sorted(interfaces):
        iface = interfaces[indice]
        nome = iface.get("nome", f"ifIndex-{indice}")
        admin = status_administrativo(iface.get("admin", "?"))
        oper = status_operacional(iface.get("oper", "?"))

        estado_style = "bold green" if oper == "UP" else "bold red"
        admin_style = "green" if admin == "habilitada" else "yellow"

        taxa = taxas.get(indice, {})
        rx_atual = formatar_taxa(taxa.get("rx_bps", 0.0))
        tx_atual = formatar_taxa(taxa.get("tx_bps", 0.0))

        rx_total = formatar_bytes(valor_inteiro(iface.get("bytes_in")))
        tx_total = formatar_bytes(valor_inteiro(iface.get("bytes_out")))

        erros = (
            valor_inteiro(iface.get("errors_in"))
            + valor_inteiro(iface.get("errors_out"))
        )
        descartes = (
            valor_inteiro(iface.get("discards_in"))
            + valor_inteiro(iface.get("discards_out"))
        )

        tabela.add_row(
            str(indice),
            nome,
            Text(admin, style=admin_style),
            Text(oper, style=estado_style),
            rx_atual,
            tx_atual,
            rx_total,
            tx_total,
            Text(str(erros), style="red" if erros else "green"),
            Text(str(descartes), style="yellow" if descartes else "green"),
        )

    console.print(tabela)


async def mostrar_saida_ssh(
    router: Router,
    usuario: str,
    senha: str,
    titulo: str,
    comando: str,
) -> None:
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — {titulo}[/bold cyan]")

    resultado = await executar_ssh(router, usuario, senha, comando)

    if resultado.ok:
        console.print(
            Panel(
                resultado.output or "Nenhum registro encontrado.",
                border_style="blue",
                box=box.ROUNDED,
            )
        )
    else:
        console.print(f"[bold red]Falha SSH:[/bold red] {resultado.error}")


async def mostrar_pppoe_formatado(router: Router, usuario: str, senha: str) -> None:
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — CLIENTES PPPoE[/bold cyan]")

    resultado = await executar_ssh(
        router,
        usuario,
        senha,
        "/ppp active print terse without-paging",
    )

    if not resultado.ok:
        console.print(f"[bold red]Falha SSH:[/bold red] {resultado.error}")
        return

    registros = [
        r for r in parse_terse_records(resultado.output)
        if r.get("service", "").lower() == "pppoe"
    ]

    if not registros:
        console.print("[dim]Nenhuma sessão PPPoE ativa.[/dim]")
        return

    tabela = Table(box=box.ROUNDED, header_style="bold cyan")
    tabela.add_column("Usuário")
    tabela.add_column("Endereço IP")
    tabela.add_column("Caller-ID")
    tabela.add_column("Uptime")
    tabela.add_column("Session-ID")

    for registro in registros:
        tabela.add_row(
            registro.get("name", "—"),
            registro.get("address", "—"),
            registro.get("caller-id", "—"),
            registro.get("uptime", "—"),
            registro.get("session-id", "—"),
        )

    console.print(tabela)


async def mostrar_clientes_dhcp(router: Router, usuario: str, senha: str) -> None:
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — LEASES DHCP ATIVAS[/bold cyan]")

    resultado = await executar_ssh(
        router,
        usuario,
        senha,
        "/ip dhcp-server lease print terse without-paging",
    )

    if not resultado.ok:
        console.print(f"[bold red]Falha SSH:[/bold red] {resultado.error}")
        return

    registros = [
        r for r in parse_terse_records(resultado.output)
        if r.get("status", "").lower() == "bound"
    ]

    if not registros:
        console.print("[dim]Nenhuma lease DHCP ativa neste equipamento.[/dim]")
        return

    tabela = Table(box=box.ROUNDED, header_style="bold cyan")
    tabela.add_column("Endereço IP")
    tabela.add_column("MAC")
    tabela.add_column("Hostname")
    tabela.add_column("Servidor")
    tabela.add_column("Expira em")
    tabela.add_column("Último contato")

    for registro in registros:
        tabela.add_row(
            registro.get("address", "—"),
            registro.get("mac-address", "—"),
            registro.get("host-name", "—"),
            registro.get("server", "—"),
            registro.get("expires-after", "—"),
            registro.get("last-seen", "—"),
        )

    console.print(tabela)


async def mostrar_mpls_ldp(router: Router, usuario: str, senha: str) -> None:
    """Exibe vizinhos, contadores e tabelas principais de MPLS/LDP."""
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — MPLS / LDP[/bold cyan]")
    console.print("[dim]Consultando vizinhos, forwarding e mappings via SSH...[/dim]\n")

    comandos = {
        "neighbors": "/mpls ldp neighbor print terse without-paging",
        "forwarding": "/mpls forwarding-table print without-paging",
        "forwarding_terse": "/mpls forwarding-table print terse without-paging",
        "local": "/mpls ldp local-mapping print without-paging",
        "local_terse": "/mpls ldp local-mapping print terse without-paging",
        "remote": "/mpls ldp remote-mapping print without-paging",
        "remote_terse": "/mpls ldp remote-mapping print terse without-paging",
    }

    def coletar_sync() -> dict[str, SSHResult]:
        cliente, _, erro = conectar_ssh_sync(router, usuario, senha)
        if cliente is None:
            falha = SSHResult(False, error=f"falha de autenticação ({erro})")
            return {nome: falha for nome in comandos}

        try:
            return {
                nome: executar_comando_no_cliente(cliente, comando)
                for nome, comando in comandos.items()
            }
        finally:
            cliente.close()

    resultados = await asyncio.to_thread(coletar_sync)

    if not resultados["neighbors"].ok:
        console.print(
            f"[bold red]Falha ao consultar MPLS/LDP:[/bold red] "
            f"{resultados['neighbors'].error}"
        )
        return

    vizinhos = parse_terse_records(resultados["neighbors"].output)
    forwarding_count = (
        len(parse_terse_records(resultados["forwarding_terse"].output))
        if resultados["forwarding_terse"].ok else 0
    )
    local_count = (
        len(parse_terse_records(resultados["local_terse"].output))
        if resultados["local_terse"].ok else 0
    )
    remote_count = (
        len(parse_terse_records(resultados["remote_terse"].output))
        if resultados["remote_terse"].ok else 0
    )

    operacionais = 0
    for vizinho in vizinhos:
        flags = vizinho.get("_flags", "").upper()
        estado = vizinho.get("state", "").lower()
        if "O" in flags or estado == "operational":
            operacionais += 1

    resumo = Table.grid(padding=(0, 2))
    resumo.add_column(width=23)
    resumo.add_column()
    linha_tabela(
        resumo,
        "Estado LDP",
        Text(
            "✓ OPERACIONAL" if vizinhos and operacionais == len(vizinhos)
            else ("⚠ PARCIAL" if vizinhos else "— sem vizinhos"),
            style=(
                "bold green" if vizinhos and operacionais == len(vizinhos)
                else ("bold yellow" if vizinhos else "dim")
            ),
        ),
    )
    linha_tabela(resumo, "Vizinhos", f"{operacionais}/{len(vizinhos)} operacionais")
    linha_tabela(resumo, "Forwarding MPLS", f"{forwarding_count} entrada(s)")
    linha_tabela(resumo, "Mappings locais", str(local_count))
    linha_tabela(resumo, "Mappings remotos", str(remote_count))

    console.print(
        Panel(
            resumo,
            title="[bold]RESUMO MPLS / LDP[/bold]",
            border_style="magenta",
            box=box.ROUNDED,
            expand=False,
            width=72,
        )
    )

    if vizinhos:
        tabela_vizinhos = Table(
            box=box.ROUNDED,
            header_style="bold cyan",
            title="Vizinhos LDP",
        )
        tabela_vizinhos.add_column("Transport")
        tabela_vizinhos.add_column("Local transport")
        tabela_vizinhos.add_column("Peer")
        tabela_vizinhos.add_column("Estado")
        tabela_vizinhos.add_column("Flags")

        for vizinho in vizinhos:
            flags = vizinho.get("_flags", "").upper()
            estado = vizinho.get("state", "").lower()
            operacional = "O" in flags or estado == "operational"
            tabela_vizinhos.add_row(
                vizinho.get("transport", "—"),
                vizinho.get("local-transport", "—"),
                vizinho.get("peer", "—"),
                Text(
                    "OPERATIONAL" if operacional else (estado.upper() or "INATIVO"),
                    style="bold green" if operacional else "bold red",
                ),
                flags or "—",
            )

        console.print(tabela_vizinhos)
    else:
        console.print("[dim]Nenhum vizinho LDP encontrado neste equipamento.[/dim]")

    if resultados["forwarding"].ok:
        console.print(
            Panel(
                resultados["forwarding"].output or "Tabela vazia.",
                title="[bold]FORWARDING TABLE MPLS[/bold]",
                border_style="blue",
                box=box.ROUNDED,
            )
        )

    if resultados["local"].ok:
        console.print(
            Panel(
                resultados["local"].output or "Nenhum mapping local.",
                title="[bold]LDP LOCAL MAPPING[/bold]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    if resultados["remote"].ok:
        console.print(
            Panel(
                resultados["remote"].output or "Nenhum mapping remoto.",
                title="[bold]LDP REMOTE MAPPING[/bold]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )


async def consultar_oid_manual(router: Router) -> None:
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — CONSULTA SNMP[/bold cyan]")

    oid = Prompt.ask("Digite o OID").strip()
    if not oid:
        return

    modo = Prompt.ask(
        "Tipo de consulta",
        choices=["get", "walk"],
        default="get",
    )

    if modo == "get":
        valor = await snmp_get(router.ip, oid)
        if valor is None:
            console.print("[bold red]A consulta não retornou valor.[/bold red]")
        else:
            tabela = Table(box=box.ROUNDED, header_style="bold cyan")
            tabela.add_column("OID")
            tabela.add_column("Valor")
            tabela.add_row(oid, valor)
            console.print(tabela)
        return

    valores = await snmp_walk(router.ip, oid)
    if not valores:
        console.print("[bold red]O walk não retornou registros.[/bold red]")
        return

    tabela = Table(box=box.ROUNDED, header_style="bold cyan")
    tabela.add_column("Índice", justify="right")
    tabela.add_column("Valor")

    for indice, valor in sorted(valores.items()):
        tabela.add_row(str(indice), valor)

    console.print(tabela)


async def comando_manual_ssh(router: Router, usuario: str, senha: str) -> None:
    limpar_tela()
    console.rule(f"[bold cyan]{router.nome} — COMANDO MANUAL SSH[/bold cyan]")

    comando = Prompt.ask("Comando RouterOS").strip()
    if not comando:
        return

    resultado = await executar_ssh(router, usuario, senha, comando)

    if resultado.ok:
        console.print(
            Panel(
                resultado.output or "O comando não retornou dados.",
                border_style="blue",
                box=box.ROUNDED,
            )
        )
    else:
        console.print(f"[bold red]Falha SSH:[/bold red] {resultado.error}")


# ============================================================
# MENUS
# ============================================================

def menu_principal_visual() -> str:
    limpar_tela()

    tabela = Table.grid(padding=(0, 2))
    tabela.add_column(style="bold cyan", width=4)
    tabela.add_column()

    tabela.add_row("1", "Visão geral de todo o laboratório")
    tabela.add_row("2", "Consultar um equipamento")
    tabela.add_row("3", "Relatório de interfaces e tráfego")
    tabela.add_row("4", "Consulta manual SNMP")
    tabela.add_row("5", "Comando manual SSH")
    tabela.add_row("0", "Sair")

    console.print(
        Panel(
            tabela,
            title="[bold]MIKROTIK LAB MONITOR[/bold]",
            subtitle="[dim]SNMP + SSH[/dim]",
            border_style="bright_blue",
            box=box.ROUNDED,
            expand=False,
            width=58,
        )
    )

    return Prompt.ask("Escolha", choices=["0", "1", "2", "3", "4", "5"])


def escolher_router(titulo: str = "Escolha o equipamento") -> Router | None:
    limpar_tela()

    tabela = Table(box=box.ROUNDED, header_style="bold cyan")
    tabela.add_column("#", justify="right")
    tabela.add_column("Equipamento")
    tabela.add_column("IP de gerenciamento")

    for numero, router in enumerate(ROTEADORES, start=1):
        tabela.add_row(str(numero), router.nome, router.ip)

    tabela.add_row("0", "Voltar", "—")
    console.print(tabela)

    escolha = Prompt.ask(
        titulo,
        choices=[str(i) for i in range(0, len(ROTEADORES) + 1)],
    )

    if escolha == "0":
        return None

    return ROTEADORES[int(escolha) - 1]


async def menu_equipamento(router: Router, usuario: str, senha: str) -> None:
    while True:
        limpar_tela()

        tabela = Table.grid(padding=(0, 2))
        tabela.add_column(style="bold cyan", width=4)
        tabela.add_column()

        opcoes = [
            ("1", "Informações gerais"),
            ("2", "Interfaces e tráfego atual"),
            ("3", "Vizinhos OSPF"),
            ("4", "Sessões BGP"),
            ("5", "Clientes PPPoE"),
            ("6", "Leases DHCP ativas"),
            ("7", "Tabela ARP completa"),
            ("8", "Rotas"),
            ("9", "MPLS / LDP"),
            ("10", "Consulta manual SNMP"),
            ("11", "Comando manual SSH"),
            ("0", "Voltar"),
        ]

        for numero, texto in opcoes:
            tabela.add_row(numero, texto)

        console.print(
            Panel(
                tabela,
                title=f"[bold]{router.nome} — {router.ip}[/bold]",
                border_style="bright_blue",
                box=box.ROUNDED,
                expand=False,
                width=58,
            )
        )

        opcao = Prompt.ask(
            "Escolha",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
        )

        if opcao == "0":
            return
        if opcao == "1":
            await mostrar_informacoes_gerais(router, usuario, senha)
        elif opcao == "2":
            await mostrar_interfaces(router)
        elif opcao == "3":
            await mostrar_saida_ssh(
                router,
                usuario,
                senha,
                "VIZINHOS OSPF",
                "/routing ospf neighbor print detail without-paging",
            )
        elif opcao == "4":
            await mostrar_saida_ssh(
                router,
                usuario,
                senha,
                "SESSÕES BGP",
                "/routing bgp session print detail without-paging",
            )
        elif opcao == "5":
            await mostrar_pppoe_formatado(router, usuario, senha)
        elif opcao == "6":
            await mostrar_clientes_dhcp(router, usuario, senha)
        elif opcao == "7":
            await mostrar_saida_ssh(
                router,
                usuario,
                senha,
                "TABELA ARP",
                "/ip arp print detail without-paging",
            )
        elif opcao == "8":
            await mostrar_saida_ssh(
                router,
                usuario,
                senha,
                "ROTAS",
                "/ip route print detail without-paging",
            )
        elif opcao == "9":
            await mostrar_mpls_ldp(router, usuario, senha)
        elif opcao == "10":
            await consultar_oid_manual(router)
        elif opcao == "11":
            await comando_manual_ssh(router, usuario, senha)

        pausar()


async def main() -> None:
    limpar_tela()
    console.print(
        Panel.fit(
            "[bold cyan]MIKROTIK LAB MONITOR[/bold cyan]\n"
            "[dim]Informe as credenciais do usuário de automação.[/dim]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
    )

    usuario = Prompt.ask("Usuário SSH", default="automacao").strip()
    senha = getpass.getpass("Senha SSH: ")

    while True:
        opcao = menu_principal_visual()

        if opcao == "0":
            limpar_tela()
            console.print("[bold cyan]Monitor encerrado.[/bold cyan]")
            return

        if opcao == "1":
            await mostrar_dashboard(usuario, senha)
            pausar()

        elif opcao == "2":
            router = escolher_router()
            if router:
                await menu_equipamento(router, usuario, senha)

        elif opcao == "3":
            router = escolher_router("Equipamento para medir")
            if router:
                await mostrar_interfaces(router)
                pausar()

        elif opcao == "4":
            router = escolher_router("Equipamento para consultar")
            if router:
                await consultar_oid_manual(router)
                pausar()

        elif opcao == "5":
            router = escolher_router("Equipamento para executar o comando")
            if router:
                await comando_manual_ssh(router, usuario, senha)
                pausar()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Programa encerrado pelo usuário.[/bold yellow]")