import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import datetime
from time import perf_counter

import paramiko
from dotenv import load_dotenv


load_dotenv()


# ============================================================
# CONFIGURAÇÕES
# ============================================================

USER = os.getenv("MIKROTIK_USER", "")
PASSWORD = os.getenv("MIKROTIK_PASSWORD", "")
PORT = int(os.getenv("MIKROTIK_PORT", "22"))

TIMEOUT = 10
LIMITE_CPU = 80
LIMITE_MEMORIA = 80


@dataclass
class Equipamento:
    nome: str
    host: str
    redes_clientes: tuple[str, ...] = ()


@dataclass
class ResultadoEquipamento:
    nome: str
    conectado: bool = False

    interfaces_total: int = 0
    interfaces_ativas: int = 0
    interfaces_inativas: int = 0

    ospf_total: int = 0
    ospf_full: int = 0

    bgp_total: int = 0
    bgp_estabelecidas: int = 0

    clientes_pppoe: int = 0
    clientes_ethernet: int = 0

    cpu: int = 0
    memoria: float = 0

    erro: str | None = None


MIKROTIKS = [
    Equipamento(
        nome="MT1",
        host=os.getenv("MT1_HOST", ""),
    ),
    Equipamento(
        nome="MT2",
        host=os.getenv("MT2_HOST", ""),
        redes_clientes=("192.168.2.0/24",),
    ),
    Equipamento(
        nome="MT3",
        host=os.getenv("MT3_HOST", ""),
        redes_clientes=("192.168.3.0/24",),
    ),
    Equipamento(
        nome="MT4",
        host=os.getenv("MT4_HOST", ""),
    ),
    Equipamento(
        nome="MT5",
        host=os.getenv("MT5_HOST", ""),
    ),
]


COMANDOS = {
    "recursos": "/system resource print without-paging",
    "interfaces": "/interface print without-paging",
    "ospf": "/routing ospf neighbor print detail without-paging",
    "bgp": "/routing bgp session print detail without-paging",
    "pppoe": "/ppp active print without-paging",
    "arp": "/ip arp print without-paging",
}


# ============================================================
# CORES DO TERMINAL
# ============================================================

class Cor:
    RESET = "\033[0m"
    NEGRITO = "\033[1m"

    VERDE = "\033[92m"
    AMARELO = "\033[93m"
    VERMELHO = "\033[91m"
    AZUL = "\033[94m"
    CIANO = "\033[96m"
    CINZA = "\033[90m"


# ============================================================
# CONEXÃO SSH
# ============================================================

def conectar(host: str) -> paramiko.SSHClient:
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    cliente.connect(
        hostname=host,
        port=PORT,
        username=USER,
        password=PASSWORD,
        timeout=TIMEOUT,
        auth_timeout=TIMEOUT,
        banner_timeout=TIMEOUT,
    )

    return cliente


def executar_comando(
    cliente: paramiko.SSHClient,
    comando: str,
) -> str:
    _, stdout, stderr = cliente.exec_command(comando)

    saida = stdout.read().decode(
        "utf-8",
        errors="replace",
    ).strip()

    erro = stderr.read().decode(
        "utf-8",
        errors="replace",
    ).strip()

    if erro:
        raise RuntimeError(erro)

    return saida


def coletar_dados(
    cliente: paramiko.SSHClient,
) -> dict[str, str]:
    dados: dict[str, str] = {}

    for nome, comando in COMANDOS.items():
        dados[nome] = executar_comando(
            cliente,
            comando,
        )

    return dados


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def extrair_valor(
    texto: str,
    campo: str,
) -> str | None:
    padrao = rf"{re.escape(campo)}:\s*(.+)"

    resultado = re.search(
        padrao,
        texto,
        re.IGNORECASE,
    )

    if resultado:
        return resultado.group(1).strip()

    return None


def converter_para_bytes(valor: str) -> float:
    padrao = r"([\d.]+)\s*(KiB|MiB|GiB|TiB|kB|MB|GB|TB|B)?"

    resultado = re.fullmatch(
        padrao,
        valor.strip(),
        re.IGNORECASE,
    )

    if not resultado:
        return 0

    numero = float(resultado.group(1))
    unidade = (resultado.group(2) or "B").lower()

    multiplicadores = {
        "b": 1,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
        "tb": 1000**4,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
    }

    return numero * multiplicadores.get(unidade, 1)


def calcular_percentual_memoria(
    recursos: str,
) -> float:
    memoria_livre = extrair_valor(
        recursos,
        "free-memory",
    )

    memoria_total = extrair_valor(
        recursos,
        "total-memory",
    )

    if not memoria_livre or not memoria_total:
        return 0

    livre_bytes = converter_para_bytes(memoria_livre)
    total_bytes = converter_para_bytes(memoria_total)

    if total_bytes == 0:
        return 0

    memoria_usada = total_bytes - livre_bytes

    return (memoria_usada / total_bytes) * 100


def extrair_cpu(recursos: str) -> int:
    cpu = extrair_valor(
        recursos,
        "cpu-load",
    )

    if not cpu:
        return 0

    resultado = re.search(r"\d+", cpu)

    return int(resultado.group()) if resultado else 0


def extrair_uptime(recursos: str) -> str:
    return extrair_valor(
        recursos,
        "uptime",
    ) or "desconhecido"


def extrair_versao(recursos: str) -> str:
    return extrair_valor(
        recursos,
        "version",
    ) or "desconhecida"


# ============================================================
# INTERFACES
# ============================================================

def analisar_interfaces(
    texto: str,
) -> tuple[int, int, list[str]]:
    total = 0
    ativas = 0
    inativas: list[str] = []

    for linha in texto.splitlines():
        if not re.search(r"\bether\d+\b", linha):
            continue

        resultado_nome = re.search(
            r"\b(ether\d+)\b",
            linha,
        )

        if not resultado_nome:
            continue

        nome = resultado_nome.group(1)
        total += 1

        trecho_antes_nome = linha[:resultado_nome.start()]

        esta_rodando = bool(
            re.search(r"\bR\b", trecho_antes_nome)
        )

        if esta_rodando:
            ativas += 1
        else:
            inativas.append(nome)

    return total, ativas, inativas


# ============================================================
# OSPF
# ============================================================

def analisar_ospf(
    texto: str,
) -> tuple[int, int]:
    total = len(
        re.findall(
            r"router-id=",
            texto,
            re.IGNORECASE,
        )
    )

    full = len(
        re.findall(
            r'state="?Full"?',
            texto,
            re.IGNORECASE,
        )
    )

    return total, full


# ============================================================
# BGP
# ============================================================

def analisar_bgp(
    texto: str,
) -> tuple[int, int]:
    total = len(
        re.findall(
            r'name="[^"]+"',
            texto,
        )
    )

    estabelecidas = len(
        re.findall(
            r"^\s*\d+\s+E\s+name=",
            texto,
            re.MULTILINE,
        )
    )

    return total, estabelecidas


# ============================================================
# PPPoE
# ============================================================

def analisar_pppoe(
    texto: str,
) -> list[dict[str, str]]:
    clientes: list[dict[str, str]] = []

    padrao = re.compile(
        r"^\s*\d+\s+"
        r"(?P<nome>\S+)\s+"
        r"(?P<servico>pppoe)\s+"
        r"(?P<mac>[0-9A-F:]+)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<uptime>\S+)",
        re.IGNORECASE | re.MULTILINE,
    )

    for resultado in padrao.finditer(texto):
        clientes.append(
            {
                "nome": resultado.group("nome"),
                "ip": resultado.group("ip"),
                "mac": resultado.group("mac"),
                "uptime": resultado.group("uptime"),
            }
        )

    return clientes


# ============================================================
# CLIENTES ETHERNET VIA ARP
# ============================================================

def analisar_clientes_ethernet(
    texto: str,
    redes_clientes: tuple[str, ...],
) -> list[dict[str, str]]:
    if not redes_clientes:
        return []

    redes = [
        ipaddress.ip_network(rede)
        for rede in redes_clientes
    ]

    clientes: list[dict[str, str]] = []

    padrao = re.compile(
        r"^\s*\d+\s+"
        r"[A-Z]*\s*"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<mac>[0-9A-F:]{17})\s+"
        r"(?P<interface>\S+)\s+"
        r"(?P<status>\S+)",
        re.IGNORECASE | re.MULTILINE,
    )

    for resultado in padrao.finditer(texto):
        endereco = ipaddress.ip_address(
            resultado.group("ip")
        )

        pertence_rede_cliente = any(
            endereco in rede
            for rede in redes
        )

        if not pertence_rede_cliente:
            continue

        if any(
            endereco == rede.network_address + 1
            for rede in redes
        ):
            continue

        clientes.append(
            {
                "ip": resultado.group("ip"),
                "mac": resultado.group("mac"),
                "interface": resultado.group("interface"),
                "status": resultado.group("status"),
            }
        )

    return clientes


# ============================================================
# FORMATAÇÃO DO PAINEL
# ============================================================

def status_percentual(
    valor: float,
    limite: float,
) -> str:
    if valor >= limite:
        return (
            f"{Cor.VERMELHO}✗ {valor:.0f}%"
            f"{Cor.RESET}"
        )

    if valor >= limite * 0.75:
        return (
            f"{Cor.AMARELO}⚠ {valor:.0f}%"
            f"{Cor.RESET}"
        )

    return (
        f"{Cor.VERDE}✓ {valor:.0f}%"
        f"{Cor.RESET}"
    )


def status_quantidade(
    atual: int,
    esperado: int,
) -> str:
    if atual == esperado:
        return (
            f"{Cor.VERDE}✓ {atual}/{esperado}"
            f"{Cor.RESET}"
        )

    return (
        f"{Cor.VERMELHO}✗ {atual}/{esperado}"
        f"{Cor.RESET}"
    )


def imprimir_linha(
    titulo: str,
    valor: str,
) -> None:
    print(f"  {titulo:<21} {valor}")


def imprimir_cabecalho(
    equipamento: Equipamento,
) -> None:
    largura = 64

    print()
    print(
        f"{Cor.CIANO}"
        f"╭{'─' * largura}╮"
        f"{Cor.RESET}"
    )

    titulo = (
        f"{equipamento.nome} — "
        f"{equipamento.host}"
    )

    print(
        f"{Cor.CIANO}│{Cor.RESET} "
        f"{Cor.NEGRITO}{titulo:<62}"
        f"{Cor.RESET}"
        f"{Cor.CIANO}│{Cor.RESET}"
    )

    print(
        f"{Cor.CIANO}"
        f"├{'─' * largura}┤"
        f"{Cor.RESET}"
    )


def imprimir_rodape() -> None:
    largura = 64

    print(
        f"{Cor.CIANO}"
        f"╰{'─' * largura}╯"
        f"{Cor.RESET}"
    )


def imprimir_resumo(
    equipamento: Equipamento,
    dados: dict[str, str],
) -> ResultadoEquipamento:
    recursos = dados["recursos"]

    cpu = extrair_cpu(recursos)
    memoria = calcular_percentual_memoria(recursos)
    uptime = extrair_uptime(recursos)
    versao = extrair_versao(recursos)

    total_interfaces, interfaces_ativas, interfaces_inativas = (
        analisar_interfaces(dados["interfaces"])
    )

    total_ospf, ospf_full = analisar_ospf(
        dados["ospf"]
    )

    total_bgp, bgp_estabelecidas = analisar_bgp(
        dados["bgp"]
    )

    clientes_pppoe = analisar_pppoe(
        dados["pppoe"]
    )

    clientes_ethernet = analisar_clientes_ethernet(
        dados["arp"],
        equipamento.redes_clientes,
    )

    imprimir_cabecalho(equipamento)

    imprimir_linha(
        "Status SSH",
        f"{Cor.VERDE}✓ conectado{Cor.RESET}",
    )

    imprimir_linha(
        "RouterOS",
        versao,
    )

    imprimir_linha(
        "Uptime",
        uptime,
    )

    imprimir_linha(
        "CPU",
        status_percentual(cpu, LIMITE_CPU),
    )

    imprimir_linha(
        "Memória utilizada",
        status_percentual(
            memoria,
            LIMITE_MEMORIA,
        ),
    )

    interfaces_status = (
        f"{Cor.VERDE}✓ {interfaces_ativas} UP"
        f"{Cor.RESET} / "
        f"{total_interfaces - interfaces_ativas} DOWN"
    )

    if interfaces_inativas:
        interfaces_status = (
            f"{Cor.VERMELHO}✗ "
            f"{interfaces_ativas} UP / "
            f"{len(interfaces_inativas)} DOWN"
            f"{Cor.RESET}"
        )

    imprimir_linha(
        "Interfaces Ethernet",
        interfaces_status,
    )

    if interfaces_inativas:
        imprimir_linha(
            "Interfaces DOWN",
            ", ".join(interfaces_inativas),
        )

    if total_ospf > 0:
        imprimir_linha(
            "Vizinhos OSPF Full",
            status_quantidade(
                ospf_full,
                total_ospf,
            ),
        )
    else:
        imprimir_linha(
            "OSPF",
            f"{Cor.CINZA}— não configurado{Cor.RESET}",
        )

    if total_bgp > 0:
        imprimir_linha(
            "Sessões BGP",
            status_quantidade(
                bgp_estabelecidas,
                total_bgp,
            ),
        )
    else:
        imprimir_linha(
            "BGP",
            f"{Cor.CINZA}— não configurado{Cor.RESET}",
        )

    imprimir_linha(
        "Clientes PPPoE",
        (
            f"{Cor.VERDE}✓ {len(clientes_pppoe)} ativo(s)"
            f"{Cor.RESET}"
        ),
    )

    for cliente in clientes_pppoe:
        imprimir_linha(
            f"  ↳ {cliente['nome']}",
            (
                f"{cliente['ip']} | "
                f"{cliente['uptime']}"
            ),
        )

    imprimir_linha(
        "Clientes Ethernet",
        (
            f"{Cor.VERDE}✓ {len(clientes_ethernet)} detectado(s)"
            f"{Cor.RESET}"
        ),
    )

    for cliente in clientes_ethernet:
        imprimir_linha(
            f"  ↳ {cliente['ip']}",
            (
                f"{cliente['interface']} | "
                f"{cliente['status']}"
            ),
        )

    imprimir_rodape()

    return ResultadoEquipamento(
        nome=equipamento.nome,
        conectado=True,
        interfaces_total=total_interfaces,
        interfaces_ativas=interfaces_ativas,
        interfaces_inativas=len(interfaces_inativas),
        ospf_total=total_ospf,
        ospf_full=ospf_full,
        bgp_total=total_bgp,
        bgp_estabelecidas=bgp_estabelecidas,
        clientes_pppoe=len(clientes_pppoe),
        clientes_ethernet=len(clientes_ethernet),
        cpu=cpu,
        memoria=memoria,
    )


def imprimir_erro(
    equipamento: Equipamento,
    mensagem: str,
) -> ResultadoEquipamento:
    imprimir_cabecalho(equipamento)

    imprimir_linha(
        "Status SSH",
        f"{Cor.VERMELHO}✗ indisponível{Cor.RESET}",
    )

    imprimir_linha(
        "Erro",
        mensagem,
    )

    imprimir_rodape()

    return ResultadoEquipamento(
        nome=equipamento.nome,
        conectado=False,
        erro=mensagem,
    )


def imprimir_resumo_geral(
    resultados: list[ResultadoEquipamento],
    inicio: float,
) -> None:
    largura = 64

    total_equipamentos = len(resultados)

    equipamentos_online = sum(
        1
        for resultado in resultados
        if resultado.conectado
    )

    interfaces_total = sum(
        resultado.interfaces_total
        for resultado in resultados
    )

    interfaces_ativas = sum(
        resultado.interfaces_ativas
        for resultado in resultados
    )

    interfaces_inativas = sum(
        resultado.interfaces_inativas
        for resultado in resultados
    )

    ospf_total = sum(
        resultado.ospf_total
        for resultado in resultados
    )

    ospf_full = sum(
        resultado.ospf_full
        for resultado in resultados
    )

    bgp_total = sum(
        resultado.bgp_total
        for resultado in resultados
    )

    bgp_estabelecidas = sum(
        resultado.bgp_estabelecidas
        for resultado in resultados
    )

    clientes_pppoe = sum(
        resultado.clientes_pppoe
        for resultado in resultados
    )

    clientes_ethernet = sum(
        resultado.clientes_ethernet
        for resultado in resultados
    )

    alertas_cpu = [
        resultado.nome
        for resultado in resultados
        if resultado.conectado
        and resultado.cpu >= LIMITE_CPU
    ]

    alertas_memoria = [
        resultado.nome
        for resultado in resultados
        if resultado.conectado
        and resultado.memoria >= LIMITE_MEMORIA
    ]

    equipamentos_com_erro = [
        resultado
        for resultado in resultados
        if not resultado.conectado
    ]

    tempo_total = perf_counter() - inicio

    data_coleta = datetime.now().strftime(
        "%d/%m/%Y %H:%M:%S"
    )

    print()
    print(
        f"{Cor.AZUL}"
        f"╭{'─' * largura}╮"
        f"{Cor.RESET}"
    )

    titulo = "RESUMO DO LABORATÓRIO"

    print(
        f"{Cor.AZUL}│{Cor.RESET} "
        f"{Cor.NEGRITO}{titulo:<62}"
        f"{Cor.RESET}"
        f"{Cor.AZUL}│{Cor.RESET}"
    )

    print(
        f"{Cor.AZUL}"
        f"├{'─' * largura}┤"
        f"{Cor.RESET}"
    )

    if equipamentos_online == total_equipamentos:
        status_equipamentos = (
            f"{Cor.VERDE}✓ "
            f"{equipamentos_online}/{total_equipamentos} online"
            f"{Cor.RESET}"
        )
    else:
        status_equipamentos = (
            f"{Cor.VERMELHO}✗ "
            f"{equipamentos_online}/{total_equipamentos} online"
            f"{Cor.RESET}"
        )

    imprimir_linha(
        "Equipamentos",
        status_equipamentos,
    )

    if interfaces_inativas == 0:
        status_interfaces = (
            f"{Cor.VERDE}✓ "
            f"{interfaces_ativas}/{interfaces_total} UP"
            f"{Cor.RESET}"
        )
    else:
        status_interfaces = (
            f"{Cor.VERMELHO}✗ "
            f"{interfaces_ativas}/{interfaces_total} UP"
            f" | {interfaces_inativas} DOWN"
            f"{Cor.RESET}"
        )

    imprimir_linha(
        "Interfaces Ethernet",
        status_interfaces,
    )

    if ospf_total > 0:
        imprimir_linha(
            "Vizinhos OSPF Full",
            status_quantidade(
                ospf_full,
                ospf_total,
            ),
        )
    else:
        imprimir_linha(
            "OSPF",
            f"{Cor.CINZA}— não configurado{Cor.RESET}",
        )

    if bgp_total > 0:
        imprimir_linha(
            "Sessões BGP",
            status_quantidade(
                bgp_estabelecidas,
                bgp_total,
            ),
        )
    else:
        imprimir_linha(
            "BGP",
            f"{Cor.CINZA}— não configurado{Cor.RESET}",
        )

    imprimir_linha(
        "Clientes PPPoE",
        (
            f"{Cor.VERDE}✓ {clientes_pppoe} ativo(s)"
            f"{Cor.RESET}"
        ),
    )

    imprimir_linha(
        "Clientes Ethernet",
        (
            f"{Cor.VERDE}✓ {clientes_ethernet} detectado(s)"
            f"{Cor.RESET}"
        ),
    )

    if alertas_cpu:
        imprimir_linha(
            "Alerta de CPU",
            (
                f"{Cor.VERMELHO}✗ "
                + ", ".join(alertas_cpu)
                + f"{Cor.RESET}"
            ),
        )
    else:
        imprimir_linha(
            "CPU",
            f"{Cor.VERDE}✓ sem alertas{Cor.RESET}",
        )

    if alertas_memoria:
        imprimir_linha(
            "Alerta de memória",
            (
                f"{Cor.VERMELHO}✗ "
                + ", ".join(alertas_memoria)
                + f"{Cor.RESET}"
            ),
        )
    else:
        imprimir_linha(
            "Memória",
            f"{Cor.VERDE}✓ sem alertas{Cor.RESET}",
        )

    if equipamentos_com_erro:
        for resultado in equipamentos_com_erro:
            imprimir_linha(
                f"Erro em {resultado.nome}",
                (
                    f"{Cor.VERMELHO}"
                    f"{resultado.erro}"
                    f"{Cor.RESET}"
                ),
            )
    else:
        imprimir_linha(
            "Falhas de conexão",
            f"{Cor.VERDE}✓ nenhuma{Cor.RESET}",
        )

    print(
        f"{Cor.AZUL}"
        f"├{'─' * largura}┤"
        f"{Cor.RESET}"
    )

    imprimir_linha(
        "Data da coleta",
        data_coleta,
    )

    imprimir_linha(
        "Tempo total",
        f"{tempo_total:.2f} segundos",
    )

    print(
        f"{Cor.AZUL}"
        f"╰{'─' * largura}╯"
        f"{Cor.RESET}"
    )


# ============================================================
# VALIDAÇÃO
# ============================================================

def validar_configuracao() -> None:
    if not USER:
        raise ValueError(
            "MIKROTIK_USER não foi definido no .env."
        )

    if not PASSWORD:
        raise ValueError(
            "MIKROTIK_PASSWORD não foi definido no .env."
        )

    sem_host = [
        equipamento.nome
        for equipamento in MIKROTIKS
        if not equipamento.host
    ]

    if sem_host:
        raise ValueError(
            "Host não definido para: "
            + ", ".join(sem_host)
        )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    validar_configuracao()

    inicio = perf_counter()
    resultados: list[ResultadoEquipamento] = []

    print()
    print(
        f"{Cor.NEGRITO}{Cor.AZUL}"
        "MIKROTIK LAB MONITOR"
        f"{Cor.RESET}"
    )

    print(
        f"{Cor.CINZA}"
        "Coletando informações dos equipamentos..."
        f"{Cor.RESET}"
    )

    for equipamento in MIKROTIKS:
        cliente = None

        try:
            cliente = conectar(
                equipamento.host
            )

            dados = coletar_dados(cliente)

            resultado = imprimir_resumo(
                equipamento,
                dados,
            )

        except paramiko.AuthenticationException:
            resultado = imprimir_erro(
                equipamento,
                "falha de autenticação",
            )

        except paramiko.SSHException as erro:
            resultado = imprimir_erro(
                equipamento,
                f"erro SSH: {erro}",
            )

        except TimeoutError:
            resultado = imprimir_erro(
                equipamento,
                "tempo de conexão esgotado",
            )

        except OSError as erro:
            resultado = imprimir_erro(
                equipamento,
                f"equipamento inacessível: {erro}",
            )

        except RuntimeError as erro:
            resultado = imprimir_erro(
                equipamento,
                f"comando recusado: {erro}",
            )

        except Exception as erro:
            resultado = imprimir_erro(
                equipamento,
                f"erro inesperado: {erro}",
            )

        finally:
            if cliente is not None:
                cliente.close()

        resultados.append(resultado)

    imprimir_resumo_geral(
        resultados,
        inicio,
    )


if __name__ == "__main__":
    main()