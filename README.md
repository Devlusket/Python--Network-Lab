# MikroTik Lab Monitor

> Sistema de monitoramento de infraestrutura desenvolvido em Python para
> laboratórios MikroTik RouterOS.

![Python](https://img.shields.io/badge/Python-3.14-blue)
![RouterOS](https://img.shields.io/badge/RouterOS-v7-orange)
![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-success)
![License](https://img.shields.io/badge/License-MIT-green)

------------------------------------------------------------------------

#  Sobre o projeto

O **MikroTik Lab Monitor** é um projeto desenvolvido para automatizar o
monitoramento de uma infraestrutura composta por roteadores MikroTik
RouterOS.

Ao invés de acessar cada equipamento individualmente via WinBox ou SSH,
o sistema conecta automaticamente em todos os roteadores do laboratório,
coleta informações operacionais e apresenta um painel organizado
diretamente no terminal.

O projeto foi criado como parte da minha formação em Infraestrutura de
Redes, com foco em automação utilizando Python e simulação de ambientes
utilizados por provedores de internet (ISP).

------------------------------------------------------------------------

#  Objetivos

-   Automatizar tarefas repetitivas de monitoramento.
-   Consolidar informações de múltiplos roteadores em uma única tela.
-   Praticar automação de infraestrutura com Python.
-   Simular um pequeno NMS (Network Management System).
-   Criar uma base para futuras integrações com Zabbix.

------------------------------------------------------------------------

#  Topologia do laboratório

``` text
                 Internet
                     │
               VirtualBox NAT
                     │
               MT5 (AS65001)
                     │
                  eBGP
                     │
               MT1 (AS65002)
              /               \
             /                 \
          MT2 ---------------- MT4
            \                 /
             \               /
                 MT3
```

## Protocolos implementados

-   OSPF
-   eBGP
-   PPPoE
-   NAT
-   ARP

## Clientes

-   Cliente PPPoE conectado ao MT2
-   Cliente Ethernet conectado ao MT3

------------------------------------------------------------------------

#  Tecnologias utilizadas

-   Python 3.14
-   Paramiko
-   python-dotenv
-   MikroTik RouterOS v7
-   SSH
-   VirtualBox
-   Fedora Linux

------------------------------------------------------------------------

#  Funcionalidades

O sistema realiza conexão SSH individual em cada roteador e coleta
automaticamente:

-   Status do equipamento
-   Versão do RouterOS
-   Uptime
-   Utilização de CPU
-   Utilização de memória
-   Interfaces Ethernet
-   Interfaces inativas
-   Vizinhos OSPF
-   Sessões BGP
-   Clientes PPPoE ativos
-   Clientes Ethernet através da tabela ARP

Ao final da coleta também apresenta:

-   Quantidade de equipamentos online
-   Resumo de interfaces
-   Resumo das sessões OSPF
-   Resumo das sessões BGP
-   Total de clientes PPPoE
-   Total de clientes Ethernet
-   Alertas de CPU
-   Alertas de memória
-   Falhas de conexão
-   Horário da coleta
-   Tempo total de execução

------------------------------------------------------------------------

#  Estrutura do projeto

``` text
lab-monitor/
│
├── .env
├── .env.example
├── .gitignore
├── main-estilizado.py
├── requirements.txt
└── README.md
```

------------------------------------------------------------------------

#  Configuração

Crie um arquivo `.env`

``` env
MIKROTIK_USER=automacao
MIKROTIK_PASSWORD=sua_senha

MIKROTIK_PORT=22

MT1_HOST=192.168.56.10
MT2_HOST=192.168.56.20
MT3_HOST=192.168.56.30
MT4_HOST=192.168.56.40
MT5_HOST=192.168.56.50
```

------------------------------------------------------------------------

#  Executando

Instale as dependências:

``` bash
pip install -r requirements.txt
```

Execute:

``` bash
python main-estilizado.py
```

------------------------------------------------------------------------

#  Exemplo de saída

``` text
MIKROTIK LAB MONITOR

MT1
✓ RouterOS 7.16
✓ CPU 0%
✓ Memória 41%
✓ OSPF 2/2
✓ BGP 1/1

MT2
✓ 1 Cliente PPPoE

MT3
✓ 1 Cliente Ethernet

RESUMO DO LABORATÓRIO

✓ 5/5 Equipamentos Online
✓ 19/19 Interfaces UP
✓ 8/8 Vizinhos OSPF
✓ 2/2 Sessões BGP
✓ 1 Cliente PPPoE
✓ 1 Cliente Ethernet
✓ Nenhuma falha encontrada
```

------------------------------------------------------------------------

#  Roadmap

## Concluído

-   [x] Conexão SSH com múltiplos roteadores
-   [x] Coleta automática de informações
-   [x] Painel organizado em terminal
-   [x] Resumo geral do laboratório
-   [x] Monitoramento de OSPF
-   [x] Monitoramento de BGP
-   [x] Monitoramento de PPPoE
-   [x] Monitoramento de clientes Ethernet

## Próximas funcionalidades

-   [ ] Exportação para JSON
-   [ ] Exportação para CSV
-   [ ] Histórico das coletas
-   [ ] Registro em banco de dados
-   [ ] Alertas configuráveis
-   [ ] Integração com Telegram
-   [ ] Integração com Discord
-   [ ] Integração com Zabbix
-   [ ] Dashboard Web (Flask/FastAPI)
-   [ ] Execução agendada (cron/systemd)

------------------------------------------------------------------------

#  Motivação

Este projeto nasceu para aproximar um laboratório de estudos de um
ambiente encontrado em provedores de internet.

Além de estudar protocolos como OSPF, BGP e PPPoE, o objetivo é
desenvolver ferramentas que auxiliem na operação da rede, reduzindo
tarefas manuais e facilitando o monitoramento da infraestrutura.

Cada nova tecnologia estudada (VLAN, VPN, MPLS, VRF, IPv6, QoS e Zabbix)
será incorporada ao projeto, transformando-o gradualmente em um pequeno
sistema de gerenciamento de redes.

------------------------------------------------------------------------

#  Autor

**Lucas Soares**

Backend Developer • Infraestrutura de Redes • Python • MikroTik • Java •
Spring Boot

LinkedIn: https://www.linkedin.com.br/in/devlusket

GitHub: https://www.github.com.br/Devlusket
