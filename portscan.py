#IMPORTAÇÃO DE BIBLIOTECA

import nmap 

# DECLARAÇÃO DE CONSTANTES

RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
YELLOW = "\033[0;93m"
CYAN  = "\033[1;36m"
PURPLE = "\033[1;35;40m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

#DECLARAÇÃO DE VARIAVÉIS
alvo = '192.168.0.17'

#DECLARAÇÃO DE FUNÇÕES

def banner():
    print("""
      _______ _____ _____            ______   _______ ______ _____ 
     |__   __/ ____/ ____|          |  ____/\|__   __|  ____/ ____|
        | | | |   | |       ______  | |__ /  \  | |  | |__ | |     
        | | | |   | |      |______| |  __/ /\ \ | |  |  __|| |     
        | | | |___| |____           | | / ____ \| |  | |___| |____ 
        |_|  \_____\_____|          |_|/_/    \_\_|  |______\_____|
                                                                            
    """)

def mostre_pergunta_verbose():
    verbose = input('Você deseja fazer a pesquisa em modo verbose (modo detalhado)? (S/N): ').upper() # PEDIR SE O USUÁRIO QUER SABER AS PORTAS FECHADAS OU NÃO
    print()
    while True:                                                 # INICIO LAÇO RESPOSTA VERBOSE
        if verbose[0] == 'S' or verbose[0] == 'N':
            return verbose[0]
        else:
            mostre_pergunta_verbose()

def porta_fechada(estado_conexao, porta):
    print(f'{RED}Porta {porta}{RESET} está fechada.')
    
def porta_aberta(resultado_porta_scan, porta, arr_query_pesquisa_cve):
    servico_conexao = resultado_porta_scan['name']
    produto_conexao = resultado_porta_scan['product']
    versao_conexao = resultado_porta_scan['version']

    if versao_conexao != '':
        print(f'{GREEN}Porta {porta}{RESET} está aberta, com o serviço {servico_conexao} do produto {produto_conexao} na versão {versao_conexao}.')
    else:
        print(f'{YELLOW}Porta {porta}{RESET} está aberta, com o serviço {servico_conexao} do produto {produto_conexao}.\n{BOLD}(Versão não identificada){RESET}.')

    query_pesquisa_cve = servico_conexao + ' ' + produto_conexao + (' ' + versao_conexao if versao_conexao != '' else '')
    arr_query_pesquisa_cve.append(query_pesquisa_cve)

def escanear(inicio_escopo_scan, fim_escopo_scan, modo_verboso):
    scanner = nmap.PortScanner()
    arr_query_pesquisa_cve = []
    for i in range(inicio_escopo_scan,fim_escopo_scan+1):
        resultado = scanner.scan(alvo,str(i),arguments='-sV')                           # USO DO PARAMETRO -sV DA FERRAMENTA NMAP
        estado_porta = resultado['scan'][alvo]['tcp'][i]['state']

        if modo_verboso == 'S' and estado_porta == 'closed':
                porta_fechada(estado_porta, i)

        if estado_porta == 'open':
            porta_aberta(resultado['scan'][alvo]['tcp'][i], i, arr_query_pesquisa_cve)
    return arr_query_pesquisa_cve

def sequencia_execucao(porta_inicio, porta_fim):
    banner()
    return escanear(porta_inicio, porta_fim, mostre_pergunta_verbose())