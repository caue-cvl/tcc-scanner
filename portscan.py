#IMPORTAÇÃO DE BIBLIOTECA

import nmap
import constantes

portas = []

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
    print(f'{constantes.RED}Porta {porta}{constantes.RESET} está fechada.')
    
def porta_aberta(resultado_porta_scan, porta, arr_query_pesquisa_cve):
    servico_conexao = resultado_porta_scan['name']
    produto_conexao = resultado_porta_scan['product']
    versao_conexao = resultado_porta_scan['version']

    if versao_conexao != '':
        print(f'{constantes.GREEN}Porta {porta}{constantes.RESET} está aberta, com o serviço {servico_conexao} do produto {produto_conexao} na versão {versao_conexao}.')
    else:
        print(f'{constantes.YELLOW}Porta {porta}{constantes.RESET} está aberta, com o serviço {servico_conexao} do produto {produto_conexao}.\n{constantes.BOLD}(Versão não identificada){constantes.RESET}.')

    query_pesquisa_cve = servico_conexao + ' ' + produto_conexao + (' ' + versao_conexao if versao_conexao != '' else '')
    arr_query_pesquisa_cve.append(query_pesquisa_cve)

def escanear(alvo, inicio_escopo_scan, fim_escopo_scan, modo_verboso):
    scanner = nmap.PortScanner()
    arr_query_pesquisa_cve = []
    for i in range(inicio_escopo_scan,fim_escopo_scan+1):
        resultado = scanner.scan(alvo,str(i),arguments='-sV')                           # USO DO PARAMETRO -sV DA FERRAMENTA NMAP
        estado_porta = resultado['scan'][alvo]['tcp'][i]['state']

        if modo_verboso == 'S' and estado_porta == 'closed':
                porta_fechada(estado_porta, i)

        if estado_porta == 'open':
            salvar_porta_aberta(resultado['nmap']['scaninfo']['tcp']['services'])
            porta_aberta(resultado['scan'][alvo]['tcp'][i], i, arr_query_pesquisa_cve)
    return arr_query_pesquisa_cve


def salvar_porta_aberta(porta):
    global portas
    portas.append(porta)

def sequencia_execucao():
    banner()
    alvo = str(input('Digite o IP da máquina ALVO: '))
    porta_inicio = int(input('Digite o número da porta inicial: '))
    porta_fim = int(input('Digite o número da porta inicial: '))
    return escanear(alvo, porta_inicio, porta_fim, mostre_pergunta_verbose())