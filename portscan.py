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

inicio_escopo_scan = 20 
fim_escopo_scan = 23
alvo = '192.168.0.26'

resultado = ''
resultado_estado_conexao = ''
resultado_servico_conexao = ''
resultado_produto_conexao = ''
resultado_versao_conexao = ''
resposta_opcao_verbose = 0
verbose = ''
query_pesquisa_cve = ''
arr_query_pesquisa_cve = []

scanner = nmap.PortScanner() # EXECUÇÃO DE SCAN

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
    global verbose
    verbose = input('Você deseja fazer a pesquisa em modo verbose (modo detalhado)? (S/N): ').upper() # PEDIR SE O USUÁRIO QUER SABER AS PORTAS FECHADAS OU NÃO
    print()

def porta_fechada():
    print(f'{RED}Porta {i}{RESET} está {resultado_estado_conexao}.')
    
def porta_aberta():
    if resultado_versao_conexao != '':
        print(f'{GREEN}Porta {i}{RESET} está {resultado_estado_conexao}, com o serviço {resultado_servico_conexao} do produto {resultado_produto_conexao} na versão {resultado_versao_conexao}.')
        query_pesquisa_cve = resultado_servico_conexao + ' ' + resultado_produto_conexao + ' ' + resultado_versao_conexao
        arr_query_pesquisa_cve.append(query_pesquisa_cve)
    else:
        print(f'{YELLOW}Porta {i}{RESET} está {resultado_estado_conexao}, com o serviço {resultado_servico_conexao} do produto {resultado_produto_conexao}.\n{BOLD}(Versão não identificada){RESET}.')
        query_pesquisa_cve = resultado_servico_conexao + ' ' + resultado_produto_conexao
        arr_query_pesquisa_cve.append(query_pesquisa_cve)

banner()                                                                           # APARECER BANNER (TCC - FATEC)

mostre_pergunta_verbose()

while resposta_opcao_verbose == 0:                                                 # INICIO LAÇO RESPOSTA VERBOSE
    if verbose[0] == 'S':
        resposta_opcao_verbose += 1
    elif verbose[0] == 'N':
        resposta_opcao_verbose += 1
    else:
        mostre_pergunta_verbose()

for i in range(inicio_escopo_scan,fim_escopo_scan+1):

    resultado = scanner.scan(alvo,str(i),arguments='-sV')                           # USO DO PARAMETRO -sV DA FERRAMENTA NMAP
    resultado_estado_conexao = resultado['scan'][alvo]['tcp'][i]['state']           # COLETA ESTADO DA PORTA (ABERTA OU FECHADA)
    resultado_servico_conexao = resultado['scan'][alvo]['tcp'][i]['name']           # COLETA SERVIÇO (HTTP, SSH, SFTP, FTP)
    resultado_produto_conexao = resultado['scan'][alvo]['tcp'][i]['product']        # COLETA DO PRODUTO (APACHE HTTPD, OPENSSH)
    resultado_versao_conexao = resultado['scan'][alvo]['tcp'][i]['version']         # COLETA VERSÃO DO PRODUTO
    
    if resultado_estado_conexao == 'closed':                                        # TRADUÇÃO DO RESULTADO, A BIBLIOTECA TRÁS O RESULTADO EM INGLÊS
        resultado_estado_conexao = 'fechada' 
    else:
        resultado_estado_conexao = 'aberta'

    if verbose[0] == 'S':                                                           # CASO ESCOLHA POSITIVAMENTE NA VARIÁVEL VERBOSE
        if resultado_estado_conexao == 'fechada':                                   # CASO ENCONTRE PORTA FECHADA MOSTRE O RESULTADO
            porta_fechada()
        else:                                                                       # CASO ENCONTRE PORTA ABERTA MOSTRE O RESULTADO
            porta_aberta()
    else:
        if resultado_estado_conexao == 'fechada':
            continue 
        else: 
            porta_aberta()