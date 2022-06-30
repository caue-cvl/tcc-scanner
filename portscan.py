#IMPORTAÇÃO DE BIBLIOTECA

import nmap 

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

def porta_fechada():
    print(f'Porta {i} está {resultado_estado_conexao}.')
def porta_aberta():
    print(f'Porta {i} está {resultado_estado_conexao}, com o serviço {resultado_servico_conexao} do produto {resultado_produto_conexao} na versão {resultado_versao_conexao}.')
    query_pesquisa_cve = resultado_servico_conexao + ' ' + resultado_produto_conexao + ' ' + resultado_versao_conexao + ' cve'
    arr_query_pesquisa_cve.append(query_pesquisa_cve)
def porta_aberta_vesao_nao_identificada():
    print(f'Porta {i} está {resultado_estado_conexao}, com o serviço {resultado_servico_conexao} do produto {resultado_produto_conexao}. (Versão não identificada).')
    query_pesquisa_cve = resultado_servico_conexao + ' ' + resultado_produto_conexao + ' cve'
    arr_query_pesquisa_cve.append(query_pesquisa_cve)

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

# INICIO DO SCRIPT   
scanner = nmap.PortScanner() # EXECUÇÃO DE SCAN

banner() # APARECER BANNER (TCC- FATEC)

verbose = input('Você deseja fazer a pesquisa em modo verbose (modo detalhado)? (S/N): ') # PEDIR SE O USUÁRIO QUER SABER AS PORTAS FECHADAS OU NÃO
print()

while resposta_opcao_verbose == 0: # INICIO LAÇO RESPOSTA VERBOSE
    if verbose == 'S' or verbose == 's':
        resposta_opcao_verbose += 1
    elif verbose == 'N' or verbose == 'n':
        resposta_opcao_verbose += 1
    else:
        verbose = input('Você deseja fazer a pesquisa em modo verbose (modo detalhado)? (S/N): ') # PEDIR SE O USUÁRIO QUER SABER AS PORTAS FECHADAS OU NÃO
        print()

for i in range(inicio_escopo_scan,fim_escopo_scan+1): # INICIO LAÇO SCAN

    resultado = scanner.scan(alvo,str(i),arguments='-sV') # USO DO PARAMETRO -sV DA FERRAMENTA NMAP
    resultado_estado_conexao = resultado['scan'][alvo]['tcp'][i]['state'] # COLETA ESTADO DA PORTA (ABERTA OU FECHADA)
    resultado_servico_conexao = resultado['scan'][alvo]['tcp'][i]['name'] # COLETA SERVIÇO (HTTP, SSH, SFTP, FTP)
    resultado_produto_conexao = resultado['scan'][alvo]['tcp'][i]['product'] # COLETA DO PRODUTO (APACHE HTTPD, OPENSSH)
    resultado_versao_conexao = resultado['scan'][alvo]['tcp'][i]['version'] # COLETA VERSÃO DO PRODUTO
    
    if resultado_estado_conexao == 'closed': # TRADUÇÃO DO RESULTADO, A BIBLIOTECA TRÁS O RESULTADO EM INGLÊS
        resultado_estado_conexao = 'fechada' # TRADUÇÃO EM CASO DE PORTA FECHADA
    else:
        resultado_estado_conexao = 'aberta' # TRADUÇÃO EM CASO DE PORTA ABERTA

    if verbose == 'S' or verbose == 's': # CASO ESCOLHA POSITIVAMENTE NA VARIÁVEL VERBOSE
        if resultado_estado_conexao == 'fechada': # CASO ENCONTRE PORTA FECHADA MOSTRE O RESULTADO
            porta_fechada()
        else: # CASO ENCONTRE PORTA ABERTA MOSTRE O RESULTADO
            if resultado_versao_conexao != '':
                porta_aberta()
            else:
                porta_aberta_vesao_nao_identificada()
    elif verbose == 'N' or verbose == 'n': # CASO ESCOLHA NEGATIVAMENTE NA VARIÁVEL VERBOSE
        if resultado_estado_conexao == 'fechada': # CASO ENCONTRE PORTA FECHADA PASSE PARA PRÓXIMO ITEM DO LAÇO
            continue 
        else: # CASO ENCONTRE PORTA ABERTA MOSTRE O RESULTADO
            if resultado_versao_conexao != '':
                porta_aberta()
            else:
                porta_aberta_vesao_nao_identificada()
    else: # CASO COLOQUE ALGO DIFERENTE DE (S/s) OU (N/n) PROSSIGA PARA PRÓXIMO ITEM DO LAÇO
        continue 