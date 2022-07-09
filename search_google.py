import requests
import json
import portscan
import constantes

def query_endpoint_to_get_cve(search):
    req = requests.get(constantes.ENDPOINT_API_SEARCH_CVE, search)
    return json.loads(req.content.decode())

def coletar_informacoes_especificas_from_endpoint_response(json_available, filtros_informacoes):
    cves_disponiveis = json_available['result']['CVE_Items']
    return catalogar_informacoes_por_severidade(cves_disponiveis, filtros_informacoes)

def catalogar_informacoes_por_severidade(cves_disponiveis, filtros_informacoes):
    severidades = {'CRITICAL':[],'HIGH':[],'MEDIUM':[],'LOW':[]}
    for cve in cves_disponiveis:
        match cve['impact']['baseMetricV2']['severity']:
            case 'CRITICAL':
                popular_informacao_desejada(severidades['CRITICAL'], cve, filtros_informacoes)
            case 'HIGH':
                popular_informacao_desejada(severidades['HIGH'], cve, filtros_informacoes)
            case 'MEDIUM':
                popular_informacao_desejada(severidades['MEDIUM'], cve, filtros_informacoes)
            case 'LOW':
                popular_informacao_desejada(severidades['LOW'], cve, filtros_informacoes)

    return severidades

def popular_informacao_desejada(severidade, cve, filtros_informacoes):
    informacao_especifica = cve
    for informacao in filtros_informacoes:
        informacao_especifica = informacao_especifica.get(informacao)
    severidade.append(informacao_especifica)


def print_cve_id_and_severity(color, text, cve_id_list, severity_arr):
    if len(cve_id_list) != 0:
        print(color + text + constantes.RESET)
        for cve_id in cve_id_list:
            print(f'[ + ] - CVE-ID: {color}{cve_id}{constantes.RESET} | BASE SCORE: {color}{severity_arr[cve_id_list.index(cve_id)]}{constantes.RESET}')
            print(f'      - REFERENCE: https://nvd.nist.gov/vuln/detail/{cve_id}')

def print_result():
    services_availables = portscan.sequencia_execucao()

    for index, service in enumerate(services_availables):
        keyword_to_search = { 'keyword': service }
        json_response_from_search_endpoint = query_endpoint_to_get_cve(keyword_to_search)
        cve_id_list = coletar_informacoes_especificas_from_endpoint_response(json_response_from_search_endpoint, ['cve', 'CVE_data_meta', 'ID'])
        severity_list = coletar_informacoes_especificas_from_endpoint_response(json_response_from_search_endpoint, ['impact', 'baseMetricV2', 'cvssV2', 'baseScore'])
        get_cves_founds_in_search_endpoint(cve_id_list, severity_list, index)


def get_cves_founds_in_search_endpoint(cve_id_list, severity_list, index):
    print_porta_cve_encontrada(cve_id_list, severity_list, index)
    print_cve_id_and_severity(constantes.PURPLE, "CRITICAL", cve_id_list['CRITICAL'], severity_list['CRITICAL'])
    print_cve_id_and_severity(constantes.RED, "HIGH", cve_id_list['HIGH'], severity_list['HIGH'])
    print_cve_id_and_severity(constantes.YELLOW, "MEDIUM", cve_id_list['MEDIUM'], severity_list['MEDIUM'])
    print_cve_id_and_severity(constantes.CYAN, "LOW", cve_id_list['LOW'], severity_list['LOW'])

def print_porta_cve_encontrada(cve_id_list, severity_list, index):
    nenhuma_cve_encontrada = cve_id_list != severity_list
    if nenhuma_cve_encontrada:
        print('\n\n')
        print('------------------------------------------------------------------------')
        print(f'\t\t\t\t{constantes.PURPLE}PORTA {portscan.portas[index]}{constantes.RESET}')
        print('------------------------------------------------------------------------')

print_result()
