import requests
import json
import portscan

# to search
query = "springboot vulnerabilites"

# Constantes
ENDPOINT_API_SEARCH_CVE = 'https://services.nvd.nist.gov/rest/json/cves/1.0/'
RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
YELLOW = "\033[0;93m"
CYAN  = "\033[1;36m"
PURPLE = "\033[1;35;40m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

def get_all_cves_available_for_search(json_response_from_endpoint_query):
    return get_cve_according_severity(json_response_from_endpoint_query)

def query_endpoint_to_get_cve(search):
    req = requests.get(ENDPOINT_API_SEARCH_CVE, search)
    return json.loads(req.content.decode())

def get_cve_according_severity(json_available):
    
    cves_available = json_available['result']['CVE_Items']
    cve_id_collection = {'CRITICAL':[],'HIGH':[],'MEDIUM':[],'LOW':[]}

    for cve in cves_available:
        if cve['impact']['baseMetricV2']['severity'] == 'CRITICAL':
            cve_id_collection['CRITICAL'].append(cve['cve']['CVE_data_meta']['ID'])
        if cve['impact']['baseMetricV2']['severity'] == 'HIGH':
            cve_id_collection['HIGH'].append(cve['cve']['CVE_data_meta']['ID'])
        if cve['impact']['baseMetricV2']['severity'] == 'MEDIUM':
            cve_id_collection['MEDIUM'].append(cve['cve']['CVE_data_meta']['ID'])
        if cve['impact']['baseMetricV2']['severity'] == 'LOW':
            cve_id_collection['LOW'].append(cve['cve']['CVE_data_meta']['ID'])

    return cve_id_collection


def get_severity_points(json_available):

    cves_available = json_available['result']['CVE_Items']
    severity_collection = {'CRITICAL':[],'HIGH':[],'MEDIUM':[],'LOW':[]}

    for cve in cves_available:
        if cve['impact']['baseMetricV2']['severity'] == 'CRITICAL':
            severity_collection['CRITICAL'].append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
        if cve['impact']['baseMetricV2']['severity'] == 'HIGH':
            severity_collection['HIGH'].append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
        if cve['impact']['baseMetricV2']['severity'] == 'MEDIUM':
            severity_collection['MEDIUM'].append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
        if cve['impact']['baseMetricV2']['severity'] == 'LOW':
            severity_collection['LOW'].append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
    return severity_collection


def print_cve_id_and_severity(color, text, cve_id_list, severity_arr):
    if len(cve_id_list) != 0:
        print(color + text + RESET)
        for cve_id in cve_id_list:
            print(f'[ + ] - CVE-ID: {color}{cve_id}{RESET} | BASE SCORE: {color}{severity_arr[cve_id_list.index(cve_id)]}{RESET}')
            print(f'      - REFERENCE: https://nvd.nist.gov/vuln/detail/{cve_id}')
        print('------------------------------------------')

def print_result():
    services_availables = portscan.sequencia_execucao(20, 23)

    for service in services_availables:
        keyword_to_search = { 'keyword': service }
        json_response_from_search_endpoint = query_endpoint_to_get_cve(keyword_to_search)
        cve_id_list = get_all_cves_available_for_search(json_response_from_search_endpoint)
        severity_list = get_severity_points(json_response_from_search_endpoint)
        get_cves_founds_in_search_endpoint(cve_id_list, severity_list)


def get_cves_founds_in_search_endpoint(cve_id_list, severity_list):
    print_cve_id_and_severity(PURPLE, "CRITICAL", cve_id_list['CRITICAL'], severity_list['CRITICAL'])
    print_cve_id_and_severity(RED, "HIGH", cve_id_list['HIGH'], severity_list['HIGH'])
    print_cve_id_and_severity(YELLOW, "MEDIUM", cve_id_list['MEDIUM'], severity_list['MEDIUM'])
    print_cve_id_and_severity(CYAN, "LOW", cve_id_list['LOW'], severity_list['LOW'])

print_result()
