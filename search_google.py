import requests
import json
import portscan

# to search
query = "springboot vulnerabilites"

# Constantes
RETRIEVE_A_COLLECTION_FROM_CVE = 'https://services.nvd.nist.gov/rest/json/cves/1.0/'
RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
YELLOW = "\033[0;93m"
CYAN  = "\033[1;36m"
PURPLE = "\033[1;35;40m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"


#variaveis

cve_id_crit = []
cve_id_high = []
cve_id_low = []
cve_id_medium = []

severity_crit_list = []
severity_high_list = []
severity_medium_list = []
severity_low_list = []

def get_all_cves_available_for_search(search):
    req = requests.get(RETRIEVE_A_COLLECTION_FROM_CVE, search)
    json_response = json.loads(req.content.decode())
    return get_cve_according_severity(json_response)

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

    get_severity_points(json_available)
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
            cve_id_collection['LOW'].append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
    print(severity_collection)
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
    print(services_availables)

    global severity_crit_list
    global severity_high_list
    global severity_medium_list
    global severity_low_list
    

    for service in services_availables:
        
        severity_crit_list = []
        severity_high_list = []
        severity_medium_list = []
        severity_low_list = []
        keyword_to_search = { 'keyword': service }
        severity_list = get_severity_points(keyword_to_search)
        cve_id_list = get_all_cves_available_for_search(keyword_to_search)  
        print_cve_id_and_severity(PURPLE, "CRITICAL", cve_id_list['CRITICAL'], severity_list['CRITICAL'])
        print_cve_id_and_severity(RED, "HIGH", cve_id_list['HIGH'], severity_list['HIGH'])
        print_cve_id_and_severity(YELLOW, "MEDIUM", cve_id_list['MEDIUM'], severity_list['MEDIUM'])
        print_cve_id_and_severity(CYAN, "LOW", cve_id_list['LOW'], severity_list['LOW'])
    return()
    

print_result()