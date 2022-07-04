import requests
import json

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
total_results_crit = 0
total_results_high = 0
total_results_medium = 0
total_results_low = 0

cve_id_crit = []
cve_id_high = []
cve_id_medium = []
cve_id_low = []

severity_crit_list = []
severity_high_list = []
severity_medium_list = []
severity_low_list = []


keyword_to_search = { 'keyword': 'ftp vsftpd 3.4' }


def get_all_cves_available_for_search():
    req = requests.get(RETRIEVE_A_COLLECTION_FROM_CVE, keyword_to_search)
    json_response = json.loads(req.content.decode())
    set_total_results_variables(json_response)
    get_cve_according_severity(json_response)


def set_total_results_variables(json_available):
    global total_results_low
    global total_results_medium
    global total_results_high
    global total_results_crit

    cves_available = json_available['result']['CVE_Items']
    for cve in cves_available:
        match cve['impact']['baseMetricV2']['severity']:
            case 'LOW':
                total_results_low+=1
            case 'MEDIUM':
                total_results_medium+=1
            case 'HIGH':
                total_results_high+=1
            case 'CRITICAL':
                total_results_crit+=1


def get_cve_according_severity(json_available):
    global cve_id_crit
    global cve_id_high
    global cve_id_medium
    global cve_id_low

    cves_available = json_available['result']['CVE_Items']
    critical_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'CRITICAL']
    high_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'HIGH']
    medium_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'MEDIUM']
    low_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'LOW']

    for cve in low_cves:
        cve_id_low.append(cve['cve']['CVE_data_meta']['ID'])
    for cve in medium_cves:
        cve_id_medium.append(cve['cve']['CVE_data_meta']['ID'])
    for cve in high_cves:
        cve_id_high.append(cve['cve']['CVE_data_meta']['ID'])
    for cve in critical_cves:
        cve_id_crit.append(cve['cve']['CVE_data_meta']['ID'])

    get_severity_points(json_available)


def get_severity_points(json_available):
    global severity_crit_list
    global severity_high_list
    global severity_medium_list
    global severity_low_list

    cves_available = json_available['result']['CVE_Items']
    critical_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'CRITICAL']
    high_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'HIGH']
    medium_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'MEDIUM']
    low_cves = [cve for cve in cves_available if cve['impact']['baseMetricV2']['severity'] == 'LOW']

    for cve in low_cves:
        severity_low_list.append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
    for cve in medium_cves:
        severity_medium_list.append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
    for cve in high_cves:
        severity_high_list.append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
    for cve in critical_cves:
        severity_crit_list.append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])


def print_cve_id_and_severity(color, text, cve_id_list, severity_arr):
    if len(cve_id_list) != 0:
        print(color + text + RESET)
        for cve_id in cve_id_list:
            print(f'[ + ] - CVE-ID: {color}{cve_id}{RESET} | BASE SCORE: {color}{severity_arr[cve_id_list.index(cve_id)]}{RESET}')
            print(f'      - REFERENCE: https://nvd.nist.gov/vuln/detail/{cve_id}')
        print('------------------------------------------')


get_all_cves_available_for_search()
print_cve_id_and_severity(PURPLE, "CRITICAL", cve_id_crit, severity_crit_list)
print_cve_id_and_severity(RED, "HIGH", cve_id_high, severity_high_list)
print_cve_id_and_severity(YELLOW, "MEDIUM", cve_id_medium, severity_medium_list)
print_cve_id_and_severity(CYAN, "LOW", cve_id_low, severity_low_list)