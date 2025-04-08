import requests
import json
import portscan
import const
from six.moves import configparser
import os

final_json = {}


def load_auth_token_from_properties_file():
    config = configparser.RawConfigParser()
    config.read('properties/auth.properties')
    return config.get('DatabaseSection', 'database.apiKey')

def query_endpoint_to_get_cve(search):
    req = requests.get(const.ENDPOINT_API_SEARCH_CVE, search)
    if req.text.find('Invalid apiKey') != -1:
        error_invalid_api_key()
    return json.loads(req.content.decode())

def error_invalid_api_key():
    raise Exception('''Invalid api Key or do not configured...
    \t   Please verify the file [auth.properties]''')

def collect_spefic_info_endpoint_response(json_available, information_filters):
    available_cves = json_available['result']['CVE_Items']
    return catalog_info_by_severity(available_cves, information_filters)

def catalog_info_by_severity(available_cves, information_filters):
    severities = {'CRITICAL':[],'HIGH':[],'MEDIUM':[],'LOW':[]}
    for cve in available_cves:
        if is_cve_homol(cve):
            match get_severity_text(cve):
                case 'CRITICAL':
                    populate_infomation_desired(severities['CRITICAL'], cve, information_filters)
                case 'HIGH':
                    populate_infomation_desired(severities['HIGH'], cve, information_filters)
                case 'MEDIUM':
                    populate_infomation_desired(severities['MEDIUM'], cve, information_filters)
                case 'LOW':
                    populate_infomation_desired(severities['LOW'], cve, information_filters)

    return severities

def is_cve_homol(cve):
    if cve['impact'] == {}:
          return False
    return True

def get_severity_text(cve):
    if 'baseMetricV2' in cve['impact']:
        return cve['impact']['baseMetricV2']['severity']
    else:
        return cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    

def populate_infomation_desired(severity, cve, information_filters):
    information_specific = cve
    if 'baseMetric' in information_filters:
        if 'baseMetricV2' in cve['impact']:
            severity.append(cve['impact']['baseMetricV2']['cvssV2']['baseScore'])
        else:
            severity.append(cve['impact']['baseMetricV3']['cvssV3']['baseScore'])
        return

    for information in information_filters:
        information_specific = information_specific.get(information)
    severity.append(information_specific)


def print_cve_id_and_severity(color, text, cve_id_list, severity_arr):
    if len(cve_id_list) != 0:
        print(color + text + const.RESET)
        for cve_id in cve_id_list:
            print(f'[ + ] - CVE-ID: {color}{cve_id}{const.RESET} | BASE SCORE: {color}{severity_arr[cve_id_list.index(cve_id)]}{const.RESET}')
            print(f'      - REFERENCE: https://nvd.nist.gov/vuln/detail/{cve_id}')

def print_non_cve_found():
    print(f'[ + ] - {const.GREEN}NENHUMA CVE ENCONTRADA{const.RESET} ')

def print_result():
    services_availables = portscan.exec_sequence()
    api_key = load_auth_token_from_properties_file()

    json_print = {}

    for index, service in enumerate(services_availables):
        json_response_from_search_endpoint = {'resultsPerPage': 0, 'startIndex': 0, 'totalResults': 0, 'result': {'CVE_Items': []}}
        if service != 'Not applicable to the search':
            keyword_to_search = { 'keyword': service, 'apiKey': api_key }
            json_response_from_search_endpoint = query_endpoint_to_get_cve(keyword_to_search)
            cve_id_list = collect_spefic_info_endpoint_response(json_response_from_search_endpoint, ['cve', 'CVE_data_meta', 'ID'])
            severity_list = collect_spefic_info_endpoint_response(json_response_from_search_endpoint, ['impact', 'baseMetric', 'cvssV2', 'baseScore'])
            get_cves_founds_in_search_endpoint(cve_id_list, severity_list, index)
        else:
            print_port_cve_found(index)
            print_non_cve_found()
        json_print = populate_final_json(index, service, json_response_from_search_endpoint)
    
    with open('data.json', 'w') as f:
        json.dump(json_print, f, indent=4)

    #if os.path.exists('data.json'):
    #    os.system('java -jar gerador_de_relatorios_detalhados.jar')

def get_cves_founds_in_search_endpoint(cve_id_list, severity_list, index):
    print_port_cve_found(index)
    if cve_id_list == severity_list:
        print_non_cve_found()
    print_cve_id_and_severity(const.PURPLE, "CRITICAL", cve_id_list['CRITICAL'], severity_list['CRITICAL'])
    print_cve_id_and_severity(const.RED, "HIGH", cve_id_list['HIGH'], severity_list['HIGH'])
    print_cve_id_and_severity(const.YELLOW, "MEDIUM", cve_id_list['MEDIUM'], severity_list['MEDIUM'])
    print_cve_id_and_severity(const.CYAN, "LOW", cve_id_list['LOW'], severity_list['LOW'])

def print_port_cve_found(index):
    print('\n\n')
    print('------------------------------------------------------------------------')
    print(f'\t\t\t\t{const.PURPLE}PORT {portscan.ports[index]}{const.RESET}')
    print('------------------------------------------------------------------------')


def populate_final_json(index, service, response):
    final_json[f"PORT {portscan.ports[index]}"] = []
    json_aux = {}
    for item in response['result']['CVE_Items']:
        if item['impact'] != {}:
            json_aux["SERVICE"] = service.split()[0]
            if len(service.split()) == 2:
                json_aux["PRODUCT"] = service.split()[1]
            else:
                json_aux["PRODUCT"] = ""
            json_aux["CVE-ID"] = item['cve']['CVE_data_meta']['ID']
            if 'baseMetricV2' in item['impact']:
                json_aux["BASE-SCORE"] =  item['impact']['baseMetricV2']['cvssV2']['baseScore']
            elif 'baseMetricV3' in item['impact']:
                json_aux["BASE-SCORE"] =  item['impact']['baseMetricV3']['cvssV3']['baseScore']
            json_aux["DESCRICAO"] = item['cve']['description']['description_data']
            ref_total = []
            for ref in item['cve']['references']['reference_data']:
                ref_total.append(ref['url'])

            json_aux["REFERENCES"] = ref_total

            final_json[f"PORT {portscan.ports[index]}"].append(json_aux)
            json_aux = {}

    return final_json

print_result()
 