import nmap
import const
import ipaddress
from ping3 import ping

ports = []


def banner():
    print("""

 __      ___    _ _      _   _        _____  _____          _   _ _   _ ______ _____  
 \ \    / / |  | | |    | \ | |      / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
  \ \  / /| |  | | |    |  \| |     | (___ | |       /  \  |  \| |  \| | |__  | |__) |
   \ \/ / | |  | | |    | . ` |      \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
    \  /  | |__| | |____| |\  |      ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
     \/    \____/|______|_| \_|     |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\
                                         
    """)

def show_question_verbose():
    verbose = input('Do you want to use the verbose mode (detail mode)? (Y/N): ').upper()
    print()
    while True:
        if verbose[0] == 'Y' or verbose[0] == 'N':
            return verbose[0]
        else:
            show_question_verbose()

def closed_port(connection_state, port):
    print(f'{const.RED}Port {port}{const.RESET} is closed.')
    
def open_port(port_scan_result, port, arr_query_search_cve):
    service = port_scan_result['name']
    product = port_scan_result['product']
    version = port_scan_result['version']

    if version != '':
        print(f'{const.GREEN}port {port}{const.RESET} is open, with the service {service} of {product} in the following version {version}.')
    else:
        print(f'{const.YELLOW}port {port}{const.RESET} is open, with the service {service} of {product}.\n{const.BOLD}(Version no identified){const.RESET}.')

    if product == '':
        query_search_cve = 'Not applicable to the search'
    else:
        query_search_cve = service + ' ' + product + (' ' + version if version != '' else '')
    arr_query_search_cve.append(query_search_cve)

def scan(target, begin_scan_scope, end_scan_scope, verbose_mode):
    scanner = nmap.PortScanner()
    arr_query_search_cve = []
    for i in range(begin_scan_scope,end_scan_scope+1):
        result = scanner.scan(target,str(i),arguments='-sV')                           # USO DO PARAMETRO -sV DA FERRAMENTA NMAP
        port_state = result['scan'][target]['tcp'][i]['state']

        if verbose_mode == 'Y' and port_state == 'closed':
                closed_port(port_state, i)

        if port_state == 'open':
            save_open_port(result['nmap']['scaninfo']['tcp']['services'])
            open_port(result['scan'][target]['tcp'][i], i, arr_query_search_cve)
    return arr_query_search_cve


def save_open_port(port):
    global ports
    ports.append(port)

def ler_input_port(port):
    ok = False
    value = 0
    while True:
        value_port = str(input(port))
        if value_port.isnumeric():
            value = int(value_port)
            ok = True
        else:
            print('Type a valide port.')
        if ok:
            break
    return value

def read_input_port(target):
    ok = False
    value = ''
    while True:
        try:
            value_target = str(input(target))
            if ipaddress.ip_address(value_target):
                value = str(value_target)
                ok = True 
            else:
                print('Type a valid IP.')
            alvo_detectavel = ping(value)
            if alvo_detectavel == None:
                print('Unreachable IP.')
                ok = False
            if ok:
                break
        except:
            print('Type a valid IP.')
    return value

def exec_sequence():
    banner()
    target = read_input_port('Type the TARGET machine IP:')
    port_inicio = ler_input_port('Type the starting port: ')
    port_fim = ler_input_port('Type the ending port: ')
    return scan(target, port_inicio, port_fim, show_question_verbose())