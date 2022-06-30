import nmap 
   
begin = 78
end = 80
target = '192.168.0.26'
   
scanner = nmap.PortScanner() 

def banner():
    print("""
  _______ _____ _____            ______   _______ ______ _____ 
 |__   __/ ____/ ____|          |  ____/\|__   __|  ____/ ____|
    | | | |   | |       ______  | |__ /  \  | |  | |__ | |     
    | | | |   | |      |______| |  __/ /\ \ | |  |  __|| |     
    | | | |___| |____           | | / ____ \| |  | |___| |____ 
    |_|  \_____\_____|          |_|/_/    \_\_|  |______\_____|
                                                                          
                                                                          """)

banner()

verbose = input('Você deseja fazer a pesquisa em verbose mode?(S/N): ')
print()

for i in range(begin,end+1):

    resu = scanner.scan(target,str(i),arguments='-sV')
    res_state = resu['scan'][target]['tcp'][i]['state']
    res_name = resu['scan'][target]['tcp'][i]['name']
    res_product = resu['scan'][target]['tcp'][i]['product']
    res_version = resu['scan'][target]['tcp'][i]['version']

    if verbose == 'S' or verbose == 's':
        if res_state == 'closed':
            print(f'Port {i} is {res_state}.')
        else:
            print(f'Port {i} is {res_state}, with {res_name} protocol in {res_product} at {res_version}.')
    elif verbose == 'N' or verbose == 'n':
        if res_state == 'closed':
            continue
        else:
            print(f'Port {i} is {res_state}, with {res_name} protocol in {res_product} at {res_version}.')
    else:
        continue