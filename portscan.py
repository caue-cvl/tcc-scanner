import nmap 
   
begin = 78
end = 80
target = '192.168.0.26'
   
scanner = nmap.PortScanner() 

def banner():
    print("""
 __      ___                       _         __       _                   
 \ \    / (_)                     | |       / _|     | |                  
  \ \  / / _ ___  __ _  ___     __| | ___  | |_ _   _| |_ _   _ _ __ ___  
   \ \/ / | / __|/ _` |/ _ \   / _` |/ _ \ |  _| | | | __| | | | '__/ _ \ 
    \  /  | \__ \ (_| | (_) | | (_| |  __/ | | | |_| | |_| |_| | | | (_) |
     \/   |_|___/\__,_|\___/   \__,_|\___| |_|  \__,_|\__|\__,_|_|  \___/ 
                                                                          
                                                                          """)

banner()
arr_ports_filtered = []
arr_ports_open = []
cont_ports_filtered = 0
cont_ports_open = 0

for i in range(begin,end+1):

    resu = scanner.scan(target,str(i),arguments='-sV')
    res_state = resu['scan'][target]['tcp'][i]['state']
    res_name = resu['scan'][target]['tcp'][i]['name']
    res_product = resu['scan'][target]['tcp'][i]['product']
    res_version = resu['scan'][target]['tcp'][i]['version']

    if res_state == 'closed':
        continue
    else:
        print(f'Port {i} is {res_state}, with {res_name} protocol in {res_product} at {res_version}.')