import nmap 
   
begin = 70
end = 80
target = '192.168.0.17'
   
scanner = nmap.PortScanner() 

def banner():
    print(""" __      ___                       _         __       _                   
 \ \    / (_)                     | |       / _|     | |                  
  \ \  / / _ ___  __ _  ___     __| | ___  | |_ _   _| |_ _   _ _ __ ___  
   \ \/ / | / __|/ _` |/ _ \   / _` |/ _ \ |  _| | | | __| | | | '__/ _ \ 
    \  /  | \__ \ (_| | (_) | | (_| |  __/ | | | |_| | |_| |_| | | | (_) |
     \/   |_|___/\__,_|\___/   \__,_|\___| |_|  \__,_|\__|\__,_|_|  \___/ 
                                                                          
                                                                          """)

banner()
arr_ports_filtered = []
arr_ports_open = []
for i in range(begin,end+1):
    res = scanner.scan(target,str(i))
    res = res['scan'][target]['tcp'][i]['state']
    if(res != 'filtered'):
        arr_ports_filtered.append(i)
        print('PORTA FILTRADA ADICIONADA')
    elif (res != 'open'):
        arr_ports_open.append(i)
        print('PORTA ABERTA ADICIONADA')

inpt_pergunta_verbosidade_portas_filtradas = str(input("Deseja verificar portas filtradas (S/N)? ")).upper()[0]
if (inpt_pergunta_verbosidade_portas_filtradas == 'S'):
    print(f"Foram detectadas {len(arr_ports_filtered)} portas filtradas. São elas: {arr_ports_filtered}")
print(f"Foram detectadas {len(arr_ports_open)} portas abertas   . São elas: {arr_ports_open}")