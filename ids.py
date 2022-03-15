#
# Esta IDS funciona apenas com ipv4 no momento.
#

import os
import time
import threading
from colorama import Fore, Back, Style
log = '/var/log/vsftpd.log' # Arquivo de log a ser monitorado.
tam = os.stat(log).st_size  # Tamanho do arquivo para comparação.
key = True                  # Chave para comparaçãod e tempo.
sec_0, sec_2 = 0,0          # Marcadores de tempo.
ip_0, ip_2 = 0,0            # Marcadores de ip.
cont = 0                    # Contador de tentativas por segundo.
ip_table_ban = []           # lista de ips banidos.

#
#   Layout menu.
#
def printMenu():
    print('Menu:\n -t -> Show banned tables.\n -a -> Unban ip manually.\n -r -> Banned ip manually.\n -h -> help.')
    print('Examples: -a [IP] ')
    print('*The commands can be used anytime.\n')
printMenu()
#
# Lista ips banidos.
#
def listBanneds():
    with open('ipsBanned.txt', 'r') as file:
        f = file.readlines()
        for i in f:
            print(i)

#
# Desbane um ip na tabela de ips de banidos.
#
def unBanIp(ip_):
    ip = ip_.split()[1]
    os.system('iptables -I INPUT -s ' + ip + ' -p tcp --dport ftp -j ACCEPT')
    print(Fore.BLACK + Back.GREEN + 'UNBAN - IP: '+ ip + Style.RESET_ALL)
    f = ''
    with open('ipsBanned.txt', 'r') as file:
        f = file.readlines() 
    f.remove(ip+'\n')
    with open('ipsBanned.txt', 'w') as file:
        file.writelines(f)
    with open('log-ids.txt', 'a') as file:                              # Registra o log do ip desbanido.
        file.write(" [UNBAN] - : ip:" + ip + " - Time: NULL stop: NULL \n")
    for i in ip_table_ban:
        if ip == i[0]:
            ip_table_ban.remove(ip)

#
# Bane um ip.
#
def banIp(ip_):
    ip = ip_.split()[1]
    os.system('iptables -I INPUT -s ' + ip + ' -p tcp --dport ftp -j REJECT')
    print(Back.RED + Fore.BLACK + 'BANNED - IP: '+ ip + Style.RESET_ALL)
    with open('ipsBanned.txt', 'a') as file:
        file.write(ip+'\n')
    with open('log-ids.txt', 'a') as file:                              # Registra o log do ip banido.
        file.write(" [BANNED] - : ip:" + ip + " - Login tried: NULL - Time: NULL start: NULL\n")


#
# Menu
#
def menu():
    while(1):
        command = input(':> ')       # Entrada de comandos
        try:
            if '-t' in command:
                listBanneds()   
            elif '-a' in command:
                unBanIp(command)
            elif '-r' in command:
                banIp(command)
            elif '-h' in command:
                printMenu()
            else:
                print('Invalid input.')
        except:
            print('Invalid input.')
            
#
# Desbane automaticamente os ips na lista
#
def unBanIpAuto(file):
    for ip in file.readlines():
        if len(ip) > 1:
            ip = ip[:len(ip)-1]
            os.system('iptables -I INPUT -s ' + ip + ' -p tcp --dport ftp -j ACCEPT')
            print(Fore.BLACK + Back.GREEN + 'UNBAN - IP: '+ ip + Style.RESET_ALL)
#
# Verifica se é possivel a leitura do arquivo de log,
# e se tem acesso privilegiado ao sitema.
#
if os.access(log, os.R_OK) and os.geteuid() == 0:
    try:                                          
        with open('ipsBanned.txt','r')as file:                                      # Lendo arquivo de ips banidos.
            unBanIpAuto(file)           
    except:
        pass
    with open('ipsBanned.txt', 'w') as file:                                        # Criando/Zerando arquivo de ips banidos.
        file.write('')        
        print('\nCleaned banned list.\n')
    
    print(Fore.GREEN + ' -- Stating Detector BruteForce FTP -- ' + Style.RESET_ALL)
    t = threading.Thread(target=menu)                                               # Thread controladora de comandos.
    t.start()
    while(1):
        if tam < os.stat(log).st_size:                                              # Compara o tamanho do arquivo, 
            tam = os.stat(log).st_size                                              # caso a condição seja positiva, o arquivo foi alterado
            with open(log, 'r') as file:
                line = file.readlines()
                line = line[len(line)-1]                                            # Recupera a ultima linha do arquvio.
                if "FAIL LOGIN" in line:             
                    ip = line.split()[11][8:]                                       # Extrai ip.
                    ip = ip[:len(ip)-1]
                    login = line.split()[7][1:]                                     # Extrai login utilizado.
                    login = login[:len(login)-1]
                    dateTime = line.split()[3]                                      # Extrai data.
                    print(Fore.RED + "LOGIN FAIL:" + Style.RESET_ALL + " ip:" + ip + " - Login tried: " + login + " - Time: " + dateTime)
                    
                    if sec_0 == int(dateTime[6:]) and ip_0 == ip:                   # Compara o ip e o tempo com a da ultima requisicao.
                        cont+=1
                        if(cont == 5):                                              # Com mais de 5 tentativas no mesmo segundo o ip é banido.
                            try:
                                start = time.time()                                 # Marca a data de inicio do ban.
                                print(Back.RED + Fore.BLACK + 'BANNED - IP: '+ ip + Style.RESET_ALL)
                                _ = int(ip.replace(".",""))                         # Verifica se realmente é um ipv4.
                                ip_table_ban.append([ip, dateTime, start])          # Insere o ip na lista de banimento.
                                with open('log-ids.txt', 'a') as file:              # Registra o log do ip banido.
                                    file.write(" [BANNED] - : ip:" + ip + " - Login tried: " + login + " - Time: " + dateTime + " start: " + str(start) + '\n')
                                with open('ipsBanned.txt', 'a') as file:            # Adiciona o ip na lista externa de banimento.
                                    file.write(ip+'\n')
                                os.system('iptables -I INPUT -s ' + ip + ' -p tcp --dport ftp -j REJECT') # Bane o ip.
                                time.sleep(5)
                                cont = 0
                            except:
                                print("IP ERROR")
                    else:                               
                        sec_0 = int(dateTime[6:])                                  
                        ip_0 = ip                                            
        #
        # Desbanindo ip com o tempo.   
        #
        for i in ip_table_ban:                                                     
            if round(time.time()- i[2]) >= 600:                                     # Desbane o ip após 600 segundos.
                print(Fore.BLACK + Back.GREEN + 'UNBAN - IP: '+ ip + Style.RESET_ALL)
                ip_table_ban.remove(i)                                              # Remove ip banido da lista
                with open('log-ids.txt', 'a') as file:                              # Registra o log do ip desbanido.
                    file.write(" [UNBAN] - : ip:" + ip + " - Time: " + dateTime + " stop: " + str(time.time()) + '\n')
                os.system('iptables -I INPUT -s ' + i[0] + ' -p tcp --dport ftp -j ACCEPT')             # Desbane o ip.
                f = ''
                with open('ipsBanned.txt', 'r') as file:                            # Removendo ip da lista externa de banimento.
                    f = file.readlines()
                f.remove(ip+'\n')
                with open('ipsBanned.txt', 'w') as file:
                    file.writelines(f)
else:
    print("Sem permissão de acesso.")
    

