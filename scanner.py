 #!/usr/bin/python3
#we going to create a very simple program taht will ask the user for the foreign IP@
#that want tonscan , it will prompt them rather than ask
#we could have a SYN scan , a UDP scan TCP ,scan 
 
from ipaddress import ip_address
from re import S
import nmap

scanner = nmap.PortScanner()
print("welcome , this is a simple nmap automation tool ")
print("===============================================")
ip_addr = input("please entr the @IP you want to scan : ")
print("the IP @ is : ", ip_addr)
type( ip_addr)
resp=input(""" \nPlease enter the type of scan you want to run : 
    1)SYN ACK scan 
    2)UDP SCAN 
    3)Comprehensive scan \n""")    
print("You have selected option : ", resp)

if resp =='1':
    print("Nmap version : ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024' , '-v -sS')
    print(scanner.scaninfo())
    print("Ip  status :"  ,scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports : ", scanner[ip_addr]['tcp'].keys())
elif resp =='2':
    print("Nmap version : ", scanner.nmap_version())
    scanner.scan(ip_addr, '21-443' , '-v -sU')
    print(scanner.scaninfo())
    print("Ip  status :"  ,scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports : ", scanner[ip_addr]['udp'].keys())
elif resp =='3':
    print("Nmap version : ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024' , '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip  status :"  ,scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports : ", scanner[ip_addr]['udp'].keys())  
elif resp >= '4':
    print("Entrez un option valide !! ")