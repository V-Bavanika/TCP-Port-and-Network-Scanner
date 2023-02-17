import scapy.all as scapy
import socket
import threading
import concurrent.futures
import colorama
from colorama import Fore
colorama.init()
print_lock = threading.Lock()

def my_networkscanner():
	print("The following are the devices connected to the n/w :")
	req=scapy.ARP()
	#print(type(req))
	request = scapy.ARP()
  
	request.pdst ='10.0.2.15/24'
	broadcast = scapy.Ether()
  
	broadcast.dst ='ff:ff:ff:ff:ff:ff' 
  
	request_broadcast = broadcast / request
	clients = scapy.srp(request_broadcast, timeout = 5)[0]
	print("Destination IP\t     MAC of Destination host     Source IP\tMAC of Source host")
	for element in clients:
		print(element[1].psrc + "                " + element[1].hwsrc+"        "+element[1].pdst+"      "+element[1].hwdst)
    
def my_portscanner(ip,port):
	scanner=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	scanner.settimeout(1)
	try:
		scanner.connect((ip,port))
		scanner.close()
		with print_lock:
    			print(Fore.WHITE +  f"[{port}]" + Fore.GREEN + "Opened")
     
	except: 
		pass


def intro():
	kk=int(input("Enter the choice:\n1:Network scanner\n2:TCP Port scanner\n"))
	if kk==1:
		my_networkscanner()
	elif kk==2:
		ip= input("Enter the IP to scan: ")
		with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
			for port in range(8000):
				executor.submit(my_portscanner,ip,port+1)
	else:
		intro()

intro()