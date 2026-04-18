import socket
import ipaddress
from datetime import datetime


target_input = input("Enter Target IP or Network: ")

try:
    network = ipaddress.ip_network(target_input, strict=False)
except ValueError:
    print("Invalid format. Please use a valid IP or CIDR block.")
    exit()


show_closed = input("Display closed ports? (y/n): ").lower() == 'y'

start_time = datetime.now()
print(f"\n[!] Scanning ports 1-5000 started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
print("-" * 65)

try:
    for ip in network:
        target = str(ip)
        print(f"\n>>> Results for Host: {target}")
        
       
        for port in range(1, 5001):
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
          
            soc.settimeout(0.2) 
            
            result = soc.connect_ex((target, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                print(f"    [+] Port {port: <5} | STATE: OPEN   | SERVICE: {service}")
            
            elif show_closed:
                print(f"    [-] Port {port: <5} | STATE: CLOSED")
            
            soc.close()

except KeyboardInterrupt:
    print("\n[!] Scan stopped by user.")

end_time = datetime.now()
print("-" * 65)
print(f"Scan finished at: {end_time.strftime('%H:%M:%S')}")
print(f"Total Duration: {end_time - start_time}")