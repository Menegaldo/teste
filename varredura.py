import socket
from concurrent.futures import ThreadPoolExecutor

TARGET = "192.168.1.10"
START_PORT = 1
END_PORT = 1024
TIMEOUT = 0.5

open_ports = []

def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)

            if s.connect_ex((TARGET, port)) == 0:
                open_ports.append(port)
                print(f"[+] Porta aberta: {port}/tcp")

    except Exception:
        pass


print(f"[*] Escaneando {TARGET}...")
print(f"[*] Portas: {START_PORT}-{END_PORT}\n")

with ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(scan_port, range(START_PORT, END_PORT + 1))


print("\n========== RESULTADO ==========")

if open_ports:
    open_ports.sort()

    print(f"[+] {len(open_ports)} porta(s) aberta(s):")

    for port in open_ports:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "desconhecido"

        print(f"    {port}/tcp - {service}")
else:
    print("[-] Nenhuma porta aberta encontrada.")
