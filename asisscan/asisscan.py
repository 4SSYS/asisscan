from scapy.all import *
import concurrent.futures
import argparse
import logging
import socket  # Importación añadida

logging.basicConfig(filename='scan_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def scan_port(ip, port, timeout=1):
    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
    try:
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(TCP):
            tcp_layer = resp.getlayer(TCP)
            if tcp_layer.flags == 0x12:
                logging.info(f"Puerto {port} está abierto")
                return port, True, resp
            elif tcp_layer.flags == 0x14:
                return port, False, resp
        return port, False, resp
    except Exception as e:
        logging.error(f"Error al intentar escanear el puerto {port}: {e}")
        return port, False, None

def scan_ports(ip, start_port=1, end_port=1024, timeout=1):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port, timeout) for port in range(start_port, end_port + 1)]
        for future in concurrent.futures.as_completed(futures):
            port, is_open, resp = future.result()
            if is_open:
                open_ports.append(port)
                print(f"El puerto {port} está abierto")
                if resp:
                    os_detection(resp)
    return open_ports

def os_detection(resp):
    ttl = resp[IP].ttl
    if ttl <= 64:
        os = "Linux/Unix"
    elif ttl <= 128:
        os = "Windows"
    else:
        os = "Desconocido"
    print(f"Posible sistema operativo: {os}")
    logging.info(f"Posible sistema operativo: {os}")

def get_mac_and_name(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=0)[0]
    for element in answered_list:
        mac_address = element[1].hwsrc
        try:
            device_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            device_name = "Desconocido"
        print(f"Dispositivo: {device_name}, Dirección MAC: {mac_address}")
        logging.info(f"Dispositivo: {device_name}, Dirección MAC: {mac_address}")

def main():
    parser = argparse.ArgumentParser(description="Escáner de puertos by Asiss")
    parser.add_argument("--start_port", type=int, default=1, help="Puerto inicial (por defecto: 1)")
    parser.add_argument("--end_port", type=int, default=1024, help="Puerto final (por defecto: 1024)")
    parser.add_argument("--timeout", type=int, default=1, help="Tiempo de espera en segundos (por defecto: 1)")
    args = parser.parse_args()

    ip = input("Introduce la dirección IP del objetivo: ")
    

    get_mac_and_name(ip)
    open_ports = scan_ports(ip, args.start_port, args.end_port, args.timeout)
    print(f"Puertos abiertos: {open_ports}")

if __name__ == "__main__":
    main()
