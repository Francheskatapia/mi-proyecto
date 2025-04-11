import ipaddress
import os
import platform
import socket
import threading
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed  # 🆕 para paralelizar ping

def ping(ip):
    comando_base = "ping -n 1" if platform.system() == "Windows" else "ping -c 1"
    comando = f"{comando_base} {ip} >nul 2>&1" if platform.system() == "Windows" else f"{comando_base} {ip} >/dev/null 2>&1"
    respuesta = os.system(comando)
    return ip if respuesta == 0 else None

def ping_sweep(segmento_red):
    print(f"\U0001F50D Escaneando la red {segmento_red}...\n")
    dispositivos_encontrados = []

    # Usamos hilos para hacer pings más rápido
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping, str(ip)): ip for ip in segmento_red.hosts()}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                dispositivos_encontrados.append(resultado)
                print(f"✔ Dispositivo activo encontrado: {resultado}")

    if not dispositivos_encontrados:
        print("❌ No se encontraron dispositivos en la red.")

    return dispositivos_encontrados

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = banner_grabbing(ip, port)
            return True, banner
        return False, None
    finally:
        s.close()

def port_scan(ip, start_port=1, end_port=65535):
    print(f"\n🎯 Escaneando puertos en {ip}...\n")
    puertos_abiertos = []
    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip}:\n")

        for port in range(start_port, end_port + 1):
            is_open, banner = scan_port(ip, port)
            if is_open:
                servicio = get_service_name(port)
                print(f"✔ Puerto {port} abierto ({servicio}) - Banner: {banner}")
                puertos_abiertos.append([port, servicio, banner])

        print(tabulate(puertos_abiertos, headers=["Puerto", "Servicio", "Banner"], tablefmt="grid"))

        for puerto in puertos_abiertos:
            archivo.write(f"Puerto {puerto[0]} abierto ({puerto[1]}) - Banner: {puerto[2]}\n")

def port_scan_comunes(ip):
    print(f"\n🎯 Escaneando puertos comunes en {ip}...\n")
    puertos_abiertos = []
    puertos_comunes = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip} (modo rápido):\n")

        for port in puertos_comunes:
            is_open, banner = scan_port(ip, port)
            if is_open:
                servicio = get_service_name(port)
                print(f"✔ Puerto {port} abierto ({servicio}) - Banner: {banner}")
                puertos_abiertos.append([port, servicio, banner])

        print(tabulate(puertos_abiertos, headers=["Puerto", "Servicio", "Banner"], tablefmt="grid"))

        for puerto in puertos_abiertos:
            archivo.write(f"Puerto {puerto[0]} abierto ({puerto[1]}) - Banner: {puerto[2]}\n")

def banner_grabbing(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = s.recv(1024).decode().strip()
        return banner if banner else "No disponible"
    except:
        return "No disponible"
    finally:
        s.close()

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Desconocido"

def main():
    print("🕸️ Bienvenido al escáner de red y puertos 🛡️")

    # Validar IP y máscara
    while True:
        ip_base = input("📥 Ingresa la dirección IP base de la red (Ej: 192.168.1.1): ").strip()
        mascara = input("📥 Ingresa la máscara de red (Ej: 255.255.255.0): ").strip()

        try:
            segmento_red = ipaddress.IPv4Network(f"{ip_base}/{mascara}", strict=False)
            break
        except ValueError:
            print("❌ Dirección IP o máscara no válidas. Intenta nuevamente.\n")

    # Selección del tipo de escaneo
    print("\n🧠 Selecciona el tipo de escaneo de puertos:")
    print("1. 🔍 Escaneo rápido (puertos comunes)")
    print("2. 🧨 Escaneo completo (todos los puertos)")

    opcion = input("👉 Opción [1/2]: ").strip()

    dispositivos_encontrados = ping_sweep(segmento_red)

    if dispositivos_encontrados:
        dispositivos_encontrados = sorted(dispositivos_encontrados)
        print(f"\n🌐 Redes encontradas y ordenadas: {dispositivos_encontrados}\n")

        hilos_puertos = []
        for dispositivo in dispositivos_encontrados:
            if opcion == "2":
                hilo = threading.Thread(target=port_scan, args=(dispositivo,))
            else:
                hilo = threading.Thread(target=port_scan_comunes, args=(dispositivo,))
            hilos_puertos.append(hilo)
            hilo.start()

        for hilo in hilos_puertos:
            hilo.join()

if __name__ == "__main__":
    main()
