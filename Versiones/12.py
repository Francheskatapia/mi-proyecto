import ipaddress
import os
import platform
import socket
import threading
import argparse
from tabulate import tabulate
def ping(ip):
    """Realiza un ping a una dirección IP y devuelve si está activa."""
    comando_base = "ping -n 1" if platform.system() == "Windows" else "ping -c 1"
    comando = f"{comando_base} {ip} >nul 2>&1" if platform.system() == "Windows" else f"{comando_base} {ip} >/dev/null 2>&1"
    respuesta = os.system(comando)
    return respuesta == 0

def ping_sweep(segmento_red):
    """Escanea un rango de direcciones IP para encontrar dispositivos activos."""
    dispositivos_encontrados = []
    print(f"\U0001F50D Escaneando la red {segmento_red}...\n")

    for ip in segmento_red.hosts():
        if ping(str(ip)):
            dispositivos_encontrados.append(str(ip))
            print(f"✔ Dispositivo activo encontrado: {ip}")

    if not dispositivos_encontrados:
        print("❌ No se encontraron dispositivos en la red.")
    return dispositivos_encontrados

def scan_port(ip, port):
    """Escanea un puerto en una dirección IP y devuelve si está abierto."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = banner_grabbing(ip, port)  # Llamar a banner_grabbing()
            return True, banner  # Devuelve True y el banner si el puerto está abierto
        return False, None
    finally:
        s.close()

def port_scan(ip, start_port=1, end_port=65535):
    """Escanea los puertos de una dirección IP dentro de un rango."""
    print(f"\n🎯 Escaneando puertos en {ip}...\n")
    puertos_abiertos = []
    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip}:\n")

        for port in range(start_port, end_port + 1):
            is_open, banner = scan_port(ip, port)  # Llama a scan_port()
            if is_open:
                servicio = get_service_name(port)
                print(f"✔ Puerto {port} abierto ({servicio}) - Banner: {banner}")
                puertos_abiertos.append([port, servicio, banner])

        # Usar Tabulate para mostrar resultados bonitos
        print(tabulate(puertos_abiertos, headers=["Puerto", "Servicio", "Banner"], tablefmt="grid"))

        # Guardar resultados ordenados
        for puerto in puertos_abiertos:
            archivo.write(f"Puerto {puerto[0]} abierto ({puerto[1]}) - Banner: {puerto[2]}\n")

def banner_grabbing(ip, port):
    """Intenta capturar el banner de un servicio en un puerto abierto."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")  # Enviar un mensaje básico HTTP
        banner = s.recv(1024).decode().strip()
        return banner if banner else "No disponible"
    except:
        return "No disponible"
    finally:
        s.close()

def get_service_name(port):
    """Devuelve el nombre del servicio asociado a un puerto."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Desconocido"

def main():
    """Punto de entrada del programa con argparse."""
    parser = argparse.ArgumentParser(description="Escáner de red y puertos.")
    parser.add_argument("ip", help="Dirección IP base de la red (Ejemplo: 192.168.1.1)")
    parser.add_argument("mascara", help="Máscara de red (Ejemplo: 255.255.255.0)")
    parser.add_argument("--start-port", type=int, default=1, help="Puerto inicial para el escaneo.")
    parser.add_argument("--end-port", type=int, default=65535, help="Puerto final para el escaneo.")
    args = parser.parse_args()

    try:
        segmento_red = ipaddress.IPv4Network(f"{args.ip}/{args.mascara}", strict=False)
        dispositivos_encontrados = ping_sweep(segmento_red)

        if dispositivos_encontrados:
            dispositivos_encontrados = sorted(dispositivos_encontrados)
            print(f"\n🌐 Redes encontradas y ordenadas: {dispositivos_encontrados}\n")

            hilos_puertos = []
            for dispositivo in dispositivos_encontrados:
                hilo = threading.Thread(target=port_scan, args=(dispositivo, args.start_port, args.end_port))
                hilos_puertos.append(hilo)
                hilo.start()

            for hilo in hilos_puertos:
                hilo.join()

    except ValueError:
        print("❌ Error: La IP o máscara de red no son válidas.")

if __name__ == "__main__":
    main()
#     # Manejo de errores