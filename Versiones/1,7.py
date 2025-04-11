import ipaddress
import platform
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import subprocess


def ping(ip):
    """Realiza un ping a una dirección IP y devuelve si está activa."""
    comando_base = ["ping", "-n", "1"] if platform.system() == "Windows" else ["ping", "-c", "1"]
    comando = comando_base + [ip]
    try:
        result = subprocess.run(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0  # Devuelve True si el ping fue exitoso
    except Exception as e:
        print(f"Error al hacer ping a {ip}: {e}")
        return False


def ping_sweep(segmento_red):
    """Escanea un rango de direcciones IP para encontrar dispositivos activos utilizando ThreadPoolExecutor."""
    dispositivos_encontrados = []
    print(f"🔍 Escaneando la red {segmento_red}...\n")

    def verificar_dispositivo(ip):
        if ping(ip):
            dispositivos_encontrados.append(ip)
            print(f"✔ Dispositivo activo encontrado: {ip}")

    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(verificar_dispositivo, map(str, segmento_red.hosts()))  # Paralelizar el escaneo

    if not dispositivos_encontrados:
        print("❌ No se encontraron dispositivos en la red.")
    return dispositivos_encontrados


def scan_port(ip, port):
    """Escanea un puerto en una dirección IP y devuelve si está abierto."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            return result == 0  # True si está abierto
    except socket.timeout:
        print(f"⚠ Tiempo de espera agotado para el puerto {port} en {ip}")
    except socket.error as e:
        print(f"⚠ Error en el puerto {port} en {ip}: {e}")
    return False


def port_scan_parallel(ip, start_port, end_port):
    """Escanea los puertos de una dirección IP dentro de un rango utilizando ThreadPoolExecutor."""
    print(f"\n🎯 Escaneando puertos en {ip}...\n")
    puertos_abiertos = []

    def verificar_puerto(port):
        if scan_port(ip, port):
            servicio = get_service_name(port)
            puertos_abiertos.append((port, servicio))

    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(verificar_puerto, range(start_port, end_port + 1))

    return puertos_abiertos


def banner_grabbing(ip, port):
    """Intenta capturar el banner de un servicio en un puerto abierto."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.1\r\n\r\n")  # Mensaje básico para obtener el banner
            banner = s.recv(1024).decode().strip()
            return banner if banner else "No disponible"
    except:
        return "No disponible"


def get_service_name(port):
    """Devuelve el nombre del servicio asociado a un puerto."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Desconocido"


def print_results(puertos_abiertos, ip):
    """Imprime los resultados del escaneo de puertos y los guarda en un archivo."""
    if puertos_abiertos:
        print(f"\nResultados del escaneo de puertos en {ip}:\n")
        print(f"{'Puerto':<10}{'Servicio':<20}")
        print("-" * 30)
        for puerto, servicio in puertos_abiertos:
            print(f"{puerto:<10}{servicio:<20}")

        # Guardar resultados en un archivo
        with open("puertos_abiertos.txt", "a") as archivo:
            archivo.write(f"\nPuertos abiertos en {ip}:\n")
            for puerto, servicio in puertos_abiertos:
                archivo.write(f"Puerto {puerto} abierto ({servicio})\n")
    else:
        print(f"\nNo se encontraron puertos abiertos en {ip}.")


if __name__ == "__main__":
    try:
        ip_base = input("🔹 Ingresa la dirección IP de la red (Ejemplo: 192.168.1.1): ")
        mascara = input("🔹 Ingresa la máscara de red (Ejemplo: 255.255.255.0): ")
        segmento_red = ipaddress.IPv4Network(f"{ip_base}/{mascara}", strict=False)

        dispositivos_encontrados = ping_sweep(segmento_red)

        if dispositivos_encontrados:
            dispositivos_encontrados = sorted(dispositivos_encontrados)
            print(f"\n🌐 Redes encontradas y ordenadas: {dispositivos_encontrados}\n")

            for dispositivo in dispositivos_encontrados:
                puertos_abiertos = port_scan_parallel(dispositivo, 1, 65535)
                print_results(puertos_abiertos, dispositivo)

    except ValueError:
        print("❌ Error: Dirección IP o máscara de red no válidas. Intenta nuevamente.")
# pequeña mejora al escaneo multihilo de puertos, para manejar múltiples hilos de manera más eficiente.