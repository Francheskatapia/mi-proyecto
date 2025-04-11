import ipaddress
import os
import platform
import socket
import threading

def ping(ip):
    """Realiza un ping a una dirección IP y devuelve si está activa."""
    comando_base = "ping -n 1" if platform.system() == "Windows" else "ping -c 1"
    comando = f"{comando_base} {ip} >nul 2>&1" if platform.system() == "Windows" else f"{comando_base} {ip} >/dev/null 2>&1"
    respuesta = os.system(comando)
    return respuesta == 0

def ping_sweep(segmento_red):
    """Escanea un rango de direcciones IP para encontrar dispositivos activos."""
    dispositivos_encontrados = []
    print(f"🔍 Escaneando la red {segmento_red}...\n")

    for ip in segmento_red.hosts():
        if ping(str(ip)):
            dispositivos_encontrados.append(str(ip))
            print(f"✔ Dispositivo activo encontrado: {ip}")

    if not dispositivos_encontrados:
        print("❌ No se encontraron dispositivos en la red.")
    return dispositivos_encontrados

def scan_port(ip, port):
    """Escanea un puerto en una dirección IP y devuelve si está abierto."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        return result == 0  # Devuelve True si el puerto está abierto

def port_scan(ip, start_port=1, end_port=65535):
    """Escanea los puertos de una dirección IP dentro de un rango."""
    print(f"\n🎯 Escaneando puertos en {ip}...\n")
    puertos_abiertos = []

    for port in range(start_port, end_port + 1):
        if scan_port(ip, port):
            servicio = get_service_name(port)
            puertos_abiertos.append((port, servicio))

    return puertos_abiertos

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
        for puerto, servicio in puertos_abiertos:
            print(f"✔ Puerto {puerto} abierto ({servicio})")

        # Guardar resultados en un archivo
        with open("puertos_abiertos.txt", "a") as archivo:
            archivo.write(f"\nPuertos abiertos en {ip}:\n")
            for puerto, servicio in puertos_abiertos:
                archivo.write(f"Puerto {puerto} abierto ({servicio})\n")
    else:
        print(f"\nNo se encontraron puertos abiertos en {ip}.")

if __name__ == "__main__":
    # Solicitar datos al usuario
    ip_base = input("🔹 Ingresa la dirección IP de la red (Ejemplo: 192.168.1.1): ")
    mascara = input("🔹 Ingresa la máscara de red (Ejemplo: 255.255.255.0): ")

    try:
        segmento_red = ipaddress.IPv4Network(f"{ip_base}/{mascara}", strict=False)
        dispositivos_encontrados = ping_sweep(segmento_red)

        if dispositivos_encontrados:
            dispositivos_encontrados = sorted(dispositivos_encontrados)
            print(f"\n🌐 Redes encontradas y ordenadas: {dispositivos_encontrados}\n")

            hilos_puertos = []

            for dispositivo in dispositivos_encontrados:
                hilo = threading.Thread(
                    target=lambda ip=dispositivo: print_results(port_scan(ip), ip)
                )
                hilos_puertos.append(hilo)
                hilo.start()

            for hilo in hilos_puertos:
                hilo.join()

    except ValueError:
        print("❌ Error: La IP o máscara de red no son válidas.")

 # se elimino el menu de opciones para escanear puertos comunes o todos los puertos, ya que no es necesario en este contexto.
# se cambio el nombre de la funcion port_scan por port_scan_comunes para evitar confusiones