import ipaddress
import os
import platform
import socket
import threading
import argparse

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
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            return True
        return False
    finally:
        s.close()

def port_scan(ip, start_port=1, end_port=65535):
    """Escanea los puertos de una dirección IP dentro de un rango."""
    print(f"\n🎯 Escaneando puertos en {ip}...\n")
    puertos_abiertos = []
    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip}:\n")

        for port in range(start_port, end_port + 1):
            if scan_port(ip, port):
                servicio = get_service_name(port)
                print(f"✔ Puerto {port} abierto ({servicio})")
                puertos_abiertos.append((port, servicio))

        # Mostrar resultados en formato sencillo
        print("\nResultados del escaneo de puertos:")
        for puerto, servicio in puertos_abiertos:
            print(f"Puerto: {puerto}, Servicio: {servicio}")

        # Guardar resultados en el archivo
        for puerto, servicio in puertos_abiertos:
            archivo.write(f"Puerto {puerto} abierto ({servicio})\n")

def get_service_name(port):
    """Devuelve el nombre del servicio asociado a un puerto."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Desconocido"

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
                hilo = threading.Thread(target=port_scan, args=(dispositivo, 1, 65535))
                hilos_puertos.append(hilo)
                hilo.start()

            for hilo in hilos_puertos:
                hilo.join()

    except ValueError:
        print("❌ Error: La IP o máscara de red no son válidas.")
# se implemento argparse para que el usuario pueda ingresar la ip y mascara de red por consola