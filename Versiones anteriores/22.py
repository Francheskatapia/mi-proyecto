import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
import argparse

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
    """Escanea un rango de direcciones IP para encontrar dispositivos activos."""
    dispositivos_encontrados = []
    print(f"🔍 Escaneando la red {segmento_red}...\n")

    def verificar_dispositivo(ip):
        if ping(ip):
            dispositivos_encontrados.append(ip)
            print(f"✔ Dispositivo activo encontrado: {ip}")

    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(verificar_dispositivo, map(str, segmento_red.hosts()))

    if not dispositivos_encontrados:
        print("❌ No se encontraron dispositivos en la red.")
    return dispositivos_encontrados

def scan_port(ip, port):
    """Escanea un puerto en una dirección IP y devuelve si está abierto."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception as e:
        print(f"⚠ Error al escanear el puerto {port} en {ip}: {e}")
        return False

def scan_all_ports(ip):
    """Escanea todos los puertos (1-65535) simultáneamente para una dirección IP."""
    print(f"\n🎯 Escaneando todos los puertos en {ip}...\n")
    puertos_abiertos = []

    def verificar_puerto(port):
        if scan_port(ip, port):
            servicio = get_service_name(port)
            puertos_abiertos.append((port, servicio))
            print(f"✔ Puerto {port} abierto ({servicio})")

    with ThreadPoolExecutor(max_workers=1000) as executor:
        executor.map(verificar_puerto, range(1, 65536))

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

def nmap_scan(ip, mode="syn"):
    """Ejecuta un escaneo con nmap según el modo seleccionado."""
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        print("❌ Dirección IP no válida.")
        return

    if mode == "syn":
        comando = ["nmap", "-sS", "-p-", ip]
    elif mode == "connect":
        comando = ["nmap", "-sT", "-p-", ip]
    elif mode == "udp":
        comando = ["nmap", "-sU", "-p-", ip]
    elif mode == "version":
        comando = ["nmap", "-sV", ip]
    else:
        print(f"❌ Modo '{mode}' no reconocido.")
        return

    try:
        print(f"🔍 Ejecutando escaneo {mode.upper()} en {ip}...\n")
        resultado = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=120)
        salida = resultado.stdout.decode()
        print(salida)
        with open(f"nmap_resultados_{mode}.txt", "w") as archivo:
            archivo.write(salida)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error al ejecutar nmap: {e.stderr.decode()}")
    except subprocess.TimeoutExpired:
        print("❌ El escaneo de nmap excedió el tiempo límite.")

if __name__ == "__main__":
    print("¿Cómo deseas ejecutar el escáner?")
    print("1. Modo normal (interactivo)")
    print("2. Modo avanzado (con argumentos desde la línea de comandos)")
    opcion = input("🔹 Elige una opción (1 o 2): ").strip()

    if opcion == "1":
        # Modo interactivo
        ip_base = input("🔹 Ingresa la dirección IP de la red (Ejemplo: 192.168.1.1): ")
        mascara = input("🔹 Ingresa la máscara de red (Ejemplo: 255.255.255.0): ")

        try:
            segmento_red = ipaddress.IPv4Network(f"{ip_base}/{mascara}", strict=False)
            dispositivos_encontrados = ping_sweep(segmento_red)

            for dispositivo in dispositivos_encontrados:
                puertos_abiertos = scan_all_ports(dispositivo)
                print_results(puertos_abiertos, dispositivo)
        except ValueError:
            print("❌ Error: Dirección IP o máscara de red no válidas.")
    elif opcion == "2":
        # Modo avanzado
        parser = argparse.ArgumentParser(description="Escáner avanzado de red y puertos.")
        parser.add_argument("--ip", help="Dirección IP base a escanear (Ejemplo: 192.168.1.1)")
        parser.add_argument("--modo", choices=["syn", "connect", "udp", "version"], default="syn", 
                            help="Tipo de escaneo: syn, connect, udp, version (por defecto: syn)")
        parser.add_argument("--mascara", help="Máscara de red para ping sweep (Ejemplo: 255.255.255.0)")
        parser.add_argument("--puertos", action="store_true", help="Realizar escaneo completo de puertos en paralelo")
        args = parser.parse_args()

        if args.ip and args.mascara:
            segmento_red = ipaddress.IPv4Network(f"{args.ip}/{args.mascara}", strict=False)
            dispositivos_encontrados = ping_sweep(segmento_red)

            for dispositivo in dispositivos_encontrados:
                if args.puertos:
                    puertos_abiertos = scan_all_ports(dispositivo)
                    print_results(puertos_abiertos, dispositivo)
                else:
                    nmap_scan(dispositivo, args.modo)
        elif args.ip:
            nmap_scan(args.ip, args.modo)
        else:
            print("❌ Argumentos inválidos. Por favor usa --ip y opcionalmente --mascara o --puertos.")
    else:
        print("❌ Opción no válida. Por favor, elige 1 o 2.")
    # me sejoro el uso de argparse (detalles menores de funcionamiento) y se mejoró la presentación de los resultados en pantalla y en el archivo de texto.
    