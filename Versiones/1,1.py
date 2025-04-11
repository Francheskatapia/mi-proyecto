import ipaddress
import os
import platform
import socket
import threading

def ping(ip):
    """Realiza un ping a una dirección IP y devuelve si está activa."""
    comando_base = "ping -n 1" if platform.system() == "Windows" else "ping -c 1"  # Comando de ping según el SO
    comando = f"{comando_base} {ip} >nul 2>&1" if platform.system() == "Windows" else f"{comando_base} {ip} >/dev/null 2>&1"
    respuesta = os.system(comando)  # Ejecutar ping
    return respuesta == 0  # Devuelve True si hay respuesta

def ping_sweep(segmento_red):
    """Escanea un rango de direcciones IP para encontrar dispositivos activos."""
    dispositivos_encontrados = []
    print(f"\U0001F50D Escaneando la red {segmento_red}...\n")

    for ip in segmento_red.hosts():  # Iterar sobre todas las IP disponibles
        if ping(str(ip)):  # Llama a la función ping()
            dispositivos_encontrados.append(str(ip))
            print(f"✔ Dispositivo activo encontrado: {ip}")

    if not dispositivos_encontrados:
        print("❌ No se encontraron dispositivos en la red.")
    return dispositivos_encontrados

def scan_port(ip, port):
    """Escanea un solo puerto en una dirección IP y devuelve si está abierto."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Crear socket TCP
        s.settimeout(0.5)  # Establecer tiempo de espera
        result = s.connect_ex((ip, port))  # Intentar conectar al puerto
        s.close()
        return result == 0  # Devuelve True si el puerto está abierto
    except:
        return False

def port_scan(ip, start_port=1, end_port=65535):
    """Escanea los puertos abiertos de una dirección IP dentro de un rango y los registra en un archivo."""
    print(f"\n🎯 Escaneando puertos en {ip}...\n")
    puertos_abiertos = []
    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip}:\n")

        for port in range(start_port, end_port + 1):  # Iterar sobre el rango de puertos
            if scan_port(ip, port):  # Llama a la función scan_port()
                servicio = get_service_name(port)
                print(f"✔ Puerto {port} abierto ({servicio})")
                puertos_abiertos.append(f"Puerto {port} abierto ({servicio})")

        puertos_abiertos = sorted(puertos_abiertos)  # Ordenar los puertos abiertos
        for puerto in puertos_abiertos:
            archivo.write(f"{puerto}\n")

def get_service_name(port):
    """Devuelve el nombre del servicio asociado a un puerto."""
    try:
        return socket.getservbyport(port)  # Obtener el nombre del servicio
    except OSError:
        return "Desconocido"  # Si no se encuentra, devolver "Desconocido"

if __name__ == "__main__":
    ip_base = input("🔹 Ingresa la dirección IP de la red (Ejemplo: 192.168.1.1): ")
    mascara = input("🔹 Ingresa la máscara de red (Ejemplo: 255.255.255.0): ")

    try:
        segmento_red = ipaddress.IPv4Network(f"{ip_base}/{mascara}", strict=False)  # Crear segmento de red

        # Escaneo de dispositivos
        dispositivos_encontrados = ping_sweep(segmento_red)

        if dispositivos_encontrados:
            dispositivos_encontrados = sorted(dispositivos_encontrados)  # Ordenar las redes encontradas
            print(f"\n🌐 Redes encontradas y ordenadas: {dispositivos_encontrados}\n")

            # Escaneo de puertos
            hilos_puertos = []
            for dispositivo in dispositivos_encontrados:
                hilo = threading.Thread(target=port_scan, args=(dispositivo,))
                hilos_puertos.append(hilo)
                hilo.start()  # Iniciar escaneo de puertos en paralelo

            for hilo in hilos_puertos:
                hilo.join()  # Esperar a que terminen todos los escaneos de puertos

    except ValueError:
        print("❌ Error: La IP o máscara de red no son válidas.")  # Manejo de error en caso de datos inválidos
# Mejoras Menores