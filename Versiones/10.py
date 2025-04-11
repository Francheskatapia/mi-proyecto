import ipaddress
import os
import platform
import socket
import threading

def obtener_dispositivos(segmento_red, dispositivos_encontrados):
    """Escanea la red completa para encontrar dispositivos activos."""
    print(f"\U0001F50D Escaneando la red {segmento_red}...\n")

    comando_base = "ping -n 1" if platform.system() == "Windows" else "ping -c 1"  # Comando de ping según el SO
    
    for ip in segmento_red.hosts():  # Iterar sobre todas las IP disponibles
        ip_str = str(ip)
        comando = f"{comando_base} {ip_str} >nul 2>&1" if platform.system() == "Windows" else f"{comando_base} {ip_str} >/dev/null 2>&1"
        respuesta = os.system(comando)  # Ejecutar ping

        if respuesta == 0:  # Si hay respuesta, el dispositivo está activo
            dispositivos_encontrados.append(ip_str)
            print(f"✔ Dispositivo activo encontrado: {ip_str}")

    if not dispositivos_encontrados:
        print("❌ No se encontraron dispositivos en la red.")

def escanear_puertos(ip):
    """Escanea los puertos abiertos de un dispositivo y almacena el resultado en un archivo ordenado."""
    print(f"\n🎯 Escaneando puertos en {ip}...\n")
    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip}:\n")

        puertos_abiertos = []
        for port in range(1, 1025):  # Iterar sobre el rango de puertos
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Crear socket TCP
            s.settimeout(0.5)  # Establecer tiempo de espera
            result = s.connect_ex((ip, port))  # Intentar conectar al puerto

            if result == 0:  # Si la conexión es exitosa, el puerto está abierto
                servicio = get_service_name(port)
                puertos_abiertos.append(f"Puerto {port} abierto ({servicio})")
            s.close()

        puertos_abiertos = sorted(puertos_abiertos)  # Ordenar los puertos abiertos

        # Escribir puertos ordenados en el archivo
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
        dispositivos_encontrados = []

        hilo_escaneo_red = threading.Thread(target=obtener_dispositivos, args=(segmento_red, dispositivos_encontrados))
        hilo_escaneo_red.start()  # Iniciar escaneo de red
        hilo_escaneo_red.join()  # Esperar a que termine el escaneo de red

        if dispositivos_encontrados:
            dispositivos_encontrados = sorted(dispositivos_encontrados)  # Ordenar las redes encontradas
            print(f"\n🌐 Redes encontradas y ordenadas: {dispositivos_encontrados}\n")

            hilos_puertos = []
            for dispositivo in dispositivos_encontrados:
                hilo = threading.Thread(target=escanear_puertos, args=(dispositivo,))
                hilos_puertos.append(hilo)
                hilo.start()  # Iniciar escaneo de puertos en paralelo

            for hilo in hilos_puertos:
                hilo.join()  # Esperar a que terminen todos los escaneos de puertos

    except ValueError:
        print("❌ Error: La IP o máscara de red no son válidas.")  # Manejo de error en caso de datos inválidos
# Codigo Base
# # Escáner de red y puertos con banner grabbing