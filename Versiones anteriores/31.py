import ipaddress
import os
import platform
import socket
import threading
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter.ttk import Progressbar

# Función para generar el nombre del archivo basado en la cantidad de archivos existentes
def generar_nombre_archivo():
    """Genera un nombre único para el archivo de resultados y lo crea inmediatamente."""
    i = 1
    while os.path.isfile(f"codigo_{i}.txt"):  # Verifica si el archivo ya existe
        i += 1
    archivo_nombre = f"codigo_{i}.txt"
    with open(archivo_nombre, "w") as archivo:  # Crea el archivo vacío
        archivo.write("Resultados del escaneo:\n")  # Opcional: escribe un encabezado
    print(f"Archivo generado: {archivo_nombre}")  # Mensaje de depuración
    return archivo_nombre

# Función de ping para descubrir dispositivos activos
def ping(ip):
    comando_base = "ping -n 1" if platform.system() == "Windows" else "ping -c 1"
    comando = f"{comando_base} {ip} >nul 2>&1" if platform.system() == "Windows" else f"{comando_base} {ip} >/dev/null 2>&1"
    respuesta = os.system(comando)
    return ip if respuesta == 0 else None

# Barrido de ping para encontrar dispositivos activos
def ping_sweep(segmento_red, output, progress_bar):
    output.insert(tk.END, f"\U0001F50D Escaneando la red {segmento_red}...\n")
    output.see(tk.END)
    dispositivos_encontrados = []

    total_ips = len(list(segmento_red.hosts()))
    progress_bar.config(maximum=total_ips, value=0)

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping, str(ip)): ip for ip in segmento_red.hosts()}
        for idx, future in enumerate(as_completed(futures)):
            resultado = future.result()
            progress_bar.config(value=idx + 1)
            if resultado:
                dispositivos_encontrados.append(resultado)
                output.insert(tk.END, f"✔ Dispositivo activo encontrado: {resultado}\n")
                output.see(tk.END)
                progress_bar.update()

    if not dispositivos_encontrados:
        output.insert(tk.END, "❌ No se encontraron dispositivos en la red.\n")
        output.see(tk.END)

    return dispositivos_encontrados

# Escaneo de puertos
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

# Escaneo completo de puertos
def port_scan(ip, start_port=1, end_port=65535, output=None, progress_bar=None, puertos_escaneados=[], archivo_nombre=None):
    output.insert(tk.END, f"\n🎯 Escaneando puertos en {ip}...\n")
    output.see(tk.END)
    puertos_abiertos = []

    with open(archivo_nombre, "a") as archivo:  # Usar el archivo generado
        archivo.write(f"\nPuertos escaneados en {ip}:\n")

        total_ports = end_port - start_port + 1
        progress_bar.config(maximum=total_ports, value=0)

        for idx, port in enumerate(range(start_port, end_port + 1)):
            if port in puertos_escaneados:  # Evitar escanear puertos ya escaneados
                continue

            is_open, banner = scan_port(ip, port)
            progress_bar.config(value=idx + 1)

            if is_open:
                servicio = get_service_name(port)
                output.insert(tk.END, f"✔ Puerto {port} abierto ({servicio}) - Banner: {banner}\n")
                output.see(tk.END)
                puertos_abiertos.append([port, servicio, banner])
                archivo.write(f"Puerto {port}: {servicio} - Banner: {banner}\n")  # Escribir en el archivo
            else:
                output.insert(tk.END, f"✘ Puerto {port} cerrado\n")
                output.see(tk.END)
                archivo.write(f"Puerto {port}: Cerrado\n")  # Escribir en el archivo

            puertos_escaneados.append(port)  # Agregar puerto escaneado a la lista
            progress_bar.update()

        output.insert(tk.END, tabulate(puertos_abiertos, headers=["Puerto", "Servicio", "Banner"], tablefmt="grid"))
        output.see(tk.END)

    return puertos_escaneados

# Escaneo rápido de puertos comunes
def port_scan_comunes(ip, output=None, progress_bar=None, puertos_escaneados=[], archivo_nombre=None):
    output.insert(tk.END, f"\n🎯 Escaneando puertos comunes en {ip}...\n")
    output.see(tk.END)
    puertos_abiertos = []
    puertos_comunes = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

    with open(archivo_nombre, "a") as archivo:  # Usar el archivo generado
        archivo.write(f"\nPuertos escaneados en {ip} (modo rápido):\n")

        total_ports = len(puertos_comunes)
        progress_bar.config(maximum=total_ports, value=0)

        for idx, port in enumerate(puertos_comunes):
            if port in puertos_escaneados:  # Evitar escanear puertos ya escaneados
                continue

            is_open, banner = scan_port(ip, port)
            progress_bar.config(value=idx + 1)

            if is_open:
                servicio = get_service_name(port)
                output.insert(tk.END, f"✔ Puerto {port} abierto ({servicio}) - Banner: {banner}\n")
                output.see(tk.END)
                puertos_abiertos.append([port, servicio, banner])
                archivo.write(f"Puerto {port}: {servicio} - Banner: {banner}\n")  # Escribir en el archivo
            else:
                output.insert(tk.END, f"✘ Puerto {port} cerrado\n")
                output.see(tk.END)
                archivo.write(f"Puerto {port}: Cerrado\n")  # Escribir en el archivo

            puertos_escaneados.append(port)  # Agregar puerto escaneado a la lista
            progress_bar.update()

        output.insert(tk.END, tabulate(puertos_abiertos, headers=["Puerto", "Servicio", "Banner"], tablefmt="grid"))
        output.see(tk.END)

    return puertos_escaneados

# Función para obtener el banner del servicio
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

# Función para obtener el nombre del servicio según el puerto
def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Desconocido"

# Iniciar el escaneo
def iniciar_escaneo():
    ip = ip_entry.get()
    mascara = mascara_entry.get()
    tipo_escaneo = tipo_escaneo_var.get()

    # Generar el nombre del archivo una sola vez
    archivo_nombre = generar_nombre_archivo()

    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Escaneando puertos...\n")
    output_text.see(tk.END)
    output_text.config(state=tk.DISABLED)

    def hilo_escaneo():
        try:
            if not escaneando[0]:  # Si no hay un escaneo en curso
                escaneando[0] = True
                ip_entry.config(state=tk.DISABLED)
                mascara_entry.config(state=tk.DISABLED)
                boton_iniciar.config(state=tk.DISABLED)

                segmento_red = ipaddress.IPv4Network(f"{ip}/{mascara}", strict=False)
                dispositivos = ping_sweep(segmento_red, output_text, progress_bar)

                puertos_escaneados = []  # Lista de puertos escaneados en cada sesión

                for dispositivo in dispositivos:
                    if tipo_escaneo == "completo":
                        puertos_escaneados = port_scan(
                            dispositivo,
                            output=output_text,
                            progress_bar=progress_bar,
                            puertos_escaneados=puertos_escaneados,
                            archivo_nombre=archivo_nombre,  # Pasar el archivo
                        )
                    else:
                        puertos_escaneados = port_scan_comunes(
                            dispositivo,
                            output=output_text,
                            progress_bar=progress_bar,
                            puertos_escaneados=puertos_escaneados,
                            archivo_nombre=archivo_nombre,  # Pasar el archivo
                        )

                # Leer el archivo generado y mostrar los resultados en la interfaz
                with open(archivo_nombre, "r") as archivo:
                    resultados = archivo.read()
                    output_text.config(state=tk.NORMAL)
                    output_text.insert(tk.END, resultados)
                    output_text.see(tk.END)
                    output_text.config(state=tk.DISABLED)

                messagebox.showinfo(
                    "Escaneo completado",
                    f"El escaneo se ha completado. Los resultados se guardaron en '{archivo_nombre}'.",
                )

                ip_entry.config(state=tk.NORMAL)
                mascara_entry.config(state=tk.NORMAL)
                boton_iniciar.config(state=tk.NORMAL)

                escaneando[0] = False  # Permitir un nuevo escaneo
        except ValueError:
            messagebox.showerror("Error", "IP o máscara inválida.")
        except Exception as e:
            print(f"Error inesperado: {e}")  # Mensaje de depuración para errores inesperados

    threading.Thread(target=hilo_escaneo).start()

# Variable para controlar si ya hay un escaneo en curso
escaneando = [False]

# Interfaz gráfica con Tkinter
ventana = tk.Tk()
ventana.title("Escaneo de puertos al estilo Nmap")

tk.Label(ventana, text="Ingresa la dirección IP de la red (Ejemplo: 192.168.1.1):").pack()
ip_entry = tk.Entry(ventana)
ip_entry.pack()
ip_entry.insert(0, "192.168.1.0")

tk.Label(ventana, text="Ingresa la máscara de red (Ejemplo: 255.255.255.0):").pack()
mascara_entry = tk.Entry(ventana)
mascara_entry.pack()
mascara_entry.insert(0, "255.255.255.0")

# Selección del tipo de escaneo
tk.Label(ventana, text="Selecciona el tipo de escaneo:").pack()
tipo_escaneo_var = tk.StringVar(value="completo")
tk.Radiobutton(ventana, text="Escaneo completo", variable=tipo_escaneo_var, value="completo").pack()
tk.Radiobutton(ventana, text="Escaneo rápido", variable=tipo_escaneo_var, value="rápido").pack()

# Botón para iniciar el escaneo
boton_iniciar = tk.Button(ventana, text="Iniciar Escaneo", command=iniciar_escaneo)
boton_iniciar.pack()

# Área de texto para mostrar los resultados
output_text = scrolledtext.ScrolledText(ventana, width=80, height=20, wrap=tk.WORD)
output_text.pack()

# Barra de progreso
progress_bar = Progressbar(ventana, length=200, mode="determinate")
progress_bar.pack()

# Iniciar la ventana Tkinter
ventana.mainloop()
# detalles menores a la intefaz grafica (barra de progreso, area de muestreo de resultados)
