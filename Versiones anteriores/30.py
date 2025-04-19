import ipaddress
import os
import platform
import socket
import threading
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import messagebox, scrolledtext

def ping(ip):
    comando_base = "ping -n 1" if platform.system() == "Windows" else "ping -c 1"
    comando = f"{comando_base} {ip} >nul 2>&1" if platform.system() == "Windows" else f"{comando_base} {ip} >/dev/null 2>&1"
    respuesta = os.system(comando)
    return ip if respuesta == 0 else None

def ping_sweep(segmento_red, output):
    output.insert(tk.END, f"\U0001F50D Escaneando la red {segmento_red}...\n")
    output.see(tk.END)
    dispositivos_encontrados = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping, str(ip)): ip for ip in segmento_red.hosts()}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                dispositivos_encontrados.append(resultado)
                output.insert(tk.END, f"✔ Dispositivo activo encontrado: {resultado}\n")
                output.see(tk.END)

    if not dispositivos_encontrados:
        output.insert(tk.END, "❌ No se encontraron dispositivos en la red.\n")
        output.see(tk.END)

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

def port_scan(ip, start_port=1, end_port=65535, output=None):
    output.insert(tk.END, f"\n🎯 Escaneando puertos en {ip}...\n")
    output.see(tk.END)
    puertos_abiertos = []
    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip}:\n")

        for port in range(start_port, end_port + 1):
            is_open, banner = scan_port(ip, port)
            if is_open:
                servicio = get_service_name(port)
                output.insert(tk.END, f"✔ Puerto {port} abierto ({servicio}) - Banner: {banner}\n")
                output.see(tk.END)
                puertos_abiertos.append([port, servicio, banner])

        output.insert(tk.END, tabulate(puertos_abiertos, headers=["Puerto", "Servicio", "Banner"], tablefmt="grid"))
        output.see(tk.END)

        for puerto in puertos_abiertos:
            archivo.write(f"Puerto {puerto[0]} abierto ({puerto[1]}) - Banner: {puerto[2]}\n")

def port_scan_comunes(ip, output=None):
    output.insert(tk.END, f"\n🎯 Escaneando puertos comunes en {ip}...\n")
    output.see(tk.END)
    puertos_abiertos = []
    puertos_comunes = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

    with open("puertos_abiertos.txt", "a") as archivo:
        archivo.write(f"\nPuertos abiertos en {ip} (modo rápido):\n")

        for port in puertos_comunes:
            is_open, banner = scan_port(ip, port)
            if is_open:
                servicio = get_service_name(port)
                output.insert(tk.END, f"✔ Puerto {port} abierto ({servicio}) - Banner: {banner}\n")
                output.see(tk.END)
                puertos_abiertos.append([port, servicio, banner])

        output.insert(tk.END, tabulate(puertos_abiertos, headers=["Puerto", "Servicio", "Banner"], tablefmt="grid"))
        output.see(tk.END)

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

def iniciar_escaneo():
    ip = ip_entry.get()
    mascara = mascara_entry.get()
    tipo_escaneo = tipo_escaneo_var.get()

    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Escaneando puertos...\n")
    output_text.see(tk.END)
    output_text.config(state=tk.DISABLED)

    def hilo_escaneo():
        try:
            segmento_red = ipaddress.IPv4Network(f"{ip}/{mascara}", strict=False)
            dispositivos = ping_sweep(segmento_red, output_text)
            for dispositivo in dispositivos:
                if tipo_escaneo == "completo":
                    port_scan(dispositivo, output=output_text)
                else:
                    port_scan_comunes(dispositivo, output=output_text)
            output_text.config(state=tk.DISABLED)
        except ValueError:
            messagebox.showerror("Error", "IP o máscara inválida.")

    threading.Thread(target=hilo_escaneo).start()

# Interfaz Tkinter
ventana = tk.Tk()
ventana.title("Escaneo de puertos")

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
tk.Radiobutton(ventana, text="Escaneo Completo", variable=tipo_escaneo_var, value="completo").pack()
tk.Radiobutton(ventana, text="Escaneo Rápido", variable=tipo_escaneo_var, value="rapido").pack()

tk.Button(ventana, text="Iniciar Escaneo", command=iniciar_escaneo).pack(pady=5)

output_text = scrolledtext.ScrolledText(ventana, height=20, width=80)
output_text.pack()
output_text.config(state=tk.DISABLED)

ventana.mainloop()

# se implemento Interfaz Grafica con Tkinter para mejorar la experiencia del usuario