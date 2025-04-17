import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import threading
import datetime
import socket
import ipaddress
import concurrent.futures
from scapy.all import IP, TCP, sr1

# Lista de puertos comunes (Top 20)
PUERTOS_COMUNES = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

def escanear_puerto(ip, puerto, timeout=1):
    """Escanea un puerto específico y retorna si está abierto"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            resultado = s.connect_ex((str(ip), puerto))
            return puerto, resultado == 0  # True si está abierto
    except (socket.timeout, socket.error):
        return puerto, False

def obtener_banner(ip, puerto, timeout=1):
    """Intenta obtener el banner del servicio en un puerto abierto."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), puerto))
            s.sendall(b"\r\n")  # Enviar una solicitud simple
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "No se pudo obtener el banner"
    except Exception:
        return "No se pudo obtener el banner"

# Función para intentar detectar el sistema operativo remoto usando Scapy
def detectar_sistema_operativo(ip):
    """Intenta detectar el sistema operativo remoto usando TCP/IP fingerprinting con Scapy."""
    try:
        # Crear un paquete TCP SYN al puerto 80
        paquete = IP(dst=ip) / TCP(dport=80, flags="S")
        respuesta = sr1(paquete, timeout=2, verbose=0)  # Enviar el paquete y esperar respuesta

        if respuesta and respuesta.haslayer(TCP):
            # Analizar la respuesta TCP para inferir el sistema operativo
            flags = respuesta[TCP].flags
            window_size = respuesta[TCP].window

            # Ejemplo básico de análisis basado en el tamaño de la ventana
            if flags == "SA":  # SYN-ACK recibido
                if window_size == 65535:
                    return "Probablemente Windows"
                elif window_size == 5840:
                    return "Probablemente Linux"
                elif window_size == 14600:
                    return "Probablemente FreeBSD"
                else:
                    return f"SO desconocido (tamaño de ventana: {window_size})"
            else:
                return "No se pudo detectar el sistema operativo (respuesta inesperada)"
        else:
            return "No se recibió respuesta del host"
    except Exception as e:
        return f"Error al detectar el sistema operativo: {e}"

def escanear_host(ip, puertos_escanear, timeout=1, detectar_so=False):
    """Escanea múltiples puertos en un host y retorna los abiertos con banners y SO si está habilitado."""
    puertos_abiertos = []
    so_detectado = None

    # Escaneo de puertos
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(escanear_puerto, ip, puerto, timeout): puerto for puerto in puertos_escanear}
        
        for future in concurrent.futures.as_completed(futures):
            puerto, abierto = future.result()
            if abierto:
                banner = obtener_banner(ip, puerto, timeout)
                puertos_abiertos.append((puerto, banner))
    
    # Escaneo de sistema operativo si está habilitado
    if detectar_so:
        so_detectado = detectar_sistema_operativo(str(ip))  # Convertir ip a cadena
    
    return ip, puertos_abiertos, so_detectado

def escanear_red(rango_ip, area_resultados, progreso, modo_escaneo="rapido", archivo_nombre=None):
    area_resultados.delete("1.0", tk.END)
    area_resultados.insert(tk.END, f"Escaneando {rango_ip} (Modo: {'Rápido' if modo_escaneo == 'rapido' else 'Completo' if modo_escaneo == 'completo' else 'Específico'})...\n")
    progreso['value'] = 0
    ventana.update_idletasks()

    try:
        red = ipaddress.ip_network(rango_ip, strict=False)
        hosts = list(red.hosts())
        progreso['maximum'] = len(hosts)
        hosts_activos = []
        
        # Definir puertos a escanear según el modo
        if modo_escaneo == "rapido":
            puertos_escanear = PUERTOS_COMUNES
        elif modo_escaneo == "completo":
            puertos_escanear = range(1, 65536)
        elif modo_escaneo == "especifico":
            try:
                puertos_escanear = [int(p) for p in entrada_puertos.get().split(",") if p.strip().isdigit()]
                if not puertos_escanear:
                    raise ValueError("No se ingresaron puertos válidos.")
            except ValueError as e:
                area_resultados.insert(tk.END, f"Error: {e}\n")
                return

        for i, host in enumerate(hosts):
            ip, puertos_abiertos, so_detectado = escanear_host(host, puertos_escanear, detectar_so=detectar_so_var.get())
            if puertos_abiertos:
                hosts_activos.append(ip)
                info_host = f"Host activo: {ip}\n"
                for puerto, banner in puertos_abiertos:
                    info_host += f"  Puerto {puerto} abierto - Banner: {banner}\n"
                if detectar_so_var.get() and so_detectado:
                    info_host += f"  Sistema Operativo detectado: {so_detectado}\n"
                area_resultados.insert(tk.END, info_host)
                if archivo_nombre:
                    with open(archivo_nombre, "a") as archivo:
                        archivo.write(info_host)
            
            progreso['value'] = i + 1
            ventana.update_idletasks()

        area_resultados.insert(tk.END, f"\nEscaneo completado. Hosts activos: {len(hosts_activos)}\n")
        if archivo_nombre:
            area_resultados.insert(tk.END, f"Resultados guardados en: {archivo_nombre}\n")

    except ValueError as e:
        area_resultados.insert(tk.END, f"Error en el rango de IP: {e}\n")
    except Exception as e:
        area_resultados.insert(tk.END, f"Error durante el escaneo: {e}\n")

# Interfaz gráfica actualizada
ventana = tk.Tk()
ventana.title("Escáner de Red - Python Puro")
ventana.geometry("700x600")

# Frame principal
frame_principal = tk.Frame(ventana, padx=10, pady=10)
frame_principal.pack(fill=tk.BOTH, expand=True)

tk.Label(frame_principal, text="Rango de IP (ej: 192.168.0.0/24 o 192.168.1.1):").pack(pady=5)
entrada_rango = tk.Entry(frame_principal, width=40)
entrada_rango.pack()

# Selector de modo de escaneo
modo_escaneo = tk.StringVar(value="rapido")
tk.Label(frame_principal, text="Modo de escaneo:").pack(pady=5)
tk.Radiobutton(frame_principal, text="Rápido (20 puertos comunes)", variable=modo_escaneo, value="rapido").pack()
tk.Radiobutton(frame_principal, text="Completo (todos los puertos)", variable=modo_escaneo, value="completo").pack()
tk.Radiobutton(frame_principal, text="Puertos específicos", variable=modo_escaneo, value="especifico").pack()

# Cuadro de texto para ingresar puertos específicos (siempre visible)
tk.Label(frame_principal, text="Puertos específicos (opcional, separados por comas):").pack(pady=5)
entrada_puertos = tk.Entry(frame_principal, width=40)
entrada_puertos.pack()

tk.Button(frame_principal, text="Iniciar Escaneo", command=lambda: iniciar_escaneo()).pack(pady=10)

guardar_resultados_var = tk.BooleanVar(value=True)
tk.Checkbutton(frame_principal, text="Guardar resultados en archivo", variable=guardar_resultados_var).pack()

# Checkbox para habilitar el escaneo de sistema operativo
detectar_so_var = tk.BooleanVar(value=False)
tk.Checkbutton(frame_principal, text="Detectar sistema operativo remoto", variable=detectar_so_var).pack()

barra_progreso = ttk.Progressbar(frame_principal, length=500, mode='determinate')
barra_progreso.pack(pady=10, fill=tk.X)

# Área de resultados con scrollbar
frame_resultados = tk.Frame(frame_principal)
frame_resultados.pack(fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(frame_resultados)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

area_resultados = tk.Text(frame_resultados, height=20, width=80, yscrollcommand=scrollbar.set)
area_resultados.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar.config(command=area_resultados.yview)

def iniciar_escaneo():
    rango_ip = entrada_rango.get()
    if not rango_ip:
        messagebox.showwarning("Entrada vacía", "Por favor, introduce un rango de IP.")
        return

    archivo_nombre = None
    if guardar_resultados_var.get():
        archivo_nombre = generar_nombre_archivo_personalizado()
        if not archivo_nombre:
            return

    hilo = threading.Thread(
        target=escanear_red,
        args=(rango_ip, area_resultados, barra_progreso, modo_escaneo.get(), archivo_nombre)
    )
    hilo.start()

def generar_nombre_archivo_personalizado():
    fecha_hora = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_sugerido = f"resultados_escaneo_{fecha_hora}.txt"
    ruta_archivo = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Archivos de texto", "*.txt")],
        initialfile=nombre_sugerido,
        title="Guardar resultados del escaneo"
    )
    if ruta_archivo:
        with open(ruta_archivo, "w") as archivo:
            archivo.write("Resultados del escaneo:\n")
        return ruta_archivo
    return None

ventana.mainloop()
# se implemento opcion puertos especificos