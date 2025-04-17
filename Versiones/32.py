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

# Función para mostrar una advertencia al seleccionar el escaneo completo
def advertencia_escaneo_completo():
    if modo_escaneo.get() == "completo":
        messagebox.showinfo(
            "Advertencia",
            "El escaneo completo puede tomar mucho tiempo dependiendo del rango de IP y la cantidad de puertos."
        )

# Interfaz gráfica mejorada
ventana = tk.Tk()
ventana.title("Escáner de Red - Python Puro")
ventana.geometry("800x700")
ventana.configure(bg="#f0f0f0")  # Fondo claro

# Frame principal
frame_principal = ttk.Frame(ventana, padding=10)
frame_principal.pack(fill=tk.BOTH, expand=True)

# Título
titulo = ttk.Label(frame_principal, text="Escáner de Red", font=("Arial", 18, "bold"))
titulo.pack(pady=10)

# Entrada de rango de IP
ttk.Label(frame_principal, text="Rango de IP (ej: 192.168.0.0/24 o 192.168.1.1):", font=("Arial", 10)).pack(pady=5, anchor="w")
entrada_rango = ttk.Entry(frame_principal, width=50)
entrada_rango.pack(pady=5)

# Selector de modo de escaneo
modo_escaneo = tk.StringVar(value="rapido")
ttk.Label(frame_principal, text="Modo de escaneo:", font=("Arial", 10)).pack(pady=5, anchor="w")
ttk.Radiobutton(frame_principal, text="Rápido (20 puertos comunes)", variable=modo_escaneo, value="rapido", command=advertencia_escaneo_completo).pack(anchor="w")
ttk.Radiobutton(frame_principal, text="Completo (todos los puertos)", variable=modo_escaneo, value="completo", command=advertencia_escaneo_completo).pack(anchor="w")
ttk.Radiobutton(frame_principal, text="Puertos específicos", variable=modo_escaneo, value="especifico", command=advertencia_escaneo_completo).pack(anchor="w")

# Cuadro de texto para ingresar puertos específicos
ttk.Label(frame_principal, text="Puertos específicos (opcional, separados por comas):", font=("Arial", 10)).pack(pady=5, anchor="w")
entrada_puertos = ttk.Entry(frame_principal, width=50)
entrada_puertos.pack(pady=5)

# Opciones adicionales
opciones_frame = ttk.Frame(frame_principal)
opciones_frame.pack(pady=10, fill=tk.X)

guardar_resultados_var = tk.BooleanVar(value=True)
ttk.Checkbutton(opciones_frame, text="Guardar resultados en archivo", variable=guardar_resultados_var).pack(side=tk.LEFT, padx=5)

detectar_so_var = tk.BooleanVar(value=False)
ttk.Checkbutton(opciones_frame, text="Detectar sistema operativo remoto", variable=detectar_so_var).pack(side=tk.LEFT, padx=5)

# Botón para iniciar el escaneo
boton_iniciar = ttk.Button(frame_principal, text="Iniciar Escaneo", command=lambda: iniciar_escaneo())
boton_iniciar.pack(pady=10)

# Barra de progreso
barra_progreso = ttk.Progressbar(frame_principal, length=600, mode='determinate')
barra_progreso.pack(pady=10, fill=tk.X)

# Área de resultados con scrollbar
frame_resultados = ttk.LabelFrame(frame_principal, text="Resultados", padding=10)
frame_resultados.pack(fill=tk.BOTH, expand=True, pady=10)

scrollbar = ttk.Scrollbar(frame_resultados)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

area_resultados = tk.Text(frame_resultados, height=20, width=80, yscrollcommand=scrollbar.set, wrap="word", bg="#ffffff", fg="#000000", font=("Courier New", 10))
area_resultados.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar.config(command=area_resultados.yview)

# Función para iniciar el escaneo
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

# Función para generar un nombre de archivo personalizado
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
# Mejora en la interfaz gráfica para una mejor experiencia de usuario.