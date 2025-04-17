import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import threading
import datetime
import socket
import ipaddress
import concurrent.futures

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

def escanear_host(ip, puertos_escanear, timeout=1):
    """Escanea múltiples puertos en un host y retorna los abiertos"""
    puertos_abiertos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(escanear_puerto, ip, puerto, timeout): puerto for puerto in puertos_escanear}
        
        for future in concurrent.futures.as_completed(futures):
            puerto, abierto = future.result()
            if abierto:
                puertos_abiertos.append(puerto)
    
    return ip, puertos_abiertos

def escanear_red(rango_ip, area_resultados, progreso, modo_escaneo="rapido", archivo_nombre=None):
    area_resultados.delete("1.0", tk.END)
    area_resultados.insert(tk.END, f"Escaneando {rango_ip} (Modo: {'Rápido' if modo_escaneo == 'rapido' else 'Completo'})...\n")
    progreso['value'] = 0
    ventana.update_idletasks()

    try:
        red = ipaddress.ip_network(rango_ip, strict=False)
        hosts = list(red.hosts())
        progreso['maximum'] = len(hosts)
        hosts_activos = []
        
        # Definir puertos a escanear según el modo
        puertos_escanear = PUERTOS_COMUNES if modo_escaneo == "rapido" else range(1, 65536)
        
        for i, host in enumerate(hosts):
            ip, puertos_abiertos = escanear_host(host, puertos_escanear)
            if puertos_abiertos:
                hosts_activos.append(ip)
                info_host = f"Host activo: {ip}\n  Puertos abiertos: {puertos_abiertos}\n"
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

tk.Button(frame_principal, text="Iniciar Escaneo", command=lambda: iniciar_escaneo()).pack(pady=10)

guardar_resultados_var = tk.BooleanVar(value=True)
tk.Checkbutton(frame_principal, text="Guardar resultados en archivo", variable=guardar_resultados_var).pack()

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
# se quitaron librerias externas para implementar un escaner de puertos en python puro.
# se agregaron mejoras en la interfaz grafica, como un scrollbar.