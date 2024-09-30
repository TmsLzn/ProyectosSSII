import socket
import sqlite3
import hashlib
import hmac

HOST = '127.0.0.1'
PORT = 3030
secret_key = b'secret_key'

# Conjunto para almacenar nonces utilizados
nonces_utilizados = set()

def conectar_db():
    conn = sqlite3.connect('usuarios.db')
    return conn

def registrar_usuario(usuario, contrasena):
    conn = conectar_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO usuarios (usuario, contrasena) VALUES (?, ?)", (usuario, contrasena))
        conn.commit()
        return "Cuenta creada correctamente"
    except sqlite3.IntegrityError:
        return "Error: El usuario ya existe."
    finally:
        conn.close()

def verificar_credenciales(usuario, contrasena):
    conn = conectar_db()
    c = conn.cursor()
    
    # Obtenemos la contraseña hasheada almacenada
    c.execute("SELECT contrasena FROM usuarios WHERE usuario = ?", (usuario,))
    resultado = c.fetchone()
    conn.close()
    
    # Verificamos si el usuario existe y comparamos la contraseña
    if resultado:
        hash_contrasena = resultado[0]
        # Comparamos la contraseña ingresada hasheada con la almacenada
        if hash_contrasena == contrasena:
            return True
    return False

def verificar_hmac(transaccion, hmac_recibido, nonce):
    hmac_calculado = hmac.new(secret_key, (transaccion + nonce).encode(), hashlib.sha256).hexdigest()
    print(f"HMAC calculado: {hmac_calculado}")  # Imprimir HMAC calculado
    return hmac.compare_digest(hmac_calculado, hmac_recibido)

def es_nonce_unico(nonce):
    if nonce in nonces_utilizados:
        return False
    nonces_utilizados.add(nonce)
    return True

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Escuchando en {HOST}:{PORT}...")

    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Conectado por {addr}")

            while True:
                try:
                    # Recibir opción de registro o login
                    datos = conn.recv(1024).decode('utf-8').split(',')
                    #print(f"Datos recibidos: {datos}")  # Imprimir los datos recibidos

                    # Validar que se reciban suficientes datos
                    if len(datos) < 3:  # Asegúrate de que haya al menos 3 elementos (tipo, usuario, contraseña)
                        #print("Error: datos insuficientes recibidos.")
                        #conn.sendall('Error: datos insuficientes'.encode('utf-8'))
                        continue

                    if datos[0] == "registro":
                        # Registrar nuevo usuario
                        usuario, contrasena = datos[1], datos[2]
                        respuesta = registrar_usuario(usuario, contrasena)
                        conn.sendall(respuesta.encode('utf-8'))

                    else:
                        # Manejar login
                        usuario, contrasena = datos[1], datos[2]
                        print(f"Intentando login para el usuario: {usuario}.")
                        if verificar_credenciales(usuario, contrasena):
                            conn.sendall('Login exitoso'.encode('utf-8'))

                            # Manejo de transacciones
                            while True:
                                datos_transaccion = conn.recv(1024).decode('utf-8')
                                
                                # Si no se reciben datos, el cliente ha cerrado la conexión
                                if not datos_transaccion:
                                    print("El cliente ha cerrado la conexión.")
                                    break  # Salir del bucle de transacciones
                                
                                # Manejo de 'salir'
                                if datos_transaccion.lower() == 'salir':
                                    print("El cliente ha cerrado la conexión.")
                                    break  # Salir del bucle de transacciones
                                
                                datos = datos_transaccion.split(',')

                                # Asegurarse de que se reciban suficientes datos para la transacción
                                if len(datos) < 3:
                                    print("Error: datos insuficientes para la transacción.")
                                    conn.sendall('Error: datos insuficientes para la transacción.'.encode('utf-8'))
                                    continue

                                transaccion = datos[0]
                                hmac_recibido = datos[1]
                                nonce = datos[2]

                                # Imprimir nonce y HMAC recibido
                                print(f"Nonce recibido: {nonce}")
                                print(f"HMAC recibido: {hmac_recibido}")

                                # Verificación del HMAC y del nonce
                                if not es_nonce_unico(nonce):
                                    print("ALERTA INTRUSO: ATAQUE REPLAY")
                                    conn.sendall('Error: nonce ya utilizado. Posible ataque replay.'.encode('utf-8'))
                                elif verificar_hmac(transaccion, hmac_recibido, nonce):
                                    print("Transacción validada")
                                    conn.sendall('Transacción verificada'.encode('utf-8'))
                                else:
                                    print("ALERTA INTRUSO: ATAQUE MAN IN THE MIDDLE")
                                    conn.sendall('Error en la verificación de integridad'.encode('utf-8'))
                                print("FIN DE TRANSACCIÓN")
                        else:
                            conn.sendall('Login fallido'.encode('utf-8'))
                            print(f"Login fallido para el usuario: {usuario}.")

                except ConnectionResetError:
                    print("La conexión ha sido cerrada por el cliente.")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    break
