import socket
import hashlib
import hmac
import os

HOST = '127.0.0.1'
PORT = 3030
secret_key = b'secret_key'

# Función para enviar datos al servidor
def enviar_datos(conn, datos):
    conn.sendall(datos.encode('utf-8'))
    respuesta = conn.recv(1024).decode('utf-8')
    return respuesta

# Función para realizar una transacción y capturar el nonce
def realizar_transaccion(conn):
    cuenta_destino = input("Introduce la cuenta de destino: ")
    cantidad = input("Introduce la cantidad a transferir: ")

    # Crear nonce
    nonce = os.urandom(16).hex()

    # Crear el mensaje de transacción
    transaccion = f"{cuenta_destino}|{cantidad}"

    # Calcular HMAC
    hmac_calculado = hmac.new(secret_key, (transaccion + nonce).encode(), hashlib.sha256).hexdigest()

    # Enviar transacción al servidor
    datos_transaccion = f"{transaccion},{hmac_calculado},{nonce}"
    respuesta = enviar_datos(conn, datos_transaccion)
    print(f"Respuesta del servidor: {respuesta}")

    # Retornar la transacción original para simular replay
    return datos_transaccion

# Función para simular un ataque de replay
def ataque_replay(conn, transaccion_original):
    if transaccion_original is None:
        print("No se pudo capturar la transacción original. Ataque de replay no puede realizarse.")
        return

    print("\nSimulando ataque de replay...")

    # Enviar el mismo mensaje (ataque de replay)
    respuesta = enviar_datos(conn, transaccion_original)
    print(f"Respuesta del servidor (replay): {respuesta}")

# Función principal
def main():
    print("Conectado al servidor.")
    
    # Conectar al servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        while True:
            print("Menú Principal ---")
            print("1. Iniciar sesión")
            print("2. Registrarse")
            opcion = input("Elige una opción (1 o 2): ")

            if opcion == '1':
                usuario = input("Introduce tu nombre de usuario: ")
                contrasena = input("Introduce tu contraseña: ")
                hash_contrasena = hashlib.sha256(contrasena.encode()).hexdigest()  # Hashea la contraseña
                datos = f"login,{usuario},{hash_contrasena}"

                # Enviar datos de login
                respuesta = enviar_datos(s, datos)
                print(respuesta)

                if respuesta == "Login exitoso":
                    # Realizar transacción y capturar el mensaje
                    transaccion_original = realizar_transaccion(s)

                    # Intentar ataque de replay enviando el mismo mensaje
                    if transaccion_original:
                        for i in range(3):  # Intentamos el replay 3 veces
                            ataque_replay(s, transaccion_original)

                    if input("¿Deseas hacer otra transacción? (s/n): ").lower() != 's':
                        break

            elif opcion == '2':
                usuario = input("Introduce tu nombre de usuario: ")
                contrasena = input("Introduce tu contraseña: ")
                hash_contrasena = hashlib.sha256(contrasena.encode()).hexdigest()  # Hashea la contraseña
                datos = f"registro,{usuario},{hash_contrasena}"
                respuesta = enviar_datos(s, datos)
                print(respuesta)

            else:
                print("Opción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    main()

