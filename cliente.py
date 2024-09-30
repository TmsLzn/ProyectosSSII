import socket
import hashlib
import hmac
import os

HOST = '127.0.0.1'
PORT = 3030
secret_key = b'secret_key'

def enviar_datos(datos):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(datos.encode('utf-8'))
        respuesta = s.recv(1024).decode('utf-8')
        return respuesta

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
    conn.sendall(datos_transaccion.encode('utf-8'))
    respuesta = conn.recv(1024).decode('utf-8')
    print(respuesta)

def main():
    print("Conectado al servidor.")

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
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(datos.encode('utf-8'))
                respuesta = s.recv(1024).decode('utf-8')
                print(respuesta)

                if respuesta == "Login exitoso":
                    # Redirigir a la creación de transacciones
                    while True:
                        realizar_transaccion(s)
                        if input("¿Deseas hacer otra transacción? (s/n): ").lower() != 's':
                            break

        elif opcion == '2':
            usuario = input("Introduce tu nombre de usuario: ")
            contrasena = input("Introduce tu contraseña: ")
            hash_contrasena = hashlib.sha256(contrasena.encode()).hexdigest()  # Hashea la contraseña
            datos = f"registro,{usuario},{hash_contrasena}"
            respuesta = enviar_datos(datos)
            print(respuesta)

        else:
            print("Opción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    main()
