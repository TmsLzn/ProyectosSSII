import sqlite3

def mostrar_usuarios():
    # Conectar a la base de datos
    conn = sqlite3.connect('usuarios.db')
    c = conn.cursor()

    # Consultar todos los usuarios
    c.execute("SELECT * FROM usuarios")
    usuarios = c.fetchall()

    # Mostrar los resultados
    print("ID | Usuario        | Contraseña (hash)")
    print("---|----------------|------------------")
    for usuario in usuarios:
        print(f"{usuario[0]:<3} | {usuario[1]:<14} | {usuario[2]}")

    # Cerrar la conexión
    conn.close()

# Ejecutar la función
mostrar_usuarios()
