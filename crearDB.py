import sqlite3
import hashlib

# Conectar o crear la base de datos
conn = sqlite3.connect('usuarios.db')

# Crear un cursor para ejecutar comandos SQL
c = conn.cursor()

# Crear la tabla de usuarios si no existe
c.execute('''CREATE TABLE IF NOT EXISTS usuarios (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             usuario TEXT UNIQUE NOT NULL,
             contrasena TEXT NOT NULL)''')

# Confirmar cambios
conn.commit()

# Función para registrar usuarios
def registrar_usuario(usuario, contrasena):
    # Hashear la contraseña usando SHA-256
    hash_contrasena = hashlib.sha256(contrasena.encode()).hexdigest()

    # Insertar el usuario y la contraseña hasheada en la tabla
    try:
        c.execute("INSERT INTO usuarios (usuario, contrasena) VALUES (?, ?)", (usuario, hash_contrasena))
        conn.commit()
        print("Usuario registrado correctamente.")
    except sqlite3.IntegrityError:
        print("Error: El usuario ya existe.")

# Registrar un usuario de prueba
registrar_usuario('admin', 'password123')

# Cerrar la conexión
conn.close()
