import sqlite3
from werkzeug.security import generate_password_hash


def crear_base_de_datos():
    conexion = sqlite3.connect('vulnerable.db')
    cursor = conexion.cursor()

    cursor.execute('DROP TABLE IF EXISTS usuarios')
    cursor.execute('''
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            rol TEXT NOT NULL,
            bio TEXT
        )
    ''')

    # CORRECCION: las contraseñas se guardan como hash (no en texto plano)
    usuarios = [
        ('admin', generate_password_hash('admin123'), 'admin', 'Cuenta de administrador del sistema.'),
        ('alumno', generate_password_hash('12345'), 'user', 'Soy un estudiante aprendiendo hacking.'),
    ]

    cursor.executemany(
        'INSERT INTO usuarios (username, password, rol, bio) VALUES (?, ?, ?, ?)',
        usuarios,
    )
    conexion.commit()
    conexion.close()
    print("Base de datos inicializada con contraseñas hasheadas.")


if __name__ == "__main__":
    crear_base_de_datos()
