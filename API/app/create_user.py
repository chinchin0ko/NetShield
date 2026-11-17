"""Create an initial user interactively; do not pass passwords on the command line."""
import getpass

from argon2 import PasswordHasher
from app.main import database


def main():
    username = input("Usuario: ").strip()
    if not username or len(username) > 128:
        raise SystemExit("Usuario inválido")
    password = getpass.getpass("Contraseña (mínimo 12 caracteres): ")
    if len(password) < 12 or password != getpass.getpass("Confirma la contraseña: "):
        raise SystemExit("Contraseña corta o confirmación incorrecta")
    with database() as conn:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, PasswordHasher().hash(password)))
    print("Usuario creado")


if __name__ == "__main__":
    main()
