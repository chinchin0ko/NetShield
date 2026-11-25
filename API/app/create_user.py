"""Create an initial user interactively; do not pass passwords on the command line."""
import getpass
import re

from app.composition import get_auth_service


def main():
    username = input("Usuario: ").strip()
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{3,64}', username):
        raise SystemExit("Usuario inválido")
    password = getpass.getpass("Contraseña (mínimo 12 caracteres): ")
    if not 12 <= len(password) <= 128 or password != getpass.getpass("Confirma la contraseña: "):
        raise SystemExit("Contraseña corta o confirmación incorrecta")
    get_auth_service().create_user(username, password)
    print("Usuario creado")


if __name__ == "__main__":
    main()
