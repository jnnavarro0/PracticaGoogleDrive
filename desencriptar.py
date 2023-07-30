import os
import io
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

# Ruta del archivo de credenciales OAuth 2.0
CLIENT_CREDENTIALS_FILE = "client_secret_897536122532-qrsr3fpt0fdsg9ag9tr5o19d1kiaugr9.apps.googleusercontent.com.json.json"

# Alcance de la API de Google Drive
SCOPES = ['https://www.googleapis.com/auth/drive']

def authenticate():
    # Cargar las credenciales OAuth 2.0 desde el archivo JSON
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_CREDENTIALS_FILE, SCOPES)
    credentials = flow.run_local_server(port=0)
    return credentials

def get_decryption_key_from_user():
    # Solicitar al usuario que ingrese la clave de desencriptación
    key = input("Ingrese la clave de desencriptación: ")
    return derive_key(key)

def derive_key(password):
    # Derivar una clave de 32 bytes utilizando PBKDF2
    backend = default_backend()
    salt = os.urandom(16)  # Generar una sal aleatoria de 16 bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def download_file_from_drive(credentials, file_id, file_path):
    # Crear una instancia del cliente de la API de Google Drive
    service = build('drive', 'v3', credentials=credentials)

    # Descargar el archivo encriptado desde Google Drive
    request = service.files().get_media(fileId=file_id)
    with io.FileIO(file_path, 'wb') as file:
        downloader = MediaIoBaseDownload(file, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()

def decrypt_file(input_file_path, output_file_path, decryption_key):
    # Leer el contenido del archivo encriptado
    with open(input_file_path, 'rb') as file:
        encrypted_content = file.read()

    # Crear el objeto de desencriptación
    fernet = Fernet(decryption_key)

    # Desencriptar el contenido del archivo
    decrypted_content = fernet.decrypt(encrypted_content)

    # Escribir el contenido desencriptado en un nuevo archivo
    with open(output_file_path, 'wb') as file:
        file.write(decrypted_content)

if __name__ == "__main__":
    # Autenticarse y obtener las credenciales
    credentials = authenticate()

    # ID del archivo encriptado en Google Drive
    file_id = "https://drive.google.com/file/d/1_NUmRjnk0yV4KM8K31TfIJnOwEhPYBAR/view?usp=sharing"

    # Ruta donde se guardará el archivo desencriptado
    decrypted_file_path = "texto_desencriptado.txt"

    # Obtener la clave de desencriptación del usuario
    decryption_key = get_decryption_key_from_user()

    # Descargar el archivo encriptado desde Google Drive
    download_file_from_drive(credentials, file_id, "texto_encrypted.txt")

    # Desencriptar el archivo y guardar el resultado en el archivo desencriptado
    decrypt_file("texto_encrypted.txt", decrypted_file_path, decryption_key)


