import os
import io
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

CLIENT_CREDENTIALS_FILE = "CREDENCIAL_DESCARGADA.json"
SCOPES = ['https://www.googleapis.com/auth/drive']

def authenticate():
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_CREDENTIALS_FILE, SCOPES)
    credentials = flow.run_local_server(port=0)
    return credentials

def get_encryption_key_from_user():
    key = input("Ingrese la clave de encriptación: ")
    return derive_key(key)

def derive_key(password):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(input_file_path, output_file_path, encryption_key):
    with open(input_file_path, 'rb') as file:
        content = file.read()

    fernet = Fernet(encryption_key)
    encrypted_content = fernet.encrypt(content)

    with open(output_file_path, 'wb') as file:
        file.write(encrypted_content)

def upload_file_to_drive(credentials, file_path, folder_id):
    service = build('drive', 'v3', credentials=credentials)
    file_metadata = {
        'name': os.path.basename(file_path),
        'parents': [folder_id]
    }
    media = MediaIoBaseUpload(io.BytesIO(open(file_path, 'rb').read()), mimetype='application/octet-stream')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print('Archivo encriptado subido con el ID:', file.get('id'))

if __name__ == "__main__":
    credentials = authenticate()
    file_path_to_encrypt = "ARCHIVO_A_ENCRIPTAR.txt"
    encryption_key = get_encryption_key_from_user()
    encrypted_file_path = "ARCHIVO_ENCRIPTADO.txt"
    encrypt_file(file_path_to_encrypt, encrypted_file_path, encryption_key)
    folder_id = "ID_CARPETA_DRIVE"
    upload_file_to_drive(credentials, encrypted_file_path, folder_id)
    os.remove(encrypted_file_path)
