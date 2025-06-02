import os
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLineEdit, QLabel, QMessageBox
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_FILE = "rsa_keys.pem"

def save_rsa_keys(private_key):
    """Save RSA private and public keys to a file."""
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def load_rsa_keys():
    """Load RSA private and public keys from a file if they exist."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            return private_key, private_key.public_key()
    return None, None

class EncryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encrypt File App")
        self.setGeometry(100, 100, 400, 300)

        # Load or generate RSA keys
        self.private_key, self.public_key = load_rsa_keys()
        if not self.private_key:
            self.private_key, self.public_key = self.generate_rsa_keys()
            save_rsa_keys(self.private_key)
        
        # Layout setup
        self.layout = QVBoxLayout()
        
        self.password_label = QLabel("Enter Password:")
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        
        self.encrypt_button = QPushButton("Encrypt File", self)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Decrypt File", self)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        self.layout.addWidget(self.decrypt_button)
        
        self.setLayout(self.layout)

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    def derive_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        # Use PBKDF2 to derive a 32-byte AES key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        aes_key = kdf.derive(password.encode())
        return aes_key, salt

    def encrypt_file(self):
        password = self.password_input.text()
        if not password:
            self.show_error_message("Password is required.")
            return
        
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt", "", "All Files (*)", options=options)
        if not file_path:
            return
        
        aes_key, salt = self.derive_key(password)
        encrypted_aes_key = self.public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as encrypted_file:
            # Write salt, iv, encrypted_aes_key, and encrypted_data
            encrypted_file.write(salt + iv + encrypted_aes_key + encrypted_data)
        
        QMessageBox.information(self, "Success", "File encrypted successfully!")

    def decrypt_file(self):
        password = self.password_input.text()
        if not password:
            self.show_error_message("Password is required.")
            return
        
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt", "", "Encrypted Files (*.enc)", options=options)
        if not file_path:
            return
        
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_aes_key = encrypted_data[32:32 + 256]
        encrypted_data = encrypted_data[32 + 256:]
        
        # Derive the AES key using the same salt and password
        aes_key, _ = self.derive_key(password, salt)
        
        try:
            decrypted_aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            self.show_error_message("Decryption failed. Incorrect password or corrupted file.")
            return
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        try:
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        except ValueError:
            self.show_error_message("Decryption failed, unauthorized access.")
            return
        
        decrypted_file_path = file_path[:-4]
        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        QMessageBox.information(self, "Success", "File decrypted successfully!")

    def show_error_message(self, message):
        QMessageBox.critical(self, "Error", message)

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = EncryptApp()
    window.show()
    sys.exit(app.exec_())