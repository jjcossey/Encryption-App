# Encryption-App
# Secure Vault

**Secure Vault** is a user-friendly, cross-platform application designed to protect your sensitive files and folders with robust encryption. Built with a modern graphical interface using PyQt5, it combines hybrid encryption techniques (AES for data encryption and RSA for key protection) to ensure your data remains confidential and secure. The application leverages the Argon2 key derivation function for secure password-based key generation, making it a reliable tool for privacy-focused users.

## Features
- **File and Folder Encryption**: Encrypt individual files or entire directories with a single click.
- **Hybrid Cryptography**: Uses AES-256 for fast data encryption and RSA-2048 for secure key management.
- **Password-Protected**: Secure your data with a user-defined password, verified during decryption.
- **Progress Tracking**: Visual progress bars display the status of encryption/decryption tasks.
- **Intuitive GUI**: A clean, tab-based interface for easy navigation between encryption, decryption, and help sections.
- **Cross-Platform**: Runs on Windows, macOS, and Linux with consistent performance.
- **Portable**: Supports packaging with PyInstaller for standalone executables.
- **Help Tab**: Includes detailed instructions for users to understand encryption and decryption workflows.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/jjcossey/secure-vault.git
   
2. Install the required libraries:
   run the command pip install -r requirements.txt

3. run the encrypt.py app in your project directory.
