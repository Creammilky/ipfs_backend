'''
Author: Carl Tan
Date: 2024-05-04 13:22:45
LastEditors: Carl Tan
LastEditTime: 2024-05-04 14:51:01
'''
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


# user file enc

def encrypt(plain_text,key):
    cipher = Fernet(key)
    cipher_text = cipher.encrypt(plain_text)
    return cipher_text

def decrypt(cipher_text,key):
    cipher = Fernet(key)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text

def encrypt_from_file(filename, key):
    fernet = Fernet(key)
    with open(filename, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(filename, 'wb') as enc_file:
        enc_file.write(encrypted)


# user file dec
def decrypt_from_file(filename, key):
    fernet = Fernet(key)
    with open(filename, 'rb') as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(filename, 'wb') as dec_file:
        dec_file.write(decrypted)


def generate_keys_and_save(file_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_key_path = os.path.join(file_path, 'private_key.pem')
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key_path = os.path.join(file_path, 'public_key.pem')
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key_path, public_key_path


def encrypt_message(message, public_key_path):
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_message(encrypted_message, private_key_path):
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()

