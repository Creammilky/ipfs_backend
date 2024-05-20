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
import base64

# user file enc

def encrypt(plain_text,key):
    cipher = Fernet(key)
    cipher_text = cipher.encrypt(plain_text)
    return cipher_text

def decrypt(cipher_text, key):
    # 确保key是bytes类型，如果是str则将其转换为bytes
    if isinstance(key, str):
        key = key.encode()
    # 检查key是否是32个字节的URL-safe base64编码
    # 如果不是，尝试对其进行编码
    try:
        # URL-safe base64编码密钥的长度必须是44（包括'='填充）
        if len(key) != 44 or not set(key.decode()).issubset(
                set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=')):
            raise ValueError("Key must be a 32 url-safe base64-encoded bytes.")

        # 生成Fernet对象
        cipher = Fernet(key)

        # 解密文本，确保cipher_text也是bytes类型
        if isinstance(cipher_text, str):
            cipher_text = cipher_text.encode()

        # 解密
        plain_text = cipher.decrypt(cipher_text)

        # 返回解密后的文本
        return plain_text.decode()
    except (ValueError, base64.binascii.Error) as e:
        raise ValueError("Invalid key or cipher text: {}".format(e))

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


def encrypt_message(message, public_key_input, is_plain=False):
    # 根据is_plain标志位读取或转换公钥
    if not is_plain:
        # 如果is_plain为False，从文件路径读取公钥
        with open(public_key_input, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
    else:
        # 如果is_plain为True，直接从字符串加载公钥
        # 需要将字符串公钥转换为字节
        public_key = serialization.load_pem_public_key(public_key_input.encode())

    # 使用公钥加密消息
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_message(encrypted_message, private_key_input, is_plain=False):
    # 根据is_plain标志位读取或转换私钥
    if not is_plain:
        # 如果is_plain为False，从文件路径读取私钥
        with open(private_key_input, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    else:
        # 如果is_plain为True，直接从字符串加载私钥
        # 需要将字符串私钥转换为字节
        private_key = serialization.load_pem_private_key(private_key_input.encode(), password=None)

    # 使用私钥解密消息
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return original_message.decode()

