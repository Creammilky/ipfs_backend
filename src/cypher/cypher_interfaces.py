from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as RSAPadding
from cryptography.hazmat.primitives import padding as AESPadding
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import *
import os

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


# RSA PUBLIC KEY ENCRYPTION
def rsa_public_key_encryption(public_key_path, plaintext, is_plain=False):
    if isinstance(plaintext, type(str)):
        plaintext = plaintext.encode()
    if is_plain is True:
        public_key = serialization.load_pem_public_key(
            public_key_path,
            backend=default_backend()
        )
    else:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    ciphertext = public_key.encrypt(
        plaintext,
        RSAPadding.OAEP(
            mgf=RSAPadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# RSA PRIVATE KEY DECRYPTION
def rsa_private_key_decryption(private_key_path, ciphertext, is_plain=False):
    if is_plain is True:
        private_key = serialization.load_pem_private_key(
            private_key_path,
            password=None,
            backend=default_backend()
        )
    else:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    plaintext = private_key.decrypt(
        ciphertext,
        RSAPadding.OAEP(
            mgf=RSAPadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def aes_encrypt_file(key_str, file_path):
    key = key_str.encode()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = AESPadding.PKCS7(128).padder()

    with open(file_path, 'rb') as f:
        plaintext = f.read()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path, 'wb') as f:
        f.write(ciphertext)


def aes_decrypt_file(key_str, file_path):
    key = key_str.encode()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = AESPadding.PKCS7(128).unpadder()

    with open(file_path, 'rb') as f:
        ciphertext = f.read()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    with open(file_path, 'wb') as f:
        f.write(plaintext)


def aes_encrypt(key_str, plaintext):
    # 将密钥转换为字节
    key = key_str.encode()
    # 创建 cipher 对象
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    # 创建 encryptor 对象
    encryptor = cipher.encryptor()
    # 创建一个 padder 对象
    padder = AESPadding.PKCS7(128).padder()
    # 添加 padding
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    # 加密
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # 使用 base64 编码以打印或者存储密文
    return b64encode(ciphertext).decode()


def aes_decrypt(key_str, ciphertext):
    # 将密钥和密文转换为字节
    key = key_str.encode()
    ct = b64decode(ciphertext)
    # 创建 cipher 对象
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    # 创建 decryptor 对象
    decryptor = cipher.decryptor()
    # 解密
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    # 创建一个 unpadder 对象
    unpadder = AESPadding.PKCS7(128).unpadder()
    # 删除 padding
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()


def file_enc_test(path, enc_key, pri_key_path):
    key = rsa_private_key_decryption(private_key_path=pri_key_path, ciphertext=enc_key)
    print(key)
    for file_path in list_files(path):
        file_path = "./files/" + file_path
        aes_encrypt_file(key_str=key.decode(), file_path=file_path)


def file_dec_test(path, enc_key, pri_key_path):
    key = rsa_private_key_decryption(private_key_path=pri_key_path, ciphertext=enc_key)
    print(key)
    for file_path in list_files(path):
        file_path = "./files/" + file_path
        aes_decrypt_file(key_str=key.decode(), file_path=file_path)


def list_files(directory):
    return [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]


# if __name__ == '__main__':
#     str = "Hello RSA"
#     path = "D:\\BUPT\\Junior.II\\Security Programming\\frontendtest\\files"
#     key = "Th1sIs@S3cretKey4orYouT0UseWh3nY"
#     print(len(key))
#     pub_key_path = "./public_key.pem"
#     pri_key_path = "./private_key.pem"
#     enc_key = (rsa_public_key_encryption(public_key_path=pub_key_path, plaintext=key))
#     file_dec_test(path, enc_key, pri_key_path)
#     print("--------")
#
#     cy = rsa_public_key_encryption(public_key_path=pub_key_path, plaintext=str)
#     print(cy)
#     pl = rsa_private_key_decryption(private_key_path=pri_key_path, ciphertext=cy)
#     print(pl)