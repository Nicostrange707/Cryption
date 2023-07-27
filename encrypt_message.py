from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
import base64

def encrypt_message(message, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(salt + cipher.iv + encrypted_data).decode()

def main():
    print("AES Message Encryption")
    message = input("Enter the message: ")
    password = input("Enter the encryption password: ")

    encrypted_message = encrypt_message(message, password)
    print("\nEncrypted message:", encrypted_message)

if __name__ == "__main__":
    main()