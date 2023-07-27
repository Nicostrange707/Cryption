from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import base64

def decrypt_message(encrypted_message, password):
    encrypted_data = base64.b64decode(encrypted_message)
    salt, iv, encrypted_data = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

def main():
    print("AES Message Decryption")
    encrypted_message = input("Enter the encrypted message: ")
    password = input("Enter the decryption password: ")

    decrypted_message = decrypt_message(encrypted_message, password)
    print("\nDecrypted message:", decrypted_message)

if __name__ == "__main__":
    main()