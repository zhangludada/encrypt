from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_AES(key, data):
    # Generate a random initialization vector
    iv = os.urandom(16)

    # Pad the data before encryption
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create an AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def decrypt_AES(key, data):
    # Extract the initialization vector and ciphertext
    iv = data[:16]
    ciphertext = data[16:]

    # Create an AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data

# my code
def encrypt_file_AES(key, filename):
    with open(filename,mode='rb') as f:
        b_txt=f.read()
    encrypted_data = encrypt_AES(key, b_txt)

    with open(f'{filename}.encrypted','wb') as f:
        f.write(encrypted_data)

def decrypt_file_AES(key,filename):
    with open(filename,mode='rb') as f:
        encrypted_data =f.read()
    decrypted_data = decrypt_AES(key, encrypted_data)
    with open(f'{filename}.decrypted','wb') as f:
        f.write(decrypted_data)


# Example usage
if __name__ == '__main__':
    key = os.urandom(32)  # Generate a random 256-bit (32-byte) key

    data_to_encrypt = b"Your secret message here"  # Data to be encrypted (in bytes)
    print("Original data:", data_to_encrypt.decode('utf-8'))

    encrypted_data = encrypt_AES(key, data_to_encrypt)
    print("Encrypted data:", encrypted_data)

    decrypted_data = decrypt_AES(key, encrypted_data)
    print("Decrypted data:", decrypted_data.decode('utf-8'))
    print(len(key))


