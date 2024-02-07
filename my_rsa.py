from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def encrypt_RSA(public_key, data):
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_RSA(private_key, encrypted_data):
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted







if __name__ == '__main__':
    # Generating RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # my coding
    # Serialize the keys (for storing or transmitting)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Deserialize the keys back to objects if needed
    loaded_private_key = serialization.load_pem_private_key(
        pem_private,
        password=None,
        backend=None
    )

    loaded_public_key = serialization.load_pem_public_key(
        pem_public,
        backend=None
    )









    # Encrypting and decrypting data


    data_to_encrypt = b"Your secret message here"  # Data to be encrypted (in bytes)
    print("Original data:", data_to_encrypt.decode('utf-8'))

    encrypted_data = encrypt_RSA(public_key, data_to_encrypt)
    print("Encrypted data:", encrypted_data)

    decrypted_data = decrypt_RSA(private_key, encrypted_data)
    print("Decrypted data:", decrypted_data.decode('utf-8'))
