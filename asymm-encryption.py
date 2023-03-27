#!/usr/bin/python3
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

if __name__ == "__main__":

    if not os.path.exists('./keys'):
        os.mkdir('./keys')

    print("Generating and storing Private key at filepath ./keys/private_key.pem")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('./keys/private_key.pem', 'wb') as f:
        f.write(private_pem)

    print("Generating and storing Public key at filepath ./keys/public_key.pem")
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('./keys/public_key.pem', 'wb') as f:
        f.write(public_pem)

    print("Generating HEX hash of test.txt file!")
    hex_hash_digest = ''
    with open('test.txt', 'rb') as f:
        bytes_read = f.read()
        hex_hash_digest = hashlib.sha256(bytes_read).hexdigest()
        print(f'Printing hex sha256 hash of test.txt: {hex_hash_digest}')

    print('Loading keys from ./keys/*.pem files')
    loaded_private_key, loaded_public_key = '', ''
    with open('./keys/private_key.pem', 'rb') as f:
        bytes_read = f.read()
        loaded_private_key = serialization.load_pem_private_key(
            bytes_read,
            password=None
        )

    with open('./keys/public_key.pem', 'rb') as f:
        bytes_read = f.read()
        loaded_public_key = serialization.load_pem_public_key(
            bytes_read
        )

    print('Encrypting ./test.txt file at filepath ./encrypted_test_file.txt with the loaded private key')
    encrypted_bytes = loaded_public_key.encrypt(
        bytes.fromhex(hex_hash_digest),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open('./encrypted_test_file.txt', 'wb') as f:
        f.write(encrypted_bytes)

    encrypted_file_content = ''
    with open('./encrypted_test_file.txt', 'rb') as f:
        encrypted_file_content = f.read()

    print('Decrypting ./encrypted_test_file.txt file with the loaded public key')
    decrypted_bytes = loaded_private_key.decrypt(
        encrypted_file_content,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted_hash_digest = decrypted_bytes.hex()
    print('Check if decrypted hash matches original test.txt file hash')
    if decrypted_hash_digest == hex_hash_digest:
        print('Decrypted test.txt hash matches original file hash')
    else:
        print('oops, asymmetric file encryption failed')
