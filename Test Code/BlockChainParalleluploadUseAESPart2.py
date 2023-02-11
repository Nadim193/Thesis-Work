import csv
import os
import sys
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient

def load_csv(file_name):
    data = []
    with open(file_name, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            data.append(row)
    return data

def encrypt_data(data, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_data(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data.encode())
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

def upload_to_blob_storage(container_name, blob_name, data):
    try:
        connection_string = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=MikZHbbEIrcJc6IePY1Y8z9Y7roS5XzPGH3cYk7cX3Vj3ocihTUZXyajfPP1GYr+ZQMi8knEsr/1+AStVWRnPQ==;EndpointSuffix=core.windows.net"
        container_client = ContainerClient.from_connection_string(connection_string, container_name)
        blob_client = container_client.get_blob_client(blob_name)
        data_str = json.dumps(data)
        blob_client.upload_blob(data_str, overwrite=True)
        blob_client.upload_blob(data)
        print("Uploaded successfully")
    except Exception as e:
        print("Upload failed: ", str(e))

def main():
    file_name = "D:/Thesis Work/DataSet/30-70cancerChdEtcTest.csv"
    key = os.urandom(32)
    container_name = "storedatausingblockchain21"
    blob_name = "encrypted_data.csv"
    data = load_csv(file_name)
    encrypted_data = []
    for row in data:
        encrypted_row = [encrypt_data(cell, key) for cell in row]
        encrypted_data.append(encrypted_row)

    try:
        upload_to_blob_storage(container_name, blob_name, encrypted_data)
    except Exception as e:
        print("Encryption failed: ", str(e))

if __name__ == '__main__':
    main()