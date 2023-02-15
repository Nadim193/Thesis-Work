import csv
import os
import base64
import hashlib
import pickle
import shutil
import io
import json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from concurrent.futures import ThreadPoolExecutor

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

def encrypt_data(data, public_key):
    if isinstance(data, str):
        data = data.encode()
    # Encrypt data using RSA
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode encrypted data in base64
    encoded_encrypted_data = base64.b64encode(encrypted_data)
    return encoded_encrypted_data

def decrypt_data(encoded_encrypted_data, private_key):
    # Decode encrypted data from base64
    encrypted_data = base64.b64decode(encoded_encrypted_data)
    # Decrypt data using RSA
    data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return data

def encrypt_aes(data, key):
    # Encrypt data using AES
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_aes(encrypted_data, key):
    # Decrypt data using AES
    fernet = Fernet(key)
    data = fernet.decrypt(encrypted_data).decode()
    return data

def upload_to_azure(encrypted_data_set):
    # Connect to Azure Blob Storage
    connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=XDX90enqsPIO19bfdMTpAWaHlN8w1ZCqUAyDKQ8Re5DQ+nGv8vzzJtBY4m/5jcJcx1+eJRjv9RYO+ASts9EL1g==;EndpointSuffix=core.windows.net"
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)

    # Create a container
    container_name = "storedatausingblockchain7"
    try:
        container_client = blob_service_client.create_container(container_name)
    except:
        container_client = blob_service_client.get_container_client(container_name)
    # Create a temporary folder
    folder_path = "temp_folder"
    try:
        os.makedirs(folder_path, exist_ok=True)
    except Exception as e:
        print(f"An error occurred while creating the folder: {e}")

    #Upload a single file to Azure Blob Storage
    def upload_file(file_path, container_client):
        blob_client = container_client.get_blob_client(file_path)
        with open(file_path, "rb") as data:
            blob_client.upload_blob(data.read(), max_size=4 * 1024 * 1024)  # set max_size to 4MB or another valid value


    # Upload the encrypted files to Azure Blob Storage
    hashes = {}
    try:
        with ThreadPoolExecutor(max_workers=1000) as executor:
            futures = []
            for index, encrypted_data in enumerate(encrypted_data_set):
                file_name = f"encrypted_data_{index}.bin"
                file_path = os.path.join(folder_path, file_name)
                with open(file_path, "wb") as file:
                    file.write(bytes(encrypted_data))
                futures.append(executor.submit(upload_file, [file_path], container_client))
            for future in futures:
                future.result()
    except Exception as e:
        print(f"An error occurred while uploading the encrypted data to Azure Blob Storage: {e}")


    #Calculate the SHA-256 hash of a single file
    def calculate_sha256_hash(file_path, index, hashes):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                sha256_hash.update(chunk)
                hashes[index] = sha256_hash.hexdigest()

    #Calculate the SHA-256 hash of each encrypted data file and store it in a dictionary
    hashes = {}
    try:
        with ThreadPoolExecutor(max_workers=1000) as executor:
            for index in range(len(encrypted_data_set)):
                file_name = F"encrypted_data_{index}.bin"
                file_path = os.path.join(folder_path, file_name)
                executor.submit(calculate_sha256_hash, file_path, index, hashes)
    except Exception as e:
        print(f"An error occurred while calculating the SHA-256 hashes of the encrypted data files: {e}")

    #Save the dictionary of SHA-256 hashes to a JSON file
    json_file_path = "EncryptData.json"
    try:
        with open(json_file_path, "w") as file:
            file.write(json.dumps(hashes))
    except Exception as e:
        print(f"An error occurred while saving the SHA-256 hashes to a JSON file: {e}")
        

    #Upload the JSON file to Azure Blob Storage
    json_blob_client = container_client.get_blob_client(json_file_path)
    try:
        with open(json_file_path, "rb") as data:
            json_blob_client.upload_blob(data)
    except Exception as e:
        print(f"An error occurred while uploading the JSON file to Azure Blob Storage: {e}")
    
    # Clean up the temporary folder
    try:
        shutil.rmtree(folder_path)
    except Exception as e:
        print(f"An error occurred while deleting the folder: {e}")
    return None

def read_from_csv(file_path):
    # Read data from CSV file
    data = []
    header = []
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)
        for row in reader:
            data.append(row)
    return data, header

def write_to_csv(file_path, data, header):
    # Write data to CSV file
    try:
        with open(file_path, 'w', newline='', encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(header)
            writer.writerows(data)
    except Exception as e:
        print("An error occurred while writing to the CSV file:", e)

def main():
    start_time3 = time.time()
    # Read data from CSV file
    file_path = "D:/Thesis Work/DataSet/30-70cancerChdEtc.csv"
    
    data, header = read_from_csv(file_path)
    # Generate AES key
    password = b"password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = base64.urlsafe_b64encode(kdf.derive(password))

    start_time = time.time()
    # Encrypt data using RSA and AES
    encrypted_data = []
    for row in data:
        encrypted_row = []
        for item in row:
            encrypted_item = encrypt_data(item.encode(), public_key)
            encrypted_item = encrypt_aes(encrypted_item.decode(), aes_key)
            encrypted_row.append(encrypted_item)
        encrypted_data.append(encrypted_row)
        
    print("Execution time for encryption:", (time.time() - start_time)/60, "Min")

    
    # Upload encrypted data to Azure
    # upload_to_azure(encrypted_data)
    # print("Encrypted data uploaded to Azure")


    start_time2 = time.time()
    # Decrypt data using RSA and AES
    decrypted_data = []
    for row in encrypted_data:
        decrypted_row = []
        for item in row:
            item = decrypt_aes(item, aes_key)
            item = decrypt_data(item.encode(), private_key).decode()
            decrypted_row.append(item)
        decrypted_data.append(decrypted_row)
    
    print("Execution time for Decryption:", (time.time() - start_time2)/60, "Min")

    
    # Write decrypted data to CSV file
    write_to_csv("Decryption_Data.csv", decrypted_data, header)
    print("Execution time:", (time.time() - start_time3)/60, "Min")


if __name__ == "__main__":
    main()