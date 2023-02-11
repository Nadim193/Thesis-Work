import os
import hashlib
import csv
import shutil
import json
import traceback
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import concurrent.futures
import requests
import time

start_time3 = time.time()

# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=XDX90enqsPIO19bfdMTpAWaHlN8w1ZCqUAyDKQ8Re5DQ+nGv8vzzJtBY4m/5jcJcx1+eJRjv9RYO+ASts9EL1g==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

# Create a container
container_name = "storedatausingblockchain12"
try:
    container_client = blob_service_client.create_container(container_name)
except:
    container_client = blob_service_client.get_container_client(container_name)

# Read CSV file
data_set = []
header = []
csv_file_path = "D:/Thesis Work/DataSet/30-70cancerChdEtc.csv"
try:
    if os.path.exists(csv_file_path):
        with open(csv_file_path, "r", encoding='utf-8') as file:
            reader = csv.reader(file)
            header = next(reader)
            for row in reader:
                data_set.extend(row)
    else:
        raise FileNotFoundError(f"The file at path '{csv_file_path}' does not exist.")
except Exception as e:
    print(f"An error occurred while reading the CSV file: {e}")

start_time = time.time()

# Generate AES key
key = os.urandom(32) # 256 bit key
iv = os.urandom(16)

# Encrypt the data
encrypted_data_set = []
try:
    for data in data_set:
        # Pad the data to the block size of the cipher
        pad = padding.PKCS7(256).padder()
        padded_data = pad.update(data.encode()) + pad.finalize()
        
        # Create the cipher object
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        
        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Add the encrypted data to the list of encrypted data
        encrypted_data_set.append(encrypted_data)
except Exception as e:
    print(f"An error occurred while encrypting the data: {e}")

print("Execution time for encryption:", (time.time() - start_time)/60, "seconds")

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
        blob_client.upload_blob(data)

#Upload the encrypted files to Azure Blob Storage
hashes = {}
try:
    with ThreadPoolExecutor(max_workers=1000) as executor:
        for index, encrypted_data in enumerate(encrypted_data_set):
            file_name = f"encrypted_data_{index}.bin"
            file_path = os.path.join(folder_path, file_name)
            with open(file_path, "wb") as file:
                file.write(encrypted_data)
                executor.submit(upload_file, file_path, container_client)

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

start_time2 = time.time()

# Decrypt the data
decrypted_data_set = []
try:
    for index, encrypted_data in enumerate(encrypted_data_set):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(256).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        decrypted_data_set.append(decrypted_data.decode())
except Exception as e:
    print(f"An error occurred while decrypting the data: {e}")
    
print("Execution time for Decryption:", (time.time() - start_time2)/60, "seconds")

# Write the decrypted data to a CSV file
csv_file_path = "decrypted_data_set.csv"
data_list = []
for i in range(0, len(decrypted_data_set), 5):
    data_list.append({header[0]: decrypted_data_set[i],
                      header[1]: decrypted_data_set[i + 1],
                      header[2]: decrypted_data_set[i + 2],
                      header[3]: decrypted_data_set[i + 3],
                      header[4]: decrypted_data_set[i + 4]})

try:
    with open(csv_file_path, "w", newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=header)
        writer.writeheader()
        for data in data_list:
            writer.writerow(data)
except Exception as e:
    print(f"An error occurred while writing the decrypted data to the CSV file: {e}")

# Clean up the temporary folder
try:
    shutil.rmtree(folder_path)
except Exception as e:
    print(f"An error occurred while deleting the folder: {e}")

print("Execution time:", (time.time() - start_time3)/60, "seconds")