import os
import hashlib
import csv
import shutil
import json
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
import time

start_time3 = time.time()

# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=XDX90enqsPIO19bfdMTpAWaHlN8w1ZCqUAyDKQ8Re5DQ+nGv8vzzJtBY4m/5jcJcx1+eJRjv9RYO+ASts9EL1g==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
    
# Create a container
container_name = "storedatausingblockchain10"
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

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=cryptography.hazmat.backends.default_backend()
)

public_key = private_key.public_key()

# Encrypt the data before uploading to Azure Blob Storage
encrypted_data_set = []
try:
    for data in data_set:
        encrypted_data = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
        encrypted_data_set.append(encrypted_data)
except Exception as e:
    print(f"An error occurred while encrypting the data: {e}")

print("Execution time for encryption:", (time.time() - start_time)/60, "seconds")

# Create a temporary folder
folder_path = "temp_folder"
try:
    os.makedirs(folder_path, exist_ok=True)
except Exception as e:
    print(f"An error occurred while creating the temporary folder: {e}")

#Upload a single file to Azure Blob Storage
def upload_file(file_path, container_client):
    blob_client = container_client.get_blob_client(file_path)
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data)

#Write encrypted data to separate files and upload them to Azure Blob Storage
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

#Clean up the temporary folder
shutil.rmtree(folder_path)

start_time2 = time.time()

# Decrypt the data after downloading from Azure Blob Storage
try:
    decrypted_data_set = []
    for index in range(len(encrypted_data_set)):
        encrypted_data = encrypted_data_set[index]
        try:
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
            decrypted_data = decrypted_data.decode()
            decrypted_data_set.append(decrypted_data)
        except InvalidSignature as e:
            print(f"Error while decrypting data at index {index}: {e}")
except Exception as e:
    print(f"An error occurred while decrypting data: {e}")

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

print("Execution time:", (time.time() - start_time3)/60, "seconds")