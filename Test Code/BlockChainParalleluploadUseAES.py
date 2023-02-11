import os
import hashlib
import csv
import shutil
import json
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor

# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=MikZHbbEIrcJc6IePY1Y8z9Y7roS5XzPGH3cYk7cX3Vj3ocihTUZXyajfPP1GYr+ZQMi8knEsr/1+AStVWRnPQ==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

# Create a container
container_name = "storedatausingblockchain72"
try:
    container_client = blob_service_client.create_container(container_name)
except:
    container_client = blob_service_client.get_container_client(container_name)

# Read CSV file
data_set = []
header = []
csv_file_path = "D:/Thesis Work/DataSet/30-70cancerChdEtcTest.csv"
if os.path.exists(csv_file_path):
    with open(csv_file_path, "r", encoding='utf-8') as file:
        reader = csv.reader(file)
        header = next(reader)
        for row in reader:
            data_set.extend(row)
else:
    raise FileNotFoundError(f"The file at path '{csv_file_path}' does not exist.")

# Generate encryption key
key = os.urandom(32) #32-byte key for AES-256 encryption

# Encrypt the data before uploading to Azure Blob Storage
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

encrypted_data_set = [encrypt_data(data, key) for data in data_set]

# Create a temporary folder
folder_path = "temp_folder"
os.makedirs(folder_path, exist_ok=True)

def upload_blob(encrypted_data):
    # Calculate the SHA-256 hash of the encrypted data
    hash = hashlib.sha256(encrypted_data).hexdigest()
    # Upload the encrypted data to a temporary local file
    local_file_path = os.path.join(folder_path, hash)
    with open(local_file_path, "wb") as f:
        f.write(encrypted_data)
        print("Successfully written to local file: " + os.path.join(folder_path, hash))
        
    # Check if the blob already exists in Azure Blob Storage
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=hash)
    try:
        blob_properties = blob_client.get_blob_properties()
        print("Blob already exists, uploading with overwrite='true'")
        blob_client.upload_blob(encrypted_data, overwrite='false')
        print("Successfully uploaded to Azure Blob Storage using Import/Export service")
    except:
        print("Blob not found, uploading with overwrite='false'")
        blob_client.upload_blob(encrypted_data, overwrite='true')
        print("Successfully uploaded to Azure Blob Storage using Import/Export service")
        
def parallel_upload():
    with ThreadPoolExecutor() as executor:
        results = [executor.submit(upload_blob, encrypted_data) for encrypted_data in encrypted_data_set]
        for future in results:
            future.result()

parallel_upload()

#Delete the temporary folder
shutil.rmtree(folder_path)

#Store the encryption key in a JSON file
key_file_path = "key.json"
key_file = {"key": key.hex()}
with open(key_file_path, "w") as f:
    json.dump(key_file, f)
    print("Successfully written to key file: " + key_file_path)

print("Data upload and encryption complete.")

#------------------------------------------------------End Of encryption--------------------------------------------

#decryption Part

#-----------------------------------------------------Start Of Decryption-------------------------------------------

# Read the encryption key from the JSON file
key_file_path = "key.json"
with open(key_file_path, "r") as f:
    key_file = json.load(f)
    key = bytes.fromhex(key_file["key"])

# Decrypt the data
def decrypt_data(encrypted_data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size).decode()

# Download the encrypted data from Azure Blob Storage
def download_blob(hash):
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=hash)
    data = blob_client.download_blob().readall()
    decrypted_data = decrypt_data(data, key)
    return decrypted_data

# Calculate the SHA-256 hash of the encrypted data
def get_hash(data):
    return hashlib.sha256(data).hexdigest()

# Get a list of all the blobs in the container
blob_list = [blob.name for blob in container_client.list_blobs()]

# Download and decrypt the data for each blob
decrypted_data_set = [download_blob(hash) for hash in blob_list]

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

print("Data download and decryption complete.")

#--------------------------------------------------------End Of Decryption-------------------------------------------