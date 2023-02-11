import os
import hashlib
import csv
import shutil
import json
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import cryptography.fernet
from concurrent.futures import ThreadPoolExecutor

# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=MikZHbbEIrcJc6IePY1Y8z9Y7roS5XzPGH3cYk7cX3Vj3ocihTUZXyajfPP1GYr+ZQMi8knEsr/1+AStVWRnPQ==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

# Create a container
container_name = "storedatausingblockchain5"
try:
    container_client = blob_service_client.create_container(container_name)
except:
    container_client = blob_service_client.get_container_client(container_name)

# Read CSV file
data_set = []
csv_file_path = "D:/Thesis Work/DataSet/30-70cancerChdEtcTest.csv"
if os.path.exists(csv_file_path):
    with open(csv_file_path, "r", encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            data_set.extend(row)
else:
    raise FileNotFoundError(f"The file at path '{csv_file_path}' does not exist.")

# Encrypt the data before uploading to Azure Blob Storage
key = cryptography.fernet.Fernet.generate_key()
cipher = cryptography.fernet.Fernet(key)
encrypted_data_set = [cipher.encrypt(data.encode()) for data in data_set]

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
    blob_client = blob_service_client.get_blob_client(container=container_name, blob="data.vhd")
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
        print("Successfully uploaded to Azure Blob Storage using Parallal Upload")

parallel_upload()

# Clean up the temporary folder
shutil.rmtree(folder_path)

# Store the encryption key securely
key_file_path = "key.key"
with open(key_file_path, "wb") as f:
    f.write(key)

#Upload the key to Azure Blob Storage
key_blob_client = blob_service_client.get_blob_client(container=container_name, blob="key.key")
try:
    key_blob_client.get_blob_properties()
    print("Key blob already exists, uploading with overwrite='True'")
    with open("key.key", "rb") as file:
        key_blob_client.upload_blob(file.read(), overwrite=True)
    print("Successfully uploaded key to Azure Blob Storage")
except:
    print("Key blob not found, uploading with overwrite='False'")
    with open("key.key", "rb") as file:
        key_blob_client.upload_blob(file.read(), overwrite=False)
    print("Successfully uploaded key to Azure Blob Storage")

#Decryption Part

# Download the encryption key
key_blob_client = blob_service_client.get_blob_client(container=container_name, blob="key.key")
try:
    key = key_blob_client.download_blob().readall()
except:
    raise Exception("Key blob not found. Ensure the key was uploaded successfully.")

# Decode the key and validate it
try:
    key = cryptography.fernet.Fernet(key)
except cryptography.fernet.InvalidToken:
    raise Exception("The encryption key is invalid. Ensure it was generated and stored securely.")

# Create a temporary folder
folder_path = "temp_folder"
os.makedirs(folder_path, exist_ok=True)

# Download all the encrypted data blobs
blob_list = container_client.list_blobs()
for blob in blob_list:
    if blob.name == "key.key":
        continue
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob.name)
    encrypted_data = blob_client.download_blob().readall()
    # Decrypt the encrypted data
    try:
        decrypted_data = key.decrypt(encrypted_data)
        decrypted_data_set = [key.decrypt(encrypted_data).decode() for encrypted_data in encrypted_data_set]
    except cryptography.fernet.InvalidToken:
        raise Exception("The encrypted data is invalid. Ensure it was encrypted correctly.")
    # Save the decrypted data to a temporary local file
    local_file_path = os.path.join(folder_path, blob.name)
    with open(local_file_path, "wb") as f:
        f.write(decrypted_data)

# Write the decrypted data to a CSV file
csv_file_path = "decrypted_data.csv"
with open(csv_file_path, "w", newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    for row in decrypted_data_set:
        writer.writerow([row])
print("Successfully written decrypted data to a CSV file")

# Clean up the temporary folder
shutil.rmtree(folder_path)