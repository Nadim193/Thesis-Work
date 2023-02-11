import base64
import hashlib
import os
import csv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient

# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=MikZHbbEIrcJc6IePY1Y8z9Y7roS5XzPGH3cYk7cX3Vj3ocihTUZXyajfPP1GYr+ZQMi8knEsr/1+AStVWRnPQ==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

# Create a container
container_name = "storedatausingblockchain4"
container_client = blob_service_client.create_container(container_name)

# Generate a random 256-bit key using PBKDF2
password = "nadim".encode()
salt = os.urandom(16)
kdf = PBKDF2HMAC(
algorithm=hashes.SHA256,
iterations=100000,
length=32,
salt=salt,
backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# Create Fernet object
f = Fernet(key)

# Read CSV file
data_set = []
with open("diabetes_012_health_indicators_BRFSS2015.csv", "r") as file:
    reader = csv.reader(file)
    for row in reader:
        data_set.extend(row)

for data in data_set:
    # Calculate the SHA-256 hash of the data
    data = data.encode()
    hash = hashlib.sha256(data).hexdigest()

    # Encrypt the data using the key
    encrypted_data = f.encrypt(data)

    # Check if the blob already exists
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=hash)
    try:
        blob_client.get_blob_properties()
        # Overwrite the existing blob if it exists
        blob_client.upload_blob(encrypted_data, overwrite='true')
    except:
        # Upload the encrypted data to the container with the hash as the file name
        blob_client.upload_blob(encrypted_data)
    print("Successfully uploaded to Azure Blob Storage with key: " + hash)

for data in data_set:
    hash = hashlib.sha256(data.encode()).hexdigest()
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=hash)
    downloaded_data = blob_client.download_blob().readall()
    # Decrypt the data using the key
    decrypted_data = f.decrypt(downloaded_data)
    print("Decrypted data: ",decrypted_data.decode())