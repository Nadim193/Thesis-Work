import base64
import hashlib
import os
import pycrypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient

# Generate a random 256-bit key using PBKDF2
password = "67".encode()
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    iterations=100000,
    length=32,
    salt=salt,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# Encrypt the data using the key
f = Fernet(key)
data = "nadim".encode()
encrypted_data = f.encrypt(data)

# Create a zero-knowledge proof for the encrypted data using Zokrates
proof = pycrypto.create_proof(data)

# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=MikZHbbEIrcJc6IePY1Y8z9Y7roS5XzPGH3cYk7cX3Vj3ocihTUZXyajfPP1GYr+ZQMi8knEsr/1+AStVWRnPQ==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

# Create a container
container_name = "storedatausingblockchain4"
container_client = blob_service_client.create_container(container_name)

# Upload the encrypted data and proof to the container
blob_client_data = blob_service_client.get_blob_client(container=container_name, blob="data")
blob_client_data.upload_blob(encrypted_data)

blob_client_proof = blob_service_client.get_blob_client(container=container_name, blob="proof")
blob_client_proof.upload_blob(proof)

print("Data and proof successfully uploaded to Azure Blob Storage")

#Download the encrypted data and proof
downloaded_data = blob_client_data.download_blob().readall()
downloaded_proof = blob_client_proof.download_blob().readall()

# Verify the proof
if pycrypto.verify_proof(downloaded_proof,data):
    # Decrypt the data using the key
    decrypted_data = f.decrypt(downloaded_data)
    print("Decrypted data: ",decrypted_data.decode())
else:
    print("Proof could not be verified")

