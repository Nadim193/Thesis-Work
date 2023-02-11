import os
import hashlib
import csv
import xlsxwriter
import openpyxl
import shutil
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import cryptography.fernet
from pathlib import Path


# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=MikZHbbEIrcJc6IePY1Y8z9Y7roS5XzPGH3cYk7cX3Vj3ocihTUZXyajfPP1GYr+ZQMi8knEsr/1+AStVWRnPQ==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

# Create a container
container_name = "storedatausingblockchain1"
container_client = blob_service_client.create_container(container_name)

# Read CSV file
data_set = []
with open("D:/Thesis Work/DataSet/30-70cancerChdEtc.csv", "r") as file:
    reader = csv.reader(file)
    for row in reader:
        data_set.extend(row)

# Encrypt the data before uploading to Azure Blob Storage
key = cryptography.fernet.Fernet.generate_key()
cipher = cryptography.fernet.Fernet(key)
encrypted_data_set = [cipher.encrypt(data.encode()) for data in data_set]

#Create the folder if it doesn't already exist
folder_path = "temp_folder"
if not os.path.exists(folder_path):
    os.makedirs(folder_path)

for encrypted_data in encrypted_data_set:
# Calculate the SHA-256 hash of the encrypted data
    hash = hashlib.sha256(encrypted_data).hexdigest()
    # Upload the encrypted data to a temporary local file
    with open(os.path.join(folder_path, hash), "wb") as file:
        file.write(encrypted_data)
        print("Successfully written to local file: " + os.path.join(folder_path, hash))


# Package the encrypted data into a .vhd file
os.system("tar -zcvf data.vhd *")

# Check if the blob already exists in Azure Blob Storage
blob_client = blob_service_client.get_blob_client(container=container_name, blob="data.vhd")
try:
    blob_properties = blob_client.get_blob_properties()
    print("Blob already exists, uploading with overwrite='true'")
    blob_client.upload_blob(encrypted_data, overwrite='true')
    print("Successfully uploaded to Azure Blob Storage using Import/Export service")
except:
    print("Blob not found, uploading with overwrite='false'")
    blob_client.upload_blob(encrypted_data, overwrite='false')
    print("Successfully uploaded to Azure Blob Storage using Import/Export service")

# Download the .vhd file from Azure Blob Storage
blob_client.download_blob().readall()

# Unpack the .vhd file and retrieve the encrypted data
os.system("tar -zxvf data.vhd")

# Decrypt the data
decrypted_data_set = [cipher.decrypt(encrypted_data).decode() for encrypted_data in encrypted_data_set]

# Clean up the temporary local files
folder_path = "D:/Thesis Work/temp_folder"
#Delete the folder
try:
   shutil.rmtree(folder_path, ignore_errors='false', onerror=None)
   print("directory is deleted")
except OSError as x:
   print("Error occured: %s : %s" % (folder_path, x.strerror))

myfile = "D:/Thesis Work/data.vhd"
# If file exists, delete it.
if os.path.isfile(myfile):
    os.remove(myfile)
else:
    # If it fails, inform the user.
    print("Error: %s file not found" % myfile)

# Write the decrypted data to a CSV file
with open("decrypted_data.csv", "w", newline='') as file:
    writer = csv.writer(file)
    for data in decrypted_data_set:
        writer.writerow([data])
print("Successfully decrypted the data and written to decrypted_data.csv file")
