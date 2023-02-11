import os
import hashlib
import csv
import xlsxwriter
import openpyxl
import shutil
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import cryptography.fernet
from pathlib import Path
import base64
import json
import requests
import web3

# Connect to Azure Blob Storage
connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=MikZHbbEIrcJc6IePY1Y8z9Y7roS5XzPGH3cYk7cX3Vj3ocihTUZXyajfPP1GYr+ZQMi8knEsr/1+AStVWRnPQ==;EndpointSuffix=core.windows.net"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)

# Create a container
container_name = "storedatausingblockchain26"
container_client = blob_service_client.create_container(container_name)

# Read CSV file
data_set = []
with open("D:/Thesis Work/DataSet/30-70cancerChdEtc.csv", "r") as file:
    reader = csv.reader(file)
    for row in reader:
        data_set.extend(row)

# Connect to the Ethereum network
w3 = web3.Web3(web3.HTTPProvider('https://mainnet.infura.io/v3/96e9fcefa6a54d7482149064d170cace'))

# Encrypt the data using the Ethereum network
# Define the smart contract for encryption
contract_address = "0x201894777D3E5f0a60E1984CFfC2D5f7d4F806C6"  # Address of the encryption smart contract
contract_abi = [{"constant":False,"inputs":[{"name":"_hash","type":"string"},{"name":"_data","type":"bytes"}],"name":"storeData","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"}]  # ABI of the encryption smart contract
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Encrypt each data in the data set
encrypted_data_set = []
for data in data_set:
    # Call the encrypt function in the smart contract
    encrypted_data = contract.functions.encrypt(data).call()
    encrypted_data_set.append(encrypted_data)

#Create the folder if it doesn't already exist
folder_path = "temp_folder"
if not os.path.exists(folder_path):
    os.makedirs(folder_path)

for encrypted_data in encrypted_data_set:
# Calculate the SHA-256 hash of the encrypted data
    hash = hashlib.sha256(encrypted_data.encode()).hexdigest()
    # Upload the encrypted data to a temporary local file
    with open(os.path.join(folder_path, hash), "wb") as file:
        file.write(encrypted_data.encode())
        print("Successfully written to local file: " + os.path.join(folder_path, hash))

# Package the encrypted data into a .vhd file
os.system("tar -zcvf data.vhd *")

# Check if the blob already exists in Azure Blob Storage
blob_client = blob_service_client.get_blob_client(container=container_name, blob="data.vhd")
try:
    blob_client.get_blob_properties()
    print("Blob already exists, skipping uploading.")
except:
    # If not, upload the .vhd file to Azure Blob Storage
    with open("data.vhd", "rb") as data:
        blob_client.upload_blob(data)
    print("Successfully uploaded to Azure Blob Storage.")

#Delete the temporary local files
shutil.rmtree(folder_path)
os.remove("data.vhd")
print("Successfully deleted temporary local files.")

myfile = "D:/Thesis Work/data.vhd"
# If file exists, delete it.
if os.path.isfile(myfile):
    os.remove(myfile)
else:
    # If it fails, inform the user.
    print("Error: %s file not found" % myfile)

#Decryption Part
#Connect to the Ethereum network
w3 = web3.Web3(web3.HTTPProvider('https://mainnet.infura.io/v3/96e9fcefa6a54d7482149064d170cace'))

#Define the smart contract for decryption
contract_address = "0x..." # Address of the decryption smart contract
contract_abi = [...] # ABI of the decryption smart contract
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

#Decrypt the data
decrypted_data_set = []
for file in os.listdir("temp_folder"):
    # Read the encrypted data from the file
    with open(os.path.join("temp_folder", file), "rb") as data:
        encrypted_data = data.read().decode()
# Call the decrypt function in the smart contract
decrypted_data = contract.functions.decrypt(encrypted_data).call()
decrypted_data_set.append(decrypted_data)
#Write the decrypted data to a CSV file
with open("decrypted_data.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerows(decrypted_data_set)
print("Successfully written decrypted data to decrypted_data.csv.")

#Delete the temporary files
shutil.rmtree("temp_folder")
os.remove("data.vhd")
print("Successfully deleted temporary files.")