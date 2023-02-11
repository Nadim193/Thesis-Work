import os
import hashlib
import csv
import shutil
import json
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
from inspect import getfullargspec
from web3 import Web3

# Connect to Ethereum blockchain network using Web3
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# Check if connected to blockchain network
# if w3.isConnected():
#     print("Connected to Ethereum blockchain network")
# else:
#     print("Not connected to Ethereum blockchain network")

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Read CSV file
data_set = []
csv_file_path = "D:/Thesis Work/DataSet/30-70cancerChdEtcTest.csv"
try:
    if os.path.exists(csv_file_path):
        with open(csv_file_path, "r", encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                data_set.extend(row)
    else:
        raise FileNotFoundError(f"The file at path '{csv_file_path}' does not exist.")
except Exception as e:
    print(f"An error occurred while reading the CSV file: {e}")

# Encrypt the data before storing on the blockchain network
encrypted_data_set = []
try:
    for data in data_set:
        encrypted_data = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_data_set.append(encrypted_data)
except Exception as e:
    print(f"An error occurred while encrypting the data: {e}")
    
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

# Calculate the SHA-256 hash of each encrypted data file
hashes = {}
try:
    with ThreadPoolExecutor(max_workers=5) as executor:
        for index, encrypted_data in enumerate(encrypted_data_set):
            executor.submit(calculate_sha256_hash, encrypted_data, index, hashes)
except Exception as e:
    print(f"An error occurred while calculating the SHA-256 hash of the encrypted data: {e}")

#Store data on Ethereum blockchain network
contract_address = "0x201894777D3E5f0a60E1984CFfC2D5f7d4F806C6" # Replace with the address of your smart contract
contract_abi = [{"constant":False,"inputs":[{"name":"_hash","type":"string"},{"name":"_data","type":"bytes"}],"name":"storeData","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"}]
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def store_data_on_blockchain(data_hash, data):
    try:
        tx_hash = contract.functions.storeData(data_hash, data).transact()
        receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        if receipt['status'] == 1:
            print(f"Data stored on the blockchain network with transaction hash: {tx_hash.hex()}")
        else:
            print("Error: Data not stored on the blockchain network")
    except Exception as e:
        print(f"An error occurred while storing data on the blockchain network: {e}")

try:
    for data_hash, data in zip(hashes.values(), encrypted_data_set):
        store_data_on_blockchain(data_hash, data)
except Exception as e:
    print(f"An error occurred while storing data on the blockchain network: {e}")