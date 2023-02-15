import csv
import os
import chardet
import shutil
import hashlib
import json
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from azure.storage.blob import BlobServiceClient
from concurrent.futures import ThreadPoolExecutor

def load_csv_data(filename):
    data = []
    header = []
    with open(filename, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']
    with open(filename, 'r', encoding=encoding) as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        for row in reader:
            data.extend(row)
    return data , header

def aes_encrypt(key, iv, data_set):
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
    return encrypted_data_set

def aes_decrypt(key, iv,  encrypted_data_set):
    decrypted_data_set = []
    try:
        for encrypted_data in encrypted_data_set:
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(256).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
            decrypted_data_set.append(decrypted_data.decode())
    except Exception as e:
        print(f"An error occurred while decrypting the data: {e}")
    return decrypted_data_set

def rsa_encrypt(public_key, plaintext):
    encrypted_key = public_key.encrypt(
        plaintext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def rsa_decrypt(private_key, encrypted_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def upload_to_azure(encrypted_data_set):
    # Connect to Azure Blob Storage
    connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=XDX90enqsPIO19bfdMTpAWaHlN8w1ZCqUAyDKQ8Re5DQ+nGv8vzzJtBY4m/5jcJcx1+eJRjv9RYO+ASts9EL1g==;EndpointSuffix=core.windows.net"
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)

    # Create a container
    container_name = "storedatausingblockchain8"
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
    
    # Clean up the temporary folder
    try:
        shutil.rmtree(folder_path)
    except Exception as e:
        print(f"An error occurred while deleting the folder: {e}")
    return None

# Download Data From Azue
def download_data():
    # Connect to Azure Blob Storage
    connect_str = "DefaultEndpointsProtocol=https;AccountName=storedatausingblockchain;AccountKey=XDX90enqsPIO19bfdMTpAWaHlN8w1ZCqUAyDKQ8Re5DQ+nGv8vzzJtBY4m/5jcJcx1+eJRjv9RYO+ASts9EL1g==;EndpointSuffix=core.windows.net"
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)

    # Create a container
    container_name = "storedatausingblockchain6"
    try:
        container_client = blob_service_client.create_container(container_name)
    except:
        container_client = blob_service_client.get_container_client(container_name)
    
    # Download the encrypted data
    blob_client = container_client.get_blob_client("EncryptData.json")
    encrypted_data = blob_client.download_blob().readall()

    # Convert the encrypted data to a list
    encrypted_data_str = encrypted_data.decode()
    encrypted_data_dict = json.loads(encrypted_data_str)
    encrypted_data_bytes = bytes(encrypted_data_dict)
    encrypted_data_list = list(encrypted_data_bytes)

    return encrypted_data_list


if __name__ == '__main__':
    start_time3 = time.time()
    # Load data from CSV file
    data, header = load_csv_data('D:/Thesis Work/DataSet/30-70cancerChdEtc.csv')
    
    start_time = time.time()
    
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # AES encryption
    key = os.urandom(32)
    iv = os.urandom(16)
    
    encrypted_data_set = aes_encrypt(key,iv, data)
    
    # RSA encryption
    encrypted_key = rsa_encrypt(public_key, key)
    print("Execution time for encryption:", (time.time() - start_time)/60, "Min")
    
    # Upload To Azure
    upload_to_azure(encrypted_data_set)
    
    #Downoad to Azure
    # encrypted_data_list = download_data()

    start_time2 = time.time()

    # RSA decryption
    decrypted_key = rsa_decrypt(private_key, encrypted_key)
    assert decrypted_key == key, 'Error: decrypted key does not match original key'
    
    # AES decryption
    decrypted_data_set = aes_decrypt(decrypted_key, iv, encrypted_data_set)

    print("Execution time for Decryption:", (time.time() - start_time2)/60, "Min")

    # Print decrypted data
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
    
    print("Execution time:", (time.time() - start_time3)/60, "Min")
        
