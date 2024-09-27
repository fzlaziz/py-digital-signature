import hashlib
import argparse
import os
import shutil
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

def hash_file(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()

    file_hash = hashlib.sha256(file_data).digest()
    return file_hash

def sign_file(file_path, private_key_path):
    file_hash = hash_file(file_path)

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    folder_name = os.path.splitext(os.path.basename(file_path))[0] + "_signed"
    os.makedirs(folder_name, exist_ok=True)

    shutil.copy(file_path, folder_name)

    signature_path = os.path.join(folder_name, "file_signature.sig")
    with open(signature_path, "wb") as sig_file:
        sig_file.write(signature)

    print(f"File has been signed. Original file and signature are saved in the '{folder_name}' folder.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign a file with a private key.")
    parser.add_argument("file_path", help="Path to the file to be signed.")
    parser.add_argument("private_key_path", help="Path to the private key.")

    args = parser.parse_args()

    sign_file(args.file_path, args.private_key_path)
