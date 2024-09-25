import hashlib
import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


def hash_file(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()

    file_hash = hashlib.sha256(file_data).digest()
    return file_hash


def verify_file_signature(file_path, signature_path, public_key_path):
    file_hash = hash_file(file_path)

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Digital signature is not valid. This is the original File that has been signed.")
    except Exception as e:
        print("Digital Signature is not valid. Either the file or the signature is not matched or changed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify the signature of a signed PDF file.")
    parser.add_argument("file_path", help="Path to the PDF file to be verified.")
    parser.add_argument("signature_path", help="Path to the signature file.")
    parser.add_argument("public_key_path", help="Path to the public key file.")

    args = parser.parse_args()

    verify_file_signature(args.file_path, args.signature_path, args.public_key_path)
