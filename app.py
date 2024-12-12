from flask import Flask, request, jsonify
from c2pa import *
from hashlib import sha256
import boto3
import json
import io

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

app.config.from_prefixed_env()
#kms_key_id = app.config["KMS_KEY_ID"]
cert_chain_path = app.config["CERT_CHAIN_PATH"]

cert_chain = open(cert_chain_path, "rb").read()

session = boto3.Session()

#print("Using KMS key: " + kms_key_id)
print("Using certificate chain: " + cert_chain_path)


@app.route("/attach", methods=["POST"])
def resize():
    request_data = request.get_data()

    manifest = json.dumps({
        "title": "image.jpg",
        "format": "image/jpeg",
        "claim_generator_info": [
            {
                "name": "c2pa test",
                "version": "0.0.1"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.edited",
                            "softwareAgent": {
                                "name": "C2PA Python Example",
                                "version": "0.1.0"
                            }
                        }
                    ]
                }
            }
        ]
    })

    builder = Builder(manifest)

    signer = create_signer(sign, SigningAlg.ES256,
                           cert_chain, "http://timestamp.digicert.com")

    result = io.BytesIO(b"")
    builder.sign(signer, "image/jpeg", io.BytesIO(request_data), result)

    return result.getvalue()


@app.route("/verify", methods=["POST"])
def verify():
    # Retrieve the uploaded file
    signed_file = request.files.get("file")
    if not signed_file:
        return jsonify({"error": "No file uploaded"}), 400

    # Read the signed file content
    content = signed_file.read()

    # Extract data and signature
    # Assuming the last 256 bytes contain the signature
    data, signature = content[:-256], content[-256:]

    # Load the public key
    with open("ps256-public.key", "rb") as pub_file:
        public_key = load_pem_public_key(pub_file.read())

    # Hash the data
    hashed_data = sha256(data).digest()

    try:
        # Verify the signature
        public_key.verify(
            signature,
            hashed_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return jsonify({"message": "Signature is valid."}), 200
    except InvalidSignature:
        return jsonify({"message": "Signature is invalid."}), 400


def sign(data: bytes) -> bytes:
    # Load the private key from the file
    with open("ps256-private.key", "rb") as priv_file:
        private_key = load_pem_private_key(
            priv_file.read(),
            password=None  # Add the password here if the private key is encrypted
        )

    # Hash the data
    hashed_data = sha256(data).digest()

    # Use the private key to sign the hashed data
    signature = private_key.sign(
        hashed_data,
        padding.PKCS1v15(),  # Adjust based on your key configuration
        hashes.SHA256()
    )
    return signature

