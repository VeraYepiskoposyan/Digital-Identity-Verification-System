import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def verify_credential(data, signature):
    # Load public key
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    message = json.dumps(data, sort_keys=True).encode()

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False