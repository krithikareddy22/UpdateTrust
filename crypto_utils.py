import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    )

def sign_bytes(private_pem: bytes, message: bytes) -> str:
    key = serialization.load_pem_private_key(private_pem, password=None)
    return base64.b64encode(key.sign(message)).decode("ascii")

def verify_bytes(public_pem: bytes, message: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        key = serialization.load_pem_public_key(public_pem)
        key.verify(signature, message)
        return True
    except Exception:
        return False
