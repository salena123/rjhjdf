import os
import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SERVER_IP = "31.76.61.133"
SERVER_PORT = 51820

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    """
    Derives a symmetric key from the shared secret using HKDF.

    :param shared_secret: The shared secret obtained from the key exchange.
    :param salt: A salt value for the key derivation.
    :return: A derived symmetric key (32 bytes).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',
    )
    return hkdf.derive(shared_secret)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

client_private_key = X25519PrivateKey.generate()
client_public_key = client_private_key.public_key()
client_public_bytes = client_public_key.public_bytes(
    encoding=Encoding.Raw,
    format=PublicFormat.Raw
)

print(f"Client Public Key: {client_public_bytes.hex()}")

sock.sendto(client_public_bytes, (SERVER_IP, SERVER_PORT))

server_public_bytes, server_address = sock.recvfrom(32)
print(f"Received Server Public Key: {server_public_bytes.hex()}")
server_public_key = X25519PublicKey.from_public_bytes(server_public_bytes)


shared_secret = client_private_key.exchange(server_public_key)

print(f"Shared Secret: {shared_secret.hex()}")

key = derive_key(shared_secret, salt=b'salt')
print(f"Derived Key: {key.hex()}")

cipher = ChaCha20Poly1305(key)
message = b"Hello, secure world!"
nonce = os.urandom(12)

ciphertext = cipher.encrypt(nonce, message, None)
print(f"Ciphertext: {ciphertext.hex()}")

packet = nonce + ciphertext

sock.sendto(packet, (SERVER_IP, SERVER_PORT))
print(f"Sent encrypted message to server: {message.decode()}")

