import socket
import os

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
from cryptography.hazmat.backends import default_backend

HOST = "0.0.0.0"
PORT = 51820

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
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print(f"Server listening on {HOST}:{PORT}")

server_private_key = X25519PrivateKey.generate()
server_public_key = server_private_key.public_key()
server_public_bytes = server_public_key.public_bytes(
    encoding=Encoding.Raw,
    format=PublicFormat.Raw
)

print(f"Server Public Key: {server_public_bytes.hex()}")

print("Waiting for client public key...")

client_public_bytes, client_address = sock.recvfrom(32)
print(f"Received Client Public Key: {client_public_bytes.hex()}")
print(f"Client Address: {client_address}")

client_public_key = X25519PublicKey.from_public_bytes(client_public_bytes)

sock.sendto(server_public_bytes, client_address)
print(f"Sent Server Public Key to {client_address}")

shared_secret = server_private_key.exchange(client_public_key)
print(f"Shared Secret: {shared_secret.hex()}")

key = derive_key(shared_secret, salt=b'salt')
print(f"Derived Key: {key.hex()}")

cipher = ChaCha20Poly1305(key)
print("Server is ready to encrypt and decrypt messages using the derived key.")

packet, addr = sock.recvfrom(1024)
print(f"Received packet from {addr}: {packet.hex()}")

nonce = packet[:12]
ciphertext = packet[12:]
print(f"Nonce: {nonce.hex()}")
print(f"Ciphertext: {ciphertext.hex()}")

plaintext = cipher.decrypt(nonce, ciphertext, None)
print(f"Decrypted message: {plaintext.decode()}")

response_message = b"Hello, secure client!"
response_nonce = os.urandom(12)
response_ciphertext = cipher.encrypt(response_nonce, response_message, None)
response_packet = response_nonce + response_ciphertext

sock.sendto(response_packet, addr)
print(f"Sent encrypted response to client: {response_message.decode()}")