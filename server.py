import socket

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend


HOST = "0.0.0.0"
PORT = 51820


# ============================================================
# Создание двух ключей из общего X25519 shared secret
# ============================================================

def derive_keys(shared_secret: bytes, salt: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"vpn-session-v1",
        backend=default_backend()
    )

    key_material = hkdf.derive(shared_secret)

    client_to_server_key = key_material[:32]
    server_to_client_key = key_material[32:]

    return client_to_server_key, server_to_client_key


# ============================================================
# Создание nonce
# ChaCha20Poly1305 требует ровно 12 байт
# ============================================================

def make_nonce(sequence: int) -> bytes:
    return b"\x00\x00\x00\x00" + sequence.to_bytes(8, "big")


# ============================================================
# Шифрование пакета
# ============================================================

def encrypt_packet(cipher, sequence: int, data: bytes) -> bytes:
    sequence_bytes = sequence.to_bytes(8, "big")

    nonce = make_nonce(sequence)

    ciphertext = cipher.encrypt(
        nonce,
        data,
        sequence_bytes
    )

    return sequence_bytes + ciphertext


# ============================================================
# Расшифровка пакета
# ============================================================

def decrypt_packet(cipher, packet: bytes):
    # 8 bytes sequence
    # минимум 16 bytes Poly1305 authentication tag
    if len(packet) < 24:
        raise ValueError("Packet is too short")

    sequence_bytes = packet[:8]
    ciphertext = packet[8:]

    sequence = int.from_bytes(
        sequence_bytes,
        "big"
    )

    nonce = make_nonce(sequence)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        sequence_bytes
    )

    return sequence, plaintext


# ============================================================
# UDP socket
# ============================================================

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)

sock.bind((HOST, PORT))

print(f"Server listening on {HOST}:{PORT}")


# ============================================================
# X25519 ключ сервера
# ============================================================

server_private_key = X25519PrivateKey.generate()

server_public_key = server_private_key.public_key()

server_public_bytes = server_public_key.public_bytes(
    encoding=Encoding.Raw,
    format=PublicFormat.Raw
)

print(
    f"Server Public Key: "
    f"{server_public_bytes.hex()}"
)


# ============================================================
# Получаем public key клиента
# ============================================================

print("Waiting for client public key...")

client_public_bytes, client_address = sock.recvfrom(32)

print(
    f"Received Client Public Key: "
    f"{client_public_bytes.hex()}"
)

print(
    f"Client Address: "
    f"{client_address}"
)

client_public_key = X25519PublicKey.from_public_bytes(
    client_public_bytes
)


# ============================================================
# Отправляем public key сервера
# ============================================================

sock.sendto(
    server_public_bytes,
    client_address
)

print(
    f"Sent Server Public Key to "
    f"{client_address}"
)


# ============================================================
# X25519 shared secret
# ============================================================

shared_secret = server_private_key.exchange(
    client_public_key
)

print(
    f"Shared Secret: "
    f"{shared_secret.hex()}"
)


# ============================================================
# Получаем два ключа
# ============================================================

c2s_key, s2c_key = derive_keys(
    shared_secret,
    salt=b"salt"
)

print(
    f"Client -> Server Key: "
    f"{c2s_key.hex()}"
)

print(
    f"Server -> Client Key: "
    f"{s2c_key.hex()}"
)


# Сервер получает через c2s
recv_cipher = ChaCha20Poly1305(c2s_key)

# Сервер отправляет через s2c
send_cipher = ChaCha20Poly1305(s2c_key)

print("Secure session established.")


# ============================================================
# Получаем сообщение клиента
# ============================================================

packet, address = sock.recvfrom(65535)

sequence, plaintext = decrypt_packet(
    recv_cipher,
    packet
)

print(
    f"Received packet #{sequence} "
    f"from {address}"
)

print(
    f"Decrypted message: "
    f"{plaintext.decode()}"
)


# ============================================================
# Отправляем ответ
# ============================================================

send_sequence = 0

response = b"Hello, secure client!"

response_packet = encrypt_packet(
    send_cipher,
    send_sequence,
    response
)

sock.sendto(
    response_packet,
    client_address
)

print(
    f"Sent packet #{send_sequence}: "
    f"{response.decode()}"
)

send_sequence += 1