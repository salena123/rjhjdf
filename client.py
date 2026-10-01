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


SERVER_IP = "31.76.61.133"
SERVER_PORT = 51820


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


def make_nonce(sequence: int) -> bytes:
    return b"\x00\x00\x00\x00" + sequence.to_bytes(8, "big")


def encrypt_packet(cipher, sequence: int, data: bytes) -> bytes:
    sequence_bytes = sequence.to_bytes(8, "big")

    nonce = make_nonce(sequence)

    ciphertext = cipher.encrypt(
        nonce,
        data,
        sequence_bytes
    )

    return sequence_bytes + ciphertext


def decrypt_packet(cipher, packet: bytes):
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
# UDP
# ============================================================

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)


# ============================================================
# X25519 ключ клиента
# ============================================================

client_private_key = X25519PrivateKey.generate()

client_public_key = client_private_key.public_key()

client_public_bytes = client_public_key.public_bytes(
    encoding=Encoding.Raw,
    format=PublicFormat.Raw
)

print(
    f"Client Public Key: "
    f"{client_public_bytes.hex()}"
)


# ============================================================
# Отправляем public key
# ============================================================

sock.sendto(
    client_public_bytes,
    (SERVER_IP, SERVER_PORT)
)


# ============================================================
# Получаем public key сервера
# ============================================================

server_public_bytes, server_address = sock.recvfrom(32)

print(
    f"Received Server Public Key: "
    f"{server_public_bytes.hex()}"
)

server_public_key = X25519PublicKey.from_public_bytes(
    server_public_bytes
)


# ============================================================
# Shared secret
# ============================================================

shared_secret = client_private_key.exchange(
    server_public_key
)

print(
    f"Shared Secret: "
    f"{shared_secret.hex()}"
)


# ============================================================
# Два ключа
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


# Клиент отправляет через c2s
send_cipher = ChaCha20Poly1305(c2s_key)

# Клиент получает через s2c
recv_cipher = ChaCha20Poly1305(s2c_key)


# ============================================================
# Отправляем сообщение
# ============================================================

send_sequence = 0

message = b"Hello, secure world!"

packet = encrypt_packet(
    send_cipher,
    send_sequence,
    message
)

sock.sendto(
    packet,
    (SERVER_IP, SERVER_PORT)
)

print(
    f"Sent packet #{send_sequence}: "
    f"{message.decode()}"
)

send_sequence += 1


# ============================================================
# Получаем ответ
# ============================================================

response_packet, address = sock.recvfrom(65535)

sequence, response_plaintext = decrypt_packet(
    recv_cipher,
    response_packet
)

print(
    f"Received packet #{sequence} "
    f"from {address}"
)

print(
    f"Decrypted response: "
    f"{response_plaintext.decode()}"
)


input("Press Enter to exit...")