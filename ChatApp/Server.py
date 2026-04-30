import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


# Use a fixed key for demonstration (32 bytes for AES-256)
# In a real app, use a secure key exchange (like Diffie-Hellman)
SHARED_KEY = b'this_is_a_very_secret_32_byte_key'
aesgcm = AESGCM(SHARED_KEY)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(1)
    print("Server listening on port 5555...")

    conn, addr = server.accept()
    print(f"Connected by {addr}")

    while True:
        try:
            # Receive encrypted data
            data = conn.recv(1024)
            if not data: break

            # AES-GCM requires the nonce to decrypt
            nonce = data[:12]
            ciphertext = data[12:]
            decrypted_msg = aesgcm.decrypt(nonce, ciphertext, None)
            
            print(f"Client: {decrypted_msg.decode()}")

            # Send a response
            reply = input("You: ").encode()
            nonce_reply = os.urandom(12)
            encrypted_reply = aesgcm.encrypt(nonce_reply, reply, None)
            conn.sendall(nonce_reply + encrypted_reply)

        except Exception as e:
            print(f"Error: {e}")
            break

    conn.close()

if __name__ == "__main__":
    start_server()