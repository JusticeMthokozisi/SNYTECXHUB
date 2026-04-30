import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

SHARED_KEY = b'this_is_a_very_secret_32_byte_key'
aesgcm = AESGCM(SHARED_KEY)

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 5555))

    while True:
        try:
            msg = input("You: ").encode()
            if msg.lower() == b'quit': break

            # Encrypt
            nonce = os.urandom(12)
            encrypted_msg = aesgcm.encrypt(nonce, msg, None)
            
            # Send Nonce + Ciphertext
            client.sendall(nonce + encrypted_msg)

            # Receive response
            data = client.recv(1024)
            nonce_rx = data[:12]
            ciphertext_rx = data[12:]
            decrypted_reply = aesgcm.decrypt(nonce_rx, ciphertext_rx, None)
            
            print(f"Server: {decrypted_reply.decode()}")

        except Exception as e:
            print(f"Error: {e}")
            break

    client.close()

if __name__ == "__main__":
    start_client()