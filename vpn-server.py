import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# ENCRYPTION_KEY: A shared 16-byte key used for AES-128 encryption and decryption.
ENCRYPTION_KEY = b'ThisIsASecretKey'

# Decrypts the incoming encrypted message.
def decrypt_message(ciphertext):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv=ciphertext[:16])  # Use the first 16 bytes as IV
    decrypted = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)  # Decrypt and unpad
    return decrypted  # Return the plaintext message

# Sets up the server to listen for incoming connections.
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 6000))  # Bind to port 5000
    server_socket.listen(5)  # Listen for incoming connections
    print("VPN server is now listening...")

    while True:
        client_socket, addr = server_socket.accept()  # Accept a new connection
        print(f"Connection from {addr} established.")
        
        encrypted_message = client_socket.recv(1024)  # Receive encrypted message
        if not encrypted_message:
            break
        
        decrypted_message = decrypt_message(encrypted_message)  # Decrypt the message
        print(f"Decrypted message: {decrypted_message.decode()}")  # Print the decrypted message
        
        client_socket.close()  # Close the connection with the client

# Main execution block for the server.
if __name__ == "__main__":
    start_server()  # Start the server
