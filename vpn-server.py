import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Shared 16-byte key for AES-128 encryption/decryption.
ENCRYPTION_KEY = b'ThisIsASecretKey'

# Decrypts the incoming encrypted message.
def decrypt_message(ciphertext):
    # Create a new AES cipher object using the key and initialization vector (IV).
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv=ciphertext[:16])  
    # Decrypt and remove padding from the message.
    return unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)  

# Sets up the server to listen for incoming connections.
def start_server():
    # Create a TCP socket.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to all interfaces and port 6000.
    server_socket.bind(('0.0.0.0', 6000))
    # Allow up to 5 simultaneous connection requests.
    server_socket.listen(5)
    print("VPN server is now listening...")

    while True:
        # Accept a new client connection.
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr} established.")
        
        # Receive the encrypted message from the client.
        encrypted_message = client_socket.recv(1024)
        if encrypted_message:  # Proceed only if data is received.
            # Decrypt the received message.
            decrypted_message = decrypt_message(encrypted_message)
            # Print the decrypted plaintext message.
            print(f"Decrypted message: {decrypted_message.decode()}")
        
        # Close the connection with the client.
        client_socket.close()

# Entry point for the server application.
if __name__ == "__main__":
    start_server()
