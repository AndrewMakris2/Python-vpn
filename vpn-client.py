import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pyotp
import qrcode
import getpass
import os
import bcrypt

# ENCRYPTION_KEY is a constant key used by both the client and server for AES-128 encryption and decryption.
ENCRYPTION_KEY = b'ThisIsASecretKey'

# Hashed admin password (hashed only once and saved securely)
ADMIN_USERNAME = "Symphony_User"
ADMIN_PASSWORD_HASH = bcrypt.hashpw(b"Password", bcrypt.gensalt())  # This would be saved securely
print(ADMIN_PASSWORD_HASH)

# Authenticate admin access
def authenticate():
    username = input("Enter admin username: ")
    password = getpass.getpass("Enter admin password: ").encode()
    
    # Verify the entered password against the stored hash
    if username == ADMIN_USERNAME and bcrypt.checkpw(password, ADMIN_PASSWORD_HASH):
        print("Admin access granted.")
    else:
        print("Invalid admin credentials. Access denied.")
        exit()

# Generate a TOTP secret for the user
def generate_totp_secret():
    return pyotp.random_base32()

# Function to save the TOTP secret to a file
def save_totp_secret(secret):
    with open("totp_secret.txt", "w") as file:
        file.write(secret)

# Function to load the TOTP secret from a file
def load_totp_secret():
    if os.path.exists("totp_secret.txt"):
        with open("totp_secret.txt", "r") as file:
            return file.read().strip()
    return None

# Creates a QR code for the TOTP secret if it doesn't already exist
def create_qr_code(totp_uri):
    if not os.path.exists('totp_qr.png'):  # Check if QR code file already exists
        img = qrcode.make(totp_uri)
        img.save('totp_qr.png')  # Save the QR code as an image
        print("QR code saved as 'totp_qr.png'. Scan this with your Microsoft Authenticator app.")
    else:
        print("QR code already exists. Please scan it if you haven't already.")

# Encrypts the message using AES encryption in CBC mode.
def encrypt_message(message):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext  # Return IV + ciphertext

# Connects to the server and sends the encrypted message.
def send_message(message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 6000))  # Connect to the server IP 127.0.0.1 is known as the localhost or loopback address
    encrypted_message = encrypt_message(message)  # Encrypt the message
    client_socket.sendall(encrypted_message)  # Send the encrypted message
    client_socket.close()  # Close the socket connection

# Main execution block for the client.
if __name__ == "__main__":
    # Authenticate admin credentials
    authenticate()

    # Load or generate the TOTP secret
    totp_secret = load_totp_secret()
    if not totp_secret:
        # Generate a new TOTP secret if not already saved
        totp_secret = generate_totp_secret()
        save_totp_secret(totp_secret)
        print(f'Generated new TOTP Secret: {totp_secret}')  # Keep this secure and associate it with the user
        # Create a QR code only the first time
        create_qr_code(pyotp.TOTP(totp_secret).provisioning_uri(name='user@example.com', issuer_name='MyApp'))
    else:
        print("Loaded existing TOTP Secret.")

    # Initialize the TOTP object with the loaded or new secret
    totp = pyotp.TOTP(totp_secret)

    # Prompt for TOTP code
    totp_code = input("Enter the TOTP code from your Authenticator app: ")
    if totp.verify(totp_code):
        print("MFA verified successfully!")
        message = input("Enter the message you want to send: ")  # Prompt for user input
        send_message(message)  # Send the message to the server
    else:
        print("Invalid TOTP code. Access denied.")
