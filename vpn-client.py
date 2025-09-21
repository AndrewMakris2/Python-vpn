import os
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pyotp
import qrcode
import bcrypt
import tkinter as tk
from tkinter import messagebox

# ENCRYPTION_KEY is a constant key used by both the client and server for AES-128 encryption and decryption.
ENCRYPTION_KEY = b'ThisIsASecretKey'

# Hashed admin password (hashed only once and saved securely)
ADMIN_USERNAME = "Symphony_User"  
ADMIN_PASSWORD_HASH = bcrypt.hashpw(b"Password", bcrypt.gensalt())  
print(ADMIN_PASSWORD_HASH)
# Function to authenticate the admin access
def authenticate(username, password):
    if username == ADMIN_USERNAME and bcrypt.checkpw(password.encode(), ADMIN_PASSWORD_HASH):  
        return True  
    return False  

# Function to generate a TOTP secret for the user
def generate_totp_secret():
    return pyotp.random_base32()

# Function to save the generated TOTP secret to a file
def save_totp_secret(secret):
    with open("totp_secret.txt", "w") as file:
        file.write(secret)

# Function to load the TOTP secret from the file
def load_totp_secret():
    if os.path.exists("totp_secret.txt"):
        with open("totp_secret.txt", "r") as file:
            return file.read().strip()
    return None

# Function to create a QR code for the TOTP secret
def create_qr_code(totp_uri):
    if not os.path.exists('totp_qr.png'):
        img = qrcode.make(totp_uri)
        img.save('totp_qr.png')
        print("QR code saved.")
    else:
        print("QR code already exists.")

# Function to encrypt a message using AES encryption in CBC mode
def encrypt_message(message):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Function to connect to the server and send the encrypted message
def send_message(server_ip, server_port, message):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    encrypted_message = encrypt_message(message)
    client_socket.sendall(encrypted_message)
    client_socket.close()

# Function to handle form submission when the user clicks the Submit button in the GUI
def on_submit():
    # Get the values from the Tkinter entry widgets (inputs)
    username = entry_username.get()  # Get the entered username
    password = entry_password.get()  # Get the entered password
    totp_code = entry_totp.get()  # Get the entered TOTP code
    server_ip = entry_server_ip.get()  # Get the server IP entered
    server_port = entry_server_port.get()  # Get the server port entered
    message = entry_message.get()  # Get the message to send entered

    # Authenticate admin credentials
    if not authenticate(username, password):  # Check if the username and password are valid
        messagebox.showerror("Authentication Failed", "Invalid username or password!")  # Show an error message if authentication fails
        return

    # Load or generate the TOTP secret
    totp_secret = load_totp_secret()  # Try to load the TOTP secret from a file
    if not totp_secret:  # If no secret is found
        # Generate a new TOTP secret if not already saved
        totp_secret = generate_totp_secret()
        save_totp_secret(totp_secret)  # Save the generated secret
        print(f'Generated new TOTP Secret: {totp_secret}')  # Print the generated secret (only for testing/debugging)
        # Create a QR code only the first time
        create_qr_code(pyotp.TOTP(totp_secret).provisioning_uri(name='user@example.com', issuer_name='MyApp'))  # Generate and create QR code

    totp = pyotp.TOTP(totp_secret)  # Create a TOTP object for generating one-time passcodes

    # Verify TOTP code
    if not totp.verify(totp_code):  # Verify if the entered TOTP code is correct
        messagebox.showerror("Authentication Failed", "Invalid TOTP code!")  # Show an error if TOTP verification fails
        return

    # Send the message to the server
    send_message(server_ip, int(server_port), message)  # Send the encrypted message to the server
    messagebox.showinfo("Success", "Message sent successfully!")  # Show a success message once the message is sent

# GUI Setup
root = tk.Tk()
root.title("VPN Client")

tk.Label(root, text="Admin Username:").grid(row=0, column=0)
entry_username = tk.Entry(root)
entry_username.grid(row=0, column=1)

tk.Label(root, text="Admin Password:").grid(row=1, column=0)
entry_password = tk.Entry(root, show="*")
entry_password.grid(row=1, column=1)

tk.Label(root, text="TOTP Code:").grid(row=2, column=0)
entry_totp = tk.Entry(root)
entry_totp.grid(row=2, column=1)

tk.Label(root, text="Server IP:").grid(row=3, column=0)
entry_server_ip = tk.Entry(root)
entry_server_ip.grid(row=3, column=1)

tk.Label(root, text="Server Port:").grid(row=4, column=0)
entry_server_port = tk.Entry(root)
entry_server_port.grid(row=4, column=1)

tk.Label(root, text="Message to Send:").grid(row=5, column=0)
entry_message = tk.Entry(root)
entry_message.grid(row=5, column=1)

submit_button = tk.Button(root, text="Submit", command=on_submit)
submit_button.grid(row=6, column=0, columnspan=2)

root.mainloop()
