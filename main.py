import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Key storage
public_keys = {}
private_keys = {}

# Functions for key generation, import/export, encryption/decryption, and signing/verification

def generate_key_pair():
    name = simpledialog.askstring("Name", "Enter your name:")
    email = simpledialog.askstring("Email", "Enter your email:")
    key_size = simpledialog.askinteger("Key Size", "Enter key size (1024 or 2048):", minvalue=1024, maxvalue=2048)
    password = simpledialog.askstring("Password", "Enter a password to protect your private key:", show="*")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_keys[email] = (name, public_pem)
    private_keys[email] = (name, private_pem)

def delete_key_pair():
    email = simpledialog.askstring("Email", "Enter the email associated with the key pair you want to delete:")
    if email in public_keys:
        del public_keys[email]
    if email in private_keys:
        del private_keys[email]

def import_key():
    file_path = filedialog.askopenfilename(title="Select a key file", filetypes=[("PEM files", "*.pem")])
    if not file_path:
        return

    with open(file_path, "rb") as key_file:
        key_data = key_file.read()

    try:
        private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        public_key = private_key.public_key()
        email = simpledialog.askstring("Email", "Enter the email associated with this key pair:")
        name = simpledialog.askstring("Name", "Enter the name associated with this key pair:")
        private_keys[email] = (name, key_data)
        public_keys[email] = (name, public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    except ValueError:
        try:
            public_key = serialization.load_pem_public_key(key_data, backend=default_backend())
            email = simpledialog.askstring("Email", "Enter the email associated with this public key:")
            name = simpledialog.askstring("Name", "Enter the name associated with this public key:")
            public_keys[email] = (name, key_data)
        except ValueError:
            messagebox.showerror("Error", "Invalid key file.")

def export_key():
    email = simpledialog.askstring("Email", "Enter the email associated with the key you want to export:")
    key_type = simpledialog.askstring("Key Type", "Enter 'public' or 'private' for the key type you want to export:")

    if key_type == 'public':
        if email in public_keys:
            name, key_data = public_keys[email]
            file_path = filedialog.asksaveasfilename(title="Save public key", defaultextension=".pem")
            if file_path:
                with open(file_path, "wb") as key_file:
                    key_file.write(key_data)
        else:
            messagebox.showerror("Error", "Public key not found.")
    elif key_type == 'private':
        if email in private_keys:
            name, key_data = private_keys[email]
            file_path = filedialog.asksaveasfilename(title="Save private key", defaultextension=".pem")
            if file_path:
                with open(file_path, "wb") as key_file:
                    key_file.write(key_data)
        else:
            messagebox.showerror("Error", "Private key not found.")
    else:
        messagebox.showerror("Error", "Invalid key type.")

def display_key_ring():
    key_ring = "Public keys:\n"
    for email, (name, key_data) in public_keys.items():
        key_ring += f"{name} <{email}>\n"

    key_ring += "\nPrivate keys:\n"
    for email, (name, key_data) in private_keys.items():
        key_ring += f"{name} <{email}>\n"

    messagebox.showinfo("Key Ring", key_ring)

def send_message():
    messagebox.showinfo("Info", "This function is not implemented in this example.")

def receive_message():
    messagebox.showinfo("Info", "This function is not implemented in this example.")

# GUI layout and elements

root = tk.Tk()
root.title("PGP Email Encryption")

generate_key_button = tk.Button(root, text="Generate Key Pair", command=generate_key_pair)
generate_key_button.pack()

delete_key_button = tk.Button(root, text="Delete Key Pair", command=delete_key_pair)
delete_key_button.pack()

import_key_button = tk.Button(root, text="Import Key", command=import_key)
import_key_button.pack()

export_key_button = tk.Button(root, text="Export Key", command=export_key)
export_key_button.pack()

display_key_ring_button = tk.Button(root, text="Display Key Ring", command=display_key_ring)
display_key_ring_button.pack()

send_message_button = tk.Button(root, text="Send Message", command=send_message)
send_message_button.pack()

receive_message_button = tk.Button(root, text="Receive Message", command=receive_message)
receive_message_button.pack()

root.mainloop()
