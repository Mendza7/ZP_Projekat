import random
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.backends import default_backend
import re
import os
import base64

from User import User
from exportKey import ExportDialog
from importKey import ImportDialog

#All users

users={"default":None,}
i = 0

# Functions for key generation, import/export, encryption/decryption, and signing/verification
def match_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    else:
        return False
def generate_key_pair():
    global i
    key_size=1024
    name = 'a' + str(i)
    email = f'a{i}@a.com'
    password = 'i'*random.randint(2,10)
    i = i+1
    while len(name)<1:
        name = simpledialog.askstring("Name", "Enter your name:")
    while not match_email_format(email):
        email = simpledialog.askstring("Email", "Enter your email:")
    while key_size not in [1024,2048]:
        if (key_size == None):
            messagebox.showerror("Exiting, please try again!")
            return
        key_size = simpledialog.askinteger("Key Size", "Enter key size (1024 or 2048):", minvalue=1024, maxvalue=2048)
    while len(password)<1:
        password = simpledialog.askstring("Password", "Enter a password of at least 1 character in length to protect your private key:", show="*")

    users[email] = User(name=name,email=email,algorithm='rsa',key_size=key_size,password=password)

    print(users)

def delete_key_pair():
    email = simpledialog.askstring("Email", "Enter the email associated with the key pair you want to delete:")
    if email in users:
        del users[email]

def open_import_dialog():
    import_dialog = ImportDialog(root, users)
    import_dialog.transient(root)
    import_dialog.grab_set()
    root.wait_window(import_dialog)
def open_export_dialog():
    export_dialog = ExportDialog(root,users)
    export_dialog.transient(root)
    export_dialog.grab_set()
    root.wait_window(export_dialog)

def display_key_ring():
   pass

def send_message():
    pass
def receive_message():
    pass
def create_new_window(root):

    # New Toplevel window
    new_window = tk.Toplevel(root)

    def cancel_action():
        new_window.destroy()

    # List of receivers
    receivers = ['Person 1', 'Person 2', 'Person 3']

    # Create from and to selection
    from_label = tk.Label(new_window, text="From:")
    from_label.pack()
    from_var = tk.StringVar(new_window)
    from_var.set(receivers[0])  # default value
    from_menu = tk.OptionMenu(new_window, from_var, *receivers)
    from_menu.pack()

    to_label = tk.Label(new_window, text="To:")
    to_label.pack()
    to_var = tk.StringVar(new_window)
    to_var.set(receivers[0])  # default value
    to_menu = tk.OptionMenu(new_window, to_var, *receivers)
    to_menu.pack()

    # Input text field
    input_field = tk.Entry(new_window)
    input_field.pack()

    # Checkboxes
    auth_var = tk.IntVar()
    encr_var = tk.IntVar()
    comp_var = tk.IntVar()
    conv_var = tk.IntVar()

    auth_check = tk.Checkbutton(new_window, text="Auth", variable=auth_var)
    encr_check = tk.Checkbutton(new_window, text="Encryption", variable=encr_var)
    comp_check = tk.Checkbutton(new_window, text="Compression", variable=comp_var)
    conv_check = tk.Checkbutton(new_window, text="Conversion", variable=conv_var)

    auth_check.pack()
    encr_check.pack()
    comp_check.pack()
    conv_check.pack()

    # Password input field
    password_label = tk.Label(new_window, text="Private key password:")
    password_label.pack()
    password_field = tk.Entry(new_window, show='*')  # hides input
    password_field.pack()

    # Buttons for save and cancel
    save_button = tk.Button(new_window, text="Save output", command=save_file)
    cancel_button = tk.Button(new_window, text="Cancel", command=cancel_action)

    save_button.pack()
    cancel_button.pack()

def save_file():
    file_path = filedialog.asksaveasfilename()
    print("Saving to:", file_path)  # replace with actual saving logic




# GUI layout and elements

root = tk.Tk()
root.title("PGP Email Encryption")

generate_key_button = tk.Button(root, text="Generate Key Pair", command=generate_key_pair)
generate_key_button.pack()

delete_key_button = tk.Button(root, text="Delete Key Pair", command=delete_key_pair)
delete_key_button.pack()

import_key_button = tk.Button(root, text="Import Key", command=open_import_dialog)
import_key_button.pack()

export_key_button = tk.Button(root, text="Export Key", command=open_export_dialog)
export_key_button.pack()

display_key_ring_button = tk.Button(root, text="Display Key Ring", command=display_key_ring)
display_key_ring_button.pack()

send_message_button = tk.Button(root, text="Send Message", command=lambda:create_new_window(root))
send_message_button.pack()

receive_message_button = tk.Button(root, text="Receive Message", command=receive_message)
receive_message_button.pack()

root.mainloop()
