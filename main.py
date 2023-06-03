import random
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.backends import default_backend
import re
import os
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from User import User
from exportKey import ExportDialog

# All users

users = {"default": None, }
i = 0


class ImportDialog(tk.Toplevel):
    def __init__(self, parent, users):
        super().__init__(parent)
        self.users = users
        self.users["New User"] = None
        self.title("Import RSA Keys")

        self.user_var = tk.StringVar(self)
        self.user_var.set('default')

        self.key_type_var = tk.StringVar(self)
        self.key_type_var.set('Private Key')

        user_label = tk.Label(self, text="Select User:")
        user_label.pack()

        user_menu = tk.OptionMenu(self, self.user_var, *users)
        user_menu.pack()

        key_type_label = tk.Label(self, text="Select Key Type:")
        key_type_label.pack()

        private_key_button = tk.Radiobutton(self, text="Private Key", variable=self.key_type_var, value="Private Key")
        private_key_button.pack()

        public_key_button = tk.Radiobutton(self, text="Public Key", variable=self.key_type_var, value="Public Key")
        public_key_button.pack()

        import_button = tk.Button(self, text="Import", command=self.import_key)
        import_button.pack()

        self.parent = parent

    def import_key(self):
        global users
        selected_user = self.user_var.get()

        if not selected_user:
            messagebox.showwarning("Warning", "Please select a user.")
            return
        selected_key_type = self.key_type_var.get()

        if not selected_key_type:
            messagebox.showwarning("Warning", "Please select a key type.")
            return

        user = self.users[selected_user]

        if selected_user == 'default':
            key_size = 1024
            name = ''
            password = ''
            while len(name) < 1:
                name = simpledialog.askstring("Name", "Enter your name:")

            email = simpledialog.askstring("Email", "Enter your email:")
            while key_size not in [1024, 2048]:
                if (key_size == None):
                    messagebox.showerror("Exiting, please try again!")
                    return
                key_size = simpledialog.askinteger("Key Size", "Enter key size (1024 or 2048):", minvalue=1024,
                                                   maxvalue=2048)
            while len(password) < 1:
                password = simpledialog.askstring("Password",
                                                  "Enter a password of at least 1 character in length to protect your private key:",
                                                  show="*")
            user = User(name=name, email=email, algorithm='rsa', key_size=key_size, password=password)
            users[email] = user

        file_path = filedialog.askopenfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
        if file_path:
            with open(file_path, "rb") as pem_file:
                pem_data = pem_file.read()

            try:
                if selected_key_type == "Private Key":
                    password = simpledialog.askstring("Password", "Enter the password for the private key:", show="*")
                    private_key = self.load_private_key_with_password(pem_data, password)
                    if private_key is not None:
                        user.set_private_key(private_key)
                        messagebox.showinfo("Success",
                                            f"{selected_key_type} for {selected_user} imported successfully.")
                    else:
                        messagebox.showerror("Error", "Incorrect password or invalid key file.")
                else:
                    public_key = serialization.load_pem_public_key(pem_data)
                    user.set_public_key(public_key)
                    messagebox.showinfo("Success", f"{selected_key_type} for {selected_user} imported successfully.")
            except (ValueError, TypeError) as e:
                messagebox.showerror("Error", "Failed to import key. Invalid file or key format.")

        self.destroy()

    def load_private_key_with_password(self, pem_data, password):
        password_provided = password.encode()
        salt = b'SomeRandomSalt'  # Replace with your own salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Adjust the number of iterations as per your requirement
            backend=default_backend()
        )

        # Derive a key from the provided password and salt
        key = kdf.derive(password_provided)

        try:
            private_key = serialization.load_pem_private_key(pem_data, password=key, backend=default_backend())
            return private_key
        except ValueError:
            return None


# Functions for key generation, import/export, encryption/decryption, and signing/verification
def match_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    else:
        return False


def generate_key_pair():
    global i
    key_size = 1024
    name = 'a' + str(i)
    # email = ""
    # password = ""
    email = f'a{i}@a.com'
    password = '123'
    i = i + 1
    while len(name) < 1:
        name = simpledialog.askstring("Name", "Enter your name:")
    while not match_email_format(email):
        email = simpledialog.askstring("Email", "Enter your email:")
    while key_size not in [1024, 2048]:
        if (key_size == None):
            messagebox.showerror("Exiting, please try again!")
            return
        key_size = simpledialog.askinteger("Key Size", "Enter key size (1024 or 2048):", minvalue=1024, maxvalue=2048)
    while len(password) < 1:
        password = simpledialog.askstring("Password",
                                          "Enter a password of at least 1 character in length to protect your private key:",
                                          show="*")

    users[email] = User(name=name, email=email, algorithm='rsa', key_size=key_size, password=password)

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
    export_dialog = ExportDialog(root, users)
    export_dialog.transient(root)
    export_dialog.grab_set()
    root.wait_window(export_dialog)


def display_private_key_ring():

    root = tk.Tk()
    root.title('Private Keyring')

    tree = ttk.Treeview(root)
    tree["columns"] = ("Timestamp", "Key ID", "Public Key", "Encrypted Private Key", "User ID")

    tree.heading("Timestamp", text="Timestamp")
    tree.heading("Key ID", text="Key ID")
    tree.heading("Public Key", text="Public Key")
    tree.heading("Encrypted Private Key", text="Encrypted Private Key")
    tree.heading("User ID", text="User ID")

    tree["show"] = "headings"
    tree.grid(row=0, column=0, sticky="nsew")

    scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")

    tree.configure(yscrollcommand=scrollbar.set)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    # tree.pack()

    for email, user in users.items():
        if user is not None:
            timestamp = user.timestamp
            key_id = user.key_id
            pem_pub = user.auth_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key = ''.join(map(lambda a: a.decode('utf-8'), pem_pub.splitlines()[1:-1]))
            pem_priv = user.auth_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(user.priv_pass)
            )
            encrypted_private_key = ''.join(map(lambda a: a.decode('utf-8'), pem_priv.splitlines()[1:-1]))

            tree.insert("", tk.END, values=(timestamp, key_id, public_key, encrypted_private_key, email))
    tree.column("Public Key", width=100, anchor="w", stretch=True)
    tree.column("Encrypted Private Key", width=300, anchor="w", stretch=True)
    root.mainloop()

def display_public_key_ring():

    root = tk.Tk()
    root.title('Public Keyring')

    tree = ttk.Treeview(root)
    tree["columns"] = ("Timestamp", "Key ID", "Public Key", "User ID")

    tree.heading("Timestamp", text="Timestamp")
    tree.heading("Key ID", text="Key ID")
    tree.heading("Public Key", text="Public Key")
    tree.heading("User ID", text="User ID")

    tree["show"] = "headings"

    tree.grid(row=0, column=0, sticky="nsew")

    scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")

    tree.configure(yscrollcommand=scrollbar.set)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    for email, user in users.items():
        if user is not None:
            timestamp = user.timestamp
            key_id = user.key_id
            pem_pub = user.auth_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key = ''.join(map(lambda a: a.decode('utf-8'), pem_pub.splitlines()[1:-1]))

            tree.insert("", tk.END, values=(timestamp, key_id, public_key, email))
    tree.column("Public Key", width=100, anchor="w", stretch=True)
    root.mainloop()




def receive_message():
    pass


def send_message(root):
    # New Toplevel window
    new_window = tk.Toplevel(root)

    def cancel_action():
        new_window.destroy()

    # List of receivers
    receivers = list({key: value for key, value in users.items() if value is not None})
    if len(receivers) == 0:
        return

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
if __name__ == '__main__':
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

    display_private_key_ring_button = tk.Button(root, text="Display Private Key Ring", command=display_private_key_ring)
    display_private_key_ring_button.pack()

    display_public_key_ring_button = tk.Button(root, text="Display Public Key Ring", command=display_public_key_ring)
    display_public_key_ring_button.pack()

    send_message_button = tk.Button(root, text="Send Message", command=lambda: send_message(root))
    send_message_button.pack()

    receive_message_button = tk.Button(root, text="Receive Message", command=receive_message)
    receive_message_button.pack()

    root.mainloop()
