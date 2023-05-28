import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class ImportDialog(tk.Toplevel):
    def __init__(self, parent, users):
        super().__init__(parent)
        self.users = users
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
        selected_user = self.user_var.get()

        if not selected_user:
            messagebox.showwarning("Warning", "Please select a user.")
            return

        selected_key_type = self.key_type_var.get()

        if not selected_key_type:
            messagebox.showwarning("Warning", "Please select a key type.")
            return

        user = self.users[selected_user]

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
                        messagebox.showinfo("Success", f"{selected_key_type} for {selected_user} imported successfully.")
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