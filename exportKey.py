import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from auth.utils import format_password_for_encryption


class ExportDialog(tk.Toplevel):
    def __init__(self, parent, users):
        super().__init__(parent)
        self.users = users
        self.title("Export RSA Keys")

        self.user_var = tk.StringVar(self)
        self.user_var.set('New User')

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

        export_button = tk.Button(self, text="Export", command=self.export_key)
        export_button.pack()

        self.parent = parent

    def export_key(self):
        selected_user = self.user_var.get()

        if not selected_user:
            messagebox.showwarning("Warning", "Please select a user.")
            return

        selected_key_type = self.key_type_var.get()

        if not selected_key_type:
            messagebox.showwarning("Warning", "Please select a key type.")
            return

        user = self.users[selected_user]



        if selected_key_type == "Private Key":
            password = simpledialog.askstring("Password",
                                              "Enter a password for your private key:",
                                              show="*")
            if user.get_private_key(password) is not None:
                key = user.get_private_key(password)
                key_name = f"{selected_user}_private_key.pem"

                encrypt_key = format_password_for_encryption(password)

                pem_data = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(encrypt_key)
                )
            else:
                messagebox.showwarning("Warning", "Incorrect password")
                return
        else:
            key = user.get_public_key()
            key_name = f"{selected_user}_public_key.pem"

            pem_data = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )

        save_path = filedialog.asksaveasfilename(defaultextension=".pem",
                                                 filetypes=[("PEM Files", "*.pem")],
                                                 initialfile=key_name)
        if save_path:
            with open(save_path, "wb") as pem_file:
                pem_file.write(pem_data)
            messagebox.showinfo("Success", f"{selected_key_type} for {selected_user} exported successfully.")

        self.destroy()







