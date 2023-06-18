import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

from cryptography.hazmat.primitives import serialization

from auth.utils import format_password_for_encryption


class ExportDialog(tk.Toplevel):
    def __init__(self, parent, users):
        super().__init__(parent)
        self.users = users
        self.title("Export RSA Keys")

        if len(users) == 0:
            messagebox.showwarning("Warning", "No users. Please add one.")
            return

        self.user_var = tk.StringVar(self)
        self.user_var.set(users[0].email)

        user_label = tk.Label(self, text="Select User:")
        user_label.pack()

        user_menu = tk.OptionMenu(self, self.user_var, *users)
        user_menu.pack()

        key_type_label = tk.Label(self, text="Select Key Type:")
        key_type_label.pack()

        priv_var = tk.BooleanVar()
        pub_var = tk.BooleanVar()

        priv_check = tk.Checkbutton(self, text="Private key", variable=priv_var)
        pub_check = tk.Checkbutton(self, text="Public key", variable=pub_var)
        priv_check.pack()
        pub_check.pack()
        self.priv = priv_var
        self.pub = pub_var

        export_button = tk.Button(self, text="Export", command=self.export_key)
        export_button.pack()

        self.parent = parent

    def export_key(self):
        selected_user = self.user_var.get()
        priv=self.priv
        pub=self.pub

        if not selected_user:
            messagebox.showwarning("Warning", "Please select a user.")
            return

        if not priv and not pub:
            messagebox.showwarning("Warning", "Please select at least one key type.")
            return

        user = self.users[selected_user]

        if priv and not pub:
            password = simpledialog.askstring("Password",
                                              "Enter a password for your private key:",
                                              show="*")
            if user.get_private_key(password) is not None:
                key = user.get_private_key(password)
                key_name = f"{selected_user}_private_key.pem"

                encrypt_key = format_password_for_encryption(password.encode())

                pem_data = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(encrypt_key)
                )
            else:
                messagebox.showwarning("Warning", "Incorrect password or no Private key found for this user.")
                return
        elif pub and not priv:
            key = user.get_public_key()
            key_name = f"{selected_user}_public_key.pem"

            pem_data = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )
        else:
            password = simpledialog.askstring("Password",
                                              "Enter a password for your private key:",
                                              show="*")
            public_key = user.get_public_key()
            private_key=user.get_private_key(password)
            key_name = f"{selected_user}_private+public_key.pem"
            # pem_data = selected_user.export_rsa_private_key_to_pem()+selected_user.export_rsa_public_key_to_pem()
            pem_data="" #TODO

        save_path = filedialog.asksaveasfilename(defaultextension=".pem",
                                                 filetypes=[("PEM Files", "*.pem")],
                                                 initialfile=key_name)
        if save_path:
            with open(save_path, "wb") as pem_file:
                pem_file.write(pem_data)
                if priv and not pub:
                    selected_key_type="Private key"
                elif not priv and pub:
                    selected_key_type = "Public key"
                else:
                    selected_key_type = "Private and Public key"
            messagebox.showinfo("Success", f"{selected_key_type} for {selected_user} exported successfully.")

        self.destroy()
