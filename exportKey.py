import tkinter as tk
from tkinter import messagebox, filedialog

from User import User


class ExportDialog(tk.Toplevel):
    def __init__(self, parent, users):
        super().__init__(parent)
        self.users = [user for user in users.values() if user is not None]
        self.title("Export Keys")

        if len(self.users) == 0:
            messagebox.showwarning("Warning", "No users. Please add one.")
            self.destroy()
            return

        self.user_var = tk.StringVar(self)
        self.user_var.set(self.users[0].email)

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
        priv = self.priv
        pub = self.pub

        if not selected_user:
            messagebox.showwarning("Warning", "Please select a user.")
            return

        if not priv and not pub:
            messagebox.showwarning("Warning", "Please select at least one key type.")
            return
        user: User = None
        for u in self.users:
            if u.email == selected_user:
                user = u

        if not user:
            messagebox.showwarning("Warning", "User does not exist")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".pem",
                                                 filetypes=[("PEM Files", "*.pem")],
                                                 initialfile='')
        pem_data = user.export_multiple_keys_to_pem(pub, priv)
        if save_path:
            with open(save_path, "w") as pem_file:
                pem_file.write(pem_data)
                if priv and not pub:
                    selected_key_type = "Private key"
                elif not priv and pub:
                    selected_key_type = "Public key"
                else:
                    selected_key_type = "Private and Public key"
            messagebox.showinfo("Success", f"{selected_key_type} for {selected_user} exported successfully.")

        self.destroy()
