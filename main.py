import json
import pprint
import re
import textwrap
import time
import tkinter as tk
import warnings
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from User import User
from auth.utils import format_password_for_encryption
from compression.utils import *
from encryption.AES128EncryptorDecryptor import AES128EncryptorDecryptor
from encryption.CAST5EncryptorDecryptor import CAST5EncryptorDecryptor
from exportKey import ExportDialog


users = {}
algs = ['AES', 'CAST']
i = 0


class ImportDialog(tk.Toplevel):
    def __init__(self, parent, users):
        super().__init__(parent)
        self.users = users
        self.users["New User"] = None
        self.title("Import RSA Keys")

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

        if selected_user == 'New User':
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
        key = format_password_for_encryption(password)

        try:
            private_key = serialization.load_pem_private_key(pem_data, password=key, backend=default_backend())
            return private_key
        except ValueError:
            return None


def match_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    else:
        return False


def generate_key_pair():
    new_window = tk.Tk()
    new_window.title("Generate key pair")

    window_width = 300
    window_height = 500

    screen_width = new_window.winfo_screenwidth()
    screen_height = new_window.winfo_screenheight()

    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)

    new_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    def submit():
        name = name_entry.get()
        email = email_entry.get()
        password = password_entry.get()
        algorithm = algorithm_var.get()
        if algorithm=='RSA':
            algorithm='rsa'
        else:
            algorithm='elgamal'

        keysize=keysize_var.get()

        while len(name) < 1:
             name = simpledialog.askstring("Name", "Name can't be empty. Please enter your name.")
        while not match_email_format(email) or users.get(email, None):
             email = simpledialog.askstring("Email", "Enter valid email:")

        while len(password) < 1:
            password = simpledialog.askstring("Password",
                                              "Enter a password of at least 1 character in length to protect your private key:",
                                              show="*")

        users[email] = User(name=name, email=email, algorithm=algorithm, key_size=keysize, password=password)
        print("Name:", name)
        print("Email:", email)
        print("Password:", password)
        print("Algorithm:", algorithm)
        print("keysize:", keysize)
        print(users[email])

    def cancel_action():
        new_window.destroy()

    name_label = ttk.Label(new_window, text="Enter your name: ")
    name_label.pack()
    name_entry = ttk.Entry(new_window)
    name_entry.pack()

    email_label = ttk.Label(new_window, text="Email:")
    email_label.pack()
    email_entry = ttk.Entry(new_window)
    email_entry.pack()

    password_label = ttk.Label(new_window, text="Password:")
    password_label.pack()
    password_entry = ttk.Entry(new_window, show="*")
    password_entry.pack()


    algorithm_label = ttk.Label(new_window, text="Algorithm:")
    algorithm_label.pack()
    algorithm_var = tk.StringVar(new_window)
    algorithm_var.set("RSA")
    algorithm_combobox = ttk.Combobox(new_window, textvariable=algorithm_var, values=["RSA", "DSA+ElGamal"], state="readonly")
    algorithm_combobox.pack()

    keysize_label = ttk.Label(new_window, text="Key size:")
    keysize_label.pack()
    keysize_var = tk.IntVar(new_window)
    keysize_var.set(1024)
    keysize_combobox = ttk.Combobox(new_window, textvariable=keysize_var, values=["1024", "2048"], state="readonly")
    keysize_combobox.pack()

    submit_button = ttk.Button(new_window, text="Submit", command=submit)
    submit_button.pack()

    root.mainloop()


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
    def show_text_preview(text):
        preview_window = tk.Toplevel(root)
        preview_window.title("Text Preview")

        text_preview = tk.Text(preview_window, height=20, width=60)
        text_preview.insert(tk.END, text)
        text_preview.config(state="disabled")
        text_preview.pack()

        preview_window.mainloop()

    def column_click(event):
        column = tree.identify_column(event.x)
        item = tree.identify_row(event.y)
        if item:
            if column == "#3":
                item = tree.identify_row(event.y)
                public_key = tree.item(item)["values"][2]
                show_text_preview(public_key)
            elif column == "#4":
                item = tree.identify_row(event.y)
                encrypted_private_key = tree.item(item)["values"][3]
                show_text_preview(encrypted_private_key)
            elif column == "#7":
                item = tree.identify_row(event.y)
                elgamal_params = tree.item(item)["values"][6]
                show_text_preview(elgamal_params)

    root = tk.Tk()
    root.title('Private Keyring')

    tree = ttk.Treeview(root)
    tree["columns"] = (
    "Timestamp", "Key ID", "Public Key", "Encrypted Private Key", "User ID", "Algorithm", "additional")

    tree.heading("Timestamp", text="Timestamp")
    tree.heading("Key ID", text="Key ID")
    tree.heading("Public Key", text="Public Key")
    tree.heading("Encrypted Private Key", text="Encrypted Private Key")
    tree.heading("User ID", text="User ID")
    tree.heading("Algorithm", text="Algorithm")
    tree.heading("additional", text=" ")

    tree["show"] = "headings"
    tree.grid(row=0, column=0, sticky="nsew")

    scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")

    tree.configure(yscrollcommand=scrollbar.set)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    for email, user in users.items():
        if user is not None:
            timestamp = str(user.timestamp).split(".")[0]
            key_id = user.key_id
            if user.auth_alg == 'rsa':
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
                alg = "RSA"
                elgamal_params = ""
            else:
                pem_pub = user.elGamal.DSAPublic.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_key = ''.join(map(lambda a: a.decode('utf-8'), pem_pub.splitlines()[1:-1]))
                pem_priv = user.elGamal.DSAPrivate.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(user.priv_pass)
                )
                encrypted_private_key = ''.join(map(lambda a: a.decode('utf-8'), pem_priv.splitlines()[1:-1]))

                p = user.elGamal.elGamalPrivate.p
                g = user.elGamal.elGamalPrivate.g
                x = str(user.elGamal.elGamalPrivate.x)
                y = user.elGamal.elGamalPrivate.y
                alg = "DSA+ElGamal"
                elgamal_params = f"p = {p}\ng={g}\nx={x}\ny={y}"

            tree.insert("", tk.END,
                        values=(timestamp, key_id, public_key, encrypted_private_key, email, alg, elgamal_params))

    tree.bind("<Button-1>", column_click)

    tree.column("Public Key", width=200, anchor="w", stretch=True)
    tree.column("Encrypted Private Key", width=200, anchor="w", stretch=True)

    root.mainloop()


def display_public_key_ring():
    def show_text_preview(text):
        preview_window = tk.Toplevel(root)
        preview_window.title("Text Preview")

        text_preview = tk.Text(preview_window, height=20, width=60)
        text_preview.insert(tk.END, text)
        text_preview.config(state="disabled")
        text_preview.pack()

        preview_window.mainloop()

    def column_click(event):
        column = tree.identify_column(event.x)
        item = tree.identify_row(event.y)
        if item:
            if column == "#3":
                item = tree.identify_row(event.y)
                public_key = tree.item(item)["values"][2]
                show_text_preview(public_key)
            elif column == "#6":
                item = tree.identify_row(event.y)
                elgamal_params = tree.item(item)["values"][5]
                show_text_preview(elgamal_params)

    root = tk.Tk()
    root.title('Public Keyring')

    tree = ttk.Treeview(root)
    tree["columns"] = ("Timestamp", "Key ID", "Public Key", "User ID", "Algorithm", "additional")

    tree.heading("Timestamp", text="Timestamp")
    tree.heading("Key ID", text="Key ID")
    tree.heading("Public Key", text="Public Key")
    tree.heading("User ID", text="User ID")
    tree.heading("Algorithm", text="Algorithm")
    tree.heading("additional", text=" ")

    tree["show"] = "headings"
    tree.grid(row=0, column=0, sticky="nsew")

    scrollbar = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")

    tree.configure(yscrollcommand=scrollbar.set)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    for email, user in users.items():
        if user is not None:
            timestamp = str(user.timestamp).split(".")[0]
            key_id = user.key_id
            if user.auth_alg == 'rsa':
                pem_pub = user.auth_pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_key = ''.join(map(lambda a: a.decode('utf-8'), pem_pub.splitlines()[1:-1]))
                alg = "RSA"
                elgamal_params = ""

            else:
                pem_pub = user.elGamal.DSAPublic.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_key = ''.join(map(lambda a: a.decode('utf-8'), pem_pub.splitlines()[1:-1]))
                p = user.elGamal.elGamalPrivate.p
                g = user.elGamal.elGamalPrivate.g
                y = user.elGamal.elGamalPrivate.y
                alg = "DSA+ElGamal"
                elgamal_params = f"p = {p}\ng={g}\ny={y}"
            tree.insert("", tk.END, values=(timestamp, key_id, public_key, email, alg, elgamal_params))

    tree.bind("<Button-1>", column_click)

    tree.column("Public Key", width=100, anchor="w", stretch=True)
    root.mainloop()


def decrypt_with_session(algorithm, message, key, iv):
    if algorithm == algs[0]:
        original = hex2bin(message)
        return AES128EncryptorDecryptor.decrypt(original, iv, key)
    else:
        to_original = hex2bin(message)
        return CAST5EncryptorDecryptor.decrypt(to_original, iv, key)


def decrypt_session(session):
    user = find_user_by_id(session['key_id'])
    password = simpledialog.askstring("Password", "Enter your password: ", show="*")
    if not user.verify_password(password):
        return None
    return {
        "key_id": session['key_id'],
        "key": hex2bin(user.decrypt_private(hex2bin(session['key']))),
        "iv": hex2bin(user.decrypt_private(hex2bin(session['iv'])))
    }


def find_user_by_id(key_id) -> User:
    user = None
    for u in users.values():
        if u.key_id == key_id:
            user = u
            break
    if user is None:
        raise ValueError
    return user


def check_supported_algorithm(key_id, alg):
    user = find_user_by_id(key_id)
    if user.auth_alg == alg:
        return True
    return False


def receive_message():
    file_path = filedialog.askopenfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])

    with open(file_path, "r") as file:
        data = json.load(file)
        if not data['header']:
            messagebox.showwarning("Warning", "invalid message format!")
            return
        data['message'] = json.loads(data['message'])

        header = data['header']
        auth = header['auth']
        encr = header['encr']
        compr = header['compr']
        conver = header['conver']
        auth_alg = header['auth_alg']
        encr_alg = header['encr_alg']

        if conver:
            data = original_data(data['message'])
            data = json.loads(data['message'])
            write_to_json('after_de_conv.json', data)
        else:
            data = data['message']

        if encr:
            session = decrypt_session(data['session'])
            if session is None:
                messagebox.showwarning("Warning", "Incorrect password!")
                return
            supported = check_supported_algorithm(session['key_id'], auth_alg)
            if not supported:
                messagebox.showwarning("Warning", "Unsupported algorithm for this user!")
                return
            data['message'] = decrypt_with_session(encr_alg, data['message'], session['key'], session['iv']).decode(
                "utf-8")
            write_to_json('after_de_encr.json', data)

        if compr:
            data = {
                "session": data['session'],
                "message": decompress_data(data['message'])
            }
            write_to_json('after_de_compr.json', data)

        verified = False
        from_user = "unknown"
        if auth:
            if not isinstance(data['message'], dict):
                data['message'] = json.loads(data['message'])
            msg = data['message']
            if not isinstance(msg['message'], dict):
                msg['message'] = json.loads(msg['message'])
            message = msg['message']
            signature = msg['signature']
            verified = verify_signature(message, signature, auth_alg)
            if verified:
                from_user = find_user_by_id(signature['key_id']).name
            write_to_json('after_de_auth.json', data)

        data = data['message']

        if isinstance(data, str):
            data = json.loads(data)

        show_received_message(data['message'], auth, verified, from_user)


def show_received_message(message, signed, verified, from_person="", ):
    if isinstance(message, str):
        message = json.loads(message)

    time = str((datetime.utcfromtimestamp(message['timestamp']))).split(".")[0]
    popup = tk.Toplevel()

    message_label = tk.Label(popup, text=f"From:{from_person}")
    message_label.pack()

    if signed:
        signed_text = 'Yes'
    else:
        signed_text = 'No'
    signed_label = tk.Label(popup, text=f"Signed: {signed_text}")
    signed_label.pack()

    if verified:
        verified_text = 'Yes'
    else:
        verified_text = 'No'
    verified_label = tk.Label(popup, text=f"Verified: {verified_text}")
    verified_label.pack()

    message_text = tk.Text(popup, height=30, width=100)
    message_text.insert(tk.END, f"Received message:\n"
                                f"{message['message']}\n"
                                f"Time:{time}\n")
    message_text.config(state="disabled")
    message_text.pack()


def send_message(root):
    if not len(users.items()) > 0:
        messagebox.showwarning("Warning", "No users! Please create a user")
        return
    new_window = tk.Toplevel(root)
    window_width = 300
    window_height = 500

    screen_width = new_window.winfo_screenwidth()
    screen_height = new_window.winfo_screenheight()

    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)

    new_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    def cancel_action():
        new_window.destroy()

    senders = list({key: value.auth_priv for key, value in users.items() if value is not None})
    receivers = list({key: value.auth_pub for key, value in users.items() if value is not None})
    if len(receivers) == 0:
        messagebox.showwarning("Warning", "No possible receivers! Please create a user")
        return

    auth_label = tk.Label(new_window, text="Authentication")
    from_label = tk.Label(new_window, text="Sender's private key: ")
    auth_label.pack()
    from_label.pack()

    selected_sender = tk.StringVar(new_window)
    selected_sender.set(receivers[0])  # default value
    sender_menu = tk.OptionMenu(new_window, selected_sender, *senders)
    sender_menu.pack()
    auth_algorithm = users[selected_sender.get()].auth_alg

    password_label = tk.Label(new_window, text="Private key password:")
    password_label.pack()
    password_field = tk.Entry(new_window, show='*')
    password_field.pack()

    auth_label = tk.Label(new_window, text="Encryption")
    auth_label.pack()
    to_label = tk.Label(new_window, text="Receiver's public key: ")
    to_label.pack()
    selected_receiver = tk.StringVar(new_window)
    selected_receiver.set(receivers[0])  # default value
    receiver_menu = tk.OptionMenu(new_window, selected_receiver, *receivers)
    receiver_menu.pack()

    auth_var = tk.BooleanVar()
    encr_var = tk.BooleanVar()
    comp_var = tk.BooleanVar()
    conv_var = tk.BooleanVar()

    auth_check = tk.Checkbutton(new_window, text="Auth", variable=auth_var)
    encr_check = tk.Checkbutton(new_window, text="Encryption", variable=encr_var)
    comp_check = tk.Checkbutton(new_window, text="Compression", variable=comp_var)
    conv_check = tk.Checkbutton(new_window, text="Conversion", variable=conv_var)

    auth_check.pack()
    encr_check.pack()
    comp_check.pack()
    conv_check.pack()

    encr_alg_label = tk.Label(new_window, text="Encryption Algorithm")
    encr_alg_label.pack()
    encr_alg_var = tk.StringVar(new_window)
    encr_alg_var.set(algs[0])  # default value
    encr_alg_menu = tk.OptionMenu(new_window, encr_alg_var, *algs)
    encr_alg_menu.pack()

    input_label = tk.Label(new_window, text="Message: ")
    input_label.pack()
    input_field = tk.Entry(new_window)
    input_field.pack()

    save_button = tk.Button(new_window, text="Save file",
                            command=lambda: save_file(auth_var.get(), encr_var.get(), comp_var.get(), conv_var.get(),
                                                      auth_algorithm, encr_alg_var.get(), input_field.get(),
                                                      selected_sender.get(), selected_receiver.get(),
                                                      password_field.get()))
    cancel_button = tk.Button(new_window, text="Cancel", command=cancel_action)

    save_button.pack()
    cancel_button.pack()


def build_message_and_session(message, alg, receiver: User):
    if alg == algs[0]:
        key_, iv_ = AES128EncryptorDecryptor.generate_iv_and_key()
    elif alg == algs[1]:
        key_, iv_ = CAST5EncryptorDecryptor.generate_iv_and_key()
    else:
        key_, iv_ = b'', b''

    key = receiver.encrypt_public(bin2hex(key_))
    iv = receiver.encrypt_public(bin2hex(iv_))

    session = {
        "key_id": receiver.key_id,
        "key": bin2hex(key),
        "iv": bin2hex(iv)
    }

    message = {
        "timestamp": time.time(),
        "message": message
    }

    return session, message, key_, iv_


def compress_data(to_compress):
    compressed = bin2hex(compress_string(to_compress))
    return compressed


def convert_data(data):
    converted = encode_string(json.dumps(data))
    return converted


def decompress_data(final_message):
    original = hex2bin(final_message)
    string = decompress_string(original)
    return string


def original_data(final_message):
    final_message['message'] = decode_string(final_message['message'])
    return final_message


def verify_signature(message, signature, alg):
    enc_hash = signature['encrypted_hash']
    user = find_user_by_id(signature['key_id'])

    verified = user.verify(message['message'], enc_hash, alg)
    return verified


def encrypt_with_session(message, alg, session):
    key = session["key"]
    iv = session["iv"]
    if alg == algs[0]:
        return bin2hex(AES128EncryptorDecryptor.encrypt(message, iv, key))
    else:
        return bin2hex(CAST5EncryptorDecryptor.encrypt(message, iv, key))


def save_file(auth, encr, comp, conv, auth_alg, encr_alg, message, priv_key_user, pub_key_user, password):
    sender: User = users[priv_key_user]
    password_correct = sender.verify_password(password)
    if not password_correct:
        messagebox.showwarning("Warning", "Incorrect password. Please enter valid password.")
        return

    receiver = users[pub_key_user]

    header = {
        "auth": auth,
        "encr": encr,
        "compr": comp,
        "conver": conv,
        "auth_alg": auth_alg,
        "encr_alg": encr_alg
    }

    session, message, key, iv = build_message_and_session(message, encr_alg, receiver)
    signature = ""

    data = {
        "session": session,
        "message": json.dumps({"signature": signature,
                               "message": message})
    }

    if auth:
        signature = sender.sign_message(message['message'])

        data = {
            "session": session,
            "message": json.dumps({"signature": signature,
                                   "message": message})
        }
        print(json.dumps(data))
        write_to_json('after_auth.json', data)

    if comp:
        data = {
            "session": session,
            "message": compress_data(data['message'])
        }
        print(json.dumps(data))
        write_to_json('after_comp.json', data)

    if encr:
        data['message'] = encrypt_with_session(data['message'], encr_alg, {"key": key, "iv": iv})
        print(json.dumps(data))
        write_to_json('after_encr.json', data)

    if conv:
        data = {
            "message": convert_data(data)
        }
        print(json.dumps(data))
        write_to_json('after_conv.json', data)

    final_message = {
        "header": header,
        "message": json.dumps(data)
    }
    print(json.dumps(final_message))

    file_path = filedialog.asksaveasfilename()
    write_to_json(file_path, final_message)


def write_to_json(file_path, final_message):
    with open(file_path, "w") as new_file:
        json.dump(final_message, new_file)


if __name__ == '__main__':
    root = tk.Tk()
    root.title("PGP Email Encryption")

    window_width = 300
    window_height = 300

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)

    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

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
