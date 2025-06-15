import os
import base64
import shutil
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Generate a key from password
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt a file
def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    with open(file_path + '.locked', 'wb') as encrypted_file:
        encrypted_file.write(salt + encrypted)

    os.remove(file_path)
    return True

# Decrypt a file
def decrypt_file(encrypted_path, password):
    with open(encrypted_path, 'rb') as encrypted_file:
        content = encrypted_file.read()

    salt = content[:16]
    encrypted = content[16:]

    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)

        # Save the decrypted zip
        original_zip_path = encrypted_path.replace('.locked', '')
        with open(original_zip_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)

        os.remove(encrypted_path)
        return original_zip_path
    except Exception:
        return None

# Zip a folder
def zip_folder(folder_path):
    zip_path = folder_path + '.zip'
    shutil.make_archive(folder_path, 'zip', folder_path)
    shutil.rmtree(folder_path)
    return zip_path

# Unzip a folder
def unzip_folder(zip_path):
    folder_path = zip_path.replace('.zip', '')
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(folder_path)
    os.remove(zip_path)

# GUI functions
def select_file_or_folder():
    choice = filedialog.askopenfilename(title="Select File or Folder")
    if not choice:
        choice = filedialog.askdirectory(title="Or Select Folder")
    entry_path.delete(0, tk.END)
    entry_path.insert(0, choice)

def lock():
    path = entry_path.get()
    password = entry_password.get()

    if not path or not password:
        messagebox.showerror("Error", "Please select a file/folder and enter a password.")
        return

    if os.path.isfile(path):
        encrypt_file(path, password)
        messagebox.showinfo("Success", "File locked successfully!")
    elif os.path.isdir(path):
        zip_path = zip_folder(path)
        encrypt_file(zip_path, password)
        messagebox.showinfo("Success", "Folder locked successfully!")
    else:
        messagebox.showerror("Error", "Invalid path.")

def unlock():
    path = entry_path.get()
    password = entry_password.get()

    if not path.endswith('.locked'):
        messagebox.showerror("Error", "Please select a '.locked' file to unlock.")
        return

    original_zip_path = decrypt_file(path, password)

    if original_zip_path:
        if original_zip_path.endswith('.zip'):
            unzip_folder(original_zip_path)
        messagebox.showinfo("Success", "Unlocked successfully!")
    else:
        messagebox.showerror("Error", "Incorrect password or corrupted file!")

# GUI
root = tk.Tk()
root.title("🔒 File & Folder Locker")
root.geometry("450x350")
root.resizable(False, False)

# Widgets
label_title = tk.Label(root, text="🔒 Secure File & Folder Locker", font=("Arial", 16, "bold"))
label_title.pack(pady=10)

frame = tk.Frame(root)
frame.pack(pady=5)

btn_select = tk.Button(frame, text="Select File/Folder", command=select_file_or_folder)
btn_select.grid(row=0, column=0, padx=5)

entry_path = tk.Entry(frame, width=40)
entry_path.grid(row=0, column=1, padx=5)

label_password = tk.Label(root, text="Enter Password:", font=("Arial", 12))
label_password.pack(pady=10)

entry_password = tk.Entry(root, show="*", width=30)
entry_password.pack()

frame_buttons = tk.Frame(root)
frame_buttons.pack(pady=20)

btn_lock = tk.Button(frame_buttons, text="Lock", command=lock, bg="red", fg="white", width=10)
btn_lock.grid(row=0, column=0, padx=10)

btn_unlock = tk.Button(frame_buttons, text="Unlock", command=unlock, bg="green", fg="white", width=10)
btn_unlock.grid(row=0, column=1, padx=10)

# Run
root.mainloop()
