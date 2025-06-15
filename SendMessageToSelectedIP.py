import socket
import os
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox

# Secret key
SECRET_KEY = b'hyry2jmYjNc6x7Nf-bTUK8EXSvxpO6coXS61OxBjbhQ='
fernet = Fernet(SECRET_KEY)

# Function to connect and send message or file
def connect_and_send(choice):
    target_ip = ip_entry.get().strip()
    target_port = port_entry.get().strip()

    if not target_ip or not target_port:
        messagebox.showwarning("Warning", "Please enter IP and Port!")
        return
    
    try:
        target_port = int(target_port)
    except ValueError:
        messagebox.showerror("Error", "Port must be an integer.")
        return

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((target_ip, target_port))
        print(f"Connected to {target_ip}:{target_port}")
        
        if choice == "message":
            message = message_entry.get("1.0", tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Message cannot be empty!")
                return
            client_socket.sendall(b"MSG")
            encrypted_message = fernet.encrypt(message.encode())
            client_socket.sendall(encrypted_message)
            messagebox.showinfo("Success", "Encrypted message sent successfully!")
        
        elif choice == "file":
            filepath = filedialog.askopenfilename()
            if not filepath:
                return

            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)

            client_socket.sendall(b"FILE")
            client_socket.sendall(filename.encode() + b'\n')
            client_socket.sendall(str(filesize).encode() + b'\n')

            with open(filepath, "rb") as f:
                while True:
                    bytes_read = f.read(1024)
                    if not bytes_read:
                        break
                    encrypted_data = fernet.encrypt(bytes_read)
                    client_socket.sendall(encrypted_data)
            messagebox.showinfo("Success", f"✅ Encrypted file '{filename}' sent successfully!")

    except Exception as e:
        messagebox.showerror("Error", f"❗ {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

# ===================== UI Setup =====================
root = tk.Tk()
root.title("Real-time Client Messenger")
root.geometry("600x400")
root.configure(bg="#e6f7ff")  # Light blue background

# Heading
heading = tk.Label(root, text="Real-time Secure Client", font=("Arial", 20, "bold"), bg="#e6f7ff", fg="black")
heading.pack(pady=10)

# Frame for Inputs
input_frame = tk.Frame(root, bg="#e6f7ff")
input_frame.pack(pady=10)

# IP Entry
tk.Label(input_frame, text="Target IP:", font=("Arial", 12), bg="#e6f7ff").grid(row=0, column=0, sticky="e", padx=5, pady=5)
ip_entry = tk.Entry(input_frame, width=30)
ip_entry.grid(row=0, column=1, pady=5)

# Port Entry
tk.Label(input_frame, text="Target Port:", font=("Arial", 12), bg="#e6f7ff").grid(row=1, column=0, sticky="e", padx=5, pady=5)
port_entry = tk.Entry(input_frame, width=30)
port_entry.grid(row=1, column=1, pady=5)
port_entry.insert(0, "12345")  # Default port

# Message Entry
tk.Label(root, text="Message:", font=("Arial", 12), bg="#e6f7ff").pack()
message_entry = tk.Text(root, height=4, width=50)
message_entry.pack(pady=5)

# Button Frame
button_frame = tk.Frame(root, bg="#e6f7ff")
button_frame.pack(pady=10)

# Send Message Button
send_msg_button = tk.Button(button_frame, text="Send Message", width=20, bg="#4CAF50", fg="white",
                            font=("Arial", 12, "bold"), command=lambda: connect_and_send("message"), bd=0)
send_msg_button.grid(row=0, column=0, padx=10)

# Send File Button
send_file_button = tk.Button(button_frame, text="Send File", width=20, bg="#4CAF50", fg="white",
                             font=("Arial", 12, "bold"), command=lambda: connect_and_send("file"), bd=0)
send_file_button.grid(row=0, column=1, padx=10)

# Quit Button
quit_button = tk.Button(root, text="Quit", width=20, bg="#4CAF50", fg="white",
                        font=("Arial", 12, "bold"), command=root.destroy, bd=0)
quit_button.pack(pady=20)

root.mainloop()
