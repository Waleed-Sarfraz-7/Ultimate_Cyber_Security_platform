import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import sys

# Function to execute a selected file
def run_selected_script(script_name):
    try:
        script_path = os.path.join(os.getcwd(), script_name)
        if os.path.exists(script_path):
            subprocess.Popen([sys.executable, script_path])
        else:
            messagebox.showerror("Error", f"{script_name} does not exist.")
    except Exception as e:
        messagebox.showerror("Execution Error", f"Error running the script: {str(e)}")

# Main Tkinter UI
app = tk.Tk()
app.title("Main Page - File Selector")
app.geometry("600x400")
app.configure(bg="#E0F7FA")  # Lightest blue background

# Instructions Label (Heading)
instructions_label = tk.Label(
    app,
    text="Select a script to run:",
    font=("Arial", 18, "bold"),
    bg="#E0F7FA",
    fg="black"  # Black heading text
)
instructions_label.pack(pady=20)

# List of available script files
scripts = [
    "FileLocker.py",
    "FiltersProtocol.py",
    "imageencoding.py",
    "network_scanner.py",
    "SendMessageToSelectedIP.py",
    "vpn.py"
]

# Create a button for each script
for script in scripts:
    button = tk.Button(
        app,
        text=script,
        command=lambda script=script: run_selected_script(script),
        width=30,
        bg="#4CAF50",  # Light green button background
        fg="white",    # White text
        activebackground="#76c776",  # Slightly darker green on click
        activeforeground="white",
        font=("Arial", 12, "bold"),
        relief="raised",
        bd=3
    )
    button.pack(pady=8)

# Start the Tkinter loop
app.mainloop()
