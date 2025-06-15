from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

# Function to encode text into an image
def encode_text_into_image(image_path, text, output_name):
    img = Image.open(image_path)
    encoded = img.copy()
    width, height = img.size
    index = 0

    binary_text = ''.join([format(ord(i), '08b') for i in text]) + '11111110'  # End marker

    for row in range(height):
        for col in range(width):
            if index < len(binary_text):
                pixel = list(img.getpixel((col, row)))

                for n in range(0, 3):
                    if index < len(binary_text):
                        pixel[n] = pixel[n] & ~1 | int(binary_text[index])
                        index += 1

                encoded.putpixel((col, row), tuple(pixel))

    output_path = '/'.join(image_path.split('/')[:-1]) + '/' + output_name + '.png'
    encoded.save(output_path)
    messagebox.showinfo("Success", f"✅ Text successfully encoded into:\n{output_path}")

# Function to decode text from an image
def decode_text_from_image(image_path):
    img = Image.open(image_path)
    binary_text = ""
    width, height = img.size

    for row in range(height):
        for col in range(width):
            pixel = list(img.getpixel((col, row)))

            for n in range(0, 3):
                binary_text += str(pixel[n] & 1)

    all_bytes = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    decoded_text = ""
    for byte in all_bytes:
        if byte == '11111110':  # End marker
            break
        decoded_text += chr(int(byte, 2))

    return decoded_text

# GUI
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Steganography Tool")
        self.root.geometry("400x300")
        self.mode_var = tk.StringVar(value="encode")

        # Widgets
        self.encode_radio = tk.Radiobutton(root, text="Encode", variable=self.mode_var, value="encode")
        self.encode_radio.pack(pady=5)

        self.decode_radio = tk.Radiobutton(root, text="Decode", variable=self.mode_var, value="decode")
        self.decode_radio.pack(pady=5)

        self.select_button = tk.Button(root, text="Select Image and Process", command=self.select_and_process)
        self.select_button.pack(pady=20)

        self.result_label = tk.Label(root, text="", wraplength=350)
        self.result_label.pack()

        self.quit_button = tk.Button(root, text="Quit", command=root.destroy)
        self.quit_button.pack(pady=10)

    def select_and_process(self):
        mode = self.mode_var.get()
        image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.bmp")])

        if not image_path:
            return

        if mode == "encode":
            secret_text = simpledialog.askstring("Secret Text", "Enter the secret text to encode:")
            output_name = simpledialog.askstring("Output Image Name", "Enter output image name (without extension):")

            if not secret_text or not output_name:
                messagebox.showerror("Error", "Secret text and output image name are required.")
                return

            encode_text_into_image(image_path, secret_text, output_name)

        elif mode == "decode":
            hidden_text = decode_text_from_image(image_path)
            self.result_label.config(text=f"Hidden Text:\n{hidden_text}")
        else:
            messagebox.showerror("Error", "Please select a mode (Encode or Decode).")

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
