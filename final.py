import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image
import numpy as np
import base64
import hashlib
from cryptography.fernet import Fernet

# Generate a Fernet-compatible key from the password
def get_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])  # Ensure compatibility with Fernet

# Encrypt text using Fernet
def encrypt_text(text, password):
    key = get_key(password)
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

# Decrypt text using Fernet
def decrypt_text(encrypted_text, password):
    key = get_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_text.encode()).decode()

# Function to encode text into an image
def encode_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.bmp;*.jpg;*.jpeg;*.tiff"), ("All files", "*.*")])
    if not file_path:
        return
    
    img = Image.open(file_path)
    img = img.convert("RGB")
    pixels = np.array(img, dtype=np.uint8)  # Ensure pixel values stay in uint8 range
    
    secret_text = text_entry.get("1.0", tk.END).strip()
    if not secret_text:
        messagebox.showwarning("Warning", "Please enter some text to hide.")
        return
    
    password = simpledialog.askstring("Password", "Enter password for encryption:", show='*')
    if not password:
        messagebox.showwarning("Warning", "Password cannot be empty.")
        return
    
    try:
        encrypted_text = encrypt_text(secret_text, password)
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")
        return
    
    binary_text = ''.join(format(ord(c), '08b') for c in encrypted_text) + '00000000'  # Null terminator
    index = 0
    
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):  # RGB channels
                if index < len(binary_text):
                    pixels[i, j, k] = (int(pixels[i, j, k]) & ~1) | int(binary_text[index])  # Fix OverflowError
                    index += 1
                else:
                    break
    
    encoded_img = Image.fromarray(pixels)
    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        encoded_img.save(save_path)
        messagebox.showinfo("Success", "Text successfully hidden in the image!")

# Function to decode text from an image
def decode_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.bmp;*.jpg;*.jpeg;*.tiff"), ("All files", "*.*")])
    if not file_path:
        return
    
    img = Image.open(file_path)
    img = img.convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    
    binary_text = ""
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                binary_text += str(pixels[i, j, k] & 1)
    
    chars = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    extracted_text = "".join(chr(int(char, 2)) for char in chars if int(char, 2) != 0)
    
    password = simpledialog.askstring("Password", "Enter password for decryption:", show='*')
    if not password:
        messagebox.showwarning("Warning", "Password cannot be empty.")
        return
    
    try:
        decrypted_text = decrypt_text(extracted_text, password)
        messagebox.showinfo("Decryption Successful", f"Decrypted Message:\n{decrypted_text}")
    except Exception:
        messagebox.showerror("Error", "Incorrect password or corrupted data.")
        return
    
    text_entry.delete("1.0", tk.END)
    text_entry.insert(tk.END, decrypted_text)
    messagebox.showinfo("Success", "Text successfully extracted from the image!")

# Create GUI window
root = tk.Tk()
root.title("LSB Image Steganography")
root.geometry("400x300")

frame = tk.Frame(root)
frame.pack(pady=20)

text_entry = tk.Text(frame, width=40, height=5)
text_entry.pack()

btn_encode = tk.Button(frame, text="Encode Text into Image", command=encode_image)
btn_encode.pack(pady=5)

btn_decode = tk.Button(frame, text="Decode Text from Image", command=decode_image)
btn_decode.pack(pady=5)

root.mainloop()
