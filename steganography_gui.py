import tkinter as tk
from tkinter import filedialog, messagebox
import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from PIL import Image
import logging
import re
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

DELIMITER = "###END###"

# AES Encryption & Decryption
def get_aes_key(password):
    """Ensures AES key is 16, 24, or 32 bytes long."""
    key = password.encode('utf-8')
    return key.ljust(32, b'\0')[:32]  # Pad or trim to 32 bytes for AES-256

def encrypt_data(data, password):
    """Encrypt data using AES-CBC encryption."""
    try:
        key = get_aes_key(password)
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + encrypted_data).decode('utf-8')
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return None

def decrypt_data(encrypted_data, password):
    """Decrypt AES-CBC encrypted data."""
    try:
        key = get_aes_key(password)
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]  # First 16 bytes are the IV
        encrypted_message = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return None

# Function to encode message in image using LSB
def encode_message(image_path, message, password):
    """Hides an encrypted message inside an image using LSB steganography."""
    try:
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError("Image could not be loaded.")

        encrypted_message = encrypt_data(message + DELIMITER, password)
        if not encrypted_message:
            raise ValueError("Encryption failed.")

        binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message)
        binary_message += '00000000' * 5  # Padding to prevent cutoff

        max_bytes = image.shape[0] * image.shape[1] * 3
        if len(binary_message) > max_bytes:
            raise ValueError("Message is too large for the image.")

        data_index = 0
        for row in image:
            for pixel in row:
                for color in range(3):  # R, G, B
                    if data_index < len(binary_message):
                        pixel[color] = (pixel[color] & 0xFE) | int(binary_message[data_index])
                        data_index += 1
                    if data_index >= len(binary_message):
                        break
                if data_index >= len(binary_message):
                    break
            if data_index >= len(binary_message):
                break

        output_path = "encoded_image.png"
        cv2.imwrite(output_path, image)
        logging.info(f"Message successfully encoded in {output_path}.")
        return output_path
    except Exception as e:
        logging.error(f"Encoding failed: {e}")
        return None

# Function to decode message from image
def decode_message(image_path, password):
    """Extracts and decrypts hidden message from an image."""
    try:
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError("Image could not be loaded.")

        binary_message = ''
        for row in image:
            for pixel in row:
                for color in range(3):
                    binary_message += str(pixel[color] & 1)  # Extract LSB

        byte_message = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
        extracted_message = ''.join(chr(int(b, 2)) for b in byte_message).split(DELIMITER)[0]

        if not extracted_message:
            raise ValueError("No valid hidden message found.")

        decrypted_message = decrypt_data(extracted_message, password)
        if not decrypted_message:
            raise ValueError("Decryption failed. Incorrect password?")

        return decrypted_message
    except Exception as e:
        logging.error(f"Decoding failed: {e}")
        return None

# Browse image function
def browse_image(entry_widget):
    """Opens file dialog to select an image and updates entry widget."""
    filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    if filepath:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filepath)

# UI for Encryption
def encrypt_ui():
    encryption_window = tk.Toplevel(root)
    encryption_window.title("Encrypt Image")

    tk.Label(encryption_window, text="Image Path:").pack(pady=5)
    image_entry = tk.Entry(encryption_window, width=40)
    image_entry.pack(pady=5)
    tk.Button(encryption_window, text="Browse", command=lambda: browse_image(image_entry)).pack(pady=5)

    tk.Label(encryption_window, text="Message:").pack(pady=5)
    message_entry = tk.Entry(encryption_window, width=40)
    message_entry.pack(pady=5)

    tk.Label(encryption_window, text="Password:").pack(pady=5)
    password_entry = tk.Entry(encryption_window, width=40, show="*")
    password_entry.pack(pady=5)

    def encrypt_image():
        image_path = image_entry.get()
        message = message_entry.get()
        password = password_entry.get()

        if not image_path or not message or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        encoded_image_path = encode_message(image_path, message, password)
        if encoded_image_path:
            messagebox.showinfo("Success", f"Message encoded in {encoded_image_path}.")
        else:
            messagebox.showerror("Error", "Encoding failed.")

    tk.Button(encryption_window, text="Encrypt & Hide", command=encrypt_image).pack(pady=10)

# UI for Decryption
def decrypt_ui():
    decryption_window = tk.Toplevel(root)
    decryption_window.title("Decrypt Image")

    tk.Label(decryption_window, text="Image Path:").pack(pady=5)
    image_entry = tk.Entry(decryption_window, width=40)
    image_entry.pack(pady=5)
    tk.Button(decryption_window, text="Browse", command=lambda: browse_image(image_entry)).pack(pady=5)

    tk.Label(decryption_window, text="Password:").pack(pady=5)
    password_entry = tk.Entry(decryption_window, width=40, show="*")
    password_entry.pack(pady=5)

    def decrypt_image():
        image_path = image_entry.get()
        password = password_entry.get()

        if not image_path or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        message = decode_message(image_path, password)
        if message:
            messagebox.showinfo("Decoded Message", message)
        else:
            messagebox.showerror("Error", "Decoding failed. Incorrect password or corrupted image.")

    tk.Button(decryption_window, text="Decode Message", command=decrypt_image).pack(pady=10)

# Main Window
root = tk.Tk()
root.title("Image Steganography")

tk.Button(root, text="Encrypt Image", width=20, command=encrypt_ui).pack(pady=10)
tk.Button(root, text="Decrypt Image", width=20, command=decrypt_ui).pack(pady=10)

root.mainloop()
