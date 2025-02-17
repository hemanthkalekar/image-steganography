import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import Fernet
import os

# Function to generate encryption key based on user input
def generate_key(password):
    key = Fernet.generate_key()
    hashed_key = password.ljust(32)[:32].encode()  # Ensure 32-byte key
    return Fernet(key)

# Encrypt message using AES with user key
def encrypt_message(message, password):
    cipher = generate_key(password)
    return cipher.encrypt(message.encode()).decode()

# Decrypt message using AES with user key
def decrypt_message(encrypted_message, password):
    cipher = generate_key(password)
    return cipher.decrypt(encrypted_message.encode()).decode()

# Convert text to binary format
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

# Convert binary to text format
def binary_to_message(binary_data):
    message = ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))
    return message.split("1111111111111110")[0]  # Stop at end marker

# Encode message into image using LSB
def encode_message():
    image_path = "avengersinfinity.jpg"  # Cover image
    message = simpledialog.askstring("Input", "Enter the message to hide:")
    password = simpledialog.askstring("Input", "Enter a security key (password):")

    encrypted_message = encrypt_message(message, password)
    binary_message = message_to_binary(encrypted_message) + '1111111111111110'  # End marker

    image = cv2.imread(image_path)
    img_data = image.flatten()

    data_index = 0
    for i in range(len(img_data)):
        if data_index < len(binary_message):
            img_data[i] = (img_data[i] & ~1) | int(binary_message[data_index])
            data_index += 1
        else:
            break

    encoded_image = img_data.reshape(image.shape)
    output_path = "encoded_image.png"
    cv2.imwrite(output_path, encoded_image)
    messagebox.showinfo("Success", f"Message encoded successfully! Saved as {output_path}")

# Decode message from image
def decode_message():
    image_path = "encoded_image.png"
    password = simpledialog.askstring("Input", "Enter the security key (password):")

    image = cv2.imread(image_path)
    binary_data = ''.join(str(pixel & 1) for pixel in image.flatten())

    try:
        encrypted_message = binary_to_message(binary_data)
        decrypted_message = decrypt_message(encrypted_message, password)
        messagebox.showinfo("Decoded Message", f"Hidden Message: {decrypted_message}")
    except:
        messagebox.showerror("Error", "Incorrect key or corrupted image!")

# GUI Application
root = tk.Tk()
root.title("🔒 Image Steganography - Avengers")

tk.Button(root, text="Encode Message", command=encode_message, width=20, height=2).pack(pady=10)
tk.Button(root, text="Decode Message", command=decode_message, width=20, height=2).pack(pady=10)
tk.Button(root, text="Exit", command=root.quit, width=20, height=2).pack(pady=10)

root.mainloop()
