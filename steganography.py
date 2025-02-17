import cv2
import os
import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet

# Function to generate encryption key based on user input
def generate_key(password):
    key = Fernet.generate_key()
    return Fernet(key)

# Encrypt message using AES with user key
def encrypt_message(message, password):
    cipher = generate_key(password)
    return cipher.encrypt(message.encode()).decode()

# Convert text to binary format
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

# Convert binary to text format
def binary_to_message(binary_data):
    try:
        message = ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))
        return message.split("1111111111111110")[0]  # Stop at end marker
    except Exception as e:
        print(f"Binary to message error: {e}")
        return None

# Encode message into image using LSB
def encode_message():
    image_path = "avengersinfinity.jpg"  # Hardcoded image path for encoding
    print(f"Attempting to load image from: {image_path}")
    
    # Check if the image file exists
    if not os.path.exists(image_path):
        messagebox.showerror("Error", f"Image file not found: {image_path}")
        return

    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", f"Failed to load image: {image_path}")
        return

    message = simpledialog.askstring("Input", "Enter the message to hide:")
    password = simpledialog.askstring("Input", "Enter a security key (password):")

    encrypted_message = encrypt_message(message, password)
    binary_message = message_to_binary(encrypted_message) + '1111111111111110'  # End marker

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

    # Check if the image was saved
    if os.path.exists(output_path):
        messagebox.showinfo("Success", f"Message encoded successfully! Saved as {output_path}")
    else:
        messagebox.showerror("Error", "Failed to save the encoded image.")

# Decode message from image
def decode_message():
    # Check if the encoded image exists
    if not os.path.exists("encoded_image.png"):
        messagebox.showerror("Error", "Encoded image not found. Please encode a message first.")
        return

    image_path = "encoded_image.png"  # Hardcoded encoded image path for decoding
    print(f"Attempting to load image from: {image_path}")
    
    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", f"Failed to load image: {image_path}")
        return

    binary_data = ''.join(str(pixel & 1) for pixel in image.flatten())
    if len(binary_data) == 0:
        messagebox.showerror("Error", "No data found in image!")
        return

    print(f"Binary Data Length: {len(binary_data)}")  # Debugging line

    encrypted_message = binary_to_message(binary_data)
    if encrypted_message is None:
        messagebox.showerror("Error", "Error decoding the binary data!")
        return

    password = simpledialog.askstring("Input", "Enter the security key (password):")
    decrypted_message = decrypt_message(encrypted_message, password)
    if decrypted_message is None:
        messagebox.showerror("Error", "Incorrect password or decryption error!")
    else:
        messagebox.showinfo("Decoded Message", f"Hidden Message: {decrypted_message}")

# Decrypt message using AES with user key
def decrypt_message(encrypted_message, password):
    cipher = generate_key(password)
    try:
        return cipher.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# GUI Application
root = tk.Tk()
root.title("🔒 Image Steganography - Avengers")

# Debugging: Check current working directory
print(f"Current Working Directory: {os.getcwd()}")

tk.Button(root, text="Encode Message", command=encode_message, width=20, height=2).pack(pady=10)
tk.Button(root, text="Decode Message", command=decode_message, width=20, height=2).pack(pady=10)
tk.Button(root, text="Exit", command=root.quit, width=20, height=2).pack(pady=10)

root.mainloop()
