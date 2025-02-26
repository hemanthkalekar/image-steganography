# LSB Image Steganography with AES Encryption

## Introduction

In the digital age, secure communication is a priority. This project provides a steganography tool that allows users to hide and retrieve secret messages within images using the Least Significant Bit (LSB) technique. To enhance security, it also incorporates AES encryption with password protection, ensuring that only authorized users can decode the hidden messages. With an intuitive Tkinter GUI, this tool makes encryption and decryption accessible for everyone, from security enthusiasts to professionals.


## Project Overview

This project implements image steganography using the Least Significant Bit (LSB) technique, combined with AES encryption (Fernet module) for enhanced security. It provides a user-friendly GUI built with Tkinter that allows users to easily hide and retrieve messages within images using password protection.

## Steganography Principles

Steganography is the practice of concealing information within a non-secret medium to avoid detection. The key principles include:

### Imperceptibility:
The hidden message should not cause noticeable changes in the carrier image.

### Robustness: 
The embedded message should withstand minor alterations (e.g., compression, resizing).

### Security: 
The method should ensure that only authorized users can extract the hidden information.

### Capacity: 
The carrier image should be able to store a significant amount of data without losing quality.

The Least Significant Bit (LSB) method is widely used because it modifies only the lowest bits of pixel values, ensuring minimal visual distortion while embedding data securely.

## Features

- **Secure Message Hiding** : Embed messages within images using LSB steganography.
- **AES Encryption**: Encrypt messages before embedding using password-based AES encryption.
- **Password Protection** :  Prevent unauthorized access with secure password authentication.
- **Compatible Image Formats** : Supports PNG, BMP, JPG, JPEG, and TIFF files
- **User-Friendly GUI** : Intuitive interface for encoding and decoding messages effortlessly.

## Installation & Setup

### Prerequisites
Ensure you have ## Python 3.7+ installed, then install the required dependencies:

```bash
pip install pillow cryptography numpy
```

### Running the Application
1. **Clone the Repository**: Clone this repository to your local machine using the following command:

   ```bash
   git clone https://github.com/hemanthkalekar/image-steganography.git
   ```

2. **Navigate to the Directory**: Move into the project directory:

   ```bash
   cd image-steganography
   ```
   
3. **Run the Script**: Execute the application by running:

   ```bash
   python steganography.py
   ```

## How to use 
- **Encoding a Message into an Image**

    1.Enter the text you want to hide.

    2.Click "Encode Text into Image".

    3.Select an image file.

    4.Enter a password for encryption.

    5.Save the encoded image.

- **Decoding a Message from an Image**
  
   1.Click "Decode Text from Image".

   2.Select the encoded image file.

   3.Enter the password for decryption.

   4.View the extracted message in a popup.
## Conclusion

This project demonstrates the power of steganography and encryption in securing digital communication. By combining LSB-based image steganography with AES encryption, it ensures that hidden messages remain both undetectable and protected. The intuitive GUI makes it accessible for users of all levels, enhancing privacy and security in digital interactions. Future improvements may include support for more image formats, improved encryption methods, and mobile compatibility to expand its usability.

If you encounter any issues, have suggestions, or want to contribute, don't hesitate to open an issue or submit a pull request. Happy coding and steganographing!

**Note**: Remember that while steganography can be fun and educational, it's important to use technology responsibly and ethically. Always respect privacy and legal boundaries when working with hidden information.
