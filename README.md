⟩ AES Encryption & Decryption Tool (GUI)
This project is a Python-based graphical tool that demonstrates the working of the Advanced Encryption Standard (AES) using the PyCryptodome library. It provides a simple Tkinter interface to perform secure encryption and decryption of messages. The application supports AES key sizes of 128, 192, and 256 bits in CBC mode, with automatic random IV generation for each encryption process.

⟩ Features
» GUI-based encryption and decryption using AES
» Supports 16, 24, or 32-byte keys
» Secure random IV handling
» Easy-to-use interface with real-time results

⟩ Installation
1. Clone the repository:
 
2. Install dependencies:
pip install pycryptodome pillow


⟩ Usage
Run the application with:
» python Aes_Sanjana.py
» Enter a valid AES key (16/24/32 characters).
» Type the message to encrypt.
» Click Encrypt to generate ciphertext.
» Click Decrypt to restore the original text.

⟩ About AES
AES is a symmetric block cipher standardized by NIST, operating on fixed 128-bit blocks. It supports keys of 128, 192, or 256 bits, with 10, 12, or 14 rounds of transformations. Unlike classical ciphers such as Caesar or Vigenère, AES is designed for modern cryptographic security and is resistant to brute-force and frequency analysis attacks.

⟩ References
» NIST AES Standard
» PyCryptodome Documentation
 
