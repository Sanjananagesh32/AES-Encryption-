import base64
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ========== AES ENCRYPTION & DECRYPTION FUNCTIONS ========== #
def encrypt_message():
    try:
        key = key_entry.get().encode()
        if len(key) not in [16, 24, 32]:
            messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes long")
            return

        message = text_entry.get("1.0", tk.END).strip().encode()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message, AES.block_size))

        iv = base64.b64encode(cipher.iv).decode()
        ct = base64.b64encode(ct_bytes).decode()

        result_entry.delete("1.0", tk.END)
        result_entry.insert(tk.END, f"IV: {iv}\nCiphertext: {ct}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_message():
    try:
        key = key_entry.get().encode()
        if len(key) not in [16, 24, 32]:
            messagebox.showerror("Error", "Key must be 16, 24, or 32 bytes long")
            return

        lines = result_entry.get("1.0", tk.END).strip().split("\n")
        iv = base64.b64decode(lines[0].split(": ")[1])
        ct = base64.b64decode(lines[1].split(": ")[1])

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)

        text_entry.delete("1.0", tk.END)
        text_entry.insert(tk.END, pt.decode())
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ========== GUI DESIGN ========== #
root = tk.Tk()
root.title("AES Encryption & Decryption")
root.geometry("600x500")
root.config(bg="#FDE2E4")  # pastel pink background

title_label = tk.Label(root, text="🔐 AES Encryption & Decryption Tool", 
                       font=("Arial", 16, "bold"), bg="#FDE2E4", fg="#6D6875")
title_label.pack(pady=10)

# Key input
key_frame = tk.Frame(root, bg="#FDE2E4")
key_frame.pack(pady=5)
tk.Label(key_frame, text="Enter Key (16/24/32 chars):", font=("Arial", 12), bg="#FDE2E4").pack(side=tk.LEFT)
key_entry = tk.Entry(key_frame, width=30, show="*", bg="#CDEAC0")  # pastel green
key_entry.pack(side=tk.LEFT, padx=5)

# Text input
tk.Label(root, text="Enter Text:", font=("Arial", 12), bg="#FDE2E4").pack()
text_entry = tk.Text(root, height=5, width=60, bg="#FFF1E6")  # pastel peach
text_entry.pack(pady=5)

# Buttons
btn_frame = tk.Frame(root, bg="#FDE2E4")
btn_frame.pack(pady=10)

encrypt_btn = tk.Button(btn_frame, text="Encrypt", font=("Arial", 12, "bold"), 
                        bg="#A0E7E5", fg="black", command=encrypt_message)  # pastel cyan
encrypt_btn.pack(side=tk.LEFT, padx=10)

decrypt_btn = tk.Button(btn_frame, text="Decrypt", font=("Arial", 12, "bold"), 
                        bg="#B4F8C8", fg="black", command=decrypt_message)  # pastel mint
decrypt_btn.pack(side=tk.LEFT, padx=10)

# Result box
tk.Label(root, text="Result (IV + Ciphertext):", font=("Arial", 12), bg="#FDE2E4").pack()
result_entry = tk.Text(root, height=7, width=60, bg="#E4C1F9")  # pastel purple
result_entry.pack(pady=5)

root.mainloop()