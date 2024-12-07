import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.backends import default_backend


# Generate encryption key and initialization vector (IV)
def generate_key():
    key = os.urandom(32)  # 256 bits
    iv = os.urandom(16)   # 128 bits
    return key, iv


# Encrypt file
def encrypt_file(input_file, output_file, key, iv):
    with open(input_file, 'rb') as file:
        data = file.read()

    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt using AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Generate HMAC
    hmac_instance = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_instance.update(encrypted_data)
    mac = hmac_instance.finalize()

    # Save encrypted data to file
    with open(output_file, 'wb') as file:
        file.write(iv + mac + encrypted_data)


# Decrypt file
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        data = file.read()

    iv = data[:16]  # First 16 bytes - IV
    mac = data[16:48]  # Next 32 bytes - HMAC
    encrypted_data = data[48:]  # Remaining data - encrypted content

    # Verify HMAC
    hmac_instance = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_instance.update(encrypted_data)
    try:
        hmac_instance.verify(mac)
    except Exception:
        messagebox.showerror("Error", "HMAC verification failed. File may be corrupted or key is incorrect.")
        return

    # Decrypt the content
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Save decrypted file
    with open(output_file, 'wb') as file:
        file.write(decrypted_data)


# Run the selected operation (encryption or decryption)
def run_encryption_decryption():
    action = action_var.get()

    if action == "Encrypt":
        input_file = filedialog.askopenfilename(title="Select a file to encrypt")
        if input_file:
            output_file = filedialog.asksaveasfilename(title="Save the encrypted file as")
            key, iv = generate_key()
            encrypt_file(input_file, output_file, key, iv)
            messagebox.showinfo("Success", "File encrypted successfully.")
    elif action == "Decrypt":
        input_file = filedialog.askopenfilename(title="Select a file to decrypt")
        if input_file:
            output_file = filedialog.asksaveasfilename(title="Save the decrypted file as")
            key = key_entry.get().encode()  # Key provided by user
            decrypt_file(input_file, output_file, key)
            messagebox.showinfo("Success", "File decrypted successfully.")


# GUI Setup
root = tk.Tk()
root.title("File Encryption and Decryption")

# Radio buttons for selecting operation
action_var = tk.StringVar(value="Encrypt")
encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=action_var, value="Encrypt")
decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=action_var, value="Decrypt")
encrypt_radio.pack()
decrypt_radio.pack()

# Entry field for decryption key
key_label = tk.Label(root, text="Enter decryption key (32 bytes):")
key_label.pack()
key_entry = tk.Entry(root, show="*")
key_entry.pack()

# Run button
run_button = tk.Button(root, text="Run", command=run_encryption_decryption)
run_button.pack()

# Start the application
root.mainloop()
