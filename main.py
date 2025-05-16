import tkinter as tk
from tkinter import messagebox
import tenseal as ts
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Constants
AES_KEY_SIZE = 32  # AES-256


def generate_encryption_key():
    return get_random_bytes(AES_KEY_SIZE)


def encrypt_key(key, encryption_key):
    serialized_key = str(key).encode('utf-8')
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(serialized_key)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')


def encrypt_and_save(context, encryption_key, file_name):
    try:
        encrypted_galois_keys = encrypt_key(context.galois_keys(), encryption_key)
        with open(file_name, "w") as file:
            json.dump({"encrypted_data": encrypted_galois_keys}, file)
        messagebox.showinfo("Success", f"Encrypted data saved to '{file_name}'")
    except Exception as e:
        messagebox.showerror("Encryption Error", f"An error occurred: {e}")


def process_input_and_encrypt():
    try:
        input_text = entry.get().replace(",", ".")
        values = [float(x.strip()) for x in input_text.split()]

        context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=16384,
            coeff_mod_bit_sizes=[60, 40, 40, 60]
        )
        context.global_scale = 2 ** 40
        context.generate_galois_keys()

        encryption_key = generate_encryption_key()
        encrypt_and_save(context, encryption_key, "encrypted_data.json")

    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter valid comma-separated numbers.")


def setup_gui():
    root = tk.Tk()
    root.title("Advanced Homomorphic Encryption Tool")

    label = tk.Label(root, text="Enter comma-separated numbers (e.g. 1.2, 3.4, 5.6):")
    label.pack(pady=10)

    global entry
    entry = tk.Entry(root, width=50)
    entry.pack(pady=5)

    encrypt_button = tk.Button(root, text="Encrypt and Save", command=process_input_and_encrypt)
    encrypt_button.pack(pady=15)

    root.mainloop()


if __name__ == "__main__":
    setup_gui()
