import tkinter as tk
from tkinter import messagebox
import tenseal as ts
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


# generate a key for AES encryption (symmetrical key)
def generate_encryption_key():
    return get_random_bytes(16)  # AES-128 key size


# serialize and encrypt the keys
def encrypt_key(key, encryption_key):
    # serialize the key object (make sure it's in a byte format)
    serialized_key = str(key).encode('utf-8')

    cipher = AES.new(encryption_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(serialized_key)

    # return encrypted data as base64 for storage
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')


# function to handle encryption and saving data
def encrypt_and_save():
    input_text = entry.get()
    try:
        # replace commas with periods and process the input data
        input_text = input_text.replace(",", ".")
        values = [float(x.strip()) for x in input_text.split()]

        # initialize CKKS context
        context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=16384,
            coeff_mod_bit_sizes=[60, 40, 40, 60]
        )
        context.global_scale = 2 ** 40
        context.generate_galois_keys()

        # generate encryption key for AES
        encryption_key = generate_encryption_key()

        # encrypt the Galois keys (serialize before encrypting)
        encrypted_galois_keys = encrypt_key(context.galois_keys(), encryption_key)

        # save encrypted data and keys to JSON
        with open("encrypted_data.json", "w") as file:
            json.dump({"encrypted_data": encrypted_galois_keys}, file)

        messagebox.showinfo("success", "encrypted data saved to 'encrypted_data.json'")

    except ValueError:
        messagebox.showerror("invalid input", "please enter valid comma-separated numbers.")


# --- gui setup ---
root = tk.Tk()
root.title("advanced homomorphic encryption tool")

label = tk.Label(root, text="enter comma-separated numbers (e.g. 1.2, 3.4, 5.6):")
label.pack(pady=10)

entry = tk.Entry(root, width=50)
entry.pack(pady=5)

encrypt_button = tk.Button(root, text="encrypt and save", command=encrypt_and_save)
encrypt_button.pack(pady=15)

root.mainloop()
