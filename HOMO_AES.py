import tkinter as tk
from tkinter import messagebox
import tenseal as ts
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# AES FUNCTIONS

def generate_aes_key():
    return get_random_bytes(32)  # AES-256


def aes_encrypt(data_bytes, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')


def aes_decrypt(encrypted_data, key):
    raw = base64.b64decode(encrypted_data)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# HOMOMORPHIC FUNCTIONS

def create_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=16384,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.global_scale = 2 ** 40
    context.generate_galois_keys()
    return context


def encrypt_and_compute(data, context):
    enc_vector = ts.ckks_vector(context, data)
    enc_add = enc_vector + enc_vector
    enc_mul = enc_vector * 3.0
    decrypted_add = enc_add.decrypt()
    decrypted_mul = enc_mul.decrypt()
    return decrypted_add, decrypted_mul


def save_results(add_result, mul_result):
    result = {
        "homomorphic_addition": add_result,
        "homomorphic_multiplication": mul_result
    }
    with open("homomorphic_results.json", "w") as f:
        json.dump(result, f)


def save_encrypted_context(context, aes_key):
    try:
        serialized_context = context.serialize(save_public_key=True, save_secret_key=True, save_galois_keys=True)
        encrypted_context = aes_encrypt(serialized_context, aes_key)
        with open("encrypted_context.json", "w") as f:
            json.dump({"aes_encrypted_context": encrypted_context}, f)
    except Exception as e:
        messagebox.showerror("AES Encryption Error", f"Failed to encrypt context: {str(e)}")


# GUI

def process_input_and_encrypt():
    try:
        input_text = entry.get().replace(",", ".")
        values = [float(x.strip()) for x in input_text.split()]

        # create CKKS context
        context = create_context()

        # perform homomorphic operations
        result_add, result_mul = encrypt_and_compute(values, context)

        # save results to file
        save_results(result_add, result_mul)

        # encrypt and save CKKS context with AES
        aes_key = generate_aes_key()
        save_encrypted_context(context, aes_key)

        # save AES key to file
        with open("aes_key.bin", "wb") as f:
            f.write(aes_key)

        messagebox.showinfo("Success", "Results and AES-encrypted context saved successfully.")

    except ValueError:
        messagebox.showerror("Input Error", "Please enter valid space-separated numbers.")
    except Exception as e:
        messagebox.showerror("Unexpected Error", str(e))


def setup_gui():
    root = tk.Tk()
    root.title("Homomorphic Encryption Tool with AES")

    label = tk.Label(root, text="Enter space-separated numbers (e.g. 1.2 3.4 5.6):")
    label.pack(pady=10)

    global entry
    entry = tk.Entry(root, width=50)
    entry.pack(pady=5)

    encrypt_button = tk.Button(root, text="Encrypt and Compute", command=process_input_and_encrypt)
    encrypt_button.pack(pady=15)

    root.mainloop()



if __name__ == "__main__":
    setup_gui()
