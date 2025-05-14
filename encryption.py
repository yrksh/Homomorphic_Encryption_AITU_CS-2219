import tenseal as ts
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json

# Generate AES encryption key
def generate_encryption_key():
    return get_random_bytes(16)

# Encrypt data (Galois keys, etc.) using AES
def encrypt_key(key, encryption_key):
    serialized_key = str(key).encode('utf-8')
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(serialized_key)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Main encryption function to encrypt data and save it
def encrypt_and_save():
    input_text = entry.get()
    try:
        input_text = input_text.replace(",", ".")
        values = [float(x.strip()) for x in input_text.split()]

        context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=[60, 40, 40, 60])
        context.global_scale = 2 ** 40
        context.generate_galois_keys()

        encryption_key = generate_encryption_key()
        encrypted_galois_keys = encrypt_key(context.galois_keys(), encryption_key)

        with open("encrypted_data.json", "w") as file:
            json.dump({"encrypted_data": encrypted_galois_keys}, file)

        messagebox.showinfo("Success", "Encrypted data saved to 'encrypted_data.json'")

    except ValueError:
        messagebox.showerror("Invalid input", "Please enter valid comma-separated numbers.")
