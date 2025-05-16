import tkinter as tk
from tkinter import messagebox
import tenseal as ts
import json


# HOMOMORPHIC FUNCTIONS

def create_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=16384,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    context.generate_galois_keys()
    context.global_scale = 2 ** 40
    return context


def encrypt_and_compute(data, context):
    enc_vector = ts.ckks_vector(context, data)

    # encryption
    enc_add = enc_vector + enc_vector
    enc_mul = enc_vector * 3.0

    # decryption
    decrypted_add = enc_add.decrypt()
    decrypted_mul = enc_mul.decrypt()

    return decrypted_add, decrypted_mul


def save_results(data_add, data_mul):
    result = {
        "homomorphic_addition": data_add,
        "homomorphic_multiplication": data_mul
    }
    with open("homomorphic_results.json", "w") as file:
        json.dump(result, file)


# GUI

def process_input_and_encrypt():
    try:
        input_text = entry.get().replace(",", ".")
        values = [float(x.strip()) for x in input_text.split()]

        # create CKKS context
        context = create_context()
        result_add, result_mul = encrypt_and_compute(values, context)

        # save results to file
        save_results(result_add, result_mul)

        # result
        messagebox.showinfo("Success",
                            "Encrypt and Save")
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter valid space-separated numbers.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred:\n{str(e)}")


def setup_gui():
    root = tk.Tk()
    root.title("Homomorphic Encryption Tool (CKKS)")

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
