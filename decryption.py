from Crypto.Cipher import AES
import base64

# Decrypt AES-encrypted key
def decrypt_key(encrypted_key, encryption_key):
    encrypted_key = base64.b64decode(encrypted_key)
    nonce, tag, ciphertext = encrypted_key[:16], encrypted_key[16:32], encrypted_key[32:]
    cipher = AES.new(encryption_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data.decode('utf-8')  # Assuming original key is a string
