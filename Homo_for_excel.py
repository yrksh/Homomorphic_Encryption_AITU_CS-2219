"""
ckks_aes_demo.py
Compute Pearson correlation between two numeric columns
under CKKS encryption; protect the context with AES‑256.
Edit ONLY the CONFIG section below.
"""

# ── CONFIG ────────────────────────────────────────────────────────────
EXCEL_PATH   = "EXCEL_PATH"          # ← path to your Excel workbook
COLUMN_X     = "COLUMN_X"             # ← first numeric column
COLUMN_Y     = "COLUMN_Y"                # ← second numeric column
POLY_DEGREE  = 16384                  # CKKS parameters
COEFF_SIZES  = [60, 40, 40, 60]
GLOBAL_SCALE = 2 ** 40
AES_KEY_BITS = 256                   # 128 / 192 / 256
# ──────────────────────────────────────────────────────────────────────

import pandas as pd, tenseal as ts, json, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ---------- AES helpers ----------
def generate_aes_key(bits=AES_KEY_BITS):
    return get_random_bytes(bits // 8)

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ct)


# ---------- CKKS helpers ----------
def create_ckks_context():
    ctx = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=POLY_DEGREE,
        coeff_mod_bit_sizes=COEFF_SIZES
    )
    ctx.global_scale = GLOBAL_SCALE
    ctx.generate_galois_keys()
    return ctx

def ckks_correlation(col_x, col_y, ctx):
    n_inv = 1.0 / len(col_x)
    enc_x, enc_y = ts.ckks_vector(ctx, col_x), ts.ckks_vector(ctx, col_y)

    mu_x = (enc_x.sum() * n_inv).decrypt()[0]
    mu_y = (enc_y.sum() * n_inv).decrypt()[0]

    enc_cx = enc_x - mu_x
    enc_cy = enc_y - mu_y

    num   = (enc_cx * enc_cy).sum().decrypt()[0]
    var_x = (enc_cx * enc_cx).sum().decrypt()[0]
    var_y = (enc_cy * enc_cy).sum().decrypt()[0]

    return num / (var_x**0.5 * var_y**0.5)


# ---------- load Excel ----------
df   = pd.read_excel(EXCEL_PATH)
colX = df[COLUMN_X].astype(float).values
colY = df[COLUMN_Y].astype(float).values

# ---------- homomorphic analytics ----------
ctx    = create_ckks_context()
rho    = ckks_correlation(colX, colY, ctx)
print(f"Pearson correlation ({COLUMN_X} vs {COLUMN_Y}): {rho:.4f}")

# ---------- protect context with AES ----------
aes_key = generate_aes_key()
enc_ctx = aes_encrypt(
    ctx.serialize(save_secret_key=True,
                  save_public_key=True,
                  save_galois_keys=True),
    aes_key
)

with open("encrypted_context.json", "w") as f:
    json.dump({"aes_ctx": enc_ctx.decode()}, f)
with open("aes_key.bin", "wb") as f:
    f.write(aes_key)

print("CKKS context encrypted with AES‑256 and saved.")
