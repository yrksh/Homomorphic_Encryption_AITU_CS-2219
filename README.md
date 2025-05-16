# Homomorphic Encryption Tool with AES Key Management

## Overview

The Homomorphic Encryption Tool with AES Key Management is a secure data processing solution designed to enable computations on encrypted data while preserving privacy. This tool combines advanced homomorphic encryption (using the CKKS scheme from TenSEAL) and AES-256 encryption to protect both sensitive input data and cryptographic keys.

It offers a modular and user-friendly platform suitable for academic research, secure computing demonstrations, and integration into larger systems.

## Features

- **Homomorphic Encryption (CKKS):** Perform secure arithmetic operations (such as addition and multiplication) directly on encrypted floating-point vectors without the need for decryption.
- **AES-256 Encryption for Key Management:** Protect TenSEAL context data (including secret and Galois keys) using AES-256 encryption in EAX mode to ensure secure key storage and transfer.
- **Graphical User Interface (Tkinter):** A clean and intuitive interface for entering data, encrypting it, and securely saving the result.
- **Modular Encryption Logic:** Separated encryption and decryption logic that can be integrated into other projects or systems for secure data processing.
- **Secure Key Handling:** AES-encrypted TenSEAL context enables secure reuse and portability of encrypted computation environments.

## Repository Structure

| File             | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `Homo_main.py`   | Main GUI application for homomorphic encryption (CKKS only).                |
| `HOMO_AES.py`    | Extended GUI version with AES-256 encryption for secure key management.     |
| `encryption.py`  | Contains reusable logic for encrypting data using CKKS.                     |
| `decryption.py`  | Decryption logic for secure environments; not required in most use cases.   |
| `README.md`      | Project documentation.                                                      |
| `LICENSE`        | MIT License file.                                                           |

## How It Works

### Homomorphic Encryption (CKKS)

The CKKS scheme allows arithmetic operations on encrypted vectors of real numbers. This enables secure processing of sensitive data without ever decrypting it. The encryption context includes a public key for encryption, secret key for decryption, and Galois keys for operations like rotation.

### AES Key Management

To protect the encryption context and keys, AES-256 is used to encrypt the serialized TenSEAL context. The AES key is generated using `Crypto.Random` and used in EAX mode to ensure both confidentiality and integrity. This allows safe storage and transfer of keys while maintaining strong security guarantees.

## Installation

Make sure you have Python 3.8 or newer installed.

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/homomorphic-encryption-tool.git
cd homomorphic-encryption-tool
