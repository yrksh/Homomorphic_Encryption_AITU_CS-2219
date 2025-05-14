# Homomorphic Encryption Tool with AES Key Management

## Overview
The **Homomorphic Encryption Tool with AES Key Management** is a secure data processing solution designed to enable computations on encrypted data while preserving privacy. This tool integrates advanced **homomorphic encryption** (specifically the **CKKS scheme**) and **AES encryption** to protect both sensitive data and cryptographic keys. With this tool, you can securely perform operations on encrypted data without exposing it, ensuring that confidentiality and data privacy are maintained at all times.

## Features
- **Homomorphic Encryption (CKKS)**: Perform computations directly on encrypted data without needing to decrypt it, ensuring data privacy and security during processing.
- **AES Encryption for Key Management**: Protect cryptographic keys used in homomorphic encryption with **AES encryption**, ensuring secure key storage and management.
- **User-friendly Graphical Interface**: A simple Tkinter-based GUI for easy interaction with encryption, decryption, and data processing functions.
- **Data Privacy Protection**: Keep sensitive data secure by ensuring that it is never exposed during calculations or while stored.
  
## How It Works
This tool leverages two powerful encryption mechanisms:
- **Homomorphic Encryption (CKKS)**: Allows for secure computations on encrypted data. You can perform necessary calculations on encrypted information without decrypting it, ensuring that no sensitive data is exposed during processing.
- **AES Encryption**: AES is used for encrypting the cryptographic keys that are needed to perform homomorphic encryption. These keys are securely stored and protected with AES, preventing unauthorized access.

## Installation

To use the **Homomorphic Encryption Tool with AES Key Management**, you must have Python installed. Follow these steps to get the tool up and running:

1. Clone the repository:
    ```bash
    git clone https://github.com/YOUR_USERNAME/homomorphic-encryption-tool.git
    cd homomorphic-encryption-tool
    ```

2. Install the required dependencies using **pip**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the tool, simply execute the following command in your terminal:

```bash
python main.py
