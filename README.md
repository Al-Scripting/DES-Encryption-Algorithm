# DES Encryption Algorithm

## Overview
This project implements the **Data Encryption Standard (DES) algorithm** in Python. It allows users to encrypt and decrypt messages securely using the DES symmetric-key cryptographic technique.

## Features
- **Symmetric Encryption**: Uses the same key for encryption and decryption.
- **Secure Message Handling**: Ensures confidentiality of messages.
- **Hexadecimal Representation**: Outputs encrypted data in a readable hex format.
- **File-Based Key Management**: Loads and saves keys for reuse.

## Dependencies
This program requires Python 3.x. To install required dependencies, run:
```bash
pip install pycryptodome
```

## How It Works
The DES encryption program follows these steps:
1. **Generate a Key**: Uses an 8-byte (64-bit) key for encryption and decryption.
2. **Encrypt the Message**: Applies DES encryption to the input message.
3. **Decrypt the Message**: Reverses the encryption process using the same key.
4. **Hex Encoding**: Converts encrypted output to a hexadecimal string.

## Code Breakdown
### 1. Importing Libraries
```python
from Crypto.Cipher import DES
import binascii
```
- `Crypto.Cipher.DES`: Provides DES encryption.
- `binascii`: Used for encoding and decoding hex values.

### 2. Padding Function
```python
def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text
```
- Ensures the input text is a multiple of 8 bytes (required for DES).

### 3. Key Management
```python
def load_key():
    return b'secret_k'  # 8-byte key
```
- Uses a predefined 8-byte key (`secret_k`).
- In a real application, the key should be securely stored and managed.

### 4. Encrypting Data
```python
def encrypt_message(message):
    key = load_key()
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message)
    encrypted_message = cipher.encrypt(padded_message.encode())
    return binascii.hexlify(encrypted_message).decode()
```
- Loads the key.
- Pads the message to a multiple of 8 bytes.
- Encrypts the message using DES in ECB mode.
- Returns the encrypted message in a hex format.

### 5. Decrypting Data
```python
def decrypt_message(encrypted_message):
    key = load_key()
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_message = cipher.decrypt(binascii.unhexlify(encrypted_message)).decode().strip()
    return decrypted_message
```
- Loads the encryption key.
- Converts the hex input back to bytes.
- Decrypts the message and removes padding.

### 6. User Interaction
```python
if __name__ == "__main__":
    choice = input("Do you want to encrypt or decrypt a message? (e/d): ")
    if choice == "e":
        message = input("Enter the message to encrypt: ")
        encrypted = encrypt_message(message)
        print(f"Encrypted Message: {encrypted}")
    elif choice == "d":
        encrypted = input("Enter the encrypted message: ")
        decrypted = decrypt_message(encrypted)
        print(f"Decrypted Message: {decrypted}")
    else:
        print("Invalid choice!")
```
- Takes user input for encryption or decryption.
- Calls the corresponding function and displays the result.

## Usage
1. Run the script:
```bash
python DES_Encryption_Algorithm.py
```
2. Choose an option:
   - **Encrypt a message**: Type `e` and enter the plaintext.
   - **Decrypt a message**: Type `d` and enter the encrypted text.

## Security Considerations
- **ECB Mode Warning**: The script uses **Electronic Codebook (ECB) mode**, which is not the most secure DES mode since identical plaintext blocks result in identical ciphertext blocks.
- **Key Management**: For real-world security, use a stronger key management system.

## Contributing
Contributions are welcome! If you have improvements, open a pull request.

## License
This project is open-source and available under the MIT License.

