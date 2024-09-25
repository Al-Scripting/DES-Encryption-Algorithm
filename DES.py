from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding  # For PKCS7 Padding
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
import os


# This function is used to apply PKCS7 padding to the plaintext
def pad(plaintext):
    padder = padding.PKCS7(64).padder()  # Block size is 64 bits (8 bytes)
    padded_data = padder.update(plaintext) + padder.finalize()
    return padded_data

# This function is used to remove PKCS7 padding from the plaintext
def unpad(padded_data):
    unpadder = padding.PKCS7(64).unpadder()  # Block size is 64 bits (8 bytes)
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def encrypt(key, plaintext):
    # Create 3DES Cipher in ECB mode (no IV required)
    cipher = Cipher(TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded plaintext
    padded_plaintext = pad(plaintext)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


def decrypt(key, ciphertext):
    # Create 3DES Cipher in ECB mode (no IV required)
    cipher = Cipher(TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and then unpad the plaintext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext)
    return plaintext

# Function to read a file
def read_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

# Function to write ciphertext to a file in hex format without using a library
def write_file_hex(filename, data):
    with open(filename, 'w') as f:
        f.write(data.hex())  # Manually converting byte data to hex string

# Function to read ciphertext from a file in hex format without using a library
def read_file_hex(filename):
    with open(filename, 'r') as f:
        hex_data = f.read()
        return bytes.fromhex(hex_data)  # Manually converting hex string back to byte data

# Function to write plaintext (after decryption) to a file
def write_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

# Function to validate key size for 3DES (8, 16, or 24 bytes)
def get_valid_key():
    while True:
        key = input("Enter 8, 16, or 24-byte key: ").encode('utf-8')
        if len(key) in [8, 16, 24]:
            return key
        else:
            print(f"Error: Key must be 8, 16, or 24 bytes long. You entered {len(key)} bytes. Please try again.")

# Function to validate file existence
def get_valid_filename(prompt):
    while True:
        filename = input(prompt)
        if os.path.isfile(filename):
            return filename
        else:
            print(f"Error: File '{filename}' not found. Please enter a valid file name.")

# Function to validate mode selection (encryption or decryption)
def get_valid_mode():
    while True:
        mode = input("Do you want to encrypt or decrypt (e/d): ").lower()
        if mode in ['e', 'd']:
            return mode
        else:
            print("Invalid option! Please choose 'e' for encryption or 'd' for decryption.")

# Main function to handle encryption and decryption
def main():
    # Get a valid key
    key = get_valid_key()

    # Get a valid mode (encryption or decryption)
    mode = get_valid_mode()

    if mode == 'e':
        file_name = get_valid_filename("Enter the file name to encrypt (plain.txt): ")
        plaintext = read_file(file_name)
        ciphertext = encrypt(key, plaintext)
        write_file_hex("cipher.txt", ciphertext)
        print("Encryption complete. Ciphertext stored in 'cipher.txt' (hex-encoded).")
    elif mode == 'd':
        file_name = get_valid_filename("Enter the file name to decrypt (cipher.txt): ")
        ciphertext = read_file_hex(file_name)
        plaintext = decrypt(key, ciphertext)
        write_file("decrypted.txt", plaintext)
        print("Decryption complete. Plaintext stored in 'decrypted.txt'.")

if __name__ == "__main__":
    main()
