💡 Overview 💡
This project simulates the encryption process to ensure text data confidentiality. It transforms readable text into a secure, protected format using Python code.


🛠 Technical Features

Encryption Algorithm: Uses AES-256 in CBC (Cipher Block Chaining) mode for high security.



Key Derivation: Implements SHA-256 to hash user passwords into a secure 32-byte key.


Padding Mechanism: Employs custom PKCS7-style padding to handle data that doesn't fit the 16-byte block size.


Data Encoding: Utilizes Base64 encoding for the final output to ensure file portability and safe storage.



Integrity Check: Includes a custom "AES" header in the encrypted file to verify the format before decryption.


🚀 How to Use
The tool is executed via the command line and requires the pycryptodome library.

1. Encrypt a file:
Bash
python AES_1.py enc input.txt output.bin
The program will securely prompt you for a password.


2. Decrypt a file:
Bash
python AES_1.py dec output.bin decrypted_output.txt
Enter the same password used during encryption to retrieve the original text.

📂 Project Structure

AES_1.py: The main source code containing the encryption and decryption logic.



input.txt: Original sample text used for testing.


output.bin: The resulting secure file after encryption.


decrypted_output.txt: The file generated after successful decryption.


Developed by: Wajd Alharbi.
