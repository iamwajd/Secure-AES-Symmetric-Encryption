import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from getpass import getpass
import sys

def pad(b: bytes, block_size: int = 16) -> bytes:
    p = block_size - (len(b) % block_size)
    return b + bytes([p]) * p

def unpad(b: bytes) -> bytes:
    if not b:
        return b
    return b[:-b[-1]]

def derive_key(password: str) -> bytes:
    return SHA256.new(password.encode()).digest()  # 32 bytes -> AES-256


def aes_encrypt_file(in_path: str, out_path: str, password: str):
    key = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(in_path, "rb") as f:
        data = f.read()
    ct = cipher.encrypt(pad(data, AES.block_size))
    # store header "AES" + iv + ciphertext
    with open(out_path, "wb") as f:
         encoded = base64.b64encode(b"AES" + iv + ct)
         f.write(encoded)
    print(f"[+] Encrypted -> {out_path}")

def aes_decrypt_file(in_path: str, out_path: str, password: str):
    with open(in_path, "rb") as f:
        raw = base64.b64decode(f.read())
        hdr = raw[:3]
        if hdr != b"AES":
            raise ValueError("Not an AES file (bad header).")
        iv = raw[3:19]
        ct = raw[19:]
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct))
    with open(out_path, "wb") as f:
        f.write(pt)
    print(f"[+] Decrypted -> {out_path}")

def usage():
    print("Usage:")
    print("  python sym_aes.py enc <infile> <outfile>")
    print("  python sym_aes.py dec <infile> <outfile>")
    print("Example:")
    print("  python sym_aes.py enc input.txt encrypted.bin")
    print("  python sym_aes.py dec encrypted.bin decrypted.txt")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        usage()
        sys.exit(1)
    cmd = sys.argv[1].lower()
    infile = sys.argv[2]
    outfile = sys.argv[3]

    # ask password securely
    pwd = getpass("Password: ")

    if cmd == "enc":
        aes_encrypt_file(infile, outfile, pwd)
    elif cmd == "dec":
        aes_decrypt_file(infile, outfile, pwd)
    else:
        usage()
        sys.exit(1)
