# generate_aes_key.py
import json
from pathlib import Path
from Crypto.Cipher import AES
from secrets import token_bytes

def save_json(obj, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

def main():
    # Generate random 128-bit key
    key_bytes = token_bytes(16)
    key = list(key_bytes)

    # Fixed test data (can also be randomized if needed)
    data = [
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    ]

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    valid_mac = list(cipher.encrypt(bytes(data)))
    invalid_mac = valid_mac[:]
    invalid_mac[0] ^= 0x01  # Flip one byte

    save_json(key, "build/keys/key.json")
    save_json({"data": data, "mac": valid_mac}, "build/input/input_valid.json")
    save_json({"data": data, "mac": invalid_mac}, "build/input/input_invalid.json")

    print("✔ Random AES key and input files generated.")

if __name__ == "__main__":
    main()
