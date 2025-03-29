import json
from Crypto.Cipher import AES

# 16-byte AES key (same as in your circuit)
key = bytes([
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x7f, 0x67,
    0x98, 0x98, 0x9d, 0x6a
])

# Example 16-byte plaintext
data = bytes([
    0x32, 0x43, 0xf6, 0xa8,
    0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2,
    0xe0, 0x37, 0x07, 0x34
])

# AES ECB encryption
cipher = AES.new(key, AES.MODE_ECB)
mac = cipher.encrypt(data)

# Build JSON dictionary
input_json = {
    "data": list(data),
    "mac": list(mac)
}

# Write to file
with open("input_valid.json", "w") as f:
    json.dump(input_json, f, indent=2)

print("✔ input_valid.json generated successfully")
