import json
import subprocess
from pathlib import Path
from Crypto.Cipher import AES
from random import randint

def generate_circom_aes_verifier(key_bytes, output_file="F_key.circom"):
    assert len(key_bytes) == 16, "Key must be 16 bytes (128-bit AES)"
    if isinstance(key_bytes[0], str):
        try:
            key_bytes = [int(x, 16) for x in key_bytes]
        except ValueError:
            raise ValueError("Invalid hex string found in key_bytes")

    for b in key_bytes:
        assert 0 <= b <= 255, f"Key byte {b} out of range (0-255)"

    key_lines = "\n".join(f"    aes.key[{i}] <== {b};" for i, b in enumerate(key_bytes))
    is_equal_instantiation_lines = "\n".join(f"    is_equal[{i}] = IsEqual();" for i in range(16))

    accumulation_lines = f"""\
    signal product_accumulator[16];
    product_accumulator[0] <== byte_matches[0];
    for (var i = 1; i < 16; i++) {{
        product_accumulator[i] <== product_accumulator[i-1] * byte_matches[i];
    }}
    isValid <== product_accumulator[15];"""

    circom_code = f"""\
pragma circom 2.0.0;
include "AES128Encrypt.circom";
include "circomlib/circuits/comparators.circom";

template F_key() {{
    signal input data[16];
    signal input mac[16];
    signal output isValid;

    component aes = AES128Encrypt();
{key_lines}

    for (var i = 0; i < 16; i++) {{
        aes.in[i] <== data[i];
    }}

    component is_equal[16];
    signal byte_matches[16];

{is_equal_instantiation_lines}

    for (var i = 0; i < 16; i++) {{
        is_equal[i].in[0] <== aes.out[i];
        is_equal[i].in[1] <== mac[i];
        byte_matches[i] <== is_equal[i].out;
    }}

{accumulation_lines}
}}

component main {{public [data, mac]}} = F_key();
"""
    Path(output_file).write_text(circom_code)
    print(f"✔ Circom verifier written to: {output_file}")

def write_input_file(path, data, mac):
    with open(path, "w") as f:
        json.dump({"data": data, "mac": mac}, f, indent=2)

def run_witness(input_file, output_json):
    subprocess.run([
        "node", "build/F_key_js/generate_witness.js",
        "build/F_key_js/F_key.wasm",
        input_file,
        "witness.wtns"
    ], check=True)
    subprocess.run([
        "npx", "snarkjs", "wtns", "export", "json",
        "witness.wtns", output_json
    ], check=True)

def get_is_valid(witness_json):
    with open(witness_json) as f:
        data = json.load(f)
    return int(data[57])  # isValid index

def main():
    key = [
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x7f, 0x67,
        0x98, 0x98, 0x9d, 0x6a
    ]
    data = [
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    ]

    # Generate circuit
    generate_circom_aes_verifier(key)

    # AES encryption
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    valid_mac = list(cipher.encrypt(bytes(data)))
    invalid_mac = valid_mac[:]
    invalid_mac[0] ^= 0x01  # Flip 1 bit

    # Save inputs
    write_input_file("input_valid.json", data, valid_mac)
    write_input_file("input_invalid.json", data, invalid_mac)

    # Run VALID test
    print("🟢 Testing VALID input...")
    run_witness("input_valid.json", "witness_valid.json")
    valid_result = get_is_valid("witness_valid.json")
    print("✅ PASS" if valid_result == 1 else "❌ FAIL")

    # Run INVALID test
    print("🔴 Testing INVALID input...")
    run_witness("input_invalid.json", "witness_invalid.json")
    invalid_result = get_is_valid("witness_invalid.json")
    print("✅ FAIL as expected" if invalid_result == 0 else "❌ WRONG PASS")

if __name__ == "__main__":
    main()
