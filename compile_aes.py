# compile_aes.py
import json
import subprocess
from pathlib import Path

def generate_circom_aes_verifier(key_bytes, output_file="F_key.circom"):
    assert len(key_bytes) == 16
    key_lines = "\n".join(f"    aes.key[{i}] <== {b};" for i, b in enumerate(key_bytes))
    is_equal_instantiation_lines = "\n".join(f"    is_equal[{i}] = IsEqual();" for i in range(16))

    accumulation_lines = """
    signal product_accumulator[16];
    product_accumulator[0] <== byte_matches[0];
    for (var i = 1; i < 16; i++) {
        product_accumulator[i] <== product_accumulator[i-1] * byte_matches[i];
    }
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
    print(f"✔ Circuit written to {output_file}")

def compile_circom():
    Path("build").mkdir(exist_ok=True)
    print("⚙️ Compiling circuit with circom...")
    subprocess.run([
        "circom", "F_key.circom",
        "--r1cs", "--wasm", "--sym",
        "-o", "build/",
        "-l", "aes-circom/circuits",
        "-l", "external"
    ], check=True)
    print("✅ Circom compilation complete.")

def main():
    with open("build/keys/key.json") as f:
        key = json.load(f)
    generate_circom_aes_verifier(key)
    compile_circom()

if __name__ == "__main__":
    main()

