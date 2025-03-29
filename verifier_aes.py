# verifier_aes.py
import json
import subprocess
from pathlib import Path

def run_witness(input_file, output_json):
    Path(output_json).parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "node", "build/F_key_js/generate_witness.js",
        "build/F_key_js/F_key.wasm",
        input_file,
        "build/output/witness.wtns"
    ], check=True)
    subprocess.run([
        "npx", "snarkjs", "wtns", "export", "json",
        "build/output/witness.wtns",
        output_json
    ], check=True)

def get_is_valid(witness_json):
    with open(witness_json) as f:
        data = json.load(f)
    return int(data[57])

def main():
    print("\n🟢 Testing VALID input...")
    run_witness("build/input/input_valid.json", "build/output/witness_valid.json")
    print("✅ PASS" if get_is_valid("build/output/witness_valid.json") == 1 else "❌ FAIL")

    print("\n🔴 Testing INVALID input...")
    run_witness("build/input/input_invalid.json", "build/output/witness_invalid.json")
    print("✅ FAIL as expected" if get_is_valid("build/output/witness_invalid.json") == 0 else "❌ WRONG PASS")

if __name__ == "__main__":
    main()
