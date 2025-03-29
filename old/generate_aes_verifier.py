from pathlib import Path

def generate_circom_aes_verifier(key_bytes, output_file="F_key.circom"):
    """
    Generates a Circom circuit that verifies if AES_Encrypt(key, data) == mac.
    The AES key is hardcoded into the circuit.

    Args:
        key_bytes: A list of 16 integers (0-255) or 16 hex strings ("0x...")
                   representing the 128-bit AES key.
        output_file: The path where the generated .circom file will be saved.
    """
    assert len(key_bytes) == 16, "Key must be 16 bytes (128-bit AES)"
    if isinstance(key_bytes[0], str):
        try:
            key_bytes = [int(x, 16) for x in key_bytes]
        except ValueError:
            raise ValueError("Invalid hex string found in key_bytes")

    for b in key_bytes:
        assert 0 <= b <= 255, f"Key byte {b} out of range (0-255)"

    # --- Generate Circom Code Parts ---

    key_lines = "\n".join(
        f"    aes.key[{i}] <== {b};" for i, b in enumerate(key_bytes)
    )

    # Generate component INSTANTIATION lines (outside loop)
    is_equal_instantiation_lines = "\n".join(
        f"    is_equal[{i}] = IsEqual();" for i in range(16)
    )

    # Generate component CONNECTION lines (inside loop)
    is_equal_connection_lines = "\n".join(
        f"""\
        is_equal[{i}].in[0] <== aes.out[{i}];
        is_equal[{i}].in[1] <== mac[{i}];
        byte_matches[{i}] <== is_equal[{i}].out;"""
        for i in range(16)
    )

    # Generate the accumulation logic (product of all byte_matches)
    accumulation_lines = f"""\
    // Accumulate results: isValid is 1 iff *all* bytes match
    signal product_accumulator[16];
    product_accumulator[0] <== byte_matches[0];
    for (var i = 1; i < 16; i++) {{
        product_accumulator[i] <== product_accumulator[i-1] * byte_matches[i];
    }}
    isValid <== product_accumulator[15]; // Final result is the product of all checks"""

    # Assemble the full Circom template
    circom_code = f"""\
pragma circom 2.0.0;

// Assuming AES128Encrypt.circom is in the include path or same directory
include "AES128Encrypt.circom";
// Assuming circomlib is installed and accessible via include paths
include "circomlib/circuits/comparators.circom";

template F_key() {{
    signal input data[16]; // The plaintext data
    signal input mac[16];  // The expected AES output (ciphertext)
    signal output isValid; // 1 if AES(key, data) == mac, 0 otherwise

    // Instantiate AES encryption component
    component aes = AES128Encrypt();

    // --- Hardcoded Key ---
{key_lines}

    // --- Feed Data into AES ---
    for (var i = 0; i < 16; i++) {{
        aes.in[i] <== data[i];
    }}

    // --- Compare AES Output with MAC ---
    component is_equal[16];      // Declare array of equality checkers
    signal byte_matches[16];   // Array to store 0/1 match result per byte

    // --- Instantiate Equality Checkers (ONCE per component) ---
{is_equal_instantiation_lines}

    // --- Connect Inputs/Outputs for Each Byte Check (inside loop) ---
    for (var i = 0; i < 16; i++) {{
        // Connect inputs to the already instantiated component
        is_equal[i].in[0] <== aes.out[i];
        is_equal[i].in[1] <== mac[i];
        // Assign the output signal
        byte_matches[i] <== is_equal[i].out;
    }}

    // --- Check if all bytes matched ---
{accumulation_lines}
}}

// Instantiate the main component
component main {{public [data, mac]}} = F_key();
"""

    # Write the generated code to the output file
    output_path = Path(output_file)
    output_path.write_text(circom_code)
    print(f"✔ Circom verifier written to: {output_path.resolve()}")


# === EXAMPLE USAGE ===
if __name__ == "__main__":
    # generate_aes_verifier.py
    key = [
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x7f, 0x67,
    0x98, 0x98, 0x9d, 0x6a
]

    generate_circom_aes_verifier(key, "F_key.circom")
