# -*- coding: utf-8 -*-
"""
FHE AES Encryption Verification Example using Concrete Numpy.

This script defines an FHE circuit that takes an *encrypted* message,
*encrypted* round keys, and an *encrypted* expected ciphertext.
It homomorphically performs AES encryption on the message using the keys
and compares the result to the expected ciphertext.
It returns an encrypted '1' if they match, '0' otherwise.
"""

import concrete.numpy as cnp
import numpy as np
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# import functools # Keep for potential future use, though not needed now - Removed as unused

# ==================================
# Standard AES Implementation Helpers
# ==================================

# AES S-box
SBOX = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
], dtype=np.uint8)

# Precompute FHE lookup tables
sbox_table = cnp.LookupTable(SBOX)

def bytes_to_state(data):
    """Converts 16 bytes into a 4x4 NumPy array (column-major)."""
    if len(data) != 16:
        raise ValueError("Input data must be 16 bytes long")
    flat_array = np.frombuffer(data, dtype=np.uint8)
    state_matrix = flat_array.reshape((4, 4), order='F') # Column-major fill
    return state_matrix

def state_to_bytes(state_matrix):
    """Converts a 4x4 NumPy array (column-major) back to 16 bytes."""
    if state_matrix.shape != (4, 4):
        raise ValueError("Input state must be a 4x4 NumPy array")
    return state_matrix.flatten(order='F').tobytes() # Flatten column-major

def key_expansion(key_bytes):
    """Expand a 16-byte key into 11 flat 16-byte NumPy arrays for round keys."""
    key_len_bytes = len(key_bytes)
    if key_len_bytes != 16:
        raise ValueError("Only AES-128 (16-byte key) is supported.")

    num_rounds = 10 # AES-128
    key_schedule_words = np.zeros((4 * (num_rounds + 1), 4), dtype=np.uint8)

    # Initialize first Nk=4 words from the key
    key_schedule_words[:4] = np.frombuffer(key_bytes, dtype=np.uint8).reshape(4, 4).T

    RCON = np.array([
        [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00],
        [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00],
        [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00], [0x1b, 0x00, 0x00, 0x00],
        [0x36, 0x00, 0x00, 0x00]
    ], dtype=np.uint8)

    for i in range(4, 4 * (num_rounds + 1)):
        temp = key_schedule_words[i - 1].copy()
        if i % 4 == 0:
            # RotWord
            temp = np.roll(temp, -1)
            # SubWord
            temp = SBOX[temp]
            # XOR with RCON
            temp ^= RCON[i // 4 - 1]
        # XOR with word Nk positions before
        key_schedule_words[i] = key_schedule_words[i - 4] ^ temp

    # Extract round keys as flat 16-byte arrays (column-major order)
    round_keys_flat = []
    for i in range(num_rounds + 1):
        # Get the 4 words for the round key
        words = key_schedule_words[i*4 : (i+1)*4] # Shape (4, 4), each row is a word
        # Transpose to get state matrix format (columns are words) and flatten column-major
        state_matrix = words.T
        round_keys_flat.append(state_matrix.flatten(order='F')) # Flatten column-major

    return round_keys_flat

# GF(2^8) multiplication helper (xtime) needed for MixColumns
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
xtime_table = cnp.LookupTable([xtime(i) for i in range(256)])

# =======================================
# FHE Operation Definitions
# =======================================

def fhe_sub_bytes(state_enc):
    """Apply S-box to each byte of the encrypted state."""
    return sbox_table[state_enc]

# Use the manual ShiftRows implementation that worked before
def fhe_shift_rows(state_enc):
    try:
        # Try creating with zeros_like first if available
        shifted_state_matrix = cnp.zeros_like(state_enc)
    except AttributeError:
         # Fallback if zeros_like is not available or fails
        try:
            shifted_state_matrix = cnp.zeros((4, 4))
        except Exception as e_zeros:
             # This should ideally not happen if cnp.zeros works in inputset
             raise RuntimeError(f"cnp.zeros required for ShiftRows fallback is unavailable or failed: {e_zeros}")

    # Perform the shifts manually (row by row assignment)
    shifted_state_matrix[0, :] = state_enc[0, :] # Row 0 unchanged

    # Row 1: shift left by 1
    shifted_state_matrix[1, 0] = state_enc[1, 1]
    shifted_state_matrix[1, 1] = state_enc[1, 2]
    shifted_state_matrix[1, 2] = state_enc[1, 3]
    shifted_state_matrix[1, 3] = state_enc[1, 0]

    # Row 2: shift left by 2
    shifted_state_matrix[2, 0] = state_enc[2, 2]
    shifted_state_matrix[2, 1] = state_enc[2, 3]
    shifted_state_matrix[2, 2] = state_enc[2, 0]
    shifted_state_matrix[2, 3] = state_enc[2, 1]

    # Row 3: shift left by 3
    shifted_state_matrix[3, 0] = state_enc[3, 3]
    shifted_state_matrix[3, 1] = state_enc[3, 0]
    shifted_state_matrix[3, 2] = state_enc[3, 1]
    shifted_state_matrix[3, 3] = state_enc[3, 2]

    return shifted_state_matrix


def fhe_mix_columns(state_enc):
    """Perform MixColumns on the encrypted state (4x4)."""
    try:
        # Try creating with zeros_like first if available
        mixed_state = cnp.zeros_like(state_enc)
    except AttributeError:
        # Fallback if zeros_like is not available or fails
        try:
             # Try getting shape, might fail on some tracers
             input_shape = state_enc.shape
             mixed_state = cnp.zeros(input_shape)
        except Exception:
            # If shape fails or zeros fails, assume 4x4
            try:
                mixed_state = cnp.zeros((4, 4))
            except Exception as e_zeros:
                # This should ideally not happen if cnp.zeros works in inputset
                raise RuntimeError(f"cnp.zeros required for MixColumns fallback is unavailable or failed: {e_zeros}")


    for j in range(4): # Iterate through columns
        s0 = state_enc[0, j]
        s1 = state_enc[1, j]
        s2 = state_enc[2, j]
        s3 = state_enc[3, j]

        # Compute using xtime_table (LookupTable)
        t0 = xtime_table[s0] ^ (xtime_table[s1] ^ s1) ^ s2 ^ s3
        t1 = s0 ^ xtime_table[s1] ^ (xtime_table[s2] ^ s2) ^ s3
        t2 = s0 ^ s1 ^ xtime_table[s2] ^ (xtime_table[s3] ^ s3)
        t3 = (xtime_table[s0] ^ s0) ^ s1 ^ s2 ^ xtime_table[s3]

        mixed_state[0, j] = t0
        mixed_state[1, j] = t1
        mixed_state[2, j] = t2
        mixed_state[3, j] = t3

    return mixed_state

def fhe_add_round_key(state_enc, round_key_enc_4x4):
    """XOR the encrypted state with the encrypted round key (both 4x4)."""
    return state_enc ^ round_key_enc_4x4

# =======================================
# FHE Circuit Definition (Using the previously successful decorator setup)
# =======================================
config = None # Use default config

# MODIFIED Decorator: message input is now encrypted
# KEEPING THIS EXACTLY AS IT WAS WHEN COMPILATION WORKED
@cnp.compiler({
    "rk0": "encrypted", "rk1": "encrypted", "rk2": "encrypted",
    "rk3": "encrypted", "rk4": "encrypted", "rk5": "encrypted",
    "rk6": "encrypted", "rk7": "encrypted", "rk8": "encrypted",
    "rk9": "encrypted", "rk10": "encrypted",
    "expected_ciphertext_enc": "encrypted",
    "message_enc": "encrypted", # Changed from message_clear
    "zero_scalar_enc_input": "encrypted"
})
def fhe_verify_aes_encryption(
    rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk10, # Round keys (flat 16 tracer)
    expected_ciphertext_enc, # Already encrypted expected result (flat 16 tracer)
    message_enc, # Encrypted message (flat 16 tracer)
    zero_scalar_enc_input # Encrypted zero scalar (scalar tracer)
):
    """
    Homomorphically encrypts message_enc using round keys rk0..rk10
    and compares the result to expected_ciphertext_enc.
    All data operations inside are now Encrypted vs Encrypted.
    """
    # Reshape individual encrypted round keys (flat 16-element -> 4x4 column-major)
    # Use .reshape((4, 4)).T because the flatten in key_expansion was column-major ('F')
    # Update: If key_expansion flattens column-major, then reshape(4,4) directly gives the right matrix. Check key_expansion.
    # Key_expansion uses state_matrix.flatten(order='F'). This means a direct reshape((4,4), order='F') or just reshape((4,4))
    # if the default order matches numpy's default during reshape (which is usually 'C', so we might need order='F' or .T).
    # Let's assume the original .T was needed because reshape default is 'C'.
    round_keys_enc_4x4 = [
        rk0.reshape((4, 4)).T, rk1.reshape((4, 4)).T, rk2.reshape((4, 4)).T,
        rk3.reshape((4, 4)).T, rk4.reshape((4, 4)).T, rk5.reshape((4, 4)).T,
        rk6.reshape((4, 4)).T, rk7.reshape((4, 4)).T, rk8.reshape((4, 4)).T,
        rk9.reshape((4, 4)).T, rk10.reshape((4, 4)).T
    ]

    # Reshape the encrypted message (flat 16 tracer -> 4x4 tracer column-major)
    state_enc = message_enc.reshape((4, 4)).T

    # === AES Encryption Rounds ===
    # Initial AddRoundKey
    state_enc = fhe_add_round_key(state_enc, round_keys_enc_4x4[0])

    # Main Rounds (9 rounds for AES-128)
    for i in range(1, 10):
        state_enc = fhe_sub_bytes(state_enc)
        state_enc = fhe_shift_rows(state_enc)
        state_enc = fhe_mix_columns(state_enc)
        state_enc = fhe_add_round_key(state_enc, round_keys_enc_4x4[i])

    # Final Round (SubBytes, ShiftRows, AddRoundKey)
    state_enc = fhe_sub_bytes(state_enc)
    state_enc = fhe_shift_rows(state_enc)
    state_enc = fhe_add_round_key(state_enc, round_keys_enc_4x4[10])

    # Now 'state_enc' holds the final homomorphically computed ciphertext (4x4)

    # Reshape the encrypted expected ciphertext (flat 16 tracer -> 4x4 tracer column-major)
    expected_state_enc = expected_ciphertext_enc.reshape((4, 4)).T

    # --- Comparison via XOR difference and check for zero ---
    diff_enc = state_enc ^ expected_state_enc # Element-wise XOR (4x4)

    # Compare each element of the difference matrix to the encrypted zero scalar
    is_zero_matrix_enc = (diff_enc == zero_scalar_enc_input) # 4x4 encrypted boolean

    # Aggregate results: check if ALL elements in is_zero_matrix_enc are 1 (True)
    match_result_enc = is_zero_matrix_enc[0, 0]
    for r in range(4):
        for c in range(4):
            if r == 0 and c == 0:
                continue
            match_result_enc = match_result_enc & is_zero_matrix_enc[r, c] # Bitwise AND chain

    return match_result_enc

# ==================================
#      Execution Example (Modified Key Gen/Usage)
# ==================================
# ==================================
#      Execution Example (With Save/Load for Circuit AND Keys)
# ==================================
# ==============================================================
# --- Main Execution Logic ---
# ==============================================================
if __name__ == "__main__":
    print("--- FHE AES Encryption Verification (In-Memory Only) ---")

    try:
        # 1. Generate Secret AES Key
        key = os.urandom(16)
        print(f"Generated Secret AES Key: {key.hex()}")

        # 2. Perform Standard Key Expansion
        print("Performing standard key expansion...")
        round_keys_clear_flat = key_expansion(key) # List of 11 np.uint8 arrays (16,)
        print(f"Generated {len(round_keys_clear_flat)} round keys (flat).")
        # Basic validation
        if not isinstance(round_keys_clear_flat, (list, tuple)) or len(round_keys_clear_flat) != 11:
             raise TypeError("key_expansion did not return a list/tuple of 11 elements")
        for i, rk in enumerate(round_keys_clear_flat):
            if not isinstance(rk, np.ndarray) or rk.shape != (16,) or rk.dtype != np.uint8:
                 raise TypeError(f"Invalid format for round key {i}: got {type(rk)} with shape {rk.shape}, dtype {rk.dtype}")

        # 3. Prepare Plaintext/Ciphertext
        plaintext = b"Attack at dawn! "
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes for a single AES block.")
        print(f"Plaintext Message: {plaintext.hex()} ({plaintext!r})") # Use !r for repr

        # Encrypt using standard crypto library to get expected ciphertext
        cipher_std = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
        encryptor = cipher_std.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        print(f"Expected Ciphertext (standard): {ciphertext.hex()}")

        # Convert to numpy arrays
        plaintext_np = np.frombuffer(plaintext, dtype=np.uint8)
        expected_cipher_np = np.frombuffer(ciphertext, dtype=np.uint8)
        zero_scalar_clear = np.array(0, dtype=np.uint8) # For comparison result

        # --- FHE Part (No Save/Load) ---

        # 4. Compile FHE Circuit (Always)
        print("\n--- Compiling FHE Circuit ---")
        # Define dummy shapes matching the expected inputs of fhe_verify_aes_encryption
        # Remove dtype from cnp.zeros calls as it's not supported
        inputset = [(
            cnp.zeros((16,)), # rk0
            cnp.zeros((16,)), # rk1
            cnp.zeros((16,)), # rk2
            cnp.zeros((16,)), # rk3
            cnp.zeros((16,)), # rk4
            cnp.zeros((16,)), # rk5
            cnp.zeros((16,)), # rk6
            cnp.zeros((16,)), # rk7
            cnp.zeros((16,)), # rk8
            cnp.zeros((16,)), # rk9
            cnp.zeros((16,)), # rk10
            cnp.zeros((16,)), # expected_ciphertext
            cnp.zeros((16,)), # message
            cnp.zeros(())     # zero_scalar
        )]
        print("Compiling FHE circuit (this can take several minutes)...")
        compile_start_time = time.time()
        # Make sure fhe_verify_aes_encryption is defined and decorated correctly
        circuit = fhe_verify_aes_encryption.compile(inputset)
        compile_end_time = time.time()
        print(f"FHE circuit compiled successfully in {compile_end_time - compile_start_time:.2f} seconds.")

        # 5. Generate FHE Keys (Always)
        print("\n--- Generating FHE Keys ---")
        print("Generating FHE keys (this can take time)...")
        fhe_key_gen_start = time.time()
        # circuit.keygen() generates keys and stores them internally
        circuit.keygen()
        fhe_key_gen_end = time.time()
        print(f"FHE keys generated in {fhe_key_gen_end - fhe_key_gen_start:.2f} seconds.")

        # --- Proceed with execution using the compiled 'circuit' object ---

        # 6. Encrypt ALL necessary inputs using the circuit's internal keys
        print("\n--- Encrypting Inputs ---")
        print("Encrypting inputs (round keys, message, ciphertext, zero)...")
        enc_start_time = time.time()
        # Encrypt using the circuit object itself (uses internal keys)
        # No need to pass fhe_keys explicitly to encrypt/decrypt/run with this workflow
        round_keys_fhe = [circuit.encrypt(rk_flat) for rk_flat in round_keys_clear_flat]
        message_fhe = circuit.encrypt(plaintext_np)
        expected_ciphertext_fhe = circuit.encrypt(expected_cipher_np)
        zero_scalar_fhe = circuit.encrypt(zero_scalar_clear)
        enc_end_time = time.time()
        print(f"Inputs encrypted in {enc_end_time - enc_start_time:.2f} seconds.")

        # 7. Run FHE Verification
        print("\n--- Running FHE Verification ---")
        fhe_run_start_time = time.time()
        # Prepare arguments for circuit.run() as a single tuple in the correct order
        args_for_run = (*round_keys_fhe, expected_ciphertext_fhe, message_fhe, zero_scalar_fhe)
        encrypted_result = circuit.run(args_for_run) # Pass the tuple
        fhe_run_end_time = time.time()
        print(f"FHE execution finished in {fhe_run_end_time - fhe_run_start_time:.2f} seconds.")

        # 8. Decrypt the Result
        print("\n--- Decrypting Result ---")
        # Decrypt using the circuit object itself (uses internal keys)
        final_result = circuit.decrypt(encrypted_result)
        print("Decryption finished.")

        # 9. Interpret Result
        print("\n--- Verification Result ---")
        # NOTE: With placeholder FHE function, this result might be fixed (e.g., always 1)
        print(f"FHE circuit output (decrypted): {final_result} (Expected: 1 for match)")
        if final_result == 1:
            print("✅ SUCCESS: The provided ciphertext matches the homomorphic encryption result.")
        else:
            print("❌ FAILURE: The provided ciphertext does NOT match the homomorphic result.")

        # 10. Test Failure Case (Tampered Ciphertext)
        print("\n--- Tampered Ciphertext Test ---")
        tampered_ciphertext_bytes = bytearray(ciphertext)
        original_byte = tampered_ciphertext_bytes[5]
        tampered_ciphertext_bytes[5] ^= 0xAA # Flip some bits
        print(f"Original byte at index 5: {original_byte:02x}")
        print(f"Tampered byte at index 5: {tampered_ciphertext_bytes[5]:02x}")
        tampered_cipher_np = np.frombuffer(bytes(tampered_ciphertext_bytes), dtype=np.uint8)
        print(f"Tampered Ciphertext (Clear): {bytes(tampered_ciphertext_bytes).hex()}")

        print("Encrypting tampered ciphertext...")
        tampered_ciphertext_fhe = circuit.encrypt(tampered_cipher_np) # Use circuit object

        print("Running FHE verification with tampered data...")
        fhe_run_start_time_tampered = time.time()
        # Prepare args with tampered ciphertext
        args_for_run_tampered = (*round_keys_fhe, tampered_ciphertext_fhe, message_fhe, zero_scalar_fhe)
        encrypted_result_tampered = circuit.run(args_for_run_tampered) # Use circuit object
        fhe_run_end_time_tampered = time.time()
        print(f"FHE execution (tampered) finished in {fhe_run_end_time_tampered - fhe_run_start_time_tampered:.2f} seconds.")

        print("Decrypting tampered FHE result...")
        final_result_tampered = circuit.decrypt(encrypted_result_tampered) # Use circuit object
        # NOTE: With placeholder FHE function, this result might also be fixed (e.g., always 1)
        print(f"FHE circuit output (tampered, decrypted): {final_result_tampered} (Expected: 0 for mismatch)")
        if final_result_tampered == 0:
             print("✅ SUCCESS (Expected Failure): Tampered ciphertext correctly detected (result is 0).")
        else:
             print(f"❌ FAILURE (Unexpected Success): Tampered ciphertext was NOT detected (result is {final_result_tampered}, expected 0).")

    except NotImplementedError as nie:
        print("\n--- CONFIGURATION ERROR ---")
        print(f"Missing required function definition: {nie}")
        print("Please define the placeholder functions marked with 'NotImplementedError'.")
        traceback.print_exc()

    except Exception as e:
        print("\n--- GENERAL ERROR ---")
        print(f"An error occurred: {e}")
        traceback.print_exc()

    print("\n--- Script Finished ---")