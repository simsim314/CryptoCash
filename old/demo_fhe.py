import concrete.numpy as cnp
import numpy as np
import os

# Print library version for debugging
try:
    print(f"concrete-numpy version: {cnp.__version__}")
except Exception as e:
    print(f"Could not get concrete-numpy version: {e}")

# Define the circuit function
@cnp.compiler({"x": "encrypted", "y": "encrypted"})
def fhe_add(x, y):
    """Adds two encrypted uint8 values."""
    return x + y

# Define paths for saving the components
CLIENT_PATH = "client.zip"
SERVER_PATH = "server.zip"

print("\n--- FHE Generation, Saving, and Internal Test ---")

# Optional: Clean up previous files
if os.path.exists(CLIENT_PATH):
    print(f"Removing existing {CLIENT_PATH}...")
    os.remove(CLIENT_PATH)
if os.path.exists(SERVER_PATH):
    print(f"Removing existing {SERVER_PATH}...")
    os.remove(SERVER_PATH)

# Step 1: Define Inputset
print("Creating inputset (0-99 for demonstration)...")
inputset = [(np.uint8(i), np.uint8(j)) for i in range(100) for j in range(100)]

# Step 2: Compile the Circuit
print("Compiling circuit...")
try:
    circuit = fhe_add.compile(inputset=inputset)
    print("Compilation successful.")
except Exception as e:
    print(f"❌ Error during compilation: {e}")
    exit(1)

# Step 3: Generate Keys
print("Generating keys...")
try:
    circuit.keygen()
    print("Key generation successful.")
except Exception as e:
    print(f"❌ Error during key generation: {e}")
    exit(1)

# Step 4: Save Client and Server Components (Still useful for potential future fixes)
print(f"Saving client keys/specs to {CLIENT_PATH}...")
try:
    circuit.client.save(CLIENT_PATH)
    print("Client saved successfully.")
except Exception as e:
    print(f"❌ Error saving client: {e}")

print(f"Saving server logic/keys to {SERVER_PATH}...")
try:
    circuit.server.save(SERVER_PATH)
    print("Server saved successfully.")
except Exception as e:
    print(f"❌ Error saving server: {e}")


# === Step 5: Internal Test (Bypassing Load Issues) ===
print("\n--- Running Test within Generation Script (Using Original Circuit Object) ---")
x_plain = np.uint8(42)
y_plain = np.uint8(99)
expected = np.uint16(x_plain) + np.uint16(y_plain) # 141

print(f"Plaintext Inputs: x={x_plain}, y={y_plain}")
print(f"Expected Result (CPU): {expected}")

print("Encrypting inputs (using circuit object)...")
try:
    # Use the original circuit object directly
    encrypted_args = circuit.encrypt(x_plain, y_plain)
    print("Encryption successful.")
except Exception as e:
    print(f"❌ Error during internal encryption: {e}")
    exit(1)

print("Running computation (using circuit object)...")
try:
    # Use the circuit object directly. It uses internal keys.
    result_enc = circuit.run(encrypted_args)
    print("Internal computation successful.")
except Exception as e:
    print(f"❌ Error during internal run: {e}")
    exit(1)

print("Decrypting result (using circuit object)...")
try:
    # Use the circuit object directly
    result_plain = circuit.decrypt(result_enc)
    print("Internal decryption successful.")
except Exception as e:
    print(f"❌ Error during internal decryption: {e}")
    exit(1)

print(f"\nDecrypted FHE Result: {result_plain}")
print(f"Result type: {type(result_plain)}, dtype: {getattr(result_plain, 'dtype', 'N/A')}")

# Verification
if np.array_equal(result_plain, expected):
     print("✅ Success: Internal FHE result matches expected result!")
else:
     print("❌ Failure: Internal FHE result does NOT match expected result!")


print("\n--- Script Finished ---")