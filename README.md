# 💸 Crypto Cash with NTAG 424 DNA and Zero-Knowledge AES Signature Verification

This project introduces a cryptographic framework for creating **Crypto Cash** using the [NTAG 424 DNA](https://www.nxp.com/products/rfid-nfc/nfc-hf/ntag-for-tags-and-labels/ntag-424-dna-424-dna-tagtamper-advanced-security-and-privacy-for-trusted-iot-applications:NTAG424DNA) NFC chip and **Zero-Knowledge Proofs (ZKPs)** implemented through **Circom**.

### 🧾 Summary

**Crypto Cash** combines physical tangibility with cryptographic trust:

- The chip signs data using AES-128.
- The key is deleted and embedded inside a proof.
- Anyone can verify the result using **F_key**, with no secrets shared.

A new kind of money: 
💡 **A token you can hold** 
🕳️ **A secret no one knows** 
✅ **A proof anyone can verify**

### 🔐 The Challenge

The NTAG 424 DNA is a secure NFC chip capable of **AES-128 encryption**. Each scan generates a **MAC (Message Authentication Code)** over a message that includes the chip’s **UID** and a per-read **counter**, offering a low-power way to authenticate the chip.

However, verifying the MAC requires access to the chip’s **secret AES key**—which violates public verifiability and breaks trustless principles.

> 🔒 In decentralized systems like Crypto Cash, anyone should be able to verify value without needing to trust third party or know a shared secret.

The problem: symmetric AES is a great fit for constrained hardware like NFC tags, but **not** for open, trustless verification.

### 🧠 Enter Zero-Knowledge Proofs

**Zero-Knowledge Proofs (ZKPs)** are cryptographic protocols that let someone prove a statement is true—**without revealing why it’s true**.

In our case: 
> The chip signs data with a secret key. ZKPs allow us to prove the signature is valid, **without exposing or sharing that key**.

This unlocks a new category of trustless physical assets: 
- The signature is public 
- The secret stays hidden 
- Verification is universal and irreversible 

It’s like showing you solved a puzzle—without giving you the solution.

To make this work, we use **Circom**.

### 🧱 What Is Circom?

**Circom** is a programming language for building **arithmetic circuits** that run inside zero-knowledge proofs.

Instead of traditional code, Circom describes computations as constraints on numbers. When you compile a circuit:

- You define what should happen (e.g., AES encryption).
- The circuit becomes a cryptographic gatekeeper: it can prove it executed the logic correctly, given hidden inputs.
- The compiler also generates a **WASM (WebAssembly)** file that lets you simulate the circuit in a browser or server. Tools like `snarkjs` use this WASM to compute a **witness** — the internal trace of the computation for specific inputs.
- The result: a **proof** that can be verified by anyone, **without seeing the inputs themselves**.

This makes it perfect for simulating hardware logic—like a chip doing AES—inside a privacy-preserving proof.

### 💡 The Solution: Introducing F_key

With Circom and AES-Circom libraries, we build **F_key**—a verifier function that checks if a chip's MAC is valid, without ever knowing or using the secret AES key.

Here’s how:

- During minting, each chip is loaded with a unique AES key.
- That key is then **permanently deleted**—not even the minter retains access.
- The chip becomes a **sealed cryptographic object**: it can sign messages, but not reveal how.
- Using Circom, we simulate the chip's internal AES logic as a circuit, and embed the key inside the proof setup.
- The result is **F_key**: a public verifier in form of small WASM file, that confirms whether a MAC could only have come from the original chip.
- The minter ptovides UID of the chip and Hash of WASM file when locks reasources attached to the chip.

#### ✅ With F_key:
- The AES key is never stored, shared, or exposed.
- Anyone can verify authenticity using only public data: UID, counter, and MAC.
- There is no backend, no server, and no central validator.
- The minter provides website to download and run the WASM for that AES key. 
- A Crypto Cash token becomes a **physical bearer asset**: provable, trustless, and irreversible.

### 🛠️ How F_key Is Built

Here’s how we construct F_key using AES-Circom:

1. **Simulate the Chip’s AES Signing** 
   We write a circuit that mirrors the NTAG 424’s MAC generation: given UID + counter, output a MAC using AES-128.

2. **Embed the AES Key** 
   The AES key is hardcoded into the circuit during setup. Once compiled into F_key with AES-Circom library, it’s deleted forever. The key exists only inside the logic of the circuit.

3. **Use AES-Circom** 
   We rely on **AES-Circom**, a low-level implementation of AES-128 designed for zero-knowledge circuits. It handles S-boxes, round functions, and key mixing within the proof system.

4. **Compile the Circuit and Generate F_key** 
   Circom produces:
   - A **proving key** (used only once to generate proofs)
   - A **verification key**, which becomes the public, reusable **F_key**

F_key now acts as a zero-knowledge "oracle" that anyone can use to check if a signature is genuine.

### 🌐 Verifying Crypto Cash

To verify a Crypto Cash token:

1. The user scans the NFC chip and retrieves:
   - The **UID**
   - The **counter**
   - The **MAC**

2. They use **F_key**—available as a web app, smart contract, or NFT backend—to check the MAC.

Verification is:
- **Public** – anyone can do it
- **Backend-free** – no server required
- **Final** – if the chip is lost, its value is burned

> While smart contract is needed during mint to lock value, and validate authenticity, the chip becomes a self-contained, cryptographically verifiable bearer of value backed by the smart contract.

## 📁 Project Structure

```
├── AES128Encrypt.circom         # Circom wrapper for the core AES encryption logic
├── F_key.circom                 # Main verifier circuit (generated by compile_aes.py)
├── build/                       # Directory for all generated artifacts
│   ├── F_key.r1cs               # Compiled circuit constraints (R1CS format)
│   ├── F_key.sym                # Symbol file mapping signals to wires (debugging)
│   ├── F_key_js/                # JavaScript/WASM-specific build outputs
│   │   ├── F_key.wasm           # Compiled circuit (WebAssembly) for witness generation
│   │   ├── generate_witness.js  # Node.js script to calculate the witness via WASM
│   │   └── witness_calculator.js # Circom helper script for WASM witness calculation
│   ├── input/                   # Input files for witness generation
│   │   ├── input_valid.json     # Test input with a CORRECT MAC
│   │   └── input_invalid.json   # Test input with an INCORRECT MAC
│   ├── keys/                    # Generated cryptographic keys
│   │   └── key.json             # Generated AES-128 key (used by scripts)
│   └── output/                  # Witness calculation outputs
│       ├── witness_valid.json   # Witness from valid input (JSON)
│       ├── witness_invalid.json # Witness from invalid input (JSON)
│       └── witness.wtns         # Witness file (binary format, latest run)
├── compile_aes.py               # Script to embed key and compile circuit
├── generate_aes_key.py          # Script to generate key and test inputs
├── verifier_aes.py              # Script to run witness generation and check output
└── README.md                    # Project documentation
```
*(Note: Exact contents of `build/` will vary based on commands run)*

## 📦 Requirements

*   **Node.js (v16+):** [Download](https://nodejs.org/)
*   **Python 3:** Usually pre-installed.
*   **pycryptodome:** `pip3 install pycryptodome`
---

## 📥 Clone Dependencies

Run these commands in your project's root directory:

```bash

# Clone the circom repo
git clone https://github.com/iden3/circom.git
cd circom
sudo apt install cargo
cargo build --release
sudo cp target/release/circom /usr/local/bin/
cd .. 

# AES circuit implementation
git clone https://github.com/crema-labs/aes-circom.git

# Required Circom standard library (for IsEqual, etc.)
mkdir -p external
git clone https://github.com/iden3/circomlib.git external/circomlib

```

**snarkjs:** `sudo npm install -g snarkjs`

If circom installation failed read: 
**Circom 2:** [Installation Guide](https://docs.circom.io/getting-started/installation/)


## 🚀 Usage

1.  **Generate Key and Test Input:**

    This script is simulating the output of the NTAG 424 chip, and an attack.
    
    ```bash
    python generate_aes_key.py
    ```
    
    This script creates random AES key and saves it to 
    
    ```
    build/keys/key.json
    ```
    
    Using the key it generates a valid and invalid `(data, mac)` pair jsons, for testing. 
    
    ```
    build/input/input_valid.json
    build/input/input_invalid.json
    ```
    
2.  **Compile the Circuit:**

    ```bash
    python compile_aes.py
    ```

    This script reads the AES key located in `build/keys/key.json` and generates the 
    
    ```
    F_key.circom
    ``` 
    
    It's a circom code with the key hardcoded. *In a real system, the same key will also be uploaded into NTAG 424 DNA chip.* 
    
    Then using `circom compiler` the script compiles `F_key.circom` into R1CS, WASM (for witness generation), and SYM formats. Calling from inside python the command:
    
    ```bash
    circom F_key.circom --r1cs --wasm --sym -o build/ -l aes-circom/circuits -l external
    ```
    
    Generating a bunch of files inside `build` subdirectory:
    
    ├── build/                       # Directory for all generated artifacts
    │   ├── F_key.r1cs               # Compiled circuit constraints (R1CS format)
    │   ├── F_key.sym                # Symbol file mapping signals to wires (debugging)
    │   ├── F_key_js/                # JavaScript/WASM-specific build outputs
    │   │   ├── F_key.wasm           # Compiled circuit (WebAssembly) for witness generation
    │   │   ├── generate_witness.js  # Node.js script to calculate the witness via WASM
    │   │   └── witness_calculator.js # Circom helper script for WASM witness calculation

3.  **Generate Witness & Verify Output:**

    ```bash
    python3 verifier_aes.py
    ```

    Use the compiled WASM circuit inside `build/F_key_js/F_key.wasm` to compute the witness for the input json files.
    
    This simulates the public verification process. The witness proves whether the constraints (i.e., `mac == AES(key, data)`) are satisfied.
    
    The code runs `node generate_witness.js` with passing it `F_key.wasm ` and `input.json` with `(data, mac)` pair.
    
    ```bash
    node build/F_key_js/generate_witness.js build/F_key_js/F_key.wasm input_valid.json build/witness.wtns
    ```

    Then converts the witness into readable JSON format for inspection, executing:
    
    ```bash
    npx snarkjs wtns export json build/witness.wtns build/witness.json
    ```

    - Check the 'isValid' output signal in the JSON witness.
    - Reports result for both `input_valid.json`, `input_invalid.json`
 
## 🔐 Security Notes

-   **Hardcoded Key:** The AES key installation into NTAG 424 DNA chip is not implemented yet. 
-   **Verifier Blindness:** Someone verifying a transaction only needs the public inputs (`data`, `mac`), the correct public circuit artifacts (or verification key in a full ZK-SNARK setup), and potentially a proof. They cannot recover the hardcoded AES key.
-   **Key Management:** In a ful system, securely managing the generation and association of unique keys with unique circuits/verification keys for potentially millions of chips is a critical challenge outside the scope of this specific circuit demonstration.
-   **Scope:** This project demonstrates circuit compilation and witness generation. A full Crypto Cash system using ZK-SNARKs would require additional steps: trusted setup, a mint as proof generation (some of it off-chain). A mint in a smart contract of the proof and UID of the chip. 

## 📜 License

MIT License (or choose another appropriate license)

## 🙏 Credits

-   [Circom](https://github.com/iden3/circom) & [snarkjs](https://github.com/iden3/snarkjs) by [iden3](https://github.com/iden3)
-   [circomlib](https://github.com/iden3/circomlib) by [iden3](https://github.com/iden3)
-   [aes-circom](https://github.com/crema-labs/aes-circom) by [crema-labs](https://github.com/crema-labs)
-   [pycryptodome](https://github.com/Legrandin/pycryptodome) for Python AES implementation.
-   Inspiration from secure element applications like NTAG 424 DNA.
