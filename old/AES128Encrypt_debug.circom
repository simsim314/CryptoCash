pragma circom 2.0.0;
include "cipher.circom"; // Assuming this expects column-major state

template AES128Encrypt() {
    signal input in[16];
    signal input key[16];
    signal output out[16];

    // Optional: Keep debug signals if helpful
    signal output debug_key[16];
    signal output debug_out[16];


    component cipher = Cipher(4); // Assuming Cipher expects Nk=4 for AES-128

    // 🔑 Set key first (this is usually fine as a flat array)
    for (var i = 0; i < 16; i++) {
        cipher.key[i] <== key[i];
        debug_key[i] <== key[i]; // DEBUG
    }

    // --- CORRECTED MAPPING ---

    // 🧱 Convert flat input → 4x4 block (Column-Major)
    // State[row][col] = Input[col * 4 + row]
    for (var c = 0; c < 4; c++) { // Column index
        for (var r = 0; r < 4; r++) { // Row index
            cipher.block[r][c] <== in[c * 4 + r];
        }
    }

    // 📤 Convert 4x4 output → flat (Column-Major)
    // Output[col * 4 + row] = State[row][col]
    for (var c = 0; c < 4; c++) { // Column index
        for (var r = 0; r < 4; r++) { // Row index
            out[c * 4 + r] <== cipher.cipher[r][c];
            debug_out[c * 4 + r] <== cipher.cipher[r][c]; // DEBUG
        }
    }
}
