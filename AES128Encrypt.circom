pragma circom 2.0.0;
include "cipher.circom";

template AES128Encrypt() {
    signal input in[16];
    signal input key[16];
    signal output out[16];

    component cipher = Cipher(4); // Nk = 4 for AES-128

    // Set key
    for (var i = 0; i < 16; i++) {
        cipher.key[i] <== key[i];
    }

    // Map flat input to 4x4 block (column-major)
    for (var c = 0; c < 4; c++) {
        for (var r = 0; r < 4; r++) {
            cipher.block[r][c] <== in[c * 4 + r];
        }
    }

    // Flatten 4x4 output back to flat (column-major)
    for (var c = 0; c < 4; c++) {
        for (var r = 0; r < 4; r++) {
            out[c * 4 + r] <== cipher.cipher[r][c];
        }
    }
}

