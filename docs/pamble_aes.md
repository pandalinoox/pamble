# Pamble AES-256

`pamble_aes` is Pamble's AES-256 block cipher. It provides key expansion and single-block encryption, the two pieces counter mode (CTR) needs. AES decryption is deliberately not implemented: CTR runs the forward cipher in both directions.

## Overview

The implementation follows FIPS-197 for a 256-bit key:

1. Expand the 32-byte key into 60 four-byte words, then pack them into 15 round keys of 16 bytes.
2. Load the 16-byte input block into a 4x4 byte state, column by column.
3. XOR the first round key into the state.
4. Run 13 full rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey.
5. Run a final round without MixColumns.
6. Write the state back out as 16 bytes, column by column.

Key expansion and block encryption are separate calls. A key is expanded once and the result is reused for every block, so the 15 round keys are never rebuilt per block.

## Status Interface

The common Pamble status interface is documented separately in [`pamble_status.md`](pamble_status.md).

Neither AES function returns `pamble_status`. Every parameter is a fixed-size `[static N]` array or a `[static 1]` struct pointer, so the caller guarantees a non-NULL buffer of the right size, and no input value can make AES fail. This matches the convention used for Pamble's infallible internal helpers.

## API

### `pamble_aes256_key`

The expanded key schedule.

```c
typedef struct {
  uint8_t round_keys[PAMBLE_AES256_ROUNDS + 1][PAMBLE_AES_BLOCK_SIZE];
} pamble_aes256_key;
```

It is a public struct so callers can keep it on the stack and threads can share one copy read-only. Wrapping the round keys in a struct also gives them a type of their own: passing a raw key, an IV or a data block where the expanded key belongs is a compile error. It holds secret key material and should be wiped when no longer needed.

### `pamble_expand_aes256_keys`

Expands a 32-byte AES-256 key into its key schedule.

```c
void pamble_expand_aes256_keys(
    const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
    pamble_aes256_key expanded_keys[static 1]
);
```

Round keys 0 and 1 are the two halves of the original key; rounds 2 to 14 are derived from them.

### `pamble_aes256_encrypt_block`

Encrypts one 16-byte block.

```c
void pamble_aes256_encrypt_block(
    const pamble_aes256_key aes256_keys[static 1],
    const uint8_t plain_text[static PAMBLE_AES_BLOCK_SIZE],
    uint8_t cipher_text_buffer[static PAMBLE_AES_BLOCK_SIZE]
);
```

`plain_text` and `cipher_text_buffer` may be the same buffer: the block is copied into the internal state before anything is written. The expanded key is only read, never modified.

## Internal Design

### Key Expansion

The key schedule is built as an array of 60 `key_word` values (4 bytes each):

- `initialize_key256_words` copies the key into words 0 to 7, four bytes per word.
- `generate_key256_words` derives words 8 to 59. Each word starts from the previous one. When the index is a multiple of 8 it applies `rot_word`, then `sub_word`, then XORs `AES_RCON[i / 8 - 1]` into the first byte. When the index is 4 past a multiple of 8 it applies `sub_word` alone; that extra step is specific to AES-256. The result is XORed with the word 8 positions back.
- `update_key256_expanded_keys` packs words 4r to 4r + 3 into round key r, one word per state column.

### State Layout

The state is `uint8_t matrix[4][4]`, indexed `[row][col]`. FIPS-197 fills it column by column:

```text
matrix[row][col] = block[row + 4 * col]
```

`plain_text_to_encryption_matrix`, `xor_matrix_keys` and `matrix_to_cipher_text` all use this mapping. Round keys are stored in the same byte order as a block, so AddRoundKey lines up byte for byte.

### Round Functions

- `sub_bytes` replaces every state byte with its `AES_SBOX` entry.
- `shift_rows` rotates row r left by r positions; row 0 is unchanged.
- `mix_cols` multiplies each column by the fixed matrix `[[2 3 1 1] [1 2 3 1] [1 1 2 3] [3 1 1 2]]` in GF(2^8).
- `xor_matrix_keys` XORs a round key into the state.
- `encryption_rounds` runs rounds 1 to 13 with round keys 1 to 13; `encryption_last_round` runs round 14 (no MixColumns) with round key 14.

### GF(2^8) Multiplication

`gf_multiplication` multiplies two bytes in the AES field by shift-and-add. For each of the 8 bits of the second factor, starting from the lowest: if the bit is set, XOR the first factor into the result; then double the first factor, reducing by `0x1B` (the low byte of x^8 + x^4 + x^3 + x + 1) when its top bit overflows; then shift the second factor right to expose the next bit.

## Error Handling

There are no error paths. Size and non-NULL requirements are expressed in the parameter types with `static`, and every 32-byte key and 16-byte block is valid input.

## Usage

```c
pamble_aes256_key expanded_keys;

pamble_expand_aes256_keys(key, &expanded_keys);

for (size_t i = 0; i < block_count; i++) {
  pamble_aes256_encrypt_block(&expanded_keys, &input[i * 16], &output[i * 16]);
}

/* wipe expanded_keys */
```

Callers normally go through the CTR layer rather than encrypting blocks directly.

## Implementation Structure

```text
pamble_expand_aes256_keys
        │
        ├── initialize_key256_words      key → words[0..7]
        ├── generate_key256_words        words[8..59]
        │       ├── rot_word
        │       ├── sub_word
        │       └── xor_key_word
        └── update_key256_expanded_keys  words → round_keys[0..14]

pamble_aes256_encrypt_block
        │
        ├── plain_text_to_encryption_matrix
        ├── xor_matrix_keys(round_keys[0])
        ├── encryption_rounds            rounds 1..13
        │       ├── sub_bytes
        │       ├── shift_rows
        │       ├── mix_cols
        │       │       └── gf_multiplication
        │       └── xor_matrix_keys(round_keys[r])
        ├── encryption_last_round        round 14
        │       ├── sub_bytes
        │       ├── shift_rows
        │       └── xor_matrix_keys(round_keys[14])
        └── matrix_to_cipher_text
```

## Important Constants

| Constant | Value | Purpose |
| --- | ---: | --- |
| `PAMBLE_AES_BLOCK_SIZE` | 16 | Bytes per AES block |
| `PAMBLE_AES256_KEY_SIZE` | 32 | Bytes per AES-256 key |
| `PAMBLE_AES256_ROUNDS` | 14 | Rounds for AES-256 (15 round keys) |
| `KEY_WORD_SIZE` | 4 | Bytes per key-schedule word |
| `WORDS_PER_256KEY` | 8 | Words in the original key |
| `WORDS_PER_BLOCK` | 4 | Words (state columns) per round key |
| `KEY256_WORDS_ARRAY_SIZE` | 60 | Total key-schedule words |
| `SUB_WORD_ONLY_POSITION` | 4 | Offset where AES-256 applies SubWord alone |
| `EMS` | 4 | Rows and columns of the state |
| `AES_SBOX` | 256 entries | FIPS-197 substitution box |
| `AES_RCON` | 10 entries | Round constants; AES-256 uses the first 7 |

## Testing

`tests/test_pamble_aes.c` checks:

- FIPS-197 Appendix C.3 (the AES-256 example block).
- NIST SP 800-38A F.1.5, all four ECB-AES256 blocks.
- All-zero and all-ones key and block, cross-checked against OpenSSL.
- Round keys 0, 1, 2 and 14 against the FIPS-197 Appendix A.3 key expansion.
- In-place encryption, and that encrypting does not modify the expanded key.

## Design Notes

- Only the forward cipher exists. Counter mode encrypts counters and XORs the result onto the data, so decryption never needs inverse S-boxes or InvMixColumns.
- The S-box is a lookup table indexed by secret bytes. On shared hardware that can leak key bits through cache timing. That is acceptable for this project; a bitsliced S-box or AES-NI instructions would remove it.
- `pamble_expand_aes256_keys` leaves the intermediate key words on its stack. Wiping them, and the caller's `pamble_aes256_key`, belongs with the secure-zero helper planned for the seal layer.
- Each call is independent and reads the expanded key without writing it, so any number of threads can encrypt with one shared `pamble_aes256_key`.
