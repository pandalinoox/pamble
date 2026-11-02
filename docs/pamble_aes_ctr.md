# Pamble AES-256-CTR

`pamble_aes_ctr` is Pamble's AES-256 counter-mode (CTR) stream cipher. It turns the AES block cipher from [`pamble_aes`](pamble_aes.md) into a cipher that can encrypt or decrypt data of any length, with both a streaming interface and a one-shot interface.

## Overview

CTR mode does not run the message through AES. It encrypts a sequence of counter blocks to produce a keystream, then XORs the keystream onto the data:

1. Build a 16-byte counter block from a 12-byte nonce and a 4-byte big-endian counter.
2. Encrypt the counter block with AES-256 to get 16 bytes of keystream.
3. XOR keystream bytes onto the input, one byte at a time.
4. When the 16 keystream bytes are used up, add one to the counter and go back to step 2.

Because XOR is its own inverse, encryption and decryption are the same operation. Only the AES forward cipher is used, which is why `pamble_aes` has no decryption.

CTR provides confidentiality only. It does not detect modified ciphertext; pair it with a MAC such as [`pamble_hmac_sha256`](pamble_hmac_sha256.md).

## Status Interface

The common Pamble status interface is documented separately in [`pamble_status.md`](pamble_status.md).

All public functions except `pamble_aes_ctr_flatten_counter_block` return `pamble_status`. The codes in use are:

| Status | Returned when |
| --- | --- |
| `PAMBLE_OK` | The operation completed. |
| `PAMBLE_INVALID_ARGUMENT` | A required context is `NULL`, or `input_message` is `NULL` while `input_message_length` is non-zero. |
| `PAMBLE_COUNTER_EXHAUSTED` | A message needs more than 2^32 keystream blocks under one nonce. |

Array parameters declared with `[static N]` (the key, the output buffer, the flatten output) must be non-`NULL` and large enough; they are not checked at run time.

## API

### Constants

```c
#define PAMBLE_AES_CTR_NONCE_BYTES 12
#define PAMBLE_AES_CTR_COUNTER_BYTES 4
#define PAMBLE_AES_CTR_BLOCK_BYTES 16
```

### `pamble_aes_ctr_counter_block`

The counter block, split into its two parts.

```c
typedef struct {
  uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES];
  uint8_t value[PAMBLE_AES_CTR_COUNTER_BYTES];
} pamble_aes_ctr_counter_block;
```

The serialized block is `nonce || value`, with `value` stored most significant byte first. The counter never carries into the nonce, so one (key, nonce) pair covers at most 2^32 blocks (64 GiB).

### `pamble_aes_ctr_ctx`

The streaming state.

```c
typedef struct {
  pamble_aes256_key expanded_aes_keys;
  pamble_aes_ctr_counter_block counter;
  uint8_t keystream_block[PAMBLE_AES_BLOCK_SIZE];
  uint8_t keystream_offset;
  bool exhausted_counter;
} pamble_aes_ctr_ctx;
```

| Field | Meaning |
| --- | --- |
| `expanded_aes_keys` | AES-256 key schedule. Secret. |
| `counter` | Counter block for the *next* keystream block. |
| `keystream_block` | Most recently generated keystream block. Secret. |
| `keystream_offset` | Bytes of `keystream_block` already used; 16 means a new block is needed. |
| `exhausted_counter` | `true` once the counter value `0xFFFFFFFF` has been used. |

The context can live on the stack. Treat its fields as opaque, and do not share one context between threads.

### `pamble_aes_ctr_flatten_counter_block`

Serializes a counter block into the 16 bytes that AES encrypts.

```c
void pamble_aes_ctr_flatten_counter_block(
    const pamble_aes_ctr_counter_block *counter_block,
    uint8_t output_buffer[static PAMBLE_AES_CTR_BLOCK_BYTES]);
```

### `pamble_aes_ctr_init`

Expands the key and prepares a context.

```c
pamble_status pamble_aes_ctr_init(
    pamble_aes_ctr_ctx *ctx,
    const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
    pamble_aes_ctr_counter_block initial_counter);
```

The first update call generates its keystream from `initial_counter`. Returns `PAMBLE_INVALID_ARGUMENT` if `ctx` is `NULL`.

### `pamble_aes_ctr_update`

Encrypts or decrypts the next chunk of a message.

```c
pamble_status pamble_aes_ctr_update(
    pamble_aes_ctr_ctx *ctx,
    const uint8_t *input_message,
    size_t input_message_length,
    uint8_t output_buffer[static input_message_length]);
```

- A message may be split across any number of calls, of any sizes, with the same result as a single call. Unused keystream bytes carry over between calls.
- `input_message` and `output_buffer` may be the same buffer. Any other overlap is not supported.
- A zero-length call succeeds and does nothing. `input_message` may be `NULL` in that case.
- If the message needs a keystream block after the counter is spent, the call returns `PAMBLE_COUNTER_EXHAUSTED`. Bytes processed before that point are already in `output_buffer`; discard them.

### `pamble_aes_ctr_cleanup`

Wipes the context with `explicit_bzero`.

```c
pamble_status pamble_aes_ctr_cleanup(pamble_aes_ctr_ctx *ctx);
```

Call this when a streaming operation is finished or abandoned. The context must be initialized again before reuse.

### `pamble_aes_ctr_crypt`

One-shot encrypt or decrypt.

```c
pamble_status pamble_aes_ctr_crypt(
    const uint8_t key[static PAMBLE_AES256_KEY_SIZE],
    uint8_t nonce[PAMBLE_AES_CTR_NONCE_BYTES],
    const uint8_t *input_message,
    size_t input_message_length,
    uint8_t output_buffer[static input_message_length]);
```

Creates an internal context, runs init, update and cleanup in order, and wipes the context before returning. The name says "encrypt" but decryption is the same call.

The context is wiped even when `update` fails (for example with `PAMBLE_COUNTER_EXHAUSTED`), so no key material is left behind on error. If the arguments are rejected, the context is not initialized. The first error encountered is the one returned.

## Internal Design

### Keystream Buffering

`keystream_block` and `keystream_offset` let the cipher work on byte boundaries. `update` loops over the input; whenever `keystream_offset` reaches 16 it generates a new block:

1. Serialize `ctx->counter` with `pamble_aes_ctr_flatten_counter_block`.
2. Encrypt it with `pamble_aes256_encrypt_block` into `keystream_block`.
3. Advance the counter (see below).
4. Reset `keystream_offset` to 0.

Each input byte is then XORed with `keystream_block[keystream_offset]` and the offset is incremented. `init` sets the offset to 16 so the first byte triggers block generation.

### Counter Increment

`increment_counter_block` adds one to the 4-byte big-endian counter. It increments the last byte and, if that wraps to zero, carries into the previous byte, stopping at the first byte that does not wrap. The nonce is never touched.

### Exhaustion

The counter has 2^32 usable values, `0x00000000` to `0xFFFFFFFF`. `is_counter_exhausted` reports whether the counter is `0xFFFFFFFF`.

When a keystream block is generated, the code checks for this before advancing:

- If the counter is below the maximum, it is incremented as usual.
- If it is at the maximum, `exhausted_counter` is set and the counter is left alone instead of wrapping to zero.

The block for `0xFFFFFFFF` is still used in full. Only when another block is needed does `update` see `exhausted_counter` and return `PAMBLE_COUNTER_EXHAUSTED`. The flag is never cleared, so later calls that need keystream keep failing.

## Error Handling

- `NULL` context in the streaming interface and `NULL` input with non-zero length are rejected before any work is done.
- A failure in the middle of `update` can leave `output_buffer` partly written. Only `PAMBLE_COUNTER_EXHAUSTED` can occur at that point.
- `pamble_aes_ctr_crypt` wipes its internal context even when it fails; see above.

## Usage

### One-shot

```c
pamble_status status = pamble_aes_ctr_crypt(
    key, nonce, plain_text, plain_text_length, cipher_text);

if (status != PAMBLE_OK) {
  /* handle error */
}
```

Decrypting is the same call with the same key and nonce, passing the ciphertext as input.

### Streaming

```c
pamble_aes_ctr_ctx ctx;

PAMBLE_RETURN_IF_ERROR(pamble_aes_ctr_init(&ctx, key, counter));

while (more_data) {
  size_t n = read_chunk(buffer, sizeof(buffer));
  status = pamble_aes_ctr_update(&ctx, buffer, n, buffer); /* in place */
  if (status != PAMBLE_OK) break;
  write_chunk(buffer, n);
}

pamble_aes_ctr_cleanup(&ctx);
```

## Implementation Structure

```text
pamble_aes_ctr_crypt
        │
        ├── pamble_aes_ctr_init
        │       └── pamble_expand_aes256_keys
        ├── pamble_aes_ctr_update
        │       ├── pamble_aes_ctr_flatten_counter_block
        │       ├── pamble_aes256_encrypt_block
        │       ├── is_counter_exhausted
        │       └── increment_counter_block
        └── pamble_aes_ctr_cleanup
                └── explicit_bzero
```

## Important Constants

| Constant | Value | Purpose |
| --- | ---: | --- |
| `PAMBLE_AES_CTR_NONCE_BYTES` | 12 | Bytes of nonce in a counter block |
| `PAMBLE_AES_CTR_COUNTER_BYTES` | 4 | Bytes of counter in a counter block |
| `PAMBLE_AES_CTR_BLOCK_BYTES` | 16 | Size of a serialized counter block |
| `PAMBLE_AES256_KEY_SIZE` | 32 | Bytes per AES-256 key |
| `PAMBLE_AES_BLOCK_SIZE` | 16 | Bytes per keystream block |

## Testing

`tests/test_pamble_aes_ctr.c` checks:

- NIST SP 800-38A F.5.5 (CTR-AES256), for one-shot encryption, one-shot decryption, streaming, and a 37-byte partial final block.
- Keystream blocks for counters `0x00000000` and `0xFFFFFFFF`, and a carry from `0x000000FF` to `0x00000100`, cross-checked against an independent AES-256-ECB implementation.
- Chunked updates at every split point and byte-at-a-time updates match the one-shot result.
- In-place operation, round trip, and different nonces giving different keystreams.
- Counter layout: flattening, big-endian increments, and the nonce staying unchanged across carries.
- Context handling: `init` state, `cleanup` zeroing the whole struct, and `encrypt` wiping its internal context on success and on failure.
- Exhaustion: the last counter value is usable, the counter does not wrap, bytes before the limit are written, the flag is sticky, and the one-shot call reports it.
- `NULL` arguments and zero-length input.

## Design Notes

- The 12-byte nonce / 4-byte counter split gives at most 64 GiB per (key, nonce). Large archives must use a fresh nonce per file or per segment.
- Never reuse a (key, nonce, counter) combination for two messages. Doing so lets an attacker XOR the two ciphertexts to get the XOR of the plaintexts.
- CTR is malleable: flipping a ciphertext bit flips the same plaintext bit. Authenticate the ciphertext (encrypt-then-MAC).
- Output is produced byte by byte, so there is no alignment requirement and no padding.
- Keystream bytes and the expanded key stay in the context until `pamble_aes_ctr_cleanup`; the stack buffer used for the serialized counter block in `update` is not wiped.
