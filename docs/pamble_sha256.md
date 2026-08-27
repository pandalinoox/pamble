# Pamble SHA-256

`pamble_sha256` is Pamble's SHA-256 implementation. It provides both a streaming interface and a one-shot convenience interface for computing SHA-256 digests.

## Overview

The implementation follows the SHA-256 block-processing model:

1. Initialize the eight-word hash state.
2. Accept message data through the update interface.
3. Buffer incomplete 512-bit blocks.
4. Convert each 512-bit block into a 64-word message schedule.
5. Run the 64 SHA-256 compression rounds.
6. Add the compressed working variables back into the hash state.
7. During finalization, append SHA-256 padding and the original message length.
8. Export the eight 32-bit state words as the 32-byte digest.

The implementation uses 32-bit words, 64-byte message blocks, and a 64-bit message-length field.

## Status Interface

The common Pamble status interface is documented separately in [`pamble_status.md`](pamble_status.md).

The SHA-256 API uses `pamble_status` for success and error reporting. This includes argument validation, SHA-256 message-size overflow detection, and propagation of internal helper failures.

See [`pamble_status.md`](pamble_status.md) for:

- The complete `pamble_status` enum.
- The meaning of each status value.
- The `PAMBLE_RETURN_IF_ERROR` propagation macro.
- General status-handling conventions used throughout Pamble.

## API

### `pamble_sha256_init`

Initializes a SHA-256 context.

```c
pamble_status pamble_sha256_init(pamble_sha256_ctx *ctx);
```

The function:

- Initializes the eight hash-state words to the SHA-256 initial constants.
- Clears the buffered message length.
- Clears the total message length.
- Clears the internal 64-byte buffer.

Passing `NULL` as `ctx` returns `PAMBLE_INVALID_ARGUMENT`.

### `pamble_sha256_update`

Adds message data to an existing SHA-256 computation.

```c
pamble_status pamble_sha256_update(
    pamble_sha256_ctx *ctx,
    const uint8_t *message,
    size_t message_length
);
```

The update operation handles input in three stages:

- Complete a previously partially filled internal block, if one exists.
- Process all complete 64-byte blocks directly from the supplied message.
- Copy the remaining bytes into the internal buffer for the next update or finalization.

The context tracks the total message length in bytes.

`message` may be `NULL` when `message_length` is zero. A `NULL` message with a non-zero length returns `PAMBLE_INVALID_ARGUMENT`.

If the message length would exceed the maximum length representable by SHA-256, the function returns `PAMBLE_SIZE_OVERFLOW`.

### `pamble_sha256_final`

Finalizes a SHA-256 computation and writes the digest.

```c
pamble_status pamble_sha256_final(
    const pamble_sha256_ctx *ctx,
    uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]
);
```

Finalization operates on a copy of the supplied context, so the original context is not modified.

The finalization process:

1. Calculates the message length in bits.
2. Appends the `0x80` padding byte.
3. Adds zero padding.
4. Appends the original message length as a 64-bit big-endian value.
5. Processes the final block, or two final blocks when necessary.
6. Converts the eight hash-state words into the 32-byte digest.

A buffered length greater than or equal to 64 bytes is treated as an invalid context and returns `PAMBLE_INVALID_ARGUMENT`.

### `pamble_sha256`

Provides the one-shot SHA-256 interface.

```c
pamble_status pamble_sha256(
    const uint8_t *message,
    size_t message_length,
    uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]
);
```

It performs:

```text
init → update → final
```

This is the preferred interface when the complete message is already available.

## Internal Design

### SHA-256 Context

The context contains:

- `hash_state[8]` — the current eight 32-bit SHA-256 state words.
- `buffer[64]` — buffered message bytes that do not yet form a complete block.
- `buffer_length` — number of bytes currently stored in the buffer.
- `message_length` — total message length in bytes.

The implementation keeps the context opaque to callers through the public API.

### Initial Hash Values

The implementation initializes the hash state with the standard SHA-256 initial values:

```text
6a09e667
bb67ae85
3c6ef372
a54ff53a
510e527f
9b05688c
1f83d9ab
5be0cd19
```

These are copied into the context during `pamble_sha256_init`.

### Message Blocks

SHA-256 processes messages in 512-bit blocks.

```text
512 bits = 64 bytes = 16 × 32-bit words
```

Each block is interpreted as sixteen big-endian 32-bit words.

The implementation converts the first sixteen words using `bytes_to_word`, then expands them into the complete 64-word message schedule.

### Message Schedule

The first 16 schedule words come directly from the message block.

Words 16 through 63 are generated using the SHA-256 small-sigma functions:

```text
W[i] = W[i-16] + σ1(W[i-15]) + W[i-7] + σ0(W[i-2])
```

The implementation's `sigma1` function computes:

```text
σ1(x) = ROTR(7, x) XOR ROTR(18, x) XOR SHR(3, x)
```

and `sigma2` computes:

```text
σ0(x) = ROTR(17, x) XOR ROTR(19, x) XOR SHR(10, x)
```

The names in the implementation are `sigma1` and `sigma2`; they correspond to the two small-sigma functions used for message-schedule expansion.

### Compression

Each block is compressed using eight working variables:

```text
a b c d e f g h
```

The working variables are initialized from the current hash state.

Each of the 64 rounds uses:

- One SHA-256 round constant `K[i]`.
- One expanded message word `W[i]`.
- The SHA-256 big-sigma functions.
- The `Ch` (choose) function.
- The `Maj` (majority) function.

The implementation computes:

```text
Σ1(e) = ROTR(6, e) XOR ROTR(11, e) XOR ROTR(25, e)

Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)

temp1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]

Σ0(a) = ROTR(2, a) XOR ROTR(13, a) XOR ROTR(22, a)

Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)

temp2 = Σ0(a) + Maj(a,b,c)
```

The working variables are then shifted and updated for the next round.

After all 64 rounds, the eight working variables are added to the current hash state.

## Padding and Finalization

SHA-256 appends padding so that the final message length is congruent to 448 bits modulo 512, leaving the final 64 bits for the original message length.

The implementation starts padding with:

```text
0x80
```

followed by zero bytes.

The original message length is stored internally in bytes and converted to bits during finalization:

```text
bit_length = message_length × 8
```

That 64-bit bit length is encoded in big-endian order into the final eight bytes of the final block.

If the current buffered message does not have enough room for both the `0x80` byte and the length field, the implementation processes an additional block before constructing the final block.

## Endianness

SHA-256 uses big-endian representation for:

- Input 32-bit message words.
- The final 64-bit message length.
- The exported 32-byte digest.

The implementation explicitly performs these conversions rather than relying on the host machine's native byte order.

## Error Handling

Error reporting for the SHA-256 API is provided by Pamble's common status interface.

See [`pamble_status.md`](pamble_status.md) for the complete list of status codes, their meanings, and the `PAMBLE_RETURN_IF_ERROR` propagation convention.

The SHA-256 implementation uses `pamble_status` consistently across its public API and internal helper functions. Internal helper failures are propagated through their callers using `PAMBLE_RETURN_IF_ERROR`.

## Streaming Usage

The streaming interface is useful when the complete input is not available at once.

Conceptually:

```text
pamble_sha256_init(ctx)

pamble_sha256_update(ctx, chunk_1, chunk_1_length)
pamble_sha256_update(ctx, chunk_2, chunk_2_length)
pamble_sha256_update(ctx, chunk_3, chunk_3_length)
...

pamble_sha256_final(ctx, digest)
```

The result is independent of how the message is divided between `update` calls. Complete blocks are processed immediately, while incomplete data remains buffered until more data arrives or finalization occurs.

## One-Shot Usage

When the complete message is already available:

```text
pamble_sha256(message, message_length, digest)
```

internally performs initialization, update, and finalization.

## Implementation Structure

The implementation is organized around the SHA-256 algorithm's major stages:

```text
pamble_sha256_init
        │
        ▼
pamble_sha256_update
        │
        ├── buffer incomplete block
        │
        └── process_message_block
                    │
                    ├── initialize_words_state
                    │       ├── initialize_initial_words
                    │       └── expand_words_state
                    │
                    ├── initialize_working_variable_values
                    │
                    ├── words_state_compression
                    │       └── sha256_compression_round × 64
                    │
                    └── update_hash_state
        │
        ▼
pamble_sha256_final
        │
        ├── apply padding
        ├── encode message length
        ├── process final block(s)
        └── export_digest
```

This keeps the block-level SHA-256 operations separate from the public streaming API.

## Important Constants

The implementation uses:

| Constant | Value | Purpose |
| --- | ---: | --- |
| `BYTES_PER_BLOCK` | 64 | SHA-256 block size |
| `BYTES_PER_LENGTH_FIELD` | 8 | Encoded message length |
| `PADDING_BYTE` | `0x80` | First padding byte |
| `H_VALUES_SIZE` | 8 | Hash-state words |
| `K_VALUES_SIZE` | 64 | Compression round constants |
| `BYTES_PER_WORD` | 4 | SHA-256 word size |
| `BITS_PER_WORD` | 32 | SHA-256 word size in bits |
| `WORDS_STATE_SIZE` | 64 | Message-schedule words |
| `WORKING_VARIABLES_SIZE` | 8 | Compression working variables |

## Digest Representation

SHA-256 produces a 256-bit digest:

```text
256 bits = 32 bytes
```

The implementation exports the eight 32-bit hash-state words consecutively in big-endian byte order.

The output buffer supplied to `pamble_sha256_final` and `pamble_sha256` therefore needs space for `PAMBLE_SHA256_DIGEST_LENGTH` bytes.

## Design Notes

- The implementation does not depend on the host machine's endianness for SHA-256 word encoding.
- The streaming API does not require callers to align input to 64-byte boundaries.
- Finalization does not mutate the caller's context.
- `pamble_status` provides the common success and error-reporting mechanism for the public API and internal helpers.
- Internal helper failures are propagated through `PAMBLE_RETURN_IF_ERROR`.
- The implementation uses fixed-size local arrays for the 64-word message schedule and eight working variables during block processing.
