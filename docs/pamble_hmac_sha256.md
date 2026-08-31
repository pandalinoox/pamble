# Pamble HMAC-SHA256

`pamble_hmac_sha256` is Pamble's HMAC-SHA256 implementation. It provides a one-shot interface for computing a keyed-hash message authentication code over a message, using `pamble_sha256` as its underlying hash function.

## Overview

The implementation follows the standard HMAC construction:

1. Normalize the supplied key to a single 64-byte block.
2. Derive the inner key by XORing the normalized key with the `ipad` byte.
3. Derive the outer key by XORing the normalized key with the `opad` byte.
4. Hash the concatenation of the inner key and the message.
5. Hash the concatenation of the outer key and the inner hash.
6. Return the result of the outer hash as the HMAC.

The implementation uses `pamble_sha256` for every hashing step and works entirely in terms of 64-byte blocks and 32-byte digests, matching SHA-256's block and digest sizes.

## Status Interface

The common Pamble status interface is documented separately in [`pamble_status.md`](pamble_status.md).

The HMAC-SHA256 API uses `pamble_status` for success and error reporting on its single public function. This includes argument validation and propagation of failures from the underlying `pamble_sha256` calls.

See [`pamble_status.md`](pamble_status.md) for:

- The complete `pamble_status` enum.
- The meaning of each status value.
- The `PAMBLE_RETURN_IF_ERROR` propagation macro.
- General status-handling conventions used throughout Pamble.

## API

### `pamble_hmac_sha256`

Computes the HMAC-SHA256 of a message under a given key.

```c
pamble_status pamble_hmac_sha256(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *message,
    size_t message_length,
    uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]
);
```

The function:

- Normalizes the key to a 64-byte block.
- Derives the inner and outer keys.
- Computes the inner hash over the inner key and message.
- Computes the outer hash over the outer key and inner hash.
- Writes the outer hash to `output_buffer` as the HMAC.

`key` may be `NULL` when `key_length` is zero. A `NULL` key with a non-zero length returns `PAMBLE_INVALID_ARGUMENT`.

`message` may be `NULL` when `message_length` is zero. A `NULL` message with a non-zero length returns `PAMBLE_INVALID_ARGUMENT`.

Because the entire message is provided up front, there is no streaming interface; the underlying SHA-256 computations are each performed as one-shot calls to `pamble_sha256`.

## Internal Design

### Key Normalization

HMAC requires a key exactly one block (64 bytes) long. The implementation's `normalize_key` function produces this from a key of any length:

- If the key is longer than 64 bytes, it is hashed with `pamble_sha256`, and the 32-byte digest becomes the normalized key.
- If the key is 64 bytes or shorter, it is copied as-is.
- The remaining bytes of the 64-byte buffer are zero-filled.

A `NULL` key with a non-zero `key_length` returns `PAMBLE_INVALID_ARGUMENT`. A hashing failure while normalizing an oversized key is propagated to the caller.

### Inner and Outer Keys

The implementation's `key_xor` function derives both the inner and outer keys from the normalized key by XORing every byte against a constant:

```text
inner_key[i] = normalized_key[i] XOR IPAD
outer_key[i] = normalized_key[i] XOR OPAD
```

where `IPAD` is `0x36` and `OPAD` is `0x5c`, applied across all 64 bytes.

### Concatenation

The implementation's `array_concat` function builds the two hash inputs required by HMAC:

- The inner hash input: the 64-byte inner key followed by the message.
- The outer hash input: the 64-byte outer key followed by the 32-byte inner hash.

Both concatenations are built into stack buffers sized to the exact combined length before being passed to `pamble_sha256`.

### Inner and Outer Hashing

The implementation computes:

```text
inner_hash = SHA256(inner_key || message)
outer_hash = SHA256(outer_key || inner_hash)
```

`outer_hash` is the HMAC-SHA256 result and is copied into the caller's `output_buffer`.

## Error Handling

Error reporting for the HMAC-SHA256 API is provided by Pamble's common status interface.

See [`pamble_status.md`](pamble_status.md) for the complete list of status codes, their meanings, and the `PAMBLE_RETURN_IF_ERROR` propagation convention.

`pamble_hmac_sha256` validates its own `key` and `message` arguments directly and propagates any failure from the internal `pamble_sha256` calls — used both for oversized-key normalization and for the inner and outer hash computations — using `PAMBLE_RETURN_IF_ERROR`. Internal helper functions (`normalize_key` aside, since it calls `pamble_sha256`) have no fallible preconditions given how they are invoked, so `key_xor` and `array_concat` return `void` rather than `pamble_status`.

## Usage

```text
pamble_hmac_sha256(key, key_length, message, message_length, mac)
```

internally performs key normalization, inner/outer key derivation, and the two nested SHA-256 computations, writing the resulting 32-byte MAC to `mac`.

Because the interface is one-shot, the complete key and message must be available at the time of the call.

## Implementation Structure

The implementation is organized around the HMAC construction's stages:

```text
pamble_hmac_sha256
        │
        ├── normalize_key
        │       └── pamble_sha256 (only if key_length > 64)
        │
        ├── key_xor(IPAD) → inner_key
        ├── key_xor(OPAD) → outer_key
        │
        ├── array_concat(inner_key, message) → inner_hash_input
        ├── pamble_sha256(inner_hash_input) → inner_hash
        │
        ├── array_concat(outer_key, inner_hash) → outer_hash_input
        └── pamble_sha256(outer_hash_input) → outer_hash → output_buffer
```

This keeps the HMAC-specific key handling and concatenation logic separate from the SHA-256 hashing itself, which is reused unmodified from `pamble_sha256`.

## Important Constants

The implementation uses:

| Constant | Value | Purpose |
| --- | ---: | --- |
| `BYTES_PER_BLOCK` | 64 | SHA-256 block size and normalized key length |
| `IPAD` | `0x36` | Inner key XOR constant |
| `OPAD` | `0x5c` | Outer key XOR constant |

`PAMBLE_SHA256_DIGEST_LENGTH` (32 bytes), defined by the SHA-256 API, sizes both the inner hash and the final HMAC output.

## Digest Representation

HMAC-SHA256 produces a 256-bit MAC, identical in size to a SHA-256 digest:

```text
256 bits = 32 bytes
```

The output buffer supplied to `pamble_hmac_sha256` therefore needs space for `PAMBLE_SHA256_DIGEST_LENGTH` bytes.

## Design Notes

- The implementation reuses `pamble_sha256` unmodified for all hashing; it contains no SHA-256 compression logic of its own.
- Key normalization, key derivation, and concatenation are each isolated in small internal helper functions.
- The interface is one-shot only; no streaming context is exposed for HMAC computation.
- `pamble_status` provides the common success and error-reporting mechanism, propagated from both argument validation and the underlying `pamble_sha256` calls via `PAMBLE_RETURN_IF_ERROR`.
- The implementation uses fixed-size and variable-length stack buffers sized exactly to the block and message lengths involved, avoiding heap allocation.
