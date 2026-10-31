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

The HMAC-SHA256 API uses `pamble_status` for success and error reporting on its public functions. This includes argument validation and propagation of failures from the underlying `pamble_sha256` calls.

See [`pamble_status.md`](pamble_status.md) for:

- The complete `pamble_status` enum.
- The meaning of each status value.
- The `PAMBLE_RETURN_IF_ERROR` propagation macro.
- General status-handling conventions used throughout Pamble.

## API

### `pamble_hmac_sha256_init`

Initializes an HMAC-SHA256 context using the supplied key.

```c
pamble_status pamble_hmac_sha256_init(
    pamble_hmac_sha256_ctx *ctx,
    const uint8_t *key,
    size_t key_length
);
```

The function normalizes the key, derives the inner and outer keys, and
initializes the corresponding SHA-256 contexts.

### `pamble_hmac_sha256_update`

Adds message data to an existing HMAC-SHA256 computation.

```c
pamble_status pamble_hmac_sha256_update(
    pamble_hmac_sha256_ctx *ctx,
    const uint8_t *message,
    size_t message_length
);
```

The update operation adds the supplied message data to the inner SHA-256
computation. The message may be supplied over multiple calls.

`message` may be `NULL` when `message_length` is zero. A `NULL` message with a
non-zero length returns `PAMBLE_INVALID_ARGUMENT`.

### `pamble_hmac_sha256_final`

Finalizes an HMAC-SHA256 computation and writes the digest.

```c
pamble_status pamble_hmac_sha256_final(
    pamble_hmac_sha256_ctx *ctx,
    uint8_t output_buffer[PAMBLE_SHA256_DIGEST_LENGTH]
);
```

Finalization computes the inner digest, adds it to the outer SHA-256
computation, and writes the resulting HMAC to `output_buffer`.

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

The one-shot function performs the same initialization, update, and finalization steps using the complete message provided in a single call.

## Streaming Usage

The streaming interface can be used when the complete message is not
available at once:

```text
init → update → update → ... → final
```

The context must be initialized before updating it, and finalization is
performed after all message data has been supplied.

## Internal Design

### Key Normalization

HMAC requires a key exactly one block (64 bytes) long. The implementation's `normalize_key` function produces this from a key of any length:

- If the key is longer than 64 bytes, it is hashed with `pamble_sha256`, and the 32-byte digest becomes the normalized key.
- If the key is 64 bytes or shorter, it is copied as-is. An empty key (which may be `NULL`) copies nothing, so `memcpy` is never called with a `NULL` source.
- The remaining bytes of the 64-byte buffer are zero-filled.

A `NULL` key with a non-zero `key_length` returns `PAMBLE_INVALID_ARGUMENT`. A hashing failure while normalizing an oversized key is propagated to the caller.

### Inner and Outer Keys

The implementation's `key_xor` function derives both the inner and outer keys from the normalized key by XORing every byte against a constant:

```text
inner_key[i] = normalized_key[i] XOR IPAD
outer_key[i] = normalized_key[i] XOR OPAD
```

where `IPAD` is `0x36` and `OPAD` is `0x5c`, applied across all 64 bytes.

### Inner and Outer Hashing

The implementation initializes the inner SHA-256 context with the inner key
and the outer SHA-256 context with the outer key.

Message data supplied through `pamble_hmac_sha256_update` is added to the
inner context. During finalization, the implementation computes:

```text
inner_hash = SHA256(inner_key || message)
outer_hash = SHA256(outer_key || inner_hash)
```

`outer_hash` is the HMAC-SHA256 result and is written to the caller's
`output_buffer`.

## Error Handling

Error reporting for the HMAC-SHA256 API is provided by Pamble's common status interface.

See [`pamble_status.md`](pamble_status.md) for the complete list of status codes, their meanings, and the `PAMBLE_RETURN_IF_ERROR` propagation convention.

`pamble_hmac_sha256_init` validates the context and key arguments, while `pamble_hmac_sha256_update` validates the context and message arguments. The update and finalization functions propagate failures from the underlying `pamble_sha256` calls. The `normalize_key` helper also propagates a failure when hashing an oversized key.

## Usage

```text
pamble_hmac_sha256_init(ctx, key, key_length)
pamble_hmac_sha256_update(ctx, message, message_length)
pamble_hmac_sha256_final(ctx, mac)
```

The message may be supplied over multiple calls to `pamble_hmac_sha256_update`. The one-shot `pamble_hmac_sha256` function performs these steps when the complete message is available at the time of the call.

## Implementation Structure

The implementation is organized around the HMAC construction's stages:

```text
pamble_hmac_sha256_init
        │
        ├── normalize_key
        │       └── pamble_sha256 (only if key_length > 64)
        │
        ├── key_xor(IPAD) → inner_key → inner SHA-256 context
        └── key_xor(OPAD) → outer_key → outer SHA-256 context

pamble_hmac_sha256_update
        └── pamble_sha256_update(inner context, message)

pamble_hmac_sha256_final
        ├── pamble_sha256_final(inner context) → inner_hash
        ├── pamble_sha256_update(outer context, inner_hash)
        └── pamble_sha256_final(outer context) → output_buffer
```

This keeps the HMAC-specific key handling separate from the SHA-256 hashing
itself, which is reused unmodified from `pamble_sha256`.

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
- Key normalization and key derivation are isolated in small internal helper functions.
- The interface provides both streaming and one-shot HMAC computation.
- `pamble_status` provides the common success and error-reporting mechanism for argument validation and the underlying `pamble_sha256` calls.
- The implementation uses fixed-size stack buffers for key normalization, key derivation, and the intermediate digest, avoiding heap allocation.
