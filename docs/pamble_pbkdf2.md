# Pamble PBKDF2

`pamble_pbkdf2` is Pamble's PBKDF2 implementation. It provides a one-shot interface for deriving a key of arbitrary length from a password and salt, using `pamble_hmac_sha256` as its underlying pseudorandom function.

## Overview

The implementation follows the standard PBKDF2 construction, as built on HMAC-SHA256:

1. Split the requested derived-key length into 32-byte blocks, numbered starting at 1.
2. For each block `i`, compute `U_1 = HMAC-SHA256(password, salt || INT(i))`, where `INT(i)` is the block index encoded as 4 big-endian bytes.
3. Repeat `U_j = HMAC-SHA256(password, U_{j-1})` for a fixed number of iterations, XORing each `U_j` into a running accumulator to produce `T_i = U_1 XOR U_2 XOR ... XOR U_c`.
4. Concatenate the blocks `T_1 || T_2 || ...`, truncating the final block as needed, to produce a derived key of exactly the requested length.

The implementation uses `pamble_hmac_sha256` for every pseudorandom-function application and works entirely in terms of 32-byte blocks, matching HMAC-SHA256's digest size.

## Status Interface

The common Pamble status interface is documented separately in [`pamble_status.md`](pamble_status.md).

The PBKDF2 API uses `pamble_status` for success and error reporting on its public derivation function. This includes argument validation and propagation of failures from the underlying `pamble_hmac_sha256` calls, as well as allocation failure for the output buffer.

See [`pamble_status.md`](pamble_status.md) for:

- The complete `pamble_status` enum.
- The meaning of each status value.
- The `PAMBLE_RETURN_IF_ERROR` propagation macro.
- General status-handling conventions used throughout Pamble.

## API

### `pamble_pbkdf2`

Derives a key of arbitrary length from a password and salt using PBKDF2-HMAC-SHA256.

```c
pamble_status pamble_pbkdf2(
    const uint8_t *password,
    size_t password_length,
    const uint8_t *salt,
    size_t salt_length,
    uint8_t **derived_key,
    size_t dk_length
);
```

The function:

- Computes the number of 32-byte blocks needed to cover `dk_length`, rounding up.
- Allocates a `dk_length`-byte output buffer for the derived key.
- Derives each block `T_i` from the password, salt, and block index.
- Copies each block (truncating the final block if necessary) into the output buffer at the correct offset.
- Writes the address of the newly allocated buffer to `*derived_key`.

`password` may be `NULL` when `password_length` is zero. A `NULL` password with a non-zero length returns `PAMBLE_INVALID_ARGUMENT`.

`salt` may be `NULL` when `salt_length` is zero. A `NULL` salt with a non-zero length returns `PAMBLE_INVALID_ARGUMENT`.

`derived_key` must not be `NULL`, and `dk_length` must be non-zero; otherwise the function returns `PAMBLE_INVALID_ARGUMENT`.

Because the interface is one-shot, the complete password and salt must be available at the time of the call, and the entire derived key is produced and returned at once.

### `pamble_free_pbkdf2_dk`

Frees a derived key previously allocated by `pamble_pbkdf2`.

```c
void pamble_free_pbkdf2_dk(uint8_t *derived_key);
```

`derived_key` may be `NULL`, in which case the call is a no-op. Callers are responsible for calling this function to release the buffer written to `*derived_key` by a successful `pamble_pbkdf2` call.

## Internal Design

### Block Index Encoding

PBKDF2 appends a big-endian, 1-based block counter to the salt when deriving each block. The implementation's `int32_be` function produces this encoding:

```text
output_buffer[i] = block_no >> ((3 - i) * 8), for i = 0..3
```

yielding the standard 4-byte big-endian representation of `block_no` used as `INT(i)` in the PBKDF2 specification.

### Concatenation

The implementation's `array_concat` function (mirroring the helper of the same name in `pamble_hmac_sha256`) builds the salt input required for each block's first HMAC application: the salt followed by the 4-byte big-endian block index. The concatenation is built into a stack buffer sized to the exact combined length before being passed to `pamble_hmac_sha256`. An empty salt (which may be `NULL`) is skipped rather than passed to `memcpy`, since `memcpy` with a `NULL` pointer is undefined behavior even when the length is zero.

### Per-Block Iteration

The implementation's `process_block` function derives a single output block, `T_i`:

- Computes `U_1 = HMAC-SHA256(password, salt || INT(block_no))`.
- Seeds the running accumulator `T` with `U_1`.
- Calls the implementation's `process_iteration` function for each remaining iteration `j = 2..PAMBLE_PBKDF2_ITERATIONS`, which computes `U_j = HMAC-SHA256(password, U_{j-1})` in place and XORs the result into `T`.
- Leaves the final accumulated value in `T`, which is `T_i`.

`PAMBLE_PBKDF2_ITERATIONS` is a fixed, compile-time iteration count; the implementation does not accept a caller-supplied iteration count.

### Output Assembly

`pamble_pbkdf2` allocates a `dk_length`-byte buffer with `calloc`. For each derived block, the implementation's `write_block_output` function copies as many of the block's 32 bytes as remain to be filled — truncating the final block if `dk_length` is not an exact multiple of 32 — into the buffer at the appropriate offset, and returns the number of bytes copied. `pamble_pbkdf2` uses this return value to update a running count of remaining unwritten bytes, which determines how much of the next block to copy.

## Error Handling

Error reporting for the PBKDF2 API is provided by Pamble's common status interface.

See [`pamble_status.md`](pamble_status.md) for the complete list of status codes, their meanings, and the `PAMBLE_RETURN_IF_ERROR` propagation convention.

`pamble_pbkdf2` validates its own `password`, `salt`, `derived_key`, and `dk_length` arguments directly. It returns `PAMBLE_SIZE_OVERFLOW` if the requested `dk_length` would require more blocks than fit in a `uint32_t`, or if allocation of the output buffer fails. Failures from the underlying `pamble_hmac_sha256` calls (performed within `process_block` and `process_iteration`) are propagated using `PAMBLE_RETURN_IF_ERROR`; on such failure, the partially filled output buffer is freed via `pamble_free_pbkdf2_dk` and `*derived_key` is set to `NULL` before the error is returned. Internal helper functions (`process_block` and `process_iteration` aside, since they call `pamble_hmac_sha256`) have no fallible preconditions given how they are invoked, so `int32_be`, `array_concat`, and `write_block_output` return `void` or a plain byte count rather than `pamble_status`.

## Usage

```text
pamble_pbkdf2(password, password_length, salt, salt_length, &derived_key, dk_length)
```

internally performs block-count calculation, output-buffer allocation, and per-block HMAC-SHA256 iteration, writing the resulting `dk_length`-byte derived key to a newly allocated buffer referenced by `derived_key`. The caller must release this buffer with `pamble_free_pbkdf2_dk` once done with it.

Because the interface is one-shot, the complete password and salt must be available at the time of the call.

## Implementation Structure

The implementation is organized around the PBKDF2 construction's stages:

```text
pamble_pbkdf2
        │
        ├── (compute block count from dk_length)
        ├── calloc → *derived_key
        │
        └── for each block_no in 1..blocks:
                │
                process_block
                        │
                        ├── int32_be(block_no) → INT(block_no)
                        ├── array_concat(salt, INT(block_no)) → salt_concat_int32_be
                        ├── pamble_hmac_sha256(password, salt_concat_int32_be) → U_1 → T
                        │
                        └── for j in 2..PAMBLE_PBKDF2_ITERATIONS:
                                process_iteration
                                        ├── pamble_hmac_sha256(password, U_{j-1}) → U_j
                                        └── T ^= U_j
                │
                write_block_output(T_i) → copy into *derived_key at the block's offset
```

This keeps the PBKDF2-specific block indexing, salt concatenation, and iteration/XOR accumulation separate from the HMAC-SHA256 computation itself, which is reused unmodified from `pamble_hmac_sha256`.

## Important Constants

The implementation uses:

| Constant | Value | Purpose |
| --- | ---: | --- |
| `BYTES_PER_32_BITS` | `sizeof(uint32_t)` (4) | Size of the big-endian block-index encoding |
| `BITS_PER_BYTE` | 8 | Used to compute per-byte shifts in `int32_be` |
| `PAMBLE_PBKDF2_ITERATIONS` | (fixed, compile-time) | Number of HMAC iterations per output block |

`PAMBLE_SHA256_DIGEST_LENGTH` (32 bytes), defined by the SHA-256 API, sizes each PBKDF2 output block `T_i`, as well as the `U` values used within each block's iteration.

## Digest and Output Representation

Each PBKDF2 output block is the size of one HMAC-SHA256 digest:

```text
256 bits = 32 bytes per block
```

The overall derived key is the concatenation of `ceil(dk_length / 32)` such blocks, with the final block truncated so the total output is exactly `dk_length` bytes.

## Design Notes

- The implementation reuses `pamble_hmac_sha256` unmodified for every pseudorandom-function application; it contains no HMAC or SHA-256 logic of its own.
- Block-index encoding, salt concatenation, per-iteration XOR accumulation, and output assembly are each isolated in small internal helper functions.
- The interface is one-shot only; no streaming context is exposed for PBKDF2 computation, and the entire password and salt must be supplied up front.
- The iteration count, `PAMBLE_PBKDF2_ITERATIONS`, is fixed at compile time rather than being a caller-supplied parameter.
- `pamble_status` provides the common success and error-reporting mechanism, propagated from both argument validation and the underlying `pamble_hmac_sha256` calls via `PAMBLE_RETURN_IF_ERROR`.
- The derived-key buffer is heap-allocated (unlike the fixed-size and variable-length stack buffers used within a single block's derivation) because its size, `dk_length`, is caller-specified and may be arbitrarily large; ownership is transferred to the caller, who must release it with `pamble_free_pbkdf2_dk`.
