# Pamble Crypto

`pamble_crypto` ties Pamble together. `pamble_encrypt_archive` packs a file or directory, encrypts it with AES-256-CTR and authenticates it with HMAC-SHA256. `pamble_decrypt_archive` checks the result and unpacks it. Both report their progress through [`pamble_progress`](pamble_progress.md).

## Overview

Encryption:

1. **Archive** the input with `pamble_archive_pack`. A bad path fails here, before any slow work.
2. **Derive keys:** PBKDF2-HMAC-SHA256 over the password and a random 12-byte salt yields 64 bytes. The first 32 are the AES key, the next 32 the MAC key.
3. **Encrypt** the archive in place with AES-256-CTR, using a random 12-byte nonce and a counter starting at 0.
4. **Authenticate:** tag = HMAC-SHA256(mac_key, header ‖ ciphertext).
5. **Write** header ‖ ciphertext ‖ tag to `<output>.tmp`, then rename it to `<output>`.

Decryption:

1. **Read** the file. Check magic, version and that the file size is exactly header + archive_length + tag.
2. **Derive keys** from the password and the salt in the header.
3. **Verify:** recompute the tag and compare it in constant time. A mismatch stops here with `PAMBLE_AUTHENTICATION_FAILED`.
4. **Decrypt** in place with AES-256-CTR.
5. **Extract** with `pamble_archive_unpack`.

Keys, the PBKDF2 output, the HMAC context and the plaintext archive are wiped with `explicit_bzero` before every return, on success and on error.

## File Format

All integers are big-endian. The header is 39 bytes.

| Field | Size (bytes) | Contents |
| --- | ---: | --- |
| magic | 6 | `PMBENC` |
| version | 1 | `PAMBLE_CRYPTO_VERSION` (1) |
| salt | 12 | Random per file |
| nonce | 12 | Random per file |
| archive_length | 8 | Bytes of ciphertext that follow |
| ciphertext | archive_length | AES-256-CTR of the packed archive |
| tag | 32 | HMAC-SHA256 over the header and ciphertext |

The tag covers the header exactly as stored, so changing the salt, the nonce or the length breaks it too.

## Status Interface

The common Pamble status interface is documented separately in [`pamble_status.md`](pamble_status.md). This module introduced `PAMBLE_AUTHENTICATION_FAILED`.

## API

### `pamble_crypto_payload`

```c
typedef struct {
  const char *input_path;
  const char *output_path;
  const uint8_t *password;
  size_t password_length;
  pamble_progress progress;
} pamble_crypto_payload;
```

| Field | Encrypt | Decrypt |
| --- | --- | --- |
| `input_path` | File or directory to pack | Encrypted file |
| `output_path` | Encrypted file to write | Existing directory to extract into |
| `password` | Password bytes; `NULL` only with length 0 | Same |
| `progress` | Progress destination; zeroed = silent | Same |

### `pamble_encrypt_archive`

```c
pamble_status pamble_encrypt_archive(pamble_crypto_payload payload);
```

| Status | When |
| --- | --- |
| `PAMBLE_OK` | The encrypted file was written |
| `PAMBLE_INVALID_ARGUMENT` | A path is `NULL`, or `password` is `NULL` with a non-zero length |
| `PAMBLE_IO_ERROR` | The input cannot be read, random bytes are unavailable, or the output cannot be written or renamed |
| `PAMBLE_SIZE_OVERFLOW` | An allocation fails or sizes overflow |
| others | Passed through from `pamble_archive_pack`, PBKDF2 or AES-CTR |

On failure nothing is left at `output_path`: the temporary file is removed and an existing file there is untouched.

### `pamble_decrypt_archive`

```c
pamble_status pamble_decrypt_archive(pamble_crypto_payload payload);
```

| Status | When |
| --- | --- |
| `PAMBLE_OK` | The archive was extracted |
| `PAMBLE_INVALID_ARGUMENT` | A path is `NULL`, or `password` is `NULL` with a non-zero length |
| `PAMBLE_INVALID_ARCHIVE` | Wrong magic or version, or the file size does not match the header |
| `PAMBLE_AUTHENTICATION_FAILED` | Wrong password, or the file was modified |
| `PAMBLE_IO_ERROR` | The file cannot be opened or read, or extraction cannot write (including existing files) |
| others | Passed through from PBKDF2, AES-CTR or `pamble_archive_unpack` |

The first three statuses are returned during the read stage, before PBKDF2 runs, so a damaged or foreign file is rejected instantly.

## Internal Design

### Messages and Keys

A `crypto_message` holds the decoded `crypto_header`, the header bytes exactly as stored (`encoded_header`), and the body buffer. The body is the plaintext archive, then the ciphertext (or the reverse when decrypting): AES-CTR runs in place, so only one copy of the data is ever in memory. A `crypto_keys` holds the AES and MAC keys.

`seal` and `unseal` run the five stages and return the first error. The public functions only validate the payload, call one of them, and then wipe the keys and release the body in a single place, so every exit path is cleaned up the same way.

### Progress

`start_stage` creates a `stage_reporter` for a stage; `stage_step` maps each stage to its position (1 to 5) so step numbers are never written by hand. Label stages call `report_done(&reporter, 0)` once. Counted stages set the total and report after each piece of work.

### Chunked AES-CTR and HMAC

`crypt_body` and `mac_body` process the body in 1 MiB pieces (`PROGRESS_CHUNK_BYTES`) and report after each. Splitting does not change the result:

- The AES-CTR context carries leftover keystream between `pamble_aes_ctr_update` calls, and the counter starts at nonce ‖ 0, the same as `pamble_aes_ctr_crypt`. Files from the earlier one-shot code still decrypt.
- `compute_tag` streams the header and then the body into one HMAC context, which gives the same tag as HMAC over the concatenation, without building that concatenation in memory.

### Reading and Size Checks

`read_sealed_file` reads the header, checks it, and compares the file size from `fstat` against header + archive_length + tag before allocating the body. A length field claiming more data than the file holds, or a file with bytes appended, is rejected as `PAMBLE_INVALID_ARCHIVE` without a large allocation and without running PBKDF2.

### Writing

`write_output` writes to `<output_path>.tmp` and renames it over `output_path` only when every byte and the close succeeded. A crash or a full disk leaves no half-written encrypted file behind.

### Tag Comparison

`tags_equal` ORs together the XOR of every byte pair and checks the result at the end, so the time taken does not reveal how many leading bytes matched.

## Usage

```c
pamble_progress_terminal terminal;
pamble_progress_terminal_init(&terminal, stderr);

pamble_crypto_payload payload = {
    .input_path = "project",
    .output_path = "project.pamble",
    .password = (const uint8_t *)password,
    .password_length = strlen(password),
    .progress = {.report = pamble_progress_terminal_report,
                 .context = &terminal},
};

pamble_status status = pamble_encrypt_archive(payload);
pamble_progress_terminal_finish(&terminal);
```

From the command line (see `src/main.c`):

```text
pamble encrypt <file-or-directory> [output-file]
pamble decrypt <encrypted-file> [output-directory]
```

`main.c` fills in what the library does not decide:

- **Default encrypt output:** the input path, trailing slashes removed, plus `.pamble`, so it lands next to the input.
- **Default decrypt output:** the directory containing the encrypted file (`.` for a bare file name). The archive's root entry recreates the original folder name there.
- **Missing decrypt output:** created like `mkdir -p` before decryption starts, after the password is read. If the operation then fails and the output directory was created by this run, it is removed with `rmdir` (which only succeeds while it is still empty).
- A decrypt output that exists but is not a directory is reported before anything runs.

The password is typed with echo off (asked twice when encrypting). When stdin is not a terminal, its first line is used as the password, which allows `echo "$PW" | pamble decrypt ...` in scripts. Exit status is 0 on success, 1 on failure and 2 for usage errors.

## Implementation Structure

```text
pamble_encrypt_archive
        ├── validate_payload
        ├── seal
        │     ├── [1/5] pamble_archive_pack
        │     ├── new_header                 random salt + nonce, encode
        │     ├── [2/5] derive_keys          pamble_pbkdf2_with_progress
        │     ├── [3/5] crypt_body           AES-CTR in 1 MiB pieces
        │     ├── [4/5] compute_tag          HMAC(header) then mac_body
        │     └── [5/5] write_output         .tmp, then rename
        └── wipe keys, release_body

pamble_decrypt_archive
        ├── validate_payload
        ├── unseal
        │     ├── [1/5] read_input → read_sealed_file
        │     │                              decode header, check size
        │     ├── [2/5] derive_keys
        │     ├── [3/5] compute_tag + tags_equal
        │     ├── [4/5] crypt_body
        │     └── [5/5] pamble_archive_unpack
        └── wipe keys, release_body
```

## Important Constants

| Constant | Value | Purpose |
| --- | ---: | --- |
| `PAMBLE_CRYPTO_VERSION` | 1 | Format version written and required |
| `PAMBLE_CRYPTO_STEP_COUNT` | 5 | Stages per operation |
| `CRYPTO_HEADER_LENGTH` | 39 | Bytes before the ciphertext |
| `CRYPTO_SALT_LENGTH` | 12 | Salt bytes |
| `PAMBLE_AES_CTR_NONCE_BYTES` | 12 | Nonce bytes |
| `DERIVED_KEY_LENGTH` | 64 | PBKDF2 output: AES key + MAC key |
| `TAG_LENGTH` | 32 | HMAC-SHA256 tag bytes |
| `PROGRESS_CHUNK_BYTES` | 1 MiB | Work between progress reports |

## Testing

`tests/test_pamble_crypto.c` covers:

- A full round trip of a directory tree, checking the extracted files byte for byte, that both operations report all five stages in order with each counted stage reaching its total, and that no `.tmp` file is left.
- A wrong password and a flipped ciphertext byte both give `PAMBLE_AUTHENTICATION_FAILED` and extract nothing.
- The file size equals 39 + archive + 32, the magic and version are right, and two encryptions of the same input use different salts and nonces and produce different ciphertext.
- Hand-built files with a bad magic, a bad version, a short body or trailing bytes are rejected before key derivation starts, as is a file shorter than the header.
- A missing input file, a missing input path (with no output file created), `NULL` paths and a `NULL` password with a non-zero length.

Every test that encrypts or decrypts real data runs PBKDF2, which takes about 1.7 seconds per 64-byte derivation in an optimized build and about 11 seconds in a Debug build. Only four tests do; the rest use hand-built files and fail before PBKDF2.

## Design Notes

- PBKDF2 derives 64 bytes, which is two output blocks, so key derivation runs 1,200,000 iterations. Deriving 32 bytes and splitting them into two keys with HMAC (HKDF-Expand) would halve the wait, but would change the key schedule, so it needs a new `PAMBLE_CRYPTO_VERSION`.
- The whole archive is held in memory, and AES-CTR runs on one thread. The chunked loop in `crypt_body` is where a threaded version would plug in.
- Wrong passwords and tampered files return the same status on purpose; telling them apart would help an attacker.
