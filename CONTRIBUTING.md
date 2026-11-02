# Contributing to pamble

Thanks for looking. pamble is small and opinionated: every primitive is implemented in the repository, tested against published vectors, and documented. Contributions that keep it that way are very welcome.

## Getting set up

You need:

| Tool | Used for |
| --- | --- |
| GCC or Clang with C17 | Building |
| CMake 3.31 or newer, pkg-config | Build configuration |
| [Criterion](https://github.com/Snaipe/Criterion) (`libcriterion-dev`) | Tests |
| clang-format | Formatting (checked in CI) |
| clang-tidy | Linting (checked in CI) |

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

Tests that encrypt or decrypt real data run PBKDF2 with 600,000 iterations. That takes about 11 seconds per key derivation in a Debug build and under 2 in Release. For quick local runs, build the tests with `-DCMAKE_BUILD_TYPE=RelWithDebInfo`.

Before opening a pull request, run what CI runs:

```sh
find src include tests -name '*.[ch]' -print0 | xargs -0 clang-format --dry-run --Werror
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
find src include -name '*.[ch]' -print0 | xargs -0 clang-tidy -p build
```

Building once with `-fsanitize=address,undefined` before submitting is strongly encouraged.

## Workflow

- `main` holds released work and `develop` collects what is next. CI runs on pushes to both and on pull requests into `main`.
- Branch from `develop` and open your pull request against it.
- Keep one change per pull request: a module, a fix, or a refactor.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), as in the existing history:

```text
feat(pbkdf2): add PBKDF2 implementation, tests, and docs
fix: skip memcpy on zero-length inputs in HMAC and PBKDF2
refactor: drop pamble_status from internal helpers with no fallible path
```

## Code style

Formatting is whatever `clang-format` produces with the repository's `.clang-format` (LLVM style). Beyond that, the code follows these conventions:

- **Naming.** Public functions and types start with `pamble_` and the module name (`pamble_aes_ctr_update`). Everything else in a `.c` file is `static`.
- **Errors.** Fallible public functions return `pamble_status` and propagate errors with `PAMBLE_RETURN_IF_ERROR`. Helpers that cannot fail return `void` or a plain value.
- **Array parameters.** Fixed-size buffers are declared `type name[static N]`, and required struct pointers `type name[static 1]`, so sizes and non-NULL requirements live in the signature instead of runtime checks.
- **Swappable parameters.** When two neighbouring parameters share a type (two `uint8_t *`, two `uint64_t`), wrap them in a struct or give one its own type. `clang-tidy` flags this.
- **No magic numbers.** Every constant gets a `#define` with a descriptive name.
- **Secrets.** Keys, derived material and plaintext are wiped with `explicit_bzero` on every exit path, error paths included.
- **No printing from the library.** Only `main.c` writes to the terminal. Long-running work reports through `pamble_progress`.

### Docstrings

Every function, public or `static`, has a comment in this form, repeated in the header and the source for public functions:

```c
/*
 * @brief One line saying what it does.
 *
 * Optional detail: behaviour, ownership, edge cases.
 *
 * @param name What it is.
 *
 * @return PAMBLE_OK if ...
 * @return PAMBLE_INVALID_ARGUMENT if ...
 */
```

## Tests

- Tests use Criterion, one file per module: `tests/test_pamble_<module>.c`.
- **One assertion per function.** A Criterion assertion counts 16 toward clang-tidy's cognitive-complexity limit of 25. Helpers return `bool` instead of asserting, and each test combines its checks into a single `cr_assert` with a message saying which part failed. Setup helpers use one assertion each.
- **Cite known answers.** Cryptographic code is tested against published vectors (FIPS-197, NIST SP 800-38A, RFC 4231, or answers cross-checked against OpenSSL). Name the source in the test name or a comment.
- **Keep PBKDF2 rare.** Build failure cases by hand so they are rejected before key derivation, and reserve real encrypt/decrypt round trips for the few tests that need them.
- **Prove the test bites.** When a test guards a security check, temporarily break the check and confirm the test fails.

## Documentation

Each module has `docs/pamble_<module>.md`. New modules follow the same outline as the existing ones:

1. Overview
2. Status Interface
3. API
4. Internal Design
5. Error Handling
6. Usage
7. Implementation Structure
8. Important Constants
9. Design Notes

Update the module's document in the same pull request as the code, and add new modules to the table in `README.md`.

## Adding a module

1. Header in `include/pamble/`, with docstrings.
2. Implementation in `src/`, helpers `static`.
3. Tests in `tests/`.
4. Both source files added to the `pamble` and `pamble_tests` targets in `CMakeLists.txt`.
5. A document in `docs/`.
6. New status codes, if any, added at the end of the enum and described in `docs/pamble_status.md`.

## Where to help: multithreading

The next major piece of work is running AES-CTR across several threads. The groundwork is in place:

- **Why CTR splits cleanly.** Keystream block `j` is AES of `nonce || be32(j)`, independent of every other block. A thread that starts at block `j` sets its counter value to `j` and needs nothing from the others.
- **Where it plugs in.** `crypt_body` in `src/pamble_crypto.c` already walks the buffer in 1 MiB pieces. Give each thread a range of whole 16-byte blocks, its own `pamble_aes_ctr_ctx`, and its starting counter.
- **Progress.** Workers add their bytes to an `atomic_uint_fast64_t`. Only the calling thread reads it and calls `pamble_progress_emit`; the terminal reporter is not thread-safe.
- **Limits.** The CTR counter is 32 bits, so one nonce covers at most 2^32 blocks (64 GiB). Ranges must stay inside that and return `PAMBLE_COUNTER_EXHAUSTED` past it.
- **Fallback.** Small inputs, under about 1 MiB, and failed `pthread_create` calls fall back to the single-threaded path.
- **Tests.** One thread and N threads must produce identical bytes, for lengths that do and do not end on a block boundary.

Also on the roadmap, and good self-contained contributions:

- Table-based GF(2^8) multiplication for MixColumns, the largest single-threaded speedup.
- Format version 2: derive 32 bytes with PBKDF2 and split them with HKDF-Expand, halving key-derivation time while still reading version 1 files.
- Chunked encrypt-then-MAC, so files no longer have to fit in memory.

Open an issue before starting on one of these, so the design can be agreed first.

## Releases

Releases are cut from `main` by pushing a version tag. The full checklist, including the version bump and release notes, is in [docs/releasing.md](docs/releasing.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE.md), the same as the rest of the project.

## Reporting security issues

pamble is an unaudited learning project, but security reports are still taken seriously. For anything that could weaken the encryption or the integrity check, contact the maintainer privately through GitHub rather than opening a public issue.
