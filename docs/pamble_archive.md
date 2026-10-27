# Pamble Archive

`pamble_archive` is Pamble's minimal tar-like archive format. It provides a one-shot interface for packing a file or a whole directory tree into a single in-memory buffer, and for unpacking such a buffer back onto disk.

The archive is produced and consumed as a plain byte buffer so that it can be passed through an encryption layer (or any other transform) between packing and writing to disk, and between reading from disk and unpacking.

## Overview

Packing walks the input path and serializes it:

1. Derive the root name from the basename of the input path (trailing separators are ignored, so `a/b` and `a/b/` both yield `b`).
2. Write the archive header: magic bytes and format version.
3. Write one entry for the root. For a directory, recursively write one entry for every child, visiting children in sorted order.
4. Write the end marker.

Unpacking reverses this:

1. Validate the entire archive without touching the filesystem: header, every entry, every path, the end marker, and the absence of trailing bytes.
2. Walk the archive a second time, creating each directory and writing each file under the output directory.

Only regular files and directories are archived. Symbolic links, devices, sockets and FIFOs below the root are skipped; a root that is not a regular file or directory is rejected.

## Status Interface

The common Pamble status interface is documented separately in [`pamble_status.md`](pamble_status.md).

The archive API uses `pamble_status` for success and error reporting on its pack and unpack functions. This includes argument validation, filesystem failures (`PAMBLE_IO_ERROR`), malformed or unsafe archives (`PAMBLE_INVALID_ARCHIVE`), and size or allocation failures (`PAMBLE_SIZE_OVERFLOW`).

See [`pamble_status.md`](pamble_status.md) for:

- The complete `pamble_status` enum.
- The meaning of each status value.
- The `PAMBLE_RETURN_IF_ERROR` propagation macro.
- General status-handling conventions used throughout Pamble.

## Archive Format

All multi-byte integers are unsigned and big-endian.

```text
archive := header entry* end_marker

header  := magic[4] = "PMBA"
           version[1] = PAMBLE_ARCHIVE_VERSION (1)

entry   := type[1]            1 = file, 2 = directory
           mode[4]            permission bits, 0000..0777
           path_length[2]     number of bytes in path
           content_length[8]  number of bytes in content (0 for directories)
           path[path_length]
           content[content_length]

end_marker := type[1] = 0
```

Each entry therefore has a fixed 15-byte header followed by its path and content.

Paths are relative, use `/` as the separator, and always start with the root name. Packing a directory `project` containing `README` and `src/main.c` produces entries in this order:

```text
project            (directory)
project/README     (file)
project/src        (directory)
project/src/main.c (file)
```

A directory entry always precedes the entries inside it, so extracting entries in archive order always has a parent directory available.

## API

### `pamble_archive_pack`

Packs a file or directory tree into an in-memory archive.

```c
pamble_status pamble_archive_pack(
    const char *input_path,
    uint8_t **archive,
    size_t *archive_length
);
```

The function:

- Derives the root archive name from the basename of `input_path`.
- Checks that `input_path` is a regular file or a directory.
- Writes the header, the root entry and (for directories) every descendant entry, followed by the end marker.
- Writes the address of the newly allocated buffer to `*archive` and its size to `*archive_length`.

`input_path`, `archive` and `archive_length` must not be `NULL`; otherwise the function returns `PAMBLE_INVALID_ARGUMENT`. A path whose basename is empty, `.` or `..` (for example `/`, `.` or `../`) also returns `PAMBLE_INVALID_ARGUMENT`, because it does not give the archive a usable root name.

`*archive` is set to `NULL` on any failure after the arguments have been validated.

Packing is deterministic: children are listed with `scandir` and `alphasort`, so packing the same unchanged tree twice produces identical bytes.

### `pamble_archive_unpack`

Unpacks an in-memory archive into an existing directory.

```c
pamble_status pamble_archive_unpack(
    const uint8_t *archive,
    size_t archive_length,
    const char *output_path
);
```

The function:

- Checks that `output_path` is an existing directory.
- Validates the full archive in a first pass.
- Extracts every entry under `output_path` in a second pass.

`archive` may be `NULL` only when `archive_length` is zero (which then fails validation with `PAMBLE_INVALID_ARCHIVE`). `output_path` must not be `NULL` and must name an existing directory; otherwise the function returns `PAMBLE_INVALID_ARGUMENT`.

Because validation happens before extraction, a malformed archive never writes anything. A filesystem error during extraction (for example an existing file) can still leave the entries extracted before it in place.

### `pamble_free_archive`

Frees an archive previously allocated by `pamble_archive_pack`.

```c
void pamble_free_archive(uint8_t *archive);
```

`archive` may be `NULL`, in which case the call is a no-op. Callers are responsible for calling this function to release the buffer written to `*archive` by a successful `pamble_archive_pack` call.

## Internal Design

### Byte Buffer

Packing appends to a growable `byte_buffer` (`data`, `length`, `capacity`). The implementation's `buffer_reserve` function grows the buffer geometrically, starting at `INITIAL_CAPACITY` and multiplying by `GROWTH_FACTOR`, and reports `PAMBLE_SIZE_OVERFLOW` if the required size overflows `size_t` or `realloc` fails. `buffer_append` reserves space and copies bytes in.

Ownership of the finished buffer is transferred to the caller, who releases it with `pamble_free_archive`.

### Big-Endian Encoding

The implementation's `encode_be` and `decode_be` functions convert between unsigned integers and big-endian byte sequences of a given width. They are used for the 4-byte mode, 2-byte path length and 8-byte content length fields.

### Entries

The `archive_entry` struct describes one entry: `type`, `mode`, `path`, `path_length`, `content` and `content_length`. The same struct is used in both directions:

- When packing, `make_entry` fills it from an `lstat` result and the entry's archive path, and `append_entry_header` writes the fixed header and the path.
- When unpacking, `read_entry` fills it with pointers into the archive buffer, without copying.

The `entry_location` struct pairs the filesystem path of an entry being packed with its path inside the archive.

### Packing Walk

The implementation's `pack_entry` function `lstat`s an entry and dispatches on its type:

- `pack_directory` writes the directory entry, lists its children with `scandir` (dropping `.` and `..`), builds each child's filesystem and archive paths with `join_path`, and recurses into `pack_entry`.
- `pack_file` writes the file entry using the size from `lstat`, then `append_file_content` reads exactly that many bytes from the file into the buffer. A short read returns `PAMBLE_IO_ERROR`.
- Any other type is skipped.

### Reading

Unpacking reads through a `byte_reader` (`data`, `length`, `offset`). The implementation's `reader_take` function returns a pointer to the next `count` bytes and advances the offset, or returns `PAMBLE_INVALID_ARCHIVE` if fewer bytes remain. Every field read goes through it, so the parser never reads past the end of the buffer.

`read_header` checks the magic and version. `read_entry` reads one entry and rejects:

- An unknown entry type.
- Mode bits outside `0777` (no setuid, setgid or sticky bits).
- A directory with a non-zero content length.
- A content length larger than the remaining bytes.
- An unsafe path (see below).

### Path Safety

The implementation's `is_safe_path` function accepts a path only if it is non-empty, contains no NUL bytes, does not start with `/`, and every `/`-separated component is non-empty and is neither `.` nor `..`. This rules out absolute paths, parent-directory traversal, `a//b`, trailing slashes and `./` prefixes, so every extracted path stays inside `output_path`.

### Extraction

The implementation's `walk_archive` function drives both passes. With a `NULL` output path it only validates; otherwise it calls `extract_entry` for each entry, which joins the entry path onto `output_path` and then:

- `extract_directory` creates the directory with mode `0700`, accepts an existing real directory (but not a file or symbolic link at that path), then applies the stored mode with the owner `rwx` bits forced on so later entries can be written into it.
- `extract_file` opens the file with `fopen(..., "wbx")`. Exclusive mode means an existing file is never overwritten and an existing symbolic link is never followed. After writing the content it applies the stored mode with `chmod`.

After the end marker, `walk_archive` returns `PAMBLE_INVALID_ARCHIVE` if any bytes remain.

## Error Handling

Error reporting for the archive API is provided by Pamble's common status interface.

See [`pamble_status.md`](pamble_status.md) for the complete list of status codes, their meanings, and the `PAMBLE_RETURN_IF_ERROR` propagation convention.

| Status | Returned when |
| --- | --- |
| `PAMBLE_INVALID_ARGUMENT` | A required pointer is `NULL`, the input path has no usable basename, the input root is not a regular file or directory, or the output path is not an existing directory. |
| `PAMBLE_IO_ERROR` | A path cannot be `lstat`ed, opened, listed, read completely, created, written or `chmod`ed, or a file already exists at an extraction path. |
| `PAMBLE_INVALID_ARCHIVE` | The archive is truncated, has a bad magic or version, contains an invalid entry or unsafe path, or has bytes after the end marker. |
| `PAMBLE_SIZE_OVERFLOW` | An archive path exceeds `UINT16_MAX` bytes, a file is too large to buffer, or an allocation fails. |

Internal helpers that can fail return `pamble_status` and are propagated with `PAMBLE_RETURN_IF_ERROR`. Helpers that hold resources (`pack_directory` with its `scandir` list, `append_file_content` and `extract_file` with their open files, `pamble_archive_pack` with its buffer) record the status, release the resource, and then return the status. Helpers with no fallible preconditions (`encode_be`, `decode_be`, `make_entry`, `is_safe_path`) do not return `pamble_status`.

## Usage

Pack a directory, hand the bytes to another layer, and unpack them later:

```c
uint8_t *archive = NULL;
size_t archive_length = 0;

pamble_status status =
    pamble_archive_pack("path/to/project", &archive, &archive_length);
PAMBLE_RETURN_IF_ERROR(status);

/* encrypt / write archive[0..archive_length) here */

status = pamble_archive_unpack(archive, archive_length, "path/to/output");

pamble_free_archive(archive);

PAMBLE_RETURN_IF_ERROR(status);
```

This recreates `path/to/output/project` with the same files, directories and permission bits.

## Implementation Structure

```text
pamble_archive_pack
        │
        ├── root_name(input_path) → name
        │
        └── build_archive
                ├── lstat(input_path) → must be file or directory
                ├── buffer_append(MAGIC, version)
                ├── pack_entry(root)
                │       │
                │       ├── pack_directory
                │       │       ├── make_entry → append_entry_header
                │       │       └── scandir → for each child:
                │       │               join_path → pack_entry(child)
                │       │
                │       └── pack_file
                │               ├── make_entry → append_entry_header
                │               └── append_file_content
                │
                └── buffer_append(end_marker)

pamble_archive_unpack
        │
        ├── stat(output_path) → must be a directory
        ├── walk_archive(archive, NULL)          validation pass
        └── walk_archive(archive, output_path)   extraction pass
                │
                ├── read_header
                └── read_entry (until end marker)
                        ├── reader_take, decode_be, is_safe_path
                        └── extract_entry
                                ├── extract_directory
                                └── extract_file
```

## Important Constants

| Constant | Value | Purpose |
| --- | ---: | --- |
| `PAMBLE_ARCHIVE_VERSION` | 1 | Format version written to and required in the header |
| `MAGIC` | `"PMBA"` | Identifies a Pamble archive |
| `MAGIC_LENGTH` | 4 | Size of the magic field |
| `VERSION_LENGTH` | 1 | Size of the version field |
| `TYPE_LENGTH` | 1 | Size of the entry type field |
| `MODE_LENGTH` | `sizeof(uint32_t)` (4) | Size of the mode field |
| `PATH_LENGTH_LENGTH` | `sizeof(uint16_t)` (2) | Size of the path length field |
| `CONTENT_LENGTH_LENGTH` | `sizeof(uint64_t)` (8) | Size of the content length field |
| `MAX_ARCHIVE_PATH_LENGTH` | `UINT16_MAX` | Longest archive path that can be stored |
| `MODE_MASK` | `0777` | Permission bits stored and accepted |
| `DIRECTORY_CREATE_MODE` | `0700` | Mode used when first creating a directory |
| `INITIAL_CAPACITY` | 4096 | First allocation size of the archive buffer |
| `GROWTH_FACTOR` | 2 | Buffer growth multiplier |

## Design Notes

- The interface is one-shot and in-memory: the whole archive is built in, or read from, a single buffer. This keeps the format independent of any I/O and makes it straightforward to encrypt or authenticate the buffer as a whole, at the cost of holding the full archive in memory.
- The format is a simple length-prefixed stream rather than POSIX `ustar`. There are no 512-byte blocks, octal fields or 100-byte name limits, and it is not readable by the `tar` tool.
- Only permission bits are preserved. Ownership, timestamps, extended attributes, hard links and symbolic links are not stored.
- Unpacking treats the archive as untrusted input: every length is bounds-checked, every path is checked for traversal, and the full archive is validated before the filesystem is touched.
- Extraction never overwrites an existing file; to replace an extracted tree, remove it first.
- `_POSIX_C_SOURCE=200809L` is defined by the build (see `CMakeLists.txt`) for `lstat`, `scandir` and `alphasort`, since the project compiles as strict C17 with extensions off.
