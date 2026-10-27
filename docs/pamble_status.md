# Pamble Status

`pamble_status` is Pamble's common status interface for reporting whether an
operation completed successfully or why it failed.

The status definition is provided by:

```c
#include "pamble/pamble_status.h"
```

## `pamble_status`

The current status enum contains five values:

```c
typedef enum {
  PAMBLE_OK = 0,
  PAMBLE_INVALID_ARGUMENT,
  PAMBLE_SIZE_OVERFLOW,
  PAMBLE_IO_ERROR,
  PAMBLE_INVALID_ARCHIVE,
} pamble_status;
```

### `PAMBLE_OK`

Indicates that the operation completed successfully.

### `PAMBLE_INVALID_ARGUMENT`

Indicates that one or more supplied arguments are invalid.

For the current Pamble SHA-256 API, this is returned for cases such as:

- A `NULL` SHA-256 context passed to initialization or update.
- A `NULL` message when the message length is non-zero.
- A `NULL` output buffer passed to finalization or the one-shot interface.
- An invalid buffered length detected during finalization.

Internal helper functions also use this status when required pointer
arguments are `NULL`.

### `PAMBLE_SIZE_OVERFLOW`

Indicates that an operation would exceed the maximum message length
representable by SHA-256.

The current SHA-256 implementation checks this in `pamble_sha256_update`
before processing the supplied message.

The archive API also returns it when an archive path exceeds `UINT16_MAX`
bytes, a file is too large to buffer, or an allocation fails.

### `PAMBLE_IO_ERROR`

Indicates that a filesystem operation failed.

The archive API returns this when a path cannot be inspected, opened,
listed, read, created, written, or given its permission bits, and when
extraction would overwrite an existing file.

### `PAMBLE_INVALID_ARCHIVE`

Indicates that archive data is malformed or unsafe to extract.

The archive API returns this for a truncated archive, a bad magic or
version, an unknown entry type, invalid mode bits, a directory with
content, an unsafe path, or bytes after the end marker.

## Error Propagation

Pamble provides `PAMBLE_RETURN_IF_ERROR` for propagating non-success status
values from internal helper functions:

```c
#define PAMBLE_RETURN_IF_ERROR(status) \
  do { \
    if ((status) != PAMBLE_OK) { \
      return (status); \
    } \
  } while (0)
```

The macro evaluates the supplied status expression and returns it from the
current function when it is not `PAMBLE_OK`.

It is intended for functions whose return type is compatible with
`pamble_status`.

For example:

```c
pamble_status status = some_operation();

PAMBLE_RETURN_IF_ERROR(status);
```

This is used throughout the SHA-256 implementation to propagate failures
through the internal helper chain without repeating the same conditional
return logic.

## API Convention

Functions that use `pamble_status` should:

1. Return `PAMBLE_OK` when the operation succeeds.
2. Return the appropriate non-success status when an error occurs.
3. Avoid silently ignoring a status returned by another Pamble operation.
4. Propagate internal failures to the public API when applicable.

The status mechanism is intentionally small at the current stage. Additional
status codes can be added to the enum as Pamble's API grows.
