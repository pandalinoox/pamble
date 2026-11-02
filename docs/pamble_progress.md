# Pamble Progress

`pamble_progress` is how long-running Pamble operations report what they are doing. Library code never prints: it sends `pamble_progress_event` values to a callback the caller supplies. A built-in terminal reporter turns those events into lines like:

```text
[1/5] archiving files...
[2/5] deriving keys: 696,000/1,200,000 iterations
[3/5] [=====>              ]  30% encrypting
```

## Overview

1. The caller puts a `pamble_progress` (a callback and a context pointer) into the operation's arguments. Leaving it zeroed makes the operation silent.
2. The operation calls `pamble_progress_emit` at the start of each stage and as work completes.
3. The callback decides what to do with each event. `pamble_progress_terminal_report` draws it; tests record it.

Separating reporting from drawing keeps the library free of output, keeps tests quiet, and lets the CLI decide the look.

## Status Interface

None of the progress functions return `pamble_status`. Reporting cannot fail in a way the operation should care about; a write error on the terminal stream is ignored rather than aborting an encryption.

## API

### Types

```c
typedef enum {
  PAMBLE_STAGE_ARCHIVE,      PAMBLE_STAGE_DERIVE_KEYS, PAMBLE_STAGE_ENCRYPT,
  PAMBLE_STAGE_AUTHENTICATE, PAMBLE_STAGE_WRITE,       PAMBLE_STAGE_READ,
  PAMBLE_STAGE_VERIFY,       PAMBLE_STAGE_DECRYPT,     PAMBLE_STAGE_EXTRACT,
} pamble_stage;

typedef struct {
  pamble_stage stage;
  unsigned step;
  unsigned step_count;
  uint64_t done;
  uint64_t total;
} pamble_progress_event;

typedef void (*pamble_progress_fn)(void *context,
                                   const pamble_progress_event *event);

typedef struct {
  pamble_progress_fn report;
  void *context;
} pamble_progress;
```

An event with `total == 0` is a label: the stage has started and will send nothing more. An event with a non-zero `total` counts `done` up to `total`, in iterations for key derivation and in bytes for the byte-processing stages. `done` and `total` live in a struct rather than being passed as two adjacent `uint64_t` parameters, which would be easy to swap.

### `pamble_progress_emit`

```c
void pamble_progress_emit(const pamble_progress *progress,
                          const pamble_progress_event *event);
```

Calls `progress->report(progress->context, event)`. Does nothing if `progress`, its `report` or `event` is `NULL`.

### `pamble_progress_stage_label`

```c
const char *pamble_progress_stage_label(pamble_stage stage);
```

Returns the stage's name, such as `"deriving keys"`, or `"working"` for a value outside the enum.

### `pamble_progress_format`

```c
size_t pamble_progress_format(const pamble_progress_event *event,
                              char *buffer, size_t buffer_length);
```

Formats one line without a trailing newline. It behaves like `snprintf`: the output is truncated to fit and always NUL-terminated, and the return value is the full length.

| Event | Line |
| --- | --- |
| `total == 0` | `[1/5] archiving files...` |
| Key derivation | `[2/5] deriving keys: 69,420/1,200,000 iterations` |
| Anything else | `[3/5] [=====>              ]  30% encrypting` |

The bar is `PAMBLE_PROGRESS_BAR_WIDTH` (20) cells. `percent * 20 / 100` cells are filled with `=`, the last one drawn as `>` until the bar reaches 100%. `done` past `total` is shown as 100%.

### Terminal reporter

```c
typedef struct {
  FILE *stream;
  bool is_tty;
  pamble_stage last_stage;
  int last_percent;
  bool line_open;
} pamble_progress_terminal;

void pamble_progress_terminal_init(pamble_progress_terminal *terminal,
                                   FILE *stream);
void pamble_progress_terminal_report(void *context,
                                     const pamble_progress_event *event);
void pamble_progress_terminal_finish(pamble_progress_terminal *terminal);
```

`init` records the stream and sets `is_tty` from `isatty(fileno(stream))`. `report` is a `pamble_progress_fn` whose context is the terminal state. `finish` ends a line left open by a stage that stopped part-way, so an error message printed afterwards starts on its own line.

How `report` writes:

- **On a terminal:** each update returns to the start of the line and clears it (`\r\x1b[2K`), then draws the new line. A finished stage gets a newline.
- **Not on a terminal** (piped or redirected): only label events and finished stages are written, one line each, with no control characters.
- **Throttling:** an event is skipped when its stage and whole-number percentage match the last one drawn. 600,000 PBKDF2 iterations become 100 redraws.
- **Stage changes:** if the previous stage's line is still open, it is ended with a newline first.

## Usage

```c
pamble_progress_terminal terminal;
pamble_progress_terminal_init(&terminal, stderr);

pamble_crypto_payload payload = {
    /* paths and password */
    .progress = {.report = pamble_progress_terminal_report,
                 .context = &terminal},
};

pamble_status status = pamble_encrypt_archive(payload);

pamble_progress_terminal_finish(&terminal);
```

To record events instead, for example in a test, pass a callback that copies each event into a struct of your own.

Progress goes to stderr so stdout stays free for real output.

## Who Reports What

| Stage | Reported by | Unit |
| --- | --- | --- |
| Archive, write, read, extract | `pamble_crypto.c`, once at the start | Label |
| Derive keys | `pamble_pbkdf2_with_progress`, every 1% of iterations | Iterations |
| Encrypt, decrypt | `pamble_crypto.c`, after each 1 MiB of AES-CTR | Bytes |
| Authenticate, verify | `pamble_crypto.c`, after each 1 MiB of HMAC | Bytes |

## Important Constants

| Constant | Value | Purpose |
| --- | ---: | --- |
| `PAMBLE_PROGRESS_BAR_WIDTH` | 20 | Cells in a progress bar |
| `LINE_BUFFER_SIZE` | 128 | Longest line the terminal reporter draws |
| `NUMBER_BUFFER_SIZE` | 32 | Room for a 64-bit number with separators |
| `CLEAR_LINE` | `\r\x1b[2K` | Return to column 0 and clear the line |

## Testing

`tests/test_pamble_progress.c` checks every line format (label, iteration counter with and without separators, bar at 0, 30, 99 and 100%, clamping, truncation), emitting to `NULL` and silent destinations, delivery of exactly one unchanged event, and the terminal reporter's output in both modes: piped output only shows finished lines, terminal output redraws in place, repeated percentages are skipped, a stage change ends an open line, and `finish` closes an open line and does nothing otherwise. The reporter writes into an `open_memstream` buffer with `is_tty` forced on or off.

## Design Notes

- Reporting is a plain callback, so the library has no dependency on a terminal, and the same events can drive a GUI or a log.
- When AES-CTR is multithreaded later, worker threads should add to an atomic byte counter and only the calling thread should emit events. The terminal reporter is not thread-safe.
- Throttling lives in the terminal reporter, not in the library, so a recording callback still sees every event.
