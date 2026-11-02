#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PAMBLE_PROGRESS_BAR_WIDTH 20

/*
 * @brief Stages reported by long-running Pamble operations.
 *
 * Encryption runs ARCHIVE, DERIVE_KEYS, ENCRYPT, AUTHENTICATE, WRITE.
 * Decryption runs READ, DERIVE_KEYS, VERIFY, DECRYPT, EXTRACT.
 */
typedef enum {
  PAMBLE_STAGE_ARCHIVE,
  PAMBLE_STAGE_DERIVE_KEYS,
  PAMBLE_STAGE_ENCRYPT,
  PAMBLE_STAGE_AUTHENTICATE,
  PAMBLE_STAGE_WRITE,
  PAMBLE_STAGE_READ,
  PAMBLE_STAGE_VERIFY,
  PAMBLE_STAGE_DECRYPT,
  PAMBLE_STAGE_EXTRACT,
} pamble_stage;

/*
 * @brief One progress update.
 *
 * step and step_count give the position of the stage within the operation
 * ("[3/5]"). For a stage with measurable work, done counts up to total
 * (iterations or bytes). A total of zero marks a stage that only has a label;
 * such an event means the stage has started and has no further updates.
 */
typedef struct {
  pamble_stage stage;
  unsigned step;
  unsigned step_count;
  uint64_t done;
  uint64_t total;
} pamble_progress_event;

/*
 * @brief Callback that receives progress updates.
 *
 * @param context The context pointer stored in pamble_progress.
 * @param event The update. Only valid for the duration of the call.
 */
typedef void (*pamble_progress_fn)(void *context,
                                   const pamble_progress_event *event);

/*
 * @brief Where an operation sends its progress updates.
 *
 * A zero-initialized pamble_progress (report == NULL) is silent.
 */
typedef struct {
  pamble_progress_fn report;
  void *context;
} pamble_progress;

/*
 * @brief State for the built-in terminal progress reporter.
 *
 * On a terminal, counted stages redraw one line in place and finish it with a
 * newline at 100%. On anything else (a pipe or a file), only label events and
 * completed stages are written, one line each. Redraws are skipped when
 * neither the stage nor the whole-number percentage changed.
 *
 *   stream        Where lines are written, normally stderr.
 *   is_tty        Whether stream is a terminal; set by init, may be overridden.
 *   last_stage    Stage of the last line written.
 *   last_percent  Percentage of the last line written, -1 if none yet.
 *   line_open     Whether the current line still awaits its newline.
 */
typedef struct {
  FILE *stream;
  bool is_tty;
  pamble_stage last_stage;
  int last_percent;
  bool line_open;
} pamble_progress_terminal;

/*
 * @brief Delivers an event to a progress callback, if one is set.
 *
 * @param progress Destination; NULL or a NULL report makes this a no-op.
 * @param event Event to deliver.
 */
void pamble_progress_emit(const pamble_progress *progress,
                          const pamble_progress_event *event);

/*
 * @brief Returns the human-readable name of a stage.
 *
 * @param stage Stage to name.
 *
 * @return A static string such as "encrypting", or "working" for an unknown
 *         stage.
 */
const char *pamble_progress_stage_label(pamble_stage stage);

/*
 * @brief Formats an event as a single line of text, without a newline.
 *
 * Produces "[step/count] label..." for label-only stages, an iteration
 * counter with thousands separators for key derivation, and a bar such as
 * "[3/5] [=====>              ]  30% encrypting" for byte-counted stages.
 *
 * Behaves like snprintf: at most buffer_length - 1 characters are written,
 * the result is always NUL-terminated when buffer_length is non-zero, and the
 * return value is the length the full line would have.
 *
 * @param event Event to format.
 * @param buffer Output buffer.
 * @param buffer_length Size of buffer in bytes.
 *
 * @return Length of the full formatted line, excluding the NUL.
 */
size_t pamble_progress_format(const pamble_progress_event *event, char *buffer,
                              size_t buffer_length);

/*
 * @brief Initializes a terminal progress reporter.
 *
 * @param terminal Reporter state to initialize.
 * @param stream Stream to write to; is_tty is set from isatty on its file
 *               descriptor.
 */
void pamble_progress_terminal_init(pamble_progress_terminal *terminal,
                                   FILE *stream);

/*
 * @brief pamble_progress_fn that draws updates on a terminal.
 *
 * Use with a pamble_progress_terminal as the context:
 * (pamble_progress){.report = pamble_progress_terminal_report,
 *                   .context = &terminal}.
 *
 * @param context Pointer to a pamble_progress_terminal.
 * @param event Event to draw.
 */
void pamble_progress_terminal_report(void *context,
                                     const pamble_progress_event *event);

/*
 * @brief Ends a line left open by an unfinished stage.
 *
 * Call before printing anything else (such as an error message) after an
 * operation that may have stopped mid-stage. Does nothing if no line is open.
 *
 * @param terminal Reporter state.
 */
void pamble_progress_terminal_finish(pamble_progress_terminal *terminal);
