#include "pamble/pamble_progress.h"

#include <inttypes.h>
#include <unistd.h>

#define PERCENT_MAX 100
#define DIGITS_PER_GROUP 3
#define NUMBER_BUFFER_SIZE 32
#define LINE_BUFFER_SIZE 128

#define BAR_FILLED '='
#define BAR_TIP '>'
#define BAR_EMPTY ' '

#define CLEAR_LINE "\r\x1b[2K"

/*
 * @brief Delivers an event to a progress callback, if one is set.
 *
 * @param progress Destination; NULL or a NULL report makes this a no-op.
 * @param event Event to deliver.
 */
void pamble_progress_emit(const pamble_progress *progress,
                          const pamble_progress_event *event) {

  if (progress == NULL || progress->report == NULL || event == NULL) {
    return;
  }

  progress->report(progress->context, event);
}

/*
 * @brief Returns the human-readable name of a stage.
 *
 * @param stage Stage to name.
 *
 * @return A static string such as "encrypting", or "working" for an unknown
 *         stage.
 */
const char *pamble_progress_stage_label(pamble_stage stage) {

  switch (stage) {
  case PAMBLE_STAGE_ARCHIVE:
    return "archiving files";
  case PAMBLE_STAGE_DERIVE_KEYS:
    return "deriving keys";
  case PAMBLE_STAGE_ENCRYPT:
    return "encrypting";
  case PAMBLE_STAGE_AUTHENTICATE:
    return "authenticating";
  case PAMBLE_STAGE_WRITE:
    return "writing output";
  case PAMBLE_STAGE_READ:
    return "reading input";
  case PAMBLE_STAGE_VERIFY:
    return "verifying";
  case PAMBLE_STAGE_DECRYPT:
    return "decrypting";
  case PAMBLE_STAGE_EXTRACT:
    return "extracting files";
  }

  return "working";
}

/*
 * @brief Computes the whole-number percentage of an event, from 0 to 100.
 *
 * A label-only event (total of zero) counts as 100%, and done is clamped to
 * total. Very large totals are divided first so the product cannot overflow.
 *
 * @param event Event to measure.
 *
 * @return Percentage complete.
 */
static int percent_of(const pamble_progress_event *event) {

  if (event->total == 0 || event->done >= event->total) {
    return PERCENT_MAX;
  }

  if (event->total > UINT64_MAX / PERCENT_MAX) {
    return (int)(event->done / (event->total / PERCENT_MAX));
  }

  return (int)((event->done * PERCENT_MAX) / event->total);
}

/*
 * @brief Formats a number with a comma between every group of three digits.
 *
 * 1200000 becomes "1,200,000".
 *
 * @param value Number to format.
 * @param output Output for the NUL-terminated text.
 */
static void format_thousands(uint64_t value,
                             char output[static NUMBER_BUFFER_SIZE]) {

  char digits[NUMBER_BUFFER_SIZE];
  const int digit_count = snprintf(digits, sizeof(digits), "%" PRIu64, value);

  size_t written = 0;

  for (int i = 0; i < digit_count; i++) {
    if (i > 0 && (digit_count - i) % DIGITS_PER_GROUP == 0) {
      output[written++] = ',';
    }
    output[written++] = digits[i];
  }

  output[written] = '\0';
}

/*
 * @brief Draws the bar cells for a percentage.
 *
 * Fills percent * PAMBLE_PROGRESS_BAR_WIDTH / 100 cells, ending in a '>' tip
 * until the bar is full.
 *
 * @param percent Percentage complete, 0 to 100.
 * @param bar Output for PAMBLE_PROGRESS_BAR_WIDTH cells plus a NUL.
 */
static void fill_bar(int percent,
                     char bar[static PAMBLE_PROGRESS_BAR_WIDTH + 1]) {

  const int filled = (percent * PAMBLE_PROGRESS_BAR_WIDTH) / PERCENT_MAX;

  for (int i = 0; i < PAMBLE_PROGRESS_BAR_WIDTH; i++) {
    if (i < filled - 1 || (i == filled - 1 && percent == PERCENT_MAX)) {
      bar[i] = BAR_FILLED;
    } else if (i == filled - 1) {
      bar[i] = BAR_TIP;
    } else {
      bar[i] = BAR_EMPTY;
    }
  }

  bar[PAMBLE_PROGRESS_BAR_WIDTH] = '\0';
}

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
                              size_t buffer_length) {

  const char *label = pamble_progress_stage_label(event->stage);
  int length;

  if (event->total == 0) {
    length = snprintf(buffer, buffer_length, "[%u/%u] %s...", event->step,
                      event->step_count, label);
  } else if (event->stage == PAMBLE_STAGE_DERIVE_KEYS) {
    char done[NUMBER_BUFFER_SIZE];
    char total[NUMBER_BUFFER_SIZE];

    format_thousands(event->done < event->total ? event->done : event->total,
                     done);
    format_thousands(event->total, total);

    length = snprintf(buffer, buffer_length, "[%u/%u] %s: %s/%s iterations",
                      event->step, event->step_count, label, done, total);
  } else {
    const int percent = percent_of(event);
    char bar[PAMBLE_PROGRESS_BAR_WIDTH + 1];

    fill_bar(percent, bar);

    length = snprintf(buffer, buffer_length, "[%u/%u] [%s] %3d%% %s",
                      event->step, event->step_count, bar, percent, label);
  }

  return length < 0 ? 0 : (size_t)length;
}

/*
 * @brief Initializes a terminal progress reporter.
 *
 * @param terminal Reporter state to initialize.
 * @param stream Stream to write to; is_tty is set from isatty on its file
 *               descriptor.
 */
void pamble_progress_terminal_init(pamble_progress_terminal *terminal,
                                   FILE *stream) {

  terminal->stream = stream;
  terminal->is_tty = isatty(fileno(stream)) == 1;
  terminal->last_stage = PAMBLE_STAGE_ARCHIVE;
  terminal->last_percent = -1;
  terminal->line_open = false;
}

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
                                     const pamble_progress_event *event) {

  pamble_progress_terminal *terminal = context;

  const int percent = percent_of(event);
  const bool finished = (event->total == 0 || event->done >= event->total) != 0;
  const bool same_stage = event->stage == terminal->last_stage;

  if (same_stage && percent == terminal->last_percent) {
    return;
  }

  if (!terminal->is_tty && !finished) {
    return;
  }

  if (!same_stage) {
    pamble_progress_terminal_finish(terminal);
  }

  char line[LINE_BUFFER_SIZE];
  pamble_progress_format(event, line, sizeof(line));

  if (terminal->is_tty) {
    fputs(CLEAR_LINE, terminal->stream);
  }

  fputs(line, terminal->stream);

  if (finished) {
    fputc('\n', terminal->stream);
  }

  terminal->line_open = ((!finished) != 0);
  terminal->last_stage = event->stage;
  terminal->last_percent = percent;

  fflush(terminal->stream);
}

/*
 * @brief Ends a line left open by an unfinished stage.
 *
 * Call before printing anything else (such as an error message) after an
 * operation that may have stopped mid-stage. Does nothing if no line is open.
 *
 * @param terminal Reporter state.
 */
void pamble_progress_terminal_finish(pamble_progress_terminal *terminal) {

  if (!terminal->line_open) {
    return;
  }

  fputc('\n', terminal->stream);
  terminal->line_open = false;
  fflush(terminal->stream);
}
