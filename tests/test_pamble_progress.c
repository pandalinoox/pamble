#include "pamble/pamble_progress.h"

#include <criterion/criterion.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_SIZE 128
#define SMALL_BUFFER_SIZE 8
#define CLEAR "\r\x1b[2K"

#define ENCRYPT_STEP 3
#define STEP_COUNT 5
#define HUNDRED 100
#define THOUSAND 1000
#define HALF 50
#define THIRTY 30
#define NINETY_NINE 99
#define ONE_PERCENT_OF_THOUSAND 10
#define STILL_ONE_PERCENT_OF_THOUSAND 11
#define UNKNOWN_STAGE 99

#define KEYS_DONE 69420
#define KEYS_TOTAL 1200000
#define SMALL_KEYS_TOTAL 600

typedef struct {
  pamble_progress_event last;
  size_t count;
} recorder;

typedef struct {
  char *text;
  size_t length;
  FILE *stream;
  pamble_progress_terminal terminal;
} capture;

static void record(void *context, const pamble_progress_event *event) {
  recorder *rec = context;
  rec->last = *event;
  rec->count++;
}

static pamble_progress_event encrypt_event(uint64_t done, uint64_t total) {
  const pamble_progress_event event = {
      .stage = PAMBLE_STAGE_ENCRYPT,
      .step = ENCRYPT_STEP,
      .step_count = STEP_COUNT,
      .done = done,
      .total = total,
  };
  return event;
}

static pamble_progress_event label_event(pamble_stage stage, unsigned step) {
  const pamble_progress_event event = {
      .stage = stage,
      .step = step,
      .step_count = STEP_COUNT,
  };
  return event;
}

static bool formats_as(pamble_progress_event event, const char *expected) {
  char line[LINE_SIZE];
  const size_t length = pamble_progress_format(&event, line, sizeof(line));
  return (length == strlen(expected) && strcmp(line, expected) == 0) != 0;
}

static void assert_formats_as(pamble_progress_event event,
                              const char *expected) {
  cr_assert(formats_as(event, expected), "expected \"%s\"", expected);
}

static void capture_open(capture *cap, bool is_tty) {
  cap->text = NULL;
  cap->length = 0;
  cap->stream = open_memstream(&cap->text, &cap->length);
  cr_assert_not_null(cap->stream, "open_memstream failed");

  pamble_progress_terminal_init(&cap->terminal, cap->stream);
  cap->terminal.is_tty = is_tty;
}

static void capture_send(capture *cap, pamble_progress_event event) {
  pamble_progress_terminal_report(&cap->terminal, &event);
}

static bool capture_equals(capture *cap, const char *expected) {
  fclose(cap->stream);
  const bool equal =
      (cap->text != NULL && strcmp(cap->text, expected) == 0) != 0;
  free(cap->text);
  return equal;
}

static size_t count_occurrences(const char *text, const char *needle) {
  size_t count = 0;
  for (const char *at = strstr(text, needle); at != NULL;
       at = strstr(at + 1, needle)) {
    count++;
  }
  return count;
}

Test(pamble_progress, format_label_stage) {
  assert_formats_as(label_event(PAMBLE_STAGE_ARCHIVE, 1),
                    "[1/5] archiving files...");
}

Test(pamble_progress, format_key_iterations_with_separators) {
  pamble_progress_event event = {
      .stage = PAMBLE_STAGE_DERIVE_KEYS,
      .step = 2,
      .step_count = STEP_COUNT,
      .done = KEYS_DONE,
      .total = KEYS_TOTAL,
  };
  assert_formats_as(event, "[2/5] deriving keys: 69,420/1,200,000 iterations");
}

Test(pamble_progress, format_key_iterations_without_separators) {
  pamble_progress_event event = {
      .stage = PAMBLE_STAGE_DERIVE_KEYS,
      .step = 2,
      .step_count = STEP_COUNT,
      .done = 0,
      .total = SMALL_KEYS_TOTAL,
  };
  assert_formats_as(event, "[2/5] deriving keys: 0/600 iterations");
}

Test(pamble_progress, format_bar_empty) {
  assert_formats_as(encrypt_event(0, HUNDRED),
                    "[3/5] [                    ]   0% encrypting");
}

Test(pamble_progress, format_bar_thirty_percent) {
  assert_formats_as(encrypt_event(THIRTY, HUNDRED),
                    "[3/5] [=====>              ]  30% encrypting");
}

Test(pamble_progress, format_bar_ninety_nine_percent) {
  assert_formats_as(encrypt_event(NINETY_NINE, HUNDRED),
                    "[3/5] [==================> ]  99% encrypting");
}

Test(pamble_progress, format_bar_full) {
  assert_formats_as(encrypt_event(HUNDRED, HUNDRED),
                    "[3/5] [====================] 100% encrypting");
}

Test(pamble_progress, format_clamps_done_past_total) {
  assert_formats_as(encrypt_event(HUNDRED + 1, HUNDRED),
                    "[3/5] [====================] 100% encrypting");
}

Test(pamble_progress, format_truncates_like_snprintf) {
  const pamble_progress_event event = label_event(PAMBLE_STAGE_ARCHIVE, 1);
  char line[SMALL_BUFFER_SIZE];

  const size_t length = pamble_progress_format(&event, line, sizeof(line));

  cr_assert(length == strlen("[1/5] archiving files...") &&
                strcmp(line, "[1/5] a") == 0,
            "expected full length and a NUL-terminated prefix");
}

Test(pamble_progress, unknown_stage_label) {
  cr_assert_str_eq(pamble_progress_stage_label((pamble_stage)UNKNOWN_STAGE),
                   "working");
}

Test(pamble_progress, emit_to_null_progress_is_noop) {
  const pamble_progress_event event = encrypt_event(1, HUNDRED);
  pamble_progress_emit(NULL, &event);
}

Test(pamble_progress, emit_to_silent_progress_is_noop) {
  const pamble_progress silent = {.report = NULL, .context = NULL};
  const pamble_progress_event event = encrypt_event(1, HUNDRED);
  pamble_progress_emit(&silent, &event);
}

Test(pamble_progress, emit_delivers_event_once) {
  recorder rec = {.count = 0};
  const pamble_progress progress = {.report = record, .context = &rec};
  const pamble_progress_event event = encrypt_event(HALF, HUNDRED);

  pamble_progress_emit(&progress, &event);

  cr_assert(rec.count == 1 && rec.last.stage == PAMBLE_STAGE_ENCRYPT &&
                rec.last.step == ENCRYPT_STEP && rec.last.done == HALF &&
                rec.last.total == HUNDRED,
            "event was not delivered exactly once, unchanged");
}

Test(pamble_progress, piped_output_prints_only_finished_stage) {
  capture cap;
  capture_open(&cap, false);

  capture_send(&cap, encrypt_event(0, HUNDRED));
  capture_send(&cap, encrypt_event(HALF, HUNDRED));
  capture_send(&cap, encrypt_event(HUNDRED, HUNDRED));

  cr_assert(capture_equals(&cap, "[3/5] [====================] 100% "
                                 "encrypting\n"),
            "piped output should hold only the finished line");
}

Test(pamble_progress, piped_output_prints_each_label) {
  capture cap;
  capture_open(&cap, false);

  capture_send(&cap, label_event(PAMBLE_STAGE_ARCHIVE, 1));
  capture_send(&cap, label_event(PAMBLE_STAGE_WRITE, STEP_COUNT));

  cr_assert(capture_equals(&cap, "[1/5] archiving files...\n"
                                 "[5/5] writing output...\n"),
            "each label should be one line");
}

Test(pamble_progress, terminal_redraws_in_place) {
  capture cap;
  capture_open(&cap, true);

  capture_send(&cap, encrypt_event(0, HUNDRED));
  capture_send(&cap, encrypt_event(HALF, HUNDRED));
  capture_send(&cap, encrypt_event(HUNDRED, HUNDRED));

  cr_assert(capture_equals(&cap, CLEAR
                           "[3/5] [                    ]   0% encrypting" CLEAR
                           "[3/5] [=========>          ]  50% encrypting" CLEAR
                           "[3/5] [====================] 100% encrypting\n"),
            "terminal output should redraw one line, then end it");
}

Test(pamble_progress, terminal_skips_unchanged_percent) {
  capture cap;
  capture_open(&cap, true);

  capture_send(&cap, encrypt_event(ONE_PERCENT_OF_THOUSAND, THOUSAND));
  capture_send(&cap, encrypt_event(STILL_ONE_PERCENT_OF_THOUSAND, THOUSAND));

  fclose(cap.stream);
  const size_t redraws = count_occurrences(cap.text, CLEAR);
  free(cap.text);

  cr_assert_eq(redraws, 1, "same percentage was drawn %zu times", redraws);
}

Test(pamble_progress, stage_change_ends_unfinished_line) {
  capture cap;
  capture_open(&cap, true);

  capture_send(&cap, encrypt_event(HALF, HUNDRED));
  capture_send(&cap, label_event(PAMBLE_STAGE_AUTHENTICATE, 4));

  cr_assert(
      capture_equals(&cap, CLEAR
                     "[3/5] [=========>          ]  50% encrypting\n" CLEAR
                     "[4/5] authenticating...\n"),
      "an unfinished line should be ended before the next stage");
}

Test(pamble_progress, finish_ends_open_line) {
  capture cap;
  capture_open(&cap, true);

  capture_send(&cap, encrypt_event(HALF, HUNDRED));
  pamble_progress_terminal_finish(&cap.terminal);

  const bool closed = (!cap.terminal.line_open) != 0;

  cr_assert(capture_equals(&cap, CLEAR "[3/5] [=========>          ]  50% "
                                       "encrypting\n") &&
                closed,
            "finish should end the open line with a newline");
}

Test(pamble_progress, finish_without_open_line_writes_nothing) {
  capture cap;
  capture_open(&cap, true);

  pamble_progress_terminal_finish(&cap.terminal);

  cr_assert(capture_equals(&cap, ""), "finish should write nothing");
}
