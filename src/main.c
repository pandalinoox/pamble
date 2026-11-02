#include "pamble/pamble_crypto.h"
#include "pamble/pamble_progress.h"
#include "pamble/pamble_status.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define PASSWORD_BUFFER_SIZE 1024

#define EXIT_OK 0
#define EXIT_FAILURE_STATUS 1
#define EXIT_USAGE 2

#define MIN_ARGUMENT_COUNT 3
#define MAX_ARGUMENT_COUNT 4
#define COMMAND_INDEX 1
#define INPUT_INDEX 2
#define OUTPUT_INDEX 3

#ifndef PAMBLE_VERSION
#define PAMBLE_VERSION "dev"
#endif

#define INFO_ARGUMENT_COUNT 2
#define NOT_AN_INFO_FLAG (-1)

#define PAMBLE_EXTENSION ".pamble"
#define PAMBLE_EXTENSION_LENGTH (sizeof(PAMBLE_EXTENSION) - 1)
#define DIRECTORY_MODE 0755
#define PATH_SEPARATOR '/'

typedef enum { COMMAND_ENCRYPT, COMMAND_DECRYPT, COMMAND_UNKNOWN } command;

/*
 * @brief Prints how to call the program.
 *
 * @param stream stdout for --help, stderr after a usage error.
 * @param program argv[0].
 */
static void print_usage(FILE *stream, const char *program) {
  fprintf(stream,
          "usage: %s encrypt <file-or-directory> [output-file]\n"
          "       %s decrypt <encrypted-file> [output-directory]\n"
          "\n"
          "Without an output, encrypt writes <input>" PAMBLE_EXTENSION
          " next to the input,\n"
          "and decrypt extracts into the directory that holds the encrypted\n"
          "file. A missing output directory is created.\n"
          "\n"
          "The password is read from the terminal, or from the first line of\n"
          "stdin when stdin is not a terminal.\n"
          "\n"
          "  -h, --help     show this help\n"
          "  -V, --version  show the version\n",
          program, program);
}

/*
 * @brief Handles --version and --help.
 *
 * @param argv Arguments; argv[1] is the only argument given and argv[0]
 *             names the program in the usage text.
 *
 * @return EXIT_OK if argv[1] was an informational flag, otherwise
 *         NOT_AN_INFO_FLAG.
 */
static int run_info_flag(char **argv) {

  const char *word = argv[COMMAND_INDEX];
  const char *program = argv[0];

  if (strcmp(word, "--version") == 0 || strcmp(word, "-V") == 0) {
    printf("pamble %s\n", PAMBLE_VERSION);
    return EXIT_OK;
  }

  if (strcmp(word, "--help") == 0 || strcmp(word, "-h") == 0) {
    print_usage(stdout, program);
    return EXIT_OK;
  }

  return NOT_AN_INFO_FLAG;
}

/*
 * @brief Maps the command-line word to a command.
 *
 * @param word argv[1].
 *
 * @return The matching command, or COMMAND_UNKNOWN.
 */
static command parse_command(const char *word) {

  if (strcmp(word, "encrypt") == 0) {
    return COMMAND_ENCRYPT;
  }

  if (strcmp(word, "decrypt") == 0) {
    return COMMAND_DECRYPT;
  }

  return COMMAND_UNKNOWN;
}

/*
 * @brief Returns a message for the user describing a failure.
 *
 * @param status Status returned by the operation.
 *
 * @return A static, human-readable message.
 */
static const char *status_message(pamble_status status) {

  switch (status) {
  case PAMBLE_OK:
    return "ok";
  case PAMBLE_INVALID_ARGUMENT:
    return "invalid arguments";
  case PAMBLE_SIZE_OVERFLOW:
    return "input too large, or out of memory";
  case PAMBLE_IO_ERROR:
    return "could not read or write a file (check the paths, and that "
           "nothing would be overwritten)";
  case PAMBLE_INVALID_ARCHIVE:
    return "not a pamble file, or the file is damaged";
  case PAMBLE_COUNTER_EXHAUSTED:
    return "input too large to encrypt (64 GiB limit)";
  case PAMBLE_AUTHENTICATION_FAILED:
    return "wrong password, or the file has been modified";
  }

  return "unknown error";
}

/*
 * @brief Reads one line into buffer and strips the line ending.
 *
 * @param stream Stream to read from.
 * @param buffer Output buffer.
 * @param length Output for the number of bytes kept.
 *
 * @return true if a line was read.
 */
static bool read_line(FILE *stream, char buffer[static PASSWORD_BUFFER_SIZE],
                      size_t *length) {

  if (fgets(buffer, PASSWORD_BUFFER_SIZE, stream) == NULL) {
    return false;
  }

  *length = strcspn(buffer, "\r\n");
  buffer[*length] = '\0';

  return true;
}

/*
 * @brief Prompts on stderr and reads a line from the terminal without echo.
 *
 * Echo is restored before returning, whatever happens.
 *
 * @param prompt Text shown before reading.
 * @param buffer Output buffer.
 * @param length Output for the number of bytes read.
 *
 * @return true if a line was read.
 */
static bool read_hidden(const char *prompt,
                        char buffer[static PASSWORD_BUFFER_SIZE],
                        size_t *length) {

  struct termios original;

  if (tcgetattr(STDIN_FILENO, &original) != 0) {
    return false;
  }

  struct termios hidden = original;
  hidden.c_lflag &= ~(tcflag_t)ECHO;

  fputs(prompt, stderr);
  fflush(stderr);

  tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden);
  const bool read_ok = read_line(stdin, buffer, length);
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);

  fputc('\n', stderr);

  return read_ok;
}

/*
 * @brief Gets the password from the terminal, or from stdin when piped.
 *
 * On a terminal the password is typed without echo; when confirm is set it
 * is asked for twice and both entries must match. When stdin is not a
 * terminal, its first line is used without a prompt. Empty passwords are
 * refused.
 *
 * @param confirm Ask twice (used for encryption).
 * @param password Output buffer.
 * @param length Output for the password length.
 *
 * @return true if a usable password was read.
 */
static bool get_password(bool confirm,
                         char password[static PASSWORD_BUFFER_SIZE],
                         size_t *length) {

  if (!isatty(STDIN_FILENO)) {
    return (read_line(stdin, password, length) && *length > 0) != 0;
  }

  if (!read_hidden("password: ", password, length) || *length == 0) {
    fputs("pamble: password must not be empty\n", stderr);
    return false;
  }

  if (!confirm) {
    return true;
  }

  char again[PASSWORD_BUFFER_SIZE];
  size_t again_length = 0;

  const bool matches =
      (read_hidden("confirm password: ", again, &again_length) &&
       again_length == *length && memcmp(again, password, *length) == 0) != 0;

  explicit_bzero(again, sizeof(again));

  if (!matches) {
    fputs("pamble: passwords do not match\n", stderr);
  }

  return matches;
}

/*
 * @brief Duplicates the first length bytes of a string.
 *
 * @param text Source string.
 * @param length Number of bytes to copy.
 *
 * @return A newly allocated NUL-terminated copy, or NULL if allocation fails.
 */
static char *copy_prefix(const char *text, size_t length) {

  char *copy = malloc(length + 1);

  if (copy != NULL) {
    memcpy(copy, text, length);
    copy[length] = '\0';
  }

  return copy;
}

/*
 * @brief Length of a path without its trailing separators.
 *
 * "photos/" and "photos//" both give the length of "photos". A path made only
 * of separators keeps its first one, so "/" stays "/".
 *
 * @param path Path to measure.
 *
 * @return Length to keep.
 */
static size_t trimmed_length(const char *path) {

  size_t length = strlen(path);

  while (length > 1 && path[length - 1] == PATH_SEPARATOR) {
    length--;
  }

  return length;
}

/*
 * @brief Default encrypt output: the input path plus ".pamble".
 *
 * "photos" and "photos/" both give "photos.pamble", next to the input.
 *
 * @param input_path Path being encrypted.
 *
 * @return A newly allocated path, or NULL if allocation fails.
 */
static char *default_encrypt_output(const char *input_path) {

  const size_t length = trimmed_length(input_path);

  char *output = copy_prefix(input_path, length + PAMBLE_EXTENSION_LENGTH);

  if (output != NULL) {
    memcpy(output + length, PAMBLE_EXTENSION, PAMBLE_EXTENSION_LENGTH + 1);
  }

  return output;
}

/*
 * @brief Default decrypt output: the directory holding the encrypted file.
 *
 * The archive already contains its own top-level folder, so extracting next
 * to "photos.pamble" recreates "photos" beside it. A bare file name gives
 * ".", and a file directly under the root gives "/".
 *
 * @param input_path Path of the encrypted file.
 *
 * @return A newly allocated path, or NULL if allocation fails.
 */
static char *default_decrypt_output(const char *input_path) {

  const size_t length = trimmed_length(input_path);

  size_t separator = length;

  while (separator > 0 && input_path[separator - 1] != PATH_SEPARATOR) {
    separator--;
  }

  if (separator == 0) {
    return copy_prefix(".", 1);
  }

  return copy_prefix(input_path, separator > 1 ? separator - 1 : 1);
}

/*
 * @brief Picks the output path: the one given, or the default for command.
 *
 * @param argc Argument count.
 * @param argv Arguments.
 * @param chosen Command being run.
 *
 * @return A newly allocated path, or NULL if allocation fails.
 */
static char *resolve_output(int argc, char **argv, command chosen) {

  if (argc == MAX_ARGUMENT_COUNT) {
    return copy_prefix(argv[OUTPUT_INDEX], strlen(argv[OUTPUT_INDEX]));
  }

  return chosen == COMMAND_ENCRYPT ? default_encrypt_output(argv[INPUT_INDEX])
                                   : default_decrypt_output(argv[INPUT_INDEX]);
}

/*
 * @brief Creates one directory, accepting one that already exists.
 *
 * @param path Directory to create.
 *
 * @return true if path is now a directory.
 */
static bool make_one_directory(const char *path) {

  if (mkdir(path, DIRECTORY_MODE) == 0) {
    return true;
  }

  struct stat info;

  return errno == EEXIST && stat(path, &info) == 0 && S_ISDIR(info.st_mode);
}

/*
 * @brief Makes sure path is a directory, creating it and its parents.
 *
 * Works like "mkdir -p". created reports whether the last component did not
 * exist before, so a failed decryption can remove a directory it made.
 *
 * @param path Directory that must exist.
 * @param created Output: true if this call created path itself.
 *
 * @return true if path is a directory.
 */
static bool ensure_directory(char *path, bool *created) {

  struct stat info;

  *created = false;

  if (stat(path, &info) == 0) {
    return S_ISDIR(info.st_mode);
  }

  for (char *at = path + 1; *at != '\0'; at++) {
    if (*at != PATH_SEPARATOR) {
      continue;
    }

    *at = '\0';
    const bool made = make_one_directory(path);
    *at = PATH_SEPARATOR;

    if (!made) {
      return false;
    }
  }

  *created = make_one_directory(path);

  return *created;
}

/*
 * @brief Runs encrypt or decrypt with terminal progress and wipes the password.
 *
 * @param chosen Command to run.
 * @param input_path Input path.
 * @param output_path Output path.
 * @param password Password buffer; wiped before returning.
 * @param password_length Number of password bytes.
 *
 * @return The operation's status.
 */
static pamble_status run(command chosen, const char *input_path,
                         const char *output_path,
                         char password[static PASSWORD_BUFFER_SIZE],
                         size_t password_length) {

  pamble_progress_terminal terminal;
  pamble_progress_terminal_init(&terminal, stderr);

  const pamble_crypto_payload payload = {
      .input_path = input_path,
      .output_path = output_path,
      .password = (const uint8_t *)password,
      .password_length = password_length,
      .progress =
          {
              .report = pamble_progress_terminal_report,
              .context = &terminal,
          },
  };

  const pamble_status status = chosen == COMMAND_ENCRYPT
                                   ? pamble_encrypt_archive(payload)
                                   : pamble_decrypt_archive(payload);

  explicit_bzero(password, PASSWORD_BUFFER_SIZE);
  pamble_progress_terminal_finish(&terminal);

  return status;
}

int main(int argc, char **argv) {

  const char *program = argc > 0 ? argv[0] : "pamble";

  if (argc == INFO_ARGUMENT_COUNT) {
    const int info_status = run_info_flag(argv);

    if (info_status != NOT_AN_INFO_FLAG) {
      return info_status;
    }
  }

  if (argc < MIN_ARGUMENT_COUNT || argc > MAX_ARGUMENT_COUNT) {
    print_usage(stderr, program);
    return EXIT_USAGE;
  }

  const command chosen = parse_command(argv[COMMAND_INDEX]);

  if (chosen == COMMAND_UNKNOWN) {
    print_usage(stderr, program);
    return EXIT_USAGE;
  }

  char *output_path = resolve_output(argc, argv, chosen);

  if (output_path == NULL) {
    fputs("pamble: out of memory\n", stderr);
    return EXIT_FAILURE_STATUS;
  }

  char password[PASSWORD_BUFFER_SIZE];
  size_t password_length = 0;

  if (!get_password(chosen == COMMAND_ENCRYPT, password, &password_length)) {
    explicit_bzero(password, sizeof(password));
    free(output_path);
    return EXIT_FAILURE_STATUS;
  }

  bool created_output = false;

  if (chosen == COMMAND_DECRYPT &&
      !ensure_directory(output_path, &created_output)) {
    fprintf(stderr, "pamble: cannot create directory %s\n", output_path);
    explicit_bzero(password, sizeof(password));
    free(output_path);
    return EXIT_FAILURE_STATUS;
  }

  const pamble_status status =
      run(chosen, argv[INPUT_INDEX], output_path, password, password_length);

  if (status != PAMBLE_OK && created_output) {
    rmdir(output_path);
  }

  if (status == PAMBLE_OK) {
    fprintf(stderr, "pamble: %s %s\n",
            chosen == COMMAND_ENCRYPT ? "wrote" : "extracted into",
            output_path);
  }

  free(output_path);

  if (status != PAMBLE_OK) {
    fprintf(stderr, "pamble: %s\n", status_message(status));
    return EXIT_FAILURE_STATUS;
  }

  return EXIT_OK;
}
