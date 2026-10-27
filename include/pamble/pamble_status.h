#pragma once

/**
 * @brief Returns from the current function if a status indicates an error.
 *
 * Evaluates the supplied status expression once. If the resulting status
 * is not PAMBLE_OK, returns that status from the current function.
 *
 * @param status Status expression to evaluate.
 *
 * @note This macro can only be used in functions whose return type is
 *       compatible with pamble_status.
 */
#define PAMBLE_RETURN_IF_ERROR(status)                                         \
  do {                                                                         \
    if ((status) != PAMBLE_OK) {                                               \
      return (status);                                                         \
    }                                                                          \
  } while (0)

/**
 * @brief Status codes returned by the Pamble API.
 *
 * Functions in the Pamble API use pamble_status to indicate whether an
 * operation completed successfully or why it failed.
 */
typedef enum {
  PAMBLE_OK = 0,
  PAMBLE_INVALID_ARGUMENT,
  PAMBLE_SIZE_OVERFLOW,
  PAMBLE_IO_ERROR,
  PAMBLE_INVALID_ARCHIVE,
} pamble_status;
