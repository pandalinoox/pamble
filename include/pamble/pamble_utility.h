#pragma once

#define PAMBLE_RETURN_IF_ERROR(status)                                         \
  do {                                                                         \
    if ((status) != 0) {                                                       \
      return (status);                                                         \
    }                                                                          \
  } while (0)
