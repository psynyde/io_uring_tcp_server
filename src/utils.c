#include "utils.h"
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

void log_info(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  fprintf(stdout, ANSI_GRAY_BG_BLACK_FG " INF " ANSI_RESET " ");
  vfprintf(stdout, fmt, args);
  fprintf(stdout, "\n");

  va_end(args);
}

void log_warn(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  fprintf(stderr, ANSI_YELLOW_BG_BLACK_FG " WRN " ANSI_RESET " ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");

  va_end(args);
}

void log_err(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  fprintf(stderr, ANSI_RED_BG_BLACK_FG " ERR " ANSI_RESET " ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");

  va_end(args);
}

int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
