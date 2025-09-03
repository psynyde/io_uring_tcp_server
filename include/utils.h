#ifndef UTILS_H
#define UTILS_H

#define ANSI_RED_BG_BLACK_FG "\033[41;30m"
#define ANSI_GREEN_BG_BLACK_FG "\033[42;30m"
#define ANSI_YELLOW_BG_BLACK_FG "\033[43;5;242;30m"
#define ANSI_GRAY_BG_BLACK_FG "\033[48;5;242;30m"
#define ANSI_RESET "\033[0m"

void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

int set_nonblocking(int fd);

#endif
