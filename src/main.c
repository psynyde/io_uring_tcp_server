#include "netdb.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <liburing.h>

#define PORT "6969"
#define BACKLOG 1080

#define QUEUE_DEPTH 256
#define BUF_SIZE 2048

#define ANSI_RED_BG_BLACK_FG "\033[41;30m"
#define ANSI_GREEN_BG_BLACK_FG "\033[42;30m"
#define ANSI_YELLOW_BG_BLACK_FG "\033[43;5;242;30m"
#define ANSI_GRAY_BG_BLACK_FG "\033[48;5;242;30m"
#define ANSI_RESET "\033[0m"

enum op_type { OP_ACCEPT = 1, OP_READ = 2, OP_WRITE = 3 };

struct io_data {
  int fd;
  enum op_type type;
  char *buf;
  size_t buflen;
  struct sockaddr_storage addr;
  socklen_t addrlen;
};

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

int loop_state = 0;
void sigint_handler(int s) {
  (void)s;
  log_info("Exiting with sigint_handler");
  loop_state = 1;
}

int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int submit_accept(struct io_uring *ring, int server_fd) {
  struct io_data *d = calloc(1, sizeof(*d));
  if (!d)
    return -1;

  d->type = OP_ACCEPT;
  d->addrlen = sizeof(d->addr);

  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (!sqe) {
    free(d);
    return -1;
  }

  io_uring_prep_accept(sqe, server_fd, (struct sockaddr *)&d->addr, &d->addrlen,
                       0);
  io_uring_sqe_set_data(sqe, d);
  int ret = io_uring_submit(ring);
  if (ret < 0) {
    free(d);
    log_warn("submit failed inside accept");
  }
  return ret;
}

int submit_recv(struct io_uring *ring, int client_fd) {
  struct io_data *d = calloc(1, sizeof(*d));
  if (!d)
    return -1;
  d->type = OP_READ;
  d->fd = client_fd;
  d->buflen = BUF_SIZE;
  d->buf = malloc(d->buflen); // NOTE: extra 1 byte for the \0
  if (!d->buf) {
    free(d);
    return -1;
  }
  memset(d->buf, 0, d->buflen);

  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (!sqe) {
    free(d->buf);
    free(d);
    return -1;
  }
  io_uring_prep_recv(sqe, client_fd, d->buf, d->buflen, 0);
  io_uring_sqe_set_data(sqe, d);
  int ret = io_uring_submit(ring);
  if (ret < 0) {
    free(d->buf);
    free(d);
    log_warn("submit failed inside recv");
  }
  return ret;
}

int submit_send(struct io_uring *ring, int client_fd, const char *msg,
                size_t len) {
  struct io_data *d = calloc(1, sizeof(*d));
  if (!d) {
    return -1;
  }
  d->type = OP_WRITE;
  d->fd = client_fd;
  d->buflen = len;
  d->buf = malloc(len + 1);
  if (!d->buf) {
    free(d);
    return -1;
  }
  memcpy(d->buf, msg, len);
  d->buf[len] = '\0';

  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (!sqe) {
    free(d->buf);
    free(d);
    return -1;
  }

  io_uring_prep_send(sqe, client_fd, d->buf, len, 0);
  io_uring_sqe_set_data(sqe, d);
  int ret = io_uring_submit(ring);
  if (ret < 0) {
    free(d->buf);
    free(d);
    log_warn("submit failed inside send");
  }
  return ret;
}

void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  } else if (sa->sa_family == AF_INET6) {
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
  } else {
    log_err("Error while get_in_addr");
    exit(1);
  }
}

int main(void) {
  if (signal(SIGINT, sigint_handler) == SIG_ERR) {
    perror("Unable to set SIGINT handler");
    return EXIT_FAILURE;
  }
  struct io_uring ring;
  if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
    perror("io_uring_queue_init");
    return 1;
  }

  int server_fd = -1;
  struct addrinfo hints, *p, *servinfo;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int rv, yes = 1;
  rv = getaddrinfo(NULL, PORT, &hints, &servinfo);
  if (rv != 0) {
    log_err("Error while get_in_addr %s", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    server_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (server_fd == -1) {
      perror("socket init");
      continue;
    }

    rv = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (rv != 0) {
      perror("setsockopt");
      exit(1);
    }
    rv = bind(server_fd, p->ai_addr, p->ai_addrlen);
    if (rv != 0) {
      close(server_fd);
      perror("binding");
      continue;
    }
    break;
  }
  freeaddrinfo(servinfo);

  if (p == NULL) {
    log_err("HOW TF THIS EVER MANAGE TO PASS ALL OTHER CHECKS");
    exit(1);
  }

  if (listen(server_fd, BACKLOG) == -1) {
    // FIX: Take ECONNREFUSED into consideration.
    // shouldn't just close & exit when a conn is refused.
    perror("listen");
    close(server_fd);
    return 1;
  }
  set_nonblocking(server_fd);

  printf(ANSI_GREEN_BG_BLACK_FG " STR " ANSI_RESET
                                " server listening on port %s\n",
         PORT);

  // submit first accept
  if (submit_accept(&ring, server_fd) < 0) {
    log_err("failed to submit initial accpet");
    return 1;
  }

  char ip_holder[INET6_ADDRSTRLEN];
  while (!loop_state) {
    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(&ring, &cqe);
    // NOTE: ret value is -errno instead of just errno so add -
    if (ret == -EINTR) {
      log_warn("EINIT encountred: %s", strerror(-ret));
      continue;
    } else if (ret < 0) {
      log_err("Unhandled io_uring_wait_cqe err: %s", strerror(-ret));
      exit(1);
    }
    struct io_data *d = io_uring_cqe_get_data(cqe);
    int res = cqe->res;

    if (!d) {
      io_uring_cqe_seen(&ring, cqe);
      continue;
    }

    if (d->type == OP_ACCEPT) {
      if (res < 0) {
        log_warn("Accecpt failed: %s", strerror(-res));
        free(d);
        if (submit_accept(&ring, server_fd) < 0) {
          log_err("failed to submit_accept inside OP_ACCEPT");
          continue;
        }
      } else {
        int client_fd = res;
        inet_ntop(d->addr.ss_family, get_in_addr((struct sockaddr *)&d->addr),
                  ip_holder, sizeof(ip_holder));
        log_info("accepted client fd=%d, addr=%s\n", client_fd, ip_holder);
        set_nonblocking(client_fd);

        if (submit_accept(&ring, server_fd) < 0) {
          log_err("failed to submit_accept inside OP_ACCEPT");
          continue;
        }

        // start reading from client
        if (submit_recv(&ring, client_fd) < 0) {
          close(client_fd);
        }
        free(d); // accept's io_data no longer needed
      }
    } else if (d->type == OP_READ) {
      if (res <= 0) { // 0 -> client closed, <0 -> error
        if (res == 0) {
          log_info("client fd=%d closed connection\n", d->fd);
        } else if (res == -ECONNRESET) {
          log_info("recv error fd=%d : %s", d->fd, strerror(-res));
        } else {
          log_warn("recv error fd=%d : %s (%d)", d->fd, strerror(-res), res);
        }
        close(d->fd);
        free(d->buf);
        free(d);

      } else {
        // got data
        size_t n = (size_t)res;

        // NOTE: n-1 cause array starts at 0 you dummy;
        // n is just total bytes read
        d->buf[n - 1] = '\0';
        // final byte always null terminated. cause the
        // client sends with \n at end not \0. \n reason terminal enter to send

        printf("client(%d) -> %s\n", d->fd, d->buf);

        // reply (Hello kitty)
        const char *msg = "Got your shit\n";
        if (submit_send(&ring, d->fd, msg, strlen(msg) + 1) < 0) {
          close(d->fd);
          free(d->buf);
          free(d);
        }

        free(d->buf);
        free(d);
      }
    } else if (d->type == OP_WRITE) {
      if (res < 0) {
        if (res == -EPIPE) {
          log_info("send error fd=%d: %s", d->fd, strerror(-res));
        } else {
          log_warn("send error fd=%d: %s (%d)", d->fd, strerror(-res), res);
        }
        close(d->fd);
        free(d->buf);
        free(d);
      } else {
        // sent ok (not handling partial sends in this simple example)
        // now re-issue a recv to keep the connection alive
        if (submit_recv(&ring, d->fd) < 0) {
          close(d->fd);
          free(d->buf);
          free(d);
        }
        free(d->buf);
        free(d);
      }
    }
    io_uring_cqe_seen(&ring, cqe);
  }

  io_uring_queue_exit(&ring);
  close(server_fd);
  return 0;
}
