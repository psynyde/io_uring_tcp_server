// #define _GNU_SOURCE
#include "netdb.h"
#include <fcntl.h>
#include <netinet/in.h>
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

#define ANSI_WHITE_BG_BLACK_FG "\033[47;30m"
#define ANSI_RED_BG_BLACK_FG "\033[41;30m"
#define ANSI_GREEN_BG_BLACK_FG "\033[42;30m"
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

int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int submit_accept(struct io_uring *ring, int listen_fd) {
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

  io_uring_prep_accept(sqe, listen_fd, (struct sockaddr *)&d->addr, &d->addrlen,
                       0);
  io_uring_sqe_set_data(sqe, d);
  return io_uring_submit(ring);
}

int submit_recv(struct io_uring *ring, int client_fd) {
  struct io_data *d = calloc(1, sizeof(*d));
  if (!d)
    return -1;
  d->type = OP_READ;
  d->fd = client_fd;
  d->buflen = BUF_SIZE;
  d->buf = malloc(d->buflen + 1);
  if (!d->buf) {
    free(d);
    return -1;
  }
  memset(d->buf, 0, d->buflen);

  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_recv(sqe, client_fd, d->buf, d->buflen, 0);
  io_uring_sqe_set_data(sqe, d);
  return io_uring_submit(ring);
}

int submit_send(struct io_uring *ring, int client_fd, const char *msg,
                size_t len) {
  struct io_data *d = calloc(1, sizeof(*d));
  if (!d)
    return -1;
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
  io_uring_prep_send(sqe, client_fd, d->buf, len, 0);
  io_uring_sqe_set_data(sqe, d);
  return io_uring_submit(ring);
}

int main(void) {
  struct io_uring ring;
  if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
    perror("io_uring_queue_init");
    return 1;
  }

  int server_fd;
  struct addrinfo hints, *p, *servinfo;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int rv, yes = 1;
  rv = getaddrinfo(NULL, PORT, &hints, &servinfo);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo err: %s\n", gai_strerror(rv));
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
    fprintf(stderr,
            "HOW TF THIS ERR EVEN MANAGE TO OCCUR AFTER ALL THOSE CHECKS");
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
    fprintf(stderr, "failed to submit initial accept\n");
    return 1;
  }

  // main completion loop
  while (1) {
    struct io_uring_cqe *cqe;
    int ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
      fprintf(stderr, "io_uring_wait_cqe: %s\n", strerror(-ret));
      break;
    }
    struct io_data *d = io_uring_cqe_get_data(cqe);
    int res = cqe->res;

    if (!d) {
      // shouldn't happen
      io_uring_cqe_seen(&ring, cqe);
      continue;
    }

    if (d->type == OP_ACCEPT) {
      if (res < 0) {
        fprintf(stderr, "accept failed: %s\n", strerror(-res));
        free(d);
        // re instantiate accept
        submit_accept(&ring, server_fd);
      } else {
        int client_fd = res;
        printf(ANSI_WHITE_BG_BLACK_FG " NEW " ANSI_RESET
                                      " accepted client fd=%d\n",
               client_fd);
        set_nonblocking(client_fd);

        submit_accept(&ring, server_fd);

        // start reading from client
        if (submit_recv(&ring, client_fd) < 0) {
          close(client_fd);
        }
        free(d); // accept's io_data no longer needed
      }
    } else if (d->type == OP_READ) {
      if (res <= 0) {
        // 0 -> client closed, <0 -> error
        if (res == 0)
          printf(ANSI_RED_BG_BLACK_FG " CLS " ANSI_RESET
                                      " client fd=%d closed connection\n",
                 d->fd);
        else
          fprintf(stderr, "recv error fd=%d: %s\n", d->fd, strerror(-res));
        close(d->fd);
        free(d->buf);
        free(d);
      } else {
        // got data
        size_t n = (size_t)res;

        if (d->buf[n - 1] == '\n') {
          d->buf[n - 1] = '\0';
        } else {
          d->buf[n] = '\0';
        }
        printf("client(%d) -> %s\n", d->fd, d->buf);

        // reply (Hello kitty)
        const char *msg = "Got your shit\n";
        if (submit_send(&ring, d->fd, msg, strlen(msg)) < 0) {
          close(d->fd);
        }
        // we free this read buffer; after the write completes we'll re-issue a
        // recv
        free(d->buf);
        free(d);
      }
    } else if (d->type == OP_WRITE) {
      if (res < 0) {
        fprintf(stderr, "send error fd=%d: %s\n", d->fd, strerror(-res));
        close(d->fd);
        free(d->buf);
        free(d);
      } else {
        // sent ok (not handling partial sends in this simple example)
        // now re-issue a recv to keep the connection alive
        if (submit_recv(&ring, d->fd) < 0) {
          close(d->fd);
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
