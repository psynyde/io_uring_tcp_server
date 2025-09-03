#include "server.h"
#include "utils.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct io_data *pending_accpet_data = NULL;

int submit_accept(struct io_uring *ring, int server_fd) {
  struct io_data *d = calloc(1, sizeof(*d));
  if (!d)
    return -1;

  d->type = OP_ACCEPT;
  d->addrlen = sizeof(d->addr);
  pending_accpet_data = d;

  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (!sqe) {
    pending_accpet_data = NULL;
    free(d);
    log_err("Err init sqe inside submit_accept");
    return -1;
  }

  io_uring_prep_accept(sqe, server_fd, (struct sockaddr *)&d->addr, &d->addrlen,
                       0);
  io_uring_sqe_set_data(sqe, d);
  int ret = io_uring_submit(ring);
  if (ret < 0) {
    pending_accpet_data = NULL;
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
  d->buf = malloc(d->buflen);
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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
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
#pragma clang diagnostic pop

int get_server_fd(void) {
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
    return -1;
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
    perror("listen");
    close(server_fd);
    return -1;
  }
  set_nonblocking(server_fd);

  printf(ANSI_GREEN_BG_BLACK_FG " STR " ANSI_RESET
                                " server listening on port %s\n",
         PORT);
  return server_fd;
}

int handle_accept(struct io_data *d, int res, int server_fd, char *ip_holder,
                  struct io_uring *ring) {
  if (d == pending_accpet_data) {
    pending_accpet_data = NULL;
  }

  if (res < 0) {
    log_warn("Accecpt failed: %s", strerror(-res));
    free(d);
    if (submit_accept(ring, server_fd) < 0) {
      log_err("failed to submit_accept inside OP_ACCEPT");
      return -1;
    }
  } else {
    int client_fd = res;
    inet_ntop(d->addr.ss_family, get_in_addr((struct sockaddr *)&d->addr),
              ip_holder, INET6_ADDRSTRLEN);
    log_info("accepted client fd=%d, addr=%s", client_fd, ip_holder);
    set_nonblocking(client_fd);

    if (submit_accept(ring, server_fd) < 0) {
      log_err("failed to submit_accept inside OP_ACCEPT");
      return -1;
    }

    if (submit_recv(ring, client_fd) < 0) {
      close(client_fd);
    }
    free(d);
  }
  return 0;
}

void handle_read(int res, struct io_data *d, struct io_uring *ring) {
  if (res <= 0) {
    if (res == 0) {
      log_info("client fd=%d closed connection", d->fd);
    } else if (res == -ECONNRESET) {
      log_info("recv error fd=%d : %s", d->fd, strerror(-res));
    } else {
      log_warn("recv error fd=%d : %s (%d)", d->fd, strerror(-res), res);
    }
    close(d->fd);
    free(d->buf);
    free(d);

  } else {
    size_t n = (size_t)res;

    d->buf[n - 1] = '\0';

    printf("client(%d) -> %s\n", d->fd, d->buf);

    const char *msg = "Got your shit\n";
    if (submit_send(ring, d->fd, msg, strlen(msg) + 1) < 0) {
      close(d->fd);
      free(d->buf);
      free(d);
    }
    free(d->buf);
    free(d);
  }
}

void handle_write(int res, struct io_data *d, struct io_uring *ring) {
  if (res < 0) {
    if (res == -EPIPE || res == -ECONNRESET) {
      log_info("send error fd=%d: %s", d->fd, strerror(-res));
    } else {
      log_warn("send error fd=%d: %s (%d)", d->fd, strerror(-res), res);
    }
    close(d->fd);
    free(d->buf);
    free(d);
  } else {
    if (submit_recv(ring, d->fd) < 0) {
      close(d->fd);
      free(d->buf);
      free(d);
    }
    free(d->buf);
    free(d);
  }
}
