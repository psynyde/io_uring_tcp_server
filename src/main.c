#define _GNU_SOURCE

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <liburing.h>

#include "server.h"
#include "utils.h"

int LOOP_STATE = 1;

void sigint_handler(int s) {
  (void)s;
  log_info("Exiting with sigint_handler");
  LOOP_STATE = 0;
}

int main(void) {
  if (signal(SIGINT, sigint_handler) == SIG_ERR) {
    perror("Unable to set SIGINT handler");
    return EXIT_FAILURE;
  }

  int server_fd = get_server_fd();
  if (server_fd < 0) {
    log_err("server_fd init err");
    return EXIT_FAILURE;
  }

  struct io_uring ring;
  if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
    perror("io_uring_queue_init");
    return 1;
  }

  if (submit_accept(&ring, server_fd) < 0) {
    log_err("failed to submit initial accpet");
    return 1;
  }

  char ip_holder[INET6_ADDRSTRLEN];
  while (LOOP_STATE) {
    struct io_uring_cqe *cqe; // NOTE: creating cqe with each iteration
    int ret = io_uring_wait_cqe(&ring, &cqe);

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

    switch (d->type) {
    case OP_ACCEPT:
      if (handle_accept(d, res, server_fd, ip_holder, &ring) != 0) {
        continue;
      }
      break;
    case OP_READ:
      handle_read(res, d, &ring);
      break;
    case OP_WRITE:
      handle_write(res, d, &ring);
      break;
    default:
      log_warn("switch err on d->type");
    }
    io_uring_cqe_seen(&ring, cqe);
  }

  // HACK: extemely hacky shit. god forbid me
  if (pending_accpet_data) {
    log_info("Freeing final pending accept operation");
    if (pending_accpet_data->buf) {
      free(pending_accpet_data->buf);
    }
    free(pending_accpet_data);
    pending_accpet_data = NULL;
  }

  io_uring_queue_exit(&ring);
  close(server_fd);
  return 0;
}
