#ifndef SERVER_H
#define SERVER_H

#define _GNU_SOURCE
#include <liburing.h>
#include <sys/socket.h>

#define PORT "6969"
#define BACKLOG 1080

#define QUEUE_DEPTH 256
#define BUF_SIZE 2048

enum op_type { OP_ACCEPT = 1, OP_READ = 2, OP_WRITE = 3 };

struct io_data {
  int fd;
  enum op_type type;
  char *buf;
  size_t buflen;
  struct sockaddr_storage addr;
  socklen_t addrlen;
};

extern struct io_data *pending_accpet_data;

int get_server_fd(void);
int submit_accept(struct io_uring *ring, int server_fd);
int submit_recv(struct io_uring *ring, int client_fd);
int submit_send(struct io_uring *ring, int client_fd, const char *msg,
                size_t len);
void *get_in_addr(struct sockaddr *sa);
int handle_accept(struct io_data *d, int res, int server_fd, char *ip_holder,
                  struct io_uring *ring);
void handle_read(int res, struct io_data *d, struct io_uring *ring);
void handle_write(int res, struct io_data *d, struct io_uring *ring);

#endif
