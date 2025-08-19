#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT "6969"
#define BACKLOG 10

int main(void) {
  printf("Hello kitty\n");
  setbuf(stdout, NULL);

  int err, sockfd, client_fd;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage client_addr;
  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((err = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "gai_error: %s \n", gai_strerror(err));
    exit(1);
  }

  int yes = 1;
  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
      perror("sock creation");
      continue;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < -1) {
      perror("setsockopt");
      exit(1);
    }

    if ((bind(sockfd, p->ai_addr, p->ai_addrlen)) != 0) {
      close(sockfd);
      perror("binding");
      continue;
    }
    break;
  }
  free(servinfo);

  if (p == NULL) {
    fprintf(stderr, "Bing goes brrr");
    exit(1);
  }
  if (listen(sockfd, BACKLOG) < 0) {
    perror("listen");
    exit(1);
  }
  printf("Started to listen on %s\n", PORT);

  socklen_t addrsize = sizeof(client_addr);
  char *msg = "Hello kitty\n";
  int len = strlen(msg);
  while (1) {
    if ((client_fd = accept(sockfd, (struct sockaddr *)&client_addr,
                            &addrsize)) == -1) {
      perror("accept");
      continue;
    }
    if ((send(client_fd, msg, len, 0) < 0)) {
      fprintf(stderr, "Err sending shit");
    }
    char buf[1024];
    if ((recv(client_fd, buf, sizeof(buf), 0)) == -1) {
      fprintf(stderr, "Gayaf");
    }
    printf("%s\n", buf);
    close(client_fd);
  }

  return EXIT_SUCCESS;
}
