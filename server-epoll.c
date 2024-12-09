/*2. **Asynchronous I/O


**Program:** Echo Server using `epoll`
*/

//server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>

#define PORT 8080
#define MAX_EVENTS 10
#define MAXLINE 1024

void set_nonblocking(int sockfd) {
    int opts = fcntl(sockfd, F_GETFL);
    if (opts < 0) {
        perror("fcntl(F_GETFL)");
        exit(EXIT_FAILURE);
    }
    opts = (opts | O_NONBLOCK);
    if (fcntl(sockfd, F_SETFL, opts) < 0) {
        perror("fcntl(F_SETFL)");
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sockfd, connfd, epollfd;
    struct sockaddr_in servaddr, cliaddr;
    struct epoll_event ev, events[MAX_EVENTS];
    char buffer[MAXLINE];
    socklen_t len;
    int nfds, n;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    set_nonblocking(sockfd);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) {
        perror("socket bind failed");
        exit(EXIT_FAILURE);
    }

    if ((listen(sockfd, 5)) != 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = sockfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        perror("epoll_ctl: sockfd");
        exit(EXIT_FAILURE);
    }

    while (1) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == sockfd) {
                len = sizeof(cliaddr);
                connfd = accept(sockfd, (struct sockaddr*)&cliaddr, &len);
                if (connfd == -1) {
                    perror("accept");
                } else {
                    set_nonblocking(connfd);
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.fd = connfd;
                    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
                        perror("epoll_ctl: connfd");
                        exit(EXIT_FAILURE);
                    }
                }
            } else {
                int clientfd = events[i].data.fd;
                n = read(clientfd, buffer, sizeof(buffer));
                if (n == 0) {
                    close(clientfd);
                } else if (n < 0) {
                    /*if (errno != EWOULDBLOCK) {
                        perror("read");
                        close(clientfd);
                    }*/
                } else {
                    buffer[n] = '\0';
                    write(clientfd, buffer, n);
                }
            }
        }
    }

    close(sockfd);
    return 0;
}

/*

```

**Explanation:**
1. **Socket Creation and Non-blocking Setup:**
    - A socket is created and set to non-blocking mode.
2. **
 Address Configuration:**
    - The server address is set up using the IP and port of the echo server.
3. **Non-blocking Connect:**
    - The client attempts to connect to the server. If the connection is in progress, it proceeds without blocking.
4. **epoll Setup:**
    - An `epoll` instance is created, and the socket is added to the `epoll` instance to monitor for read and write events.
5. **Event Loop:**
    - The client waits for events using `epoll_wait`.
    - When the socket is ready for writing, it sends the message to the server and modifies the event to wait for read events.
    - When the socket is ready for reading, it reads the echoed message from the server and prints it.

Compile the code using:

```sh
gcc -o async_client async_client.c
```

Run the client using:

```sh
./async_client
```

Ensure you have an echo server running on `127.0.0.1:8080` for the client to connect and interact with.
*/
