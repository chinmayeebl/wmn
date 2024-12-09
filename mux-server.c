/*
### 3. **Multiplexing with `select`**

**Program:** Chat Server using `select`

```c

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>

#define PORT 8080
#define MAX_CLIENTS 30
#define MAXLINE 1024

int main() {
    int sockfd, connfd, max_sd, activity;
    struct sockaddr_in servaddr, cliaddr;
    fd_set readfds;
    int client_socket[MAX_CLIENTS] = {0};
    char buffer[MAXLINE];
    socklen_t len;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

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

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        max_sd = sockfd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_socket[i];
            if (sd > 0)
                FD_SET(sd, &readfds);
            if (sd > max_sd)
                max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
       // if ((activity < 0) && (errno != EINTR)) {
            perror("select error");
        //}

        if (FD_ISSET(sockfd, &readfds)) {
            len = sizeof(cliaddr);
            connfd = accept(sockfd, (struct sockaddr*)&cliaddr, &len);
            if (connfd < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = connfd;
                    printf("Adding client to list of sockets at index %d\n", i);
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_socket[i];
            if (FD_ISSET(sd, &readfds)) {
                int n = read(sd, buffer, sizeof(buffer));
                if (n == 0) {
                    close(sd);
                    client_socket[i] = 0;
                } else {
                    buffer[n] = '\0';
                    printf("Client %d: %s\n", i, buffer);
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (client_socket[j] != 0 && j != i) {
                            write(client_socket[j], buffer, n);
                        }
                    }
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
- A server socket is created and set to listen for incoming connections.
- The `select` function is used to monitor multiple sockets for readability.
- When a new connection is accepted, it is added to the list of monitored sockets.
- When data is available on a client socket, it is read and broadcast to all other connected clients.


Sure! Below is an example of a simple chat client that communicates with a chat server using the `select` system call for multiplexing. This example assumes you have a chat server running that uses the `select` system call to handle multiple clients.

*/

