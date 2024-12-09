/*### Chat Client Using `select`

#### Step 1: Write the Client Code

Here's the C code for a chat client using `select`:

```c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define MAXLINE 1024

void handle_connection(int sockfd) {
    fd_set readfds;
    char sendline[MAXLINE], recvline[MAXLINE];
    int n;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds); // Add stdin to the set
        FD_SET(sockfd, &readfds); // Add the socket to the set

        int maxfd = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO;

        int activity = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            perror("select error");
            exit(EXIT_FAILURE);
        }

        // Check if data is available to read from stdin
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(sendline, MAXLINE, stdin) != NULL) {
                n = write(sockfd, sendline, strlen(sendline));
                if (n < 0) {
                    perror("write failed");
                    exit(EXIT_FAILURE);
                }
            }
        }

        // Check if data is available to read from the socket
        if (FD_ISSET(sockfd, &readfds)) {
            n = read(sockfd, recvline, MAXLINE);
            if (n < 0) {
                perror("read failed");
                exit(EXIT_FAILURE);
            } else if (n == 0) {
                printf("Server closed connection\n");
                close(sockfd);
                exit(EXIT_SUCCESS);
            } else {
                recvline[n] = '\0';
                printf("Server: %s", recvline);
            }
        }
    }
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &servaddr.sin_addr) <= 0) {
        perror("inet_pton error");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server. Type your messages below:\n");

    handle_connection(sockfd);

    close(sockfd);
    return 0;
}

/*
```

**Explanation:**
1. **Socket Creation and Server Address Configuration:**
    - A socket is created and configured to connect to the server using the specified IP and port.
2. **Connection to the Server:**
    - The client connects to the server.
3. **Multiplexing with `select`:**
    - An infinite loop is used to handle user input and server messages.
    - `select` is used to monitor both the standard input (`stdin`) and the socket for any data to read.
4. **Handling User Input and Server Messages:**
    - If there is data available on `stdin`, it reads the user input and sends it to the server.
    - If there is data available on the socket, it reads the server message and prints it.

#### Step 2: Compile and Run the Client

Compile the client code using:

```sh
gcc -o chat_client chat_client.c
```

Run the client using:

```sh
./chat_client
```

Make sure you have the corresponding chat server running that can handle multiple clients using the `select` system call. The client will connect to the server, allowing you to type messages which are then sent to the server, and any messages from the server will be displayed on the client terminal.

*/
