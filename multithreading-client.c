// client

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define MAXLINE 1024

void *receive_messages(void *sockfd) {
    int n;
    char recvline[MAXLINE];
    int sock = *(int*)sockfd;

    while (1) {
        n = read(sock, recvline, MAXLINE);
        if (n < 0) {
            perror("read error");
            exit(EXIT_FAILURE);
        } else if (n == 0) {
            printf("Server closed connection\n");
            close(sock);
            exit(EXIT_SUCCESS);
        }
        recvline[n] = '\0';
        printf("Server: %s", recvline);
    }

    return NULL;
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr;
    char sendline[MAXLINE];
    pthread_t recv_thread;

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

    // Create a thread to receive messages from the server
    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)&sockfd) != 0) {
        perror("pthread_create error");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Main thread sends messages to the server
    while (1) {
        if (fgets(sendline, MAXLINE, stdin) != NULL) {
            if (write(sockfd, sendline, strlen(sendline)) < 0) {
                perror("write error");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }
    }

    // Clean up
    close(sockfd);
    pthread_cancel(recv_thread);  // Optionally cancel the receiving thread
    pthread_join(recv_thread, NULL);
    
    return 0;
}


/*
```

**Explanation:**
1. **Socket Creation and Server Address Configuration:**
    - A socket is created and configured to connect to the server using the specified IP and port.
2. **Connection to the Server:**
    - The client connects to the server.
3. **Multithreaded Receiving:**
    - A separate thread is created to handle receiving messages from the server. This thread continuously reads messages from the server and prints them.
4. **Sending Messages:**
    - The main thread handles user input and sends messages to the server.
5. **Thread Cleanup:**
    - The client optionally cancels and joins the receiving thread before exiting.

#### Step 2: Compile and Run the Client

Compile the client code using:

```sh
gcc -o chat_client chat_client.c -lpthread
```

Run the client using:

```sh
./chat_client
```

Ensure that the multithreaded server is running and ready to accept connections. This client will connect to the server, allowing you to type messages, which are then sent to the server, and any messages from the server will be displayed in the client terminal.

*/

