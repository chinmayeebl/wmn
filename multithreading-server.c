/*### 5. **Multithreaded Socket Programming**

**Program:** Multithreaded Server

```c

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#define PORT 8080
#define MAXLINE 1024

void *handle_client(void *arg) {
    int connfd = *((int *)arg);
    free(arg);
    char buffer[MAXLINE];
    int n;

    while ((n = read(connfd, buffer, sizeof(buffer))) > 0) {
        buffer[n] = '\0';
        printf("Client: %s\n", buffer);
        write(connfd, buffer, n);
    }

    close(connfd);
    return NULL;
}

int main() {
    int sockfd, *connfd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len;
    pthread_t tid;

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
        len = sizeof(cliaddr);
        connfd = malloc(sizeof(int));
        *connfd = accept(sockfd, (struct sockaddr*)&cliaddr, &len);
        if (*connfd < 0) {
            perror("accept");
            free(connfd);
            continue;
        }

        pthread_create(&tid, NULL, handle_client, connfd);
        pthread_detach(tid);
    }

    close(sockfd);
    return 0;
}

/*```

**Explanation:**
- Each client connection is handled in a separate thread.
- When a new connection is accepted, a new thread is created to handle the client's communication.
- The `pthread_detach` function is used to automatically clean up thread resources when it finishes.

Sure! Below is an example of a simple chat client that communicates with a multithreaded chat server. This client connects to the server, sends messages, and receives messages from the server in a separate thread.

### Multithreaded Chat Client

#### Step 1: Write the Client Code

Here's the C code for a chat client that works with a multithreaded server:

```c
*/


