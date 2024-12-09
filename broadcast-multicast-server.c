/*### 7. **Broadcast and Multicast Sockets**

**Program:** Multicast Chat Application

**Server:**

```c
*/
// server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define GROUP "127.0.0.1"
#define MAXLINE 1024

int main() {
    int sockfd;
    struct sockaddr_in servaddr;
    char message[MAXLINE] = "Hello, Multicast!";

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(GROUP);
    servaddr.sin_port = htons(PORT);

    while (1) {
        sendto(sockfd, message, strlen(message), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
        printf("Message sent: %s\n", message);
        sleep(2);
    }

    close(sockfd);
    return 0;
}
/*

**Explanation:**
- The server sends multicast messages to a specific multicast group.
- The client joins the multicast group and receives messages sent by the server.
- The `setsockopt` function with `IP_ADD_MEMBERSHIP` is used to join the multicast group.
*/
