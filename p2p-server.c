// peer_server.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFSIZE 1024

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void send_file(int newsockfd, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        error("File not found");
    }

    char buffer[BUFSIZE];
    size_t n;

    while ((n = fread(buffer, 1, BUFSIZE, file)) > 0) {
        if (send(newsockfd, buffer, n, 0) < 0) {
            error("Send failed");
        }
    }

    fclose(file);
}

int main() {
    int sockfd, newsockfd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t cliaddrlen;
    char buffer[BUFSIZE];

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error("Socket creation failed");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        error("Bind failed");
    }

    // Listen for incoming connections
    if (listen(sockfd, 5) < 0) {
        error("Listen failed");
    }

    printf("Peer server is listening on port %d...\n", PORT);

    while (1) {
        cliaddrlen = sizeof(cliaddr);
        // Accept a new connection
        if ((newsockfd = accept(sockfd, (struct sockaddr *)&cliaddr, &cliaddrlen)) < 0) {
            error("Accept failed");
        }

        // Receive filename from client
        memset(buffer, 0, BUFSIZE);
        int n = read(newsockfd, buffer, BUFSIZE);
        if (n < 0) {
            error("Read failed");
        }
        printf("File requested: %s\n", buffer);

        // Send file to client
        send_file(newsockfd, buffer);

        close(newsockfd);
    }

    close(sockfd);
    return 0;
}