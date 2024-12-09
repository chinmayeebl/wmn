// peer_client.c

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

void receive_file(int sockfd, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        error("File open failed");
    }

    char buffer[BUFSIZE];
    size_t n;

    while ((n = recv(sockfd, buffer, BUFSIZE, 0)) > 0) {
        fwrite(buffer, 1, n, file);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <peer_ip> <filename>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *peer_ip = argv[1];
    const char *filename = argv[2];

    int sockfd;
    struct sockaddr_in servaddr;
    char buffer[BUFSIZE];

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error("Socket creation failed");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);

    // Convert IP address
    if (inet_pton(AF_INET, peer_ip, &servaddr.sin_addr) <= 0) {
        error("Invalid address/ Address not supported");
    }

    // Connect to peer server
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        error("Connection failed");
    }

    // Send filename to peer server
    write(sockfd, filename, strlen(filename));

    // Receive file from peer server
    receive_file(sockfd, filename);

    printf("File received: %s\n", filename);

    close(sockfd);
    return 0;
}