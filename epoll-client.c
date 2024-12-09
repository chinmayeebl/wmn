/* client epoll */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
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
    int sockfd, epollfd, n;
    struct sockaddr_in servaddr;
    struct epoll_event ev, events[MAX_EVENTS];
    char sendline[MAXLINE] = "Hello, server!";
    char recvline[MAXLINE];
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    set_nonblocking(sockfd);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &servaddr.sin_addr) <= 0) {
        perror("inet_pton error");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
       /* if (errno != EINPROGRESS) {
            perror("connect failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }*/
    }

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1 failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
    ev.data.fd = sockfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        perror("epoll_ctl failed");
        close(sockfd);
        close(epollfd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait failed");
            close(sockfd);
            close(epollfd);
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].events & EPOLLOUT) {
                n = write(sockfd, sendline, strlen(sendline));
                if (n < 0) {
                    perror("write failed");
                    close(sockfd);
                    close(epollfd);
                    exit(EXIT_FAILURE);
                }
                printf("Sent: %s\n", sendline);
                ev.events = EPOLLIN | EPOLLET;
                epoll_ctl(epollfd, EPOLL_CTL_MOD, sockfd, &ev);
            }

            if (events[i].events & EPOLLIN) {
                n = read(sockfd, recvline, MAXLINE);
                if (n < 0) {
                    perror("read failed");
                    close(sockfd);
                    close(epollfd);
                    exit(EXIT_FAILURE);
                }
                recvline[n] = '\0';
                printf("Received: %s\n", recvline);
                close(sockfd);
                close(epollfd);
                exit(EXIT_SUCCESS);
            }
        }
    }

    close(sockfd);
    close(epollfd);
    return 0;
}
