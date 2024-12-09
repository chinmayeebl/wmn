// ssl_server.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sockfd, new_sock;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("Unable to create socket");
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        error("Unable to bind");
    }

    if (listen(sockfd, 1) < 0) {
        error("Unable to listen");
    }

    printf("Server is listening on port %d...\n", PORT);
    
    while (1) {
        new_sock = accept(sockfd, (struct sockaddr*)&addr, &len);
        if (new_sock < 0) {
            error("Unable to accept");
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buffer[256] = {0};
            SSL_read(ssl, buffer, sizeof(buffer));
            printf("Client message: %s\n", buffer);
            SSL_write(ssl, "Hello, Client!", strlen("Hello, Client!"));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_sock);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}