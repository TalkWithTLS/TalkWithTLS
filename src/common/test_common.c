#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "test_common.h"

int create_udp_sock()
{
    int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("socket creation failed, errno%d\n", errno);
        return -1;
    }
    return fd;
}

int create_udp_serv_sock(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int fd;
    fd = create_udp_sock();
    if (fd < 0) {
        printf("socket creation failed\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
        printf("bind failed, errno=%d\n", errno);
        goto err_handler;
    }
    return fd;
err_handler:
    close(fd);
    return -1;
}

int do_tcp_connection(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int count = 0;
    int fd;
    int ret;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }
    printf("Client fd=%d created\n", fd);

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    do {
        ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (ret) {
            printf("Connect failed, errno=%d\n", errno);
            goto err_handler;
        } else {
            break;
        }
        count++;
        usleep(TCP_CON_RETRY_WAIT_TIME_MS);
    } while (count < TCP_CON_RETRY_COUNT);
    
    printf("TLS connection succeeded, fd=%d\n", fd);
    return fd;
err_handler:
    close(fd);
    return -1;
}

int do_tcp_listen(const char *server_ip, uint16_t port)
{
    struct sockaddr_in addr;
    int optval = 1;
    int lfd;
    int ret;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    addr.sin_port = htons(port);

    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
        printf("set sock reuseaddr failed\n");
    }
    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        printf("bind failed %s:%d\n", server_ip, port);
        goto err_handler;
    }

    ret = listen(lfd, 5);
    if (ret) {
        printf("listen failed\n");
        goto err_handler;
    }
    printf("Listening on %s:%d\n", server_ip, port);
    printf("TCP listen fd=%d\n", lfd);
    return lfd;
err_handler:
    close(lfd);
    return -1;
}

int do_tcp_accept(int lfd)
{
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int cfd;

    printf("Waiting for TCP connection from client...\n");
    cfd = accept(lfd, (struct sockaddr *)&peeraddr, &peerlen);
    if (cfd < 0) {
        printf("accept failed, errno=%d\n", errno);
        return -1;
    }

    printf("TCP connection accepted fd=%d\n", cfd);
    return cfd;
}
