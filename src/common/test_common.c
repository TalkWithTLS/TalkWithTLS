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
        PRINT("socket creation failed, errno%d\n", errno);
        return -1;
    }
    return fd;
}

int create_udp_serv_sock(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int optval = 1;
    int fd;

    fd = create_udp_sock();
    if (fd < 0) {
        PRINT("socket creation failed\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        PRINT("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
        PRINT("set sock reuseaddr failed\n");
    }
    if (bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
        PRINT("bind failed, errno=%d\n", errno);
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
        PRINT("Socket creation failed\n");
        return -1;
    }
    PRINT("Client fd=%d created\n", fd);

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        PRINT("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    PRINT("Connecting to %s:%d...\n", server_ip, port);
    do {
        ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (ret) {
            PRINT("Connect failed, errno=%d\n", errno);
            goto err_handler;
        } else {
            break;
        }
        count++;
        usleep(TCP_CON_RETRY_WAIT_TIME_MS);
    } while (count < TCP_CON_RETRY_COUNT);
    
    PRINT("TLS connection succeeded, fd=%d\n", fd);
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
        PRINT("Socket creation failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &addr.sin_addr) == 0) {
        PRINT("inet_aton failed\n");
        goto err_handler;
    }
    addr.sin_port = htons(port);

    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
        PRINT("set sock reuseaddr failed\n");
    }
    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        PRINT("bind failed %s:%d\n", server_ip, port);
        goto err_handler;
    }

    PRINT("TCP listening on %s:%d...\n", server_ip, port);
    ret = listen(lfd, 5);
    if (ret) {
        PRINT("listen failed\n");
        goto err_handler;
    }
    PRINT("TCP listen fd=%d\n", lfd);
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

    PRINT("Waiting for TCP connection from client on listen fd=%d...\n", lfd);
    cfd = accept(lfd, (struct sockaddr *)&peeraddr, &peerlen);
    if (cfd < 0) {
        PRINT("accept failed, errno=%d\n", errno);
        return -1;
    }

    PRINT("TCP connection accepted fd=%d\n", cfd);
    return cfd;
}

int set_receive_to(int fd, int secs)
{
    struct timeval tv;
    tv.tv_sec = secs;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) != 0) {
        PRINT("Setting receive timeout on fd=%d failed\n", fd);
        return -1;
    }
    PRINT("Set receive timeout=%dsecs on fd=%d\n", secs, fd);
    return 0;
}

void check_and_close(int *fd)
{
    if (*fd < 0) {
        return;
    }
    if (*fd == 0 || *fd == 1 || *fd == 2) {
        PRINT("Trying to close fd=%d, skipping it !!!\n", *fd);
    }
    PRINT("Closing fd=%d\n", *fd);
    close(*fd);
    *fd = -1;
}
