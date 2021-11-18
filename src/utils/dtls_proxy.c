/*
 * DTLS Proxy
 *
 * Acts as a Layer 4 proxy and converts DTLS over TCP to DTLS over UDP
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>

#include "test_common.h"


#define MAX_MSG_SIZE   16389 // 5 + 16384

#define MAX_MSG     10

#define RECORD_SIZE 5

#define MAX_EPOLL_EVENTS 2

#define MAX_IP_STR  64

/* mode in struct dtls_conn */
enum dtls_conn_mode {
    UDP_SERV_TCP_CLNT = 0,
    UDP_CLNT_TCP_SERV,
    DTLS_CONN_MODE_MAX
};

enum sock_conn_type {
    UDP_CONN = 0,
    TCP_CONN
};

struct saddr {
    char ip[MAX_IP_STR];
    uint16_t port;
};

struct dtls_msg {
    uint8_t buf[MAX_MSG_SIZE];
    uint16_t buf_data_len;
    /* expected_tot_len is used only on TCP to receive complete record */
    uint16_t expected_tot_len;
};

struct sock_conn {
    int fd;
    struct dtls_msg msg;
    enum sock_conn_type type;
    struct sockaddr_in peeraddr; /* updated only for UDP */
};

struct dtls_conn {
    struct sock_conn tcp;
    struct sock_conn udp;
    int efd; /* epoll fd */
    enum dtls_conn_mode mode;
};

#define MAX_MODE_STR    32
char g_mode_str[DTLS_CONN_MODE_MAX][MAX_MODE_STR] = {
    "UDP_SERV_TCP_CLNT",
    "UDP_CLNT_TCP_SERV"
};

void free_dtls_conn(struct dtls_conn *conn)
{
    if (conn == NULL) {
        return;
    }
    check_and_close(&conn->tcp.fd);
    check_and_close(&conn->udp.fd);
    check_and_close(&conn->efd);
    free(conn);
}

int create_connections_for_udp_serv_tcp_clnt(struct dtls_conn *conn,
                                            struct saddr *ds_addr,
                                            struct saddr *us_addr)
{
    conn->udp.fd = create_udp_serv_sock(ds_addr->ip, ds_addr->port);
    if (conn->udp.fd < 0) {
        ERR("UDP server socket creation on %s:%d failed\n", ds_addr->ip,
                                                        ds_addr->port);
        goto err;
    }
    DBG("Created UDP server socket fd=%d for downstream on %s:%d\n",
                    conn->udp.fd, ds_addr->ip, ds_addr->port);

    conn->tcp.fd = do_tcp_connection(us_addr->ip, us_addr->port);
    if (conn->tcp.fd == -1) {
        ERR("TCP Connection to upstream failed\n");
        goto err;
    }
    DBG("Established upstream TCP Connection on fd=%d\n", conn->tcp.fd);

    conn->udp.type = UDP_CONN;
    conn->tcp.type = TCP_CONN;
    return TWT_SUCCESS;
err:
    free_dtls_conn(conn);
    return TWT_FAILURE;
}

int create_connections_for_tcp_serv_udp_clnt(struct dtls_conn *conn,
                                            struct saddr *ds_addr,
                                            struct saddr *us_addr)
{
    //TODO
    return TWT_FAILURE;
}

int create_epoll_fd(struct dtls_conn *conn)
{
    struct epoll_event event = {0};
    int ret;

    if ((conn->efd = epoll_create1(0)) == -1) {
        ERR("Epoll fd creation failed\n");
        goto err;
    }

    DBG("Created epoll fd=%d\n", conn->efd);

    event.data.ptr = &conn->tcp;
    event.events = EPOLLIN;
    ret = epoll_ctl(conn->efd, EPOLL_CTL_ADD, conn->tcp.fd, &event);
    if (ret != 0) {
        ERR("Epoll add failed for tcp_fd=%d\n", conn->tcp.fd);
        goto err;
    }

    memset(&event, 0, sizeof(event));
    event.data.ptr = &conn->udp;
    event.events = EPOLLIN;
    ret = epoll_ctl(conn->efd, EPOLL_CTL_ADD, conn->udp.fd, &event);
    if (ret != 0) {
        ERR("Epoll add failed for udp_fd=%d\n", conn->udp.fd);
        goto err;
    }

    return TWT_SUCCESS;
err:
    return TWT_FAILURE;
}

struct dtls_conn *create_dtls_conn(struct saddr *ds_addr, struct saddr *us_addr,
                                                    enum dtls_conn_mode mode)
{
    struct dtls_conn *conn;
    int ret;

    if ((conn = calloc(1, sizeof(struct dtls_conn))) == NULL) {
        ERR("dtls_conn alloc failed\n");
        return NULL;
    }
    conn->tcp.fd = -1;
    conn->udp.fd = -1;
    conn->efd = -1;

    if (mode == UDP_SERV_TCP_CLNT) {
        ret = create_connections_for_udp_serv_tcp_clnt(conn, ds_addr, us_addr);
    } else if (mode == UDP_CLNT_TCP_SERV) {
        ret = create_connections_for_tcp_serv_udp_clnt(conn, ds_addr, us_addr);
    } else {
        ERR("Invalid mode=%d\n", mode);
        goto err;
    }
    if (ret != TWT_SUCCESS) {
        goto err;
    }

    if (create_epoll_fd(conn) != TWT_SUCCESS) {
        ERR("Creating epoll fd failed\n");
        goto err;
    }
    conn->mode = mode;
    DBG("Created DTLS connection of mode [%s]\n", g_mode_str[mode]);
    return conn;
err:
    free_dtls_conn(conn);
    return NULL;
}

int send_msg_on_udp_conn(struct dtls_conn *conn, uint8_t *buf, uint16_t len)
{
    int ret;

    ret = sendto(conn->udp.fd, buf, len, 0,
                    (struct sockaddr *)&conn->udp.peeraddr,
                    sizeof(conn->udp.peeraddr));
    if (ret == -1) {
        ERR("sendmsg on UDP failed errno=%d\n", errno);
        return TWT_FAILURE;
    }
    DBG("Send %d len msg on UDP\n", len);
    return TWT_SUCCESS;
}

int send_msg_on_tcp_conn(struct dtls_conn *conn, uint8_t *buf, uint16_t len)
{
    int ret;

    ret = send(conn->tcp.fd, buf, len, 0);
    if (ret == -1) {
        ERR("sendmsg on TCP failed errno=%d\n", errno);
        return TWT_FAILURE;
    }
    DBG("Send %d len msg on TCP\n", len);
    return TWT_SUCCESS;
}

void handle_ingress_tcp_msg(struct dtls_conn *conn, struct sock_conn *sock)
{
    uint16_t len;
    uint8_t *buf;
    int ret;

    do {
        if (sock->msg.buf_data_len > 0) {
            buf = sock->msg.buf + sock->msg.buf_data_len;
            len = sock->msg.expected_tot_len - sock->msg.buf_data_len;
        } else {
            buf = sock->msg.buf;
            len = RECORD_SIZE;
        }
        ret = recv(sock->fd, buf, len, MSG_DONTWAIT);
        if (ret < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                DBG("Received stopped\n");
            } else {
                ERR("Receive msg on TCP sock %d failed, errno=%d\n",
                                                    sock->fd, errno);
            }
            return;
        }
        DBG("[TCP MSG] Received %d size msg\n", ret);
        /* If fresh record, then get length from record header */
        if (sock->msg.buf_data_len == 0) {
            sock->msg.buf_data_len = RECORD_SIZE;
            sock->msg.expected_tot_len = RECORD_SIZE + ((buf[3] << 8) | buf[4]);
            DBG("Record header received and payload length is %d\n",
                                    sock->msg.expected_tot_len);
            continue;
        }
        sock->msg.buf_data_len += ret;
        /* Complete record is received */
        if (sock->msg.buf_data_len == sock->msg.expected_tot_len) {
            send_msg_on_udp_conn(conn, sock->msg.buf, sock->msg.buf_data_len);
            sock->msg.buf_data_len = 0;
            sock->msg.expected_tot_len = 0;
        }
    } while (1);
}

void handle_ingress_udp_msg(struct dtls_conn *conn, struct sock_conn *sock)
{
    struct sockaddr_in *peeraddr = &sock->peeraddr;
    char peer_ip[MAX_IP_STR] = {0};
    socklen_t socklen = sizeof(sock->peeraddr);
    int ret;

    ret = recvfrom(sock->fd, sock->msg.buf, sizeof(sock->msg.buf), 0,
                    (struct sockaddr *)peeraddr, &socklen);
    if (ret < 0) {
        ERR("Receive msg on UDP sock %d failed, errno=%d\n", sock->fd, errno);
        return;
    }

    if (inet_ntop(AF_INET, &peeraddr->sin_addr, peer_ip, sizeof(peer_ip))
                                                            == NULL) {
        ERR("Getting peer IP string failed\n");
    }
    DBG("[UDP_MSG] Received %d size msg from %s:%d\n", ret, peer_ip,
                                            ntohs(peeraddr->sin_port));
    send_msg_on_tcp_conn(conn, sock->msg.buf, ret);
}

void handle_ingress_msg(struct dtls_conn *conn, struct sock_conn *sock)
{
    if (sock->type == TCP_CONN) {
        handle_ingress_tcp_msg(conn, sock);
    } else if (sock->type == UDP_CONN) {
        handle_ingress_udp_msg(conn, sock);
    } else {
        ERR("Invalid socket connection =%d\n", sock->type);
    }
}

int run_dtls_proxy(struct dtls_conn *conn)
{
    struct epoll_event events[MAX_EPOLL_EVENTS];
    int i, num;

    DBG("Going to listen on epoll..\n");
    do {
        memset(events, 0, sizeof(events));
        num = epoll_wait(conn->efd, (struct epoll_event *)&events,
                                        MAX_EPOLL_EVENTS, -1);
        if (num < 0) {
            ERR("Epoll wait err, errno=%d\n", errno);
            return TWT_FAILURE;
        }
        if (num > 0) {
            DBG("Events %d\n", num);
            for (i = 0; i < num; i++) {
                handle_ingress_msg(conn, events[i].data.ptr);
            }
        }
    } while (1);

    return TWT_SUCCESS;
}

int main(int argc, char *argv[])
{
    struct saddr ds_addr = {0}, us_addr = {0};
    struct dtls_conn *conn;
    int ret;

    strcpy(ds_addr.ip, "127.0.0.1");
    ds_addr.port = 17721;
    strcpy(us_addr.ip, "29.1.1.2");
    us_addr.port = 55000;

    conn = create_dtls_conn(&ds_addr, &us_addr, UDP_SERV_TCP_CLNT);
    if (conn == NULL) {
        ERR("Creating connection failed\n");
        return -1;
    }

    DBG("Starting DTLS Proxy\n");
    ret = run_dtls_proxy(conn);
    free_dtls_conn(conn);
    return ret;
}
