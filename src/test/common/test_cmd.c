#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "errno.h"

#include "test_cmd.h"

#define TWT_TC_SUCCESS "success"
#define TWT_TC_FAILURE "failure"

/* TC cmds are in below format
 * +------+--------------+-------------------~~------+
 * | type |      len     |          Payload          |
 * +------+--------------+-------------------~~------+
 */

enum tc_cmd_type {
    TC_START = 1,
    TC_ARG,
    TC_RESULT,
    TC_STOP
};

#pragma pack(1)

typedef struct tc_cmd_hdr_st {
    uint8_t type;
    uint16_t len;
}TC_CMD_HDR;

typedef struct tc_cmd_result_st {
    TC_CMD_HDR hdr;
    uint8_t result;
}TC_CMD_RESULT;

#pragma pack()

/* Description: Reads data from socket of buf_size
 *
 * @return: TWT_SUCCESS or TWT_FAILURE */
int receive_n(int test_fd, char *buf, size_t buf_size)
{
    int ret;
    int off = 0; /* received */
    do {
        if ((ret = recv(test_fd, buf + off, buf_size - off, 0)) <= 0) {
            ERR("Test FD receive failed, ret=%d, errno=%d\n", ret, errno);
            return TWT_FAILURE;
        }
        off += ret;
    } while (off < buf_size);
    return TWT_SUCCESS;
}

int receive_tc(TC_AUTOMATION *ta, char *buf, size_t buf_size)
{
    TC_CMD_HDR hdr;
    size_t payload_len;
    memset(&hdr, 0, sizeof(hdr));
    if (receive_n(ta->test_fd, (char *)&hdr, sizeof(hdr)) != TWT_SUCCESS) {
        return TWT_FAILURE;
    }
    if (hdr.type == TC_STOP) {
        DBG("Received TC_STOP msg\n");
        return TWT_STOP_AUTOMATION;
    }
    payload_len = ntohs(hdr.len);
    if (payload_len > (buf_size - 1)) {
        ERR("Insufficient buffer for size=%zu\n", payload_len);
        return TWT_FAILURE;
    }
    if (receive_n(ta->test_fd, buf, payload_len) != TWT_SUCCESS) {
        return TWT_FAILURE;
    }
    buf[payload_len] = '\0';
    return TWT_SUCCESS;
}

int send_tc_result(TC_AUTOMATION *ta, int result_val)
{
    TC_CMD_RESULT result;
    int ret;
    memset(&result, 0, sizeof(result));
    result.hdr.type = TC_RESULT;
    result.hdr.len = htons(1);
    if (result_val == TWT_SUCCESS) {
        result.result = 0;
        DBG("TC Success\n");
    } else {
        result.result = 1;
        ERR("TC Failure\n");
    }
    result.result = (result_val == TWT_SUCCESS) ? 0 : 1;
    if ((ret = send(ta->test_fd, &result, sizeof(result), 0)) <= 0) {
        ERR("Send Test result failed, ret=%d, errno=%d\n", ret, errno);
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}
