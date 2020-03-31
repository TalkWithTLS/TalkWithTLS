#include "msg_cb.h"

const char *get_handshake_msg_type(const void *buf, size_t len)
{
    if (len < 1) {
        return "Handshake zero len";
    }
    switch (*((uint8_t *)buf)) {
        case SSL3_MT_HELLO_REQUEST:
            return "Hello Request";
        case SSL3_MT_CLIENT_HELLO:
            return "Client Hello";
        case SSL3_MT_SERVER_HELLO:
            return "Server Hello";
        case SSL3_MT_NEWSESSION_TICKET:
            return "New session ticket";
        case SSL3_MT_END_OF_EARLY_DATA:
            return "End of Ealy Data";
        case SSL3_MT_ENCRYPTED_EXTENSIONS:
            return "Encrypted extensions";
        case SSL3_MT_CERTIFICATE:
            return "Certificate";
        case SSL3_MT_SERVER_KEY_EXCHANGE:
            return "Server key exchange";
        case SSL3_MT_CERTIFICATE_REQUEST:
            return "Certificate Request";
        case SSL3_MT_SERVER_DONE:
            return "Server Done";
        case SSL3_MT_CERTIFICATE_VERIFY:
            return "Certificate Verify";
        case SSL3_MT_CLIENT_KEY_EXCHANGE:
            return "Client Key exchange";
        case SSL3_MT_FINISHED:
            return "Finished";
        case SSL3_MT_CERTIFICATE_URL:
            return "Certificate URL";
        case SSL3_MT_CERTIFICATE_STATUS:
            return "Certificate Status";
        case SSL3_MT_SUPPLEMENTAL_DATA:
            return "Supplemental Data";
        case SSL3_MT_KEY_UPDATE:
            return "Key Update";
        case SSL3_MT_NEXT_PROTO:
            return "Next Protocol";
        case SSL3_MT_MESSAGE_HASH:
            return "Message hash";
        case DTLS1_MT_HELLO_VERIFY_REQUEST:
            return "DTLS Hello Verify Request";
    }
    return NULL;
}

void print_content_type(int write_p, int version, int content_type, const void *buf,
                                                    size_t len, const char *prefix_str)
{
    const char *op = (write_p ? "Sent" : "Received");
    const char *cont_type = "Unknown msg";
    const char *handshake_type = NULL;
    int first_byte_val = -1;
    if (len >= 1) {
        first_byte_val = *((char*)buf);
    }
    switch(content_type) {
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            cont_type = "Change Cipher Spec";
            break;
        case SSL3_RT_ALERT:
            cont_type = "Alert";
            break;
        case SSL3_RT_HANDSHAKE:
            handshake_type = get_handshake_msg_type(buf, len);
            cont_type = handshake_type ? handshake_type : "Unknown Handshake";
            break;
        case SSL3_RT_APPLICATION_DATA:
            cont_type = "Application";
            break;
        case SSL3_RT_HEADER:
            cont_type = "Header";
            break;
        case SSL3_RT_INNER_CONTENT_TYPE:
            cont_type = "Inner Content";
            break;
    }
    printf("%s[ver=%04X]%s %s msg[len=%zu]", prefix_str, version, op, cont_type, len);
    if (content_type == SSL3_RT_HEADER) {
        printf(" rec_type=%d", first_byte_val);
    } else if (content_type == SSL3_RT_INNER_CONTENT_TYPE) {
        printf(" val=%d", first_byte_val);
    } else if (handshake_type == NULL) {
        printf(" type_val=%d", first_byte_val);
    }
}

#define MSG_CB_PREFIX "[MSG_CB]"
void ssl_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
                                                                SSL *ssl, void *arg)
{
    TC_CONF *conf = SSL_get_ex_data(ssl, SSL_EX_DATA_TC_CONF);
    int i;
    print_content_type(write_p, version, content_type, buf, len, MSG_CB_PREFIX);
    if (conf->cb.msg_cb_detailed) {
        printf(":");
        for (i = 0; i < len; i++) {
            printf(" %02X", *(((uint8_t *)buf) + i));
        }
    }
    printf("\n");
}

