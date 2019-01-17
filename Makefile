TLS12_CLIENT = tls12_client
TLS12_SERVER = tls12_server
TLS12_VERF_CB_CLIENT = tls12_verify_cb_client
TLS12_VERF_CB_SERVER = tls12_verify_cb_server
TLS13_CLIENT = tls13_client
TLS13_SERVER = tls13_server
TARGET=$(TLS12_CLIENT) $(TLS12_SERVER) $(TLS12_VERF_CB_CLIENT) $(TLS12_VERF_CB_SERVER) $(TLS13_CLIENT) $(TLS13_SERVER)

ifeq ($(OSSL_PATH),)
OPENSSL_PATH=../openssl-1.1.1
else
OPENSSL_PATH=$(OSSL_PATH)
endif

CFLAGS = -g -ggdb -Wall -Werror -I $(OPENSSL_PATH)/include
LDFLAGS = -L ./ -lssl -lcrypto -lpthread -ldl

CC = gcc
CP = cp
RM = rm

#.PHONY all init_task clean

all : init_task $(TARGET)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

init_task:
	@$(CP) $(OPENSSL_PATH)/libcrypto.a .
	@$(CP) $(OPENSSL_PATH)/libssl.a .

$(TLS13_CLIENT):$(TLS13_CLIENT).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS12_CLIENT):$(TLS12_CLIENT).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS13_SERVER):$(TLS13_SERVER).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS12_SERVER):$(TLS12_SERVER).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS12_VERF_CB_CLIENT):$(TLS12_VERF_CB_CLIENT).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS12_VERF_CB_SERVER):$(TLS12_VERF_CB_SERVER).o
	$(CC) $^ $(LDFLAGS) -o $@

clean:
	@$(RM) -rf *.o *.a
	@$(RM) -rf $(TARGET)
