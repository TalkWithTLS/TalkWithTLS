BIN_DIR=bin
TLS12_CLIENT = tls12_client
TLS12_SERVER = tls12_server
TLS12_VERF_CB_CLIENT = tls12_verify_cb_client
TLS12_VERF_CB_SERVER = tls12_verify_cb_server
TLS13_CLIENT = tls13_client
TLS13_SERVER = tls13_server
TLS13_CLIENT_DHE = tls13_client_dhe
TLS13_SERVER_DHE = tls13_server_dhe
TLS13_RESUMPTION_CLIENT = tls13_resumption_client
TLS13_RESUMPTION_SERVER = tls13_resumption_server
TARGET=$(TLS12_CLIENT) $(TLS12_SERVER) $(TLS13_CLIENT_DHE) $(TLS13_SERVER_DHE) $(TLS12_VERF_CB_CLIENT) $(TLS12_VERF_CB_SERVER) $(TLS13_CLIENT) $(TLS13_SERVER) $(TLS13_RESUMPTION_CLIENT) $(TLS13_RESUMPTION_SERVER)

DEPENDENCY_DIR=dependency
OPENSSL_1_1_1=openssl-1.1.1a
OPENSSL_1_1_1_DIR=$(DEPENDENCY_DIR)/$(OPENSSL_1_1_1)
OPENSSL_1_1_1_LIBS=$(OPENSSL_1_1_1_DIR)/libssl.a
DEPENDENCY = $(OPENSSL_1_1_1_LIBS)

CFLAGS = -g -ggdb -Wall -Werror -I $(OPENSSL_1_1_1_DIR)/include
LDFLAGS = $(OPENSSL_1_1_1_DIR)/libssl.a $(OPENSSL_1_1_1_DIR)/libcrypto.a -lpthread -ldl

CC = gcc
CP = cp
RM = rm

#.PHONY all init_task clean

all : init_task build_dependency $(TARGET)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

build_dependency:$(DEPENDENCY)

$(OPENSSL_1_1_1_LIBS): $(OPENSSL_1_1_1_DIR).tar.gz
	cd $(DEPENDENCY_DIR) && tar -zxvf $(OPENSSL_1_1_1).tar.gz
	cd $(OPENSSL_1_1_1_DIR) && ./config -d
	cd $(OPENSSL_1_1_1_DIR) && make

init_task:
	@mkdir -p $(BIN_DIR)

$(TLS13_RESUMPTION_SERVER):$(TLS13_RESUMPTION_SERVER).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS13_RESUMPTION_CLIENT):$(TLS13_RESUMPTION_CLIENT).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS13_SERVER_DHE):$(TLS13_SERVER_DHE).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS13_CLIENT_DHE):$(TLS13_CLIENT_DHE).o
	$(CC) $^ $(LDFLAGS) -o $@

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
