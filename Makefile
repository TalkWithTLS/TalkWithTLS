TLS12_CLIENT = tls12_client
TLS12_SERVER = tls12_server
TARGET=$(TLS12_CLIENT) $(TLS12_SERVER)

OPENSSL_PATH=../openssl-1.1.1

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

$(TLS12_CLIENT):$(TLS12_CLIENT).o
	$(CC) $^ $(LDFLAGS) -o $@

$(TLS12_SERVER):$(TLS12_SERVER).o
	$(CC) $^ $(LDFLAGS) -o $@

clean:
	@$(RM) -rf *.o
	@$(RM) -rf $(TARGET)
