################################################################################
# Configuration variables are
# - BIN_PATH
# - OSSL111_PATH
# - OSSL111_PATH_REL
# - OSSL300_PATH
# - OSSL300_PATH_REL
# - NOSAN=1 - To disable address sanitizer in debug builds
# - GPROF=1 - To enable gprofile flags in debug builds
# Build mode
# - sample_bin - To build sample bins
# - test_bin - To build test bins
# - perf_bin - To build both release and debug bin of perf
# - perf_bin_dbg - To build only debug bins of perf
# - perf_bin_rel - To build only release bins of perf
################################################################################
SRC_DIR=src
BIN_DIR=bin
OBJ_DIR=obj

ifneq ($(BIN_PATH),)
	BIN_DIR=$(BIN_PATH)
endif

COMMON_DIR=common
SAMPLE_DIR=sample
PERF_DIR=perf
UTILS_DIR=utils

OPENSSL = openssl
BORINGSSL = boringssl

# Binary suffixes
DBG=_dbg
REL=_rel
OSSL_111_SUFFIX=_openssl_111
OSSL_300_SUFFIX=_openssl_300

# Sample binaries
OPENSSL_SAMPLE_NB_CLNT = openssl_nb_client
OPENSSL_SAMPLE_NB_SERV = openssl_nb_server
OPENSSL_D12_CLNT = openssl_dtls12_client
OPENSSL_D12_SERV = openssl_dtls12_server
OPENSSL_D12_CUSTOM_BIO_CLNT = openssl_dtls12_custom_bio_client
OPENSSL_D12_NB_CLNT = openssl_dtls12_nb_client
OPENSSL_D12_NB_SERV = openssl_dtls12_nb_server
OPENSSL_T12_SERV = openssl_tls12_server
OPENSSL_T12_CLNT = openssl_tls12_client
OPENSSL_T_SERV_MULTI_CLNT = openssl_tls_server_multi_client
OPENSSL_T12_VERF_CB_CLNT = openssl_tls12_verify_cb_client
OPENSSL_T12_VERF_CB_SERV = openssl_tls12_verify_cb_server
OPENSSL_T13_CLNT = openssl_tls13_client
OPENSSL_T13_SERV = openssl_tls13_server
OPENSSL_T13_CLNT_BOTH_AUTH = openssl_tls13_client_both_auth
OPENSSL_T13_SERV_BOTH_AUTH = openssl_tls13_server_both_auth
OPENSSL_T13_CLNT_DHE = openssl_tls13_dhe_client
OPENSSL_T13_SERV_DHE = openssl_tls13_dhe_server
OPENSSL_T13RESUMPTION_CLNT = openssl_tls13_resumption_client
OPENSSL_T13RESUMPTION_SERV = openssl_tls13_resumption_server
OPENSSL_T13_PSK_CLNT = openssl_tls13_psk_out_of_band_client
OPENSSL_T13_PSK_SERV = openssl_tls13_psk_out_of_band_server
OPENSSL_T13_0_RTT_CLNT = openssl_tls13_0_rtt_client
OPENSSL_T13_0_RTT_SERV = openssl_tls13_0_rtt_server
BSSL_T13_PSK_CLNT = boringssl_tls13_psk_out_of_band_client
BSSL_T13_PSK_SERV = boringssl_tls13_psk_out_of_band_server
BSSL_T13_RESUMPTION_CLNT = boringssl_tls13_resumption_client
BSSL_T13_RESUMPTION_SERV = boringssl_tls13_resumption_server

SAMPLE_BIN_DIR=$(BIN_DIR)/$(SAMPLE_DIR)

SAMPLE_BIN=$(SAMPLE_BIN_DIR)/$(OPENSSL_SAMPLE_NB_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_SAMPLE_NB_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_CUSTOM_BIO_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_NB_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_NB_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T_SERV_MULTI_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_CLNT_DHE) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_SERV_DHE) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_VERF_CB_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_VERF_CB_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_CLNT_BOTH_AUTH) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_SERV_BOTH_AUTH) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13RESUMPTION_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13RESUMPTION_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_PSK_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_PSK_SERV) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_0_RTT_CLNT) \
	$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_0_RTT_SERV) \
	$(SAMPLE_BIN_DIR)/$(BSSL_T13_PSK_CLNT) \
	$(SAMPLE_BIN_DIR)/$(BSSL_T13_PSK_SERV) \
	$(SAMPLE_BIN_DIR)/$(BSSL_T13_RESUMPTION_CLNT) \
	$(SAMPLE_BIN_DIR)/$(BSSL_T13_RESUMPTION_SERV)

# Perf binaries
SPEED = speed
S_SERVER = s_server
S_TIME = s_time
PERF_BIN_DIR = $(BIN_DIR)/$(PERF_DIR)
SPEED_OSSL_111_DBG = $(PERF_BIN_DIR)/$(SPEED)$(OSSL_111_SUFFIX)$(DBG)
SPEED_OSSL_300_DBG = $(PERF_BIN_DIR)/$(SPEED)$(OSSL_300_SUFFIX)$(DBG)
S_SERVER_OSSL_111_DBG = $(PERF_BIN_DIR)/$(S_SERVER)$(OSSL_111_SUFFIX)$(DBG)
S_TIME_OSSL_111_DBG = $(PERF_BIN_DIR)/$(S_TIME)$(OSSL_111_SUFFIX)$(DBG)
S_SERVER_OSSL_300_DBG = $(PERF_BIN_DIR)/$(S_SERVER)$(OSSL_300_SUFFIX)$(DBG)
S_TIME_OSSL_300_DBG = $(PERF_BIN_DIR)/$(S_TIME)$(OSSL_300_SUFFIX)$(DBG)
SPEED_OSSL_111_REL = $(PERF_BIN_DIR)/$(SPEED)$(OSSL_111_SUFFIX)$(REL)
SPEED_OSSL_300_REL = $(PERF_BIN_DIR)/$(SPEED)$(OSSL_300_SUFFIX)$(REL)
S_SERVER_OSSL_111_REL = $(PERF_BIN_DIR)/$(S_SERVER)$(OSSL_111_SUFFIX)$(REL)
S_TIME_OSSL_111_REL = $(PERF_BIN_DIR)/$(S_TIME)$(OSSL_111_SUFFIX)$(REL)
S_SERVER_OSSL_300_REL = $(PERF_BIN_DIR)/$(S_SERVER)$(OSSL_300_SUFFIX)$(REL)
S_TIME_OSSL_300_REL = $(PERF_BIN_DIR)/$(S_TIME)$(OSSL_300_SUFFIX)$(REL)

PERF_BIN_DBG = $(SPEED_OSSL_111_DBG) \
		   $(SPEED_OSSL_300_DBG) \
		   $(S_SERVER_OSSL_111_DBG) \
		   $(S_TIME_OSSL_111_DBG) \
		   $(S_SERVER_OSSL_300_DBG) \
		   $(S_TIME_OSSL_300_DBG)
PERF_BIN_REL = $(SPEED_OSSL_111_REL) \
		   $(SPEED_OSSL_300_REL) \
		   $(S_SERVER_OSSL_111_REL) \
		   $(S_TIME_OSSL_111_REL) \
		   $(S_SERVER_OSSL_300_REL) \
		   $(S_TIME_OSSL_300_REL)
PERF_BIN = $(PERF_BIN_DBG) $(PERF_BIN_REL)

# Test binaries
TEST_COMMON_LIB = $(BIN_DIR)/libtest_common.a
TEST_PREFIX = test
TEST_OSSL_111_BIN=$(BIN_DIR)/$(TEST_PREFIX)$(OSSL_111_SUFFIX)
TEST_OSSL_300_BIN=$(BIN_DIR)/$(TEST_PREFIX)$(OSSL_300_SUFFIX)
TEST_BIN=$(TEST_COMMON_LIB) $(TEST_OSSL_111_BIN) $(TEST_OSSL_300_BIN)

COMMON_SRC=$(SRC_DIR)/$(COMMON_DIR)
SAMPLE_SRC=$(SRC_DIR)/$(SAMPLE_DIR)
PERF_SRC=$(SRC_DIR)/$(PERF_DIR)
TEST_COMMON_DIR=$(SRC_DIR)/test/common
TEST_OPENSSL_DIR=$(SRC_DIR)/test/openssl
UTILS_SRC=$(SRC_DIR)/$(UTILS_DIR)

# Utils binaries
DTLS_PROXY=dtls_proxy

UTILS_BIN_DIR = $(BIN_DIR)/$(UTILS_DIR)
UTILS_BIN = $(UTILS_BIN_DIR)/$(DTLS_PROXY)

# Common Code Srcs
COMM_SRC_FILES=$(wildcard $(COMMON_SRC)/*.c)

# Sample Code Srcs
OPENSSL_SAMPLE_NB_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_SAMPLE_NB_CLNT).c $(COMM_SRC_FILES)
OPENSSL_SAMPLE_NB_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_SAMPLE_NB_SERV).c $(COMM_SRC_FILES)
OPENSSL_D12_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_D12_CLNT).c $(COMM_SRC_FILES)
OPENSSL_D12_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_D12_SERV).c $(COMM_SRC_FILES)
OPENSSL_D12_CUSTOM_BIO_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_D12_CUSTOM_BIO_CLNT).c $(COMM_SRC_FILES)
OPENSSL_D12_NB_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_D12_NB_CLNT).c $(COMM_SRC_FILES)
OPENSSL_D12_NB_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_D12_NB_SERV).c $(COMM_SRC_FILES)
OPENSSL_T12_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_T12_SERV).c $(COMM_SRC_FILES)
OPENSSL_T12_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_T12_CLNT).c $(COMM_SRC_FILES)
OPENSSL_T_SERV_MULTI_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_T_SERV_MULTI_CLNT).c $(COMM_SRC_FILES)
OPENSSL_T12_VERF_CB_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_T12_VERF_CB_CLNT).c $(COMM_SRC_FILES)
OPENSSL_T12_VERF_CB_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_T12_VERF_CB_SERV).c $(COMM_SRC_FILES)
OPENSSL_T13_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_CLNT).c $(COMM_SRC_FILES)
OPENSSL_T13_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_SERV).c $(COMM_SRC_FILES)
OPENSSL_T13_CLNT_BOTH_AUTH_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_CLNT_BOTH_AUTH).c $(COMM_SRC_FILES)
OPENSSL_T13_SERV_BOTH_AUTH_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_SERV_BOTH_AUTH).c $(COMM_SRC_FILES)
OPENSSL_T13_CLNT_DHE_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_CLNT_DHE).c $(COMM_SRC_FILES)
OPENSSL_T13_SERV_DHE_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_SERV_DHE).c $(COMM_SRC_FILES)
OPENSSL_T13RESUMPTION_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13RESUMPTION_CLNT).c $(COMM_SRC_FILES)
OPENSSL_T13RESUMPTION_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13RESUMPTION_SERV).c $(COMM_SRC_FILES)
OPENSSL_T13_PSK_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_PSK_CLNT).c \
						 $(COMM_SRC_FILES)
OPENSSL_T13_PSK_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_PSK_SERV).c \
						 $(COMM_SRC_FILES)
OPENSSL_T13_0_RTT_CLNT_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_0_RTT_CLNT).c $(COMM_SRC_FILES)
OPENSSL_T13_0_RTT_SERV_SRC=$(SAMPLE_SRC)/$(OPENSSL_T13_0_RTT_SERV).c $(COMM_SRC_FILES)

BSSL_T13_PSK_CLNT_SRC=$(SAMPLE_SRC)/$(BSSL_T13_PSK_CLNT).c $(COMM_SRC_FILES)
BSSL_T13_PSK_SERV_SRC=$(SAMPLE_SRC)/$(BSSL_T13_PSK_SERV).c $(COMM_SRC_FILES)
BSSL_T13_RESUMPTION_CLNT_SRC=$(SAMPLE_SRC)/$(BSSL_T13_RESUMPTION_CLNT).c \
							 $(COMM_SRC_FILES)
BSSL_T13_RESUMPTION_SERV_SRC=$(SAMPLE_SRC)/$(BSSL_T13_RESUMPTION_SERV).c \
							 $(COMM_SRC_FILES)

# Perf Code Srcs
SPEED_SRC=$(PERF_SRC)/$(SPEED).c
S_SERVER_SRC=$(PERF_SRC)/$(S_SERVER).c
S_TIME_SRC=$(PERF_SRC)/$(S_TIME).c

# Test code Srcs
TEST_COMMON_SRC=$(wildcard $(TEST_COMMON_DIR)/*.c) $(COMM_SRC_FILES)
TEST_OPENSSL_SRC=$(wildcard $(TEST_OPENSSL_DIR)/*.c)

# Utils Code Srcs
DTLS_PROXY_SRC=$(UTILS_SRC)/$(DTLS_PROXY).c $(COMM_SRC_FILES)

# Common Code Objs
COMM_OBJ=$(addprefix $(OBJ_DIR)/,$(COMM_SRC_FILES:.c=.o))

# Sample Code Objs
OPENSSL_SAMPLE_NB_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_SAMPLE_NB_CLNT_SRC:.c=.o))
OPENSSL_SAMPLE_NB_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_SAMPLE_NB_SERV_SRC:.c=.o))
OPENSSL_D12_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_D12_CLNT_SRC:.c=.o))
OPENSSL_D12_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_D12_SERV_SRC:.c=.o))
OPENSSL_D12_CUSTOM_BIO_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_D12_CUSTOM_BIO_CLNT_SRC:.c=.o))
OPENSSL_D12_NB_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_D12_NB_CLNT_SRC:.c=.o))
OPENSSL_D12_NB_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_D12_NB_SERV_SRC:.c=.o))

OPENSSL_T12_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T12_CLNT_SRC:.c=.o))
OPENSSL_T12_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T12_SERV_SRC:.c=.o))
OPENSSL_T_SERV_MULTI_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T_SERV_MULTI_CLNT_SRC:.c=.o))
OPENSSL_T12_VERF_CB_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T12_VERF_CB_CLNT_SRC:.c=.o))
OPENSSL_T12_VERF_CB_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T12_VERF_CB_SERV_SRC:.c=.o))
OPENSSL_T13_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_CLNT_SRC:.c=.o))
OPENSSL_T13_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_SERV_SRC:.c=.o))
OPENSSL_T13_CLNT_BOTH_AUTH_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_CLNT_BOTH_AUTH_SRC:.c=.o))
OPENSSL_T13_SERV_BOTH_AUTH_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_SERV_BOTH_AUTH_SRC:.c=.o))
OPENSSL_T13_CLNT_DHE_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_CLNT_DHE_SRC:.c=.o))
OPENSSL_T13_SERV_DHE_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_SERV_DHE_SRC:.c=.o))
OPENSSL_T13RESUMPTION_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13RESUMPTION_SERV_SRC:.c=.o))
OPENSSL_T13RESUMPTION_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13RESUMPTION_CLNT_SRC:.c=.o))
OPENSSL_T13_PSK_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,\
						 $(OPENSSL_T13_PSK_CLNT_SRC:.c=.o))
OPENSSL_T13_PSK_SERV_OBJ=$(addprefix $(OBJ_DIR)/,\
						 $(OPENSSL_T13_PSK_SERV_SRC:.c=.o))

OPENSSL_T13_0_RTT_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_0_RTT_SERV_SRC:.c=.o))
OPENSSL_T13_0_RTT_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(OPENSSL_T13_0_RTT_CLNT_SRC:.c=.o))
BSSL_T13_PSK_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,$(BSSL_T13_PSK_CLNT_SRC:.c=.o))
BSSL_T13_PSK_SERV_OBJ=$(addprefix $(OBJ_DIR)/,$(BSSL_T13_PSK_SERV_SRC:.c=.o))
BSSL_T13_RESUMPTION_CLNT_OBJ=$(addprefix $(OBJ_DIR)/,\
							 $(BSSL_T13_RESUMPTION_CLNT_SRC:.c=.o))
BSSL_T13_RESUMPTION_SERV_OBJ=$(addprefix $(OBJ_DIR)/,\
							 $(BSSL_T13_RESUMPTION_SERV_SRC:.c=.o))

# Perf Code Objs
SPEED_OSSL_111_OBJ_DBG=$(addprefix $(OBJ_DIR)/,$(SPEED_SRC:.c=$(OSSL_111_SUFFIX)$(DBG).o))
SPEED_OSSL_300_OBJ_DBG=$(addprefix $(OBJ_DIR)/,$(SPEED_SRC:.c=$(OSSL_300_SUFFIX)$(DBG).o))
S_SERVER_OSSL_111_OBJ_DBG=$(addprefix $(OBJ_DIR)/,$(S_SERVER_SRC:.c=$(OSSL_111_SUFFIX)$(DBG).o))
S_SERVER_OSSL_300_OBJ_DBG=$(addprefix $(OBJ_DIR)/,$(S_SERVER_SRC:.c=$(OSSL_300_SUFFIX)$(DBG).o))
S_TIME_OSSL_111_OBJ_DBG=$(addprefix $(OBJ_DIR)/,$(S_TIME_SRC:.c=$(OSSL_111_SUFFIX)$(DBG).o))
S_TIME_OSSL_300_OBJ_DBG=$(addprefix $(OBJ_DIR)/,$(S_TIME_SRC:.c=$(OSSL_300_SUFFIX)$(DBG).o))
SPEED_OSSL_111_OBJ_REL=$(addprefix $(OBJ_DIR)/,$(SPEED_SRC:.c=$(OSSL_111_SUFFIX)$(REL).o))
SPEED_OSSL_300_OBJ_REL=$(addprefix $(OBJ_DIR)/,$(SPEED_SRC:.c=$(OSSL_300_SUFFIX)$(REL).o))
S_SERVER_OSSL_111_OBJ_REL=$(addprefix $(OBJ_DIR)/,$(S_SERVER_SRC:.c=$(OSSL_111_SUFFIX)$(REL).o))
S_SERVER_OSSL_300_OBJ_REL=$(addprefix $(OBJ_DIR)/,$(S_SERVER_SRC:.c=$(OSSL_300_SUFFIX)$(REL).o))
S_TIME_OSSL_111_OBJ_REL=$(addprefix $(OBJ_DIR)/,$(S_TIME_SRC:.c=$(OSSL_111_SUFFIX)$(REL).o))
S_TIME_OSSL_300_OBJ_REL=$(addprefix $(OBJ_DIR)/,$(S_TIME_SRC:.c=$(OSSL_300_SUFFIX)$(REL).o))

# Test code Objs
TEST_COMMON_OBJ=$(addprefix $(OBJ_DIR)/,$(TEST_COMMON_SRC:.c=.o))
TEST_OSSL_111_OBJ=$(addprefix $(OBJ_DIR)/,\
					$(TEST_OPENSSL_SRC:.c=$(OSSL_111_SUFFIX).o))
TEST_OSSL_300_OBJ=$(addprefix $(OBJ_DIR)/,\
					$(TEST_OPENSSL_SRC:.c=$(OSSL_300_SUFFIX).o))

# Utils Code Objs
DTLS_PROXY_OBJ=$(addprefix $(OBJ_DIR)/,$(DTLS_PROXY_SRC:.c=.o))

DEPENDENCY_DIR=dependency
OSSL_1_1_1=openssl-1.1.1
OSSL_1_1_1_REL=openssl-1.1.1-rel
OSSL_MASTER=openssl-master
OSSL_MASTER_REL=openssl-master-rel

OSSL_1_1_1_DIR=$(DEPENDENCY_DIR)/$(OSSL_1_1_1)
OSSL_1_1_1_DIR_REL=$(DEPENDENCY_DIR)/$(OSSL_1_1_1_REL)
OSSL_300_DIR=$(DEPENDENCY_DIR)/$(OSSL_MASTER)
OSSL_300_DIR_REL=$(DEPENDENCY_DIR)/$(OSSL_MASTER_REL)

ifneq ($(OSSL111_PATH),)
	OSSL_1_1_1_DIR=$(OSSL111_PATH)
endif
ifneq ($(OSSL111_PATH_REL),)
	OSSL_1_1_1_DIR_REL=$(OSSL111_PATH_REL)
endif
ifneq ($(OSSL300_PATH),)
	OSSL_300_DIR=$(OSSL300_PATH)
endif
ifneq ($(OSSL300_PATH_REL),)
	OSSL_300_DIR_REL=$(OSSL300_PATH_REL)
endif

OSSL_111_LIBS_DBG=$(OSSL_1_1_1_DIR)/libssl.a
OSSL_111_LIBS_REL=$(OSSL_1_1_1_DIR_REL)/libssl.a
OSSL_300_LIBS_DBG=$(OSSL_300_DIR)/libssl.a
OSSL_300_LIBS_REL=$(OSSL_300_DIR_REL)/libssl.a

BSSL_MASTER=boringssl-master
BSSL_MASTER_DIR=$(DEPENDENCY_DIR)/$(BSSL_MASTER)
BSSL_MASTER_LIBS_DBG=$(BSSL_MASTER)/build_dbg/ssl/libssl.a

# Gprofile flags
GPROF_FLAGS =
ifeq ($(GPROF),1)
	GPROF_FLAGS = -p
	NOSAN=1
endif

# Address Sanitizer flags
SANFLAGS = -fsanitize=address
ifeq ($(NOSTATICASAN),)
	ifeq ($(CLANG),)
		SANFLAGS += -static-libasan
	endif
endif
OSSL_SANFLAGS = enable-asan
ifeq ($(NOSAN),1)
	SANFLAGS =
	OSSL_SANFLAGS =
endif

CFLAGS_DBG = -g $(GPROF_FLAGS) -ggdb -O0 -Wall -Werror -fstack-protector-all $(SANFLAGS) -I $(COMMON_SRC)
CFLAGS_REL = -O3 -Wall -Werror -I $(COMMON_SRC)
COMMON_CFLAGS = $(CFLAGS_DBG)
OSSL_111_CFLAGS_DBG = $(CFLAGS_DBG) -I $(OSSL_1_1_1_DIR)/include -DWITH_OSSL -DWITH_OSSL_111
OSSL_111_CFLAGS_REL = $(CFLAGS_REL) -I $(OSSL_1_1_1_DIR_REL)/include -DWITH_OSSL -DWITH_OSSL_111
OSSL_300_CFLAGS_DBG = $(CFLAGS_DBG) -I $(OSSL_300_DIR)/include -DWITH_OSSL -DWITH_OSSL_300
OSSL_300_CFLAGS_REL = $(CFLAGS_REL) -I $(OSSL_300_DIR_REL)/include -DWITH_OSSL -DWITH_OSSL_300
BSSL_MASTER_CFLAGS_DBG = $(CFLAGS_DBG) -I $(BSSL_MASTER_DIR)/include

TEST_COMMON_CFLAGS = -I $(TEST_COMMON_DIR)
TEST_OSSL_CFLAGS = -I $(TEST_COMMON_DIR) -I $(TEST_OPENSSL_DIR)
TEST_OSSL_111_CFLAGS = $(TEST_OSSL_CFLAGS)
TEST_OSSL_300_CFLAGS = $(TEST_OSSL_CFLAGS)

LDFLAGS_DBG = $(GPROF_FLAGS)
OSSL_LDFLAGS = -lpthread -ldl
OSSL_111_LDFLAGS_DBG = $(LDFLAGS_DBG) $(OSSL_1_1_1_DIR)/libssl.a \
					   $(OSSL_1_1_1_DIR)/libcrypto.a \
					   $(OSSL_LDFLAGS) $(SANFLAGS)
OSSL_111_LDFLAGS_REL = $(OSSL_1_1_1_DIR_REL)/libssl.a \
					   $(OSSL_1_1_1_DIR_REL)/libcrypto.a \
					   $(OSSL_LDFLAGS)
OSSL_300_LDFLAGS_DBG = $(LDFLAGS_DBG) $(OSSL_300_DIR)/libssl.a \
					   $(OSSL_300_DIR)/libcrypto.a \
					   $(OSSL_LDFLAGS) $(SANFLAGS)
OSSL_300_LDFLAGS_REL = $(OSSL_300_DIR_REL)/libssl.a \
					   $(OSSL_300_DIR_REL)/libcrypto.a \
					   $(OSSL_LDFLAGS)

BSSL_LDFLAGS = -lpthread
BSSL_MASTER_LDFLAGS_DBG = $(LDFLAGS_DBG) \
						  $(BSSL_MASTER_DIR)/build_dbg/ssl/libssl.a \
						  $(BSSL_MASTER_DIR)/build_dbg/crypto/libcrypto.a \
						  $(BSSL_LDFLAGS) $(SANFLAGS)

TEST_LDFLAGS = -L $(BIN_DIR) -ltest_common
TEST_OSSL_111_LDFLAGS = $(TEST_LDFLAGS)
TEST_OSSL_300_LDFLAGS = $(TEST_LDFLAGS)

ifeq ($(CC),cc)
	CC=gcc
endif
ifeq ($(AR),ar)
	AR=ar
endif

ifeq ($(CLANG),1)
	CC=clang
	AR=llvm-ar
endif

CP = cp
RM = rm

OSSL_111_CC_DBG="$(CC) -g $(GPROF_FLAGS) -ggdb -Wall -Werror -fstack-protector-all $(SANFLAGS)"
OSSL_111_CC_REL="$(CC) -Wall -Werror"
OSSL_300_CC_DBG="$(CC) -g $(GPROF_FLAGS) -ggdb -Wall -Werror -fstack-protector-all"
OSSL_300_CC_REL="$(CC) -Wall -Werror"

TARGET=$(SAMPLE_BIN) $(PERF_BIN) $(TEST_BIN)

#.PHONY all init_task clean clobber test_bin sample_bin perf_bin utils_bin

all : init_task $(TARGET)

test_bin : init_task $(TEST_BIN)

sample_bin : init_task $(SAMPLE_BIN)

perf_bin : init_task $(PERF_BIN)

perf_bin_dbg : init_task $(PERF_BIN_DBG)

perf_bin_rel : init_task $(PERF_BIN_REL)

utils_bin : init_task $(UTILS_BIN)

#TODO Better to avoid using DEPENDENCY_DIR instead use generic way while untaring

$(OSSL_111_LIBS_DBG):
	@echo "Building $(OSSL_1_1_1_DIR)..."
	@if [ ! -f $(OSSL_1_1_1_DIR)/config ]; then \
		cd $(DEPENDENCY_DIR) && tar -zxvf $(OSSL_1_1_1).tar.gz > /dev/null; fi
	@cd $(OSSL_1_1_1_DIR) && export CC=$(OSSL_111_CC_DBG) && ./config -d > /dev/null
	@cd $(OSSL_1_1_1_DIR) && $(MAKE) > /dev/null
	@echo ""

$(OSSL_111_LIBS_REL):
	@echo "Building $(OSSL_1_1_1_DIR_REL)..."
	@if [ ! -d $(OSSL_1_1_1_DIR_REL) ]; then \
		mkdir -p $(OSSL_1_1_1_DIR_REL); fi
	@if [ ! -f $(OSSL_1_1_1_DIR_REL)/config ]; then \
		cd $(DEPENDENCY_DIR) && rm $(OSSL_1_1_1_REL)/*; \
		tar -zxvf $(OSSL_1_1_1).tar.gz -C $(OSSL_1_1_1_REL) > /dev/null; \
		mv $(OSSL_1_1_1_REL)/$(OSSL_1_1_1)/* $(OSSL_1_1_1_REL); fi
	@cd $(OSSL_1_1_1_DIR_REL) && export CC=$(OSSL_111_CC_REL) && ./config > /dev/null
	@cd $(OSSL_1_1_1_DIR_REL) && $(MAKE) > /dev/null
	@echo ""

$(OSSL_300_LIBS_DBG):
	@echo "Building $(OSSL_300_DIR)..."
	@if [ ! -f $(OSSL_300_DIR)/config ]; then \
		cd $(DEPENDENCY_DIR) && tar -zxvf $(OSSL_MASTER).tar.gz > /dev/null; fi
	@cd $(OSSL_300_DIR) && export CC=$(OSSL_300_CC_DBG) && ./config -d $(OSSL_SANFLAGS) > /dev/null
	@cd $(OSSL_300_DIR) && $(MAKE) > /dev/null
	@echo ""

$(OSSL_300_LIBS_REL):
	@echo "Building $(OSSL_300_DIR_REL)..."
	@if [ ! -d $(OSSL_300_DIR_REL) ]; then \
		mkdir -p $(OSSL_300_DIR_REL); fi
	@if [ ! -f $(OSSL_300_DIR_REL)/config ]; then \
		cd $(DEPENDENCY_DIR) && rm $(OSSL_MASTER_REL)/*; \
		tar -zxvf $(OSSL_MASTER).tar.gz -C $(OSSL_MASTER_REL) > /dev/null; \
		mv $(OSSL_MASTER_REL)/$(OSSL_MASTER)/* $(OSSL_MASTER_REL); fi
	@cd $(OSSL_300_DIR_REL) && export CC=$(OSSL_300_CC_REL) && ./config > /dev/null
	@cd $(OSSL_300_DIR_REL) && $(MAKE) > /dev/null
	@echo ""

$(BSSL_MASTER_LIBS_DBG):
	@echo "Building $(BSSL_MASTER)..."
	@if [ ! -f $(BSSL_MASTER)/.gitignore ]; then \
		cd $(DEPENDENCY_DIR) && tar -zxvf $(BSSL_MASTER).tar.gz > /dev/null; fi
	@mkdir -p $(BSSL_MASTER_DIR)/build_dbg
	@cd $(BSSL_MASTER_DIR)/build_dbg \
		&& cmake -DCMAKE_BUILD_TYPE=Debug .. > /dev/null \
		&& $(MAKE) > /dev/null

init_task:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BIN_DIR)/$(SAMPLE_DIR)
	@mkdir -p $(BIN_DIR)/$(PERF_DIR)
	@mkdir -p $(BIN_DIR)/$(UTILS_DIR)
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/$(COMMON_SRC)
	@mkdir -p $(OBJ_DIR)/$(SAMPLE_SRC)
	@mkdir -p $(OBJ_DIR)/$(PERF_SRC)
	@mkdir -p $(OBJ_DIR)/$(TEST_COMMON_DIR)
	@mkdir -p $(OBJ_DIR)/$(TEST_OPENSSL_DIR)
	@mkdir -p $(OBJ_DIR)/$(UTILS_SRC)

$(OBJ_DIR)/$(COMMON_SRC)%.o:$(COMMON_SRC)%.c
	$(CC) $(COMMON_CFLAGS) -c $< -o $@

$(OBJ_DIR)/$(SAMPLE_SRC)/$(OPENSSL)%.o:$(SAMPLE_SRC)/$(OPENSSL)%.c \
									   $(OSSL_111_LIBS_DBG)
	$(CC) $(OSSL_111_CFLAGS_DBG) -c $< -o $@

$(OBJ_DIR)/$(SAMPLE_SRC)/$(BORINGSSL)%.o:$(SAMPLE_SRC)/$(BORINGSSL)%.c \
							           $(BSSL_MASTER_LIBS_DBG)
	$(CC) $(BSSL_MASTER_CFLAGS_DBG) -c $< -o $@

$(OBJ_DIR)/$(PERF_SRC)/%$(OSSL_111_SUFFIX)$(DBG).o:$(PERF_SRC)/%.c \
				                                   $(OSSL_111_LIBS_DBG)
	$(CC) $(OSSL_111_CFLAGS_DBG) -c $< -o $@

$(OBJ_DIR)/$(PERF_SRC)/%$(OSSL_300_SUFFIX)$(DBG).o:$(PERF_SRC)/%.c \
			                                       $(OSSL_300_LIBS_DBG)
	$(CC) $(OSSL_300_CFLAGS_DBG) -c $< -o $@

$(OBJ_DIR)/$(PERF_SRC)/%$(OSSL_111_SUFFIX)$(REL).o:$(PERF_SRC)/%.c \
												   $(OSSL_111_LIBS_REL)
	$(CC) $(OSSL_111_CFLAGS_REL) -c $< -o $@

$(OBJ_DIR)/$(PERF_SRC)/%$(OSSL_300_SUFFIX)$(REL).o:$(PERF_SRC)/%.c \
												   $(OSSL_300_LIBS_REL)
	$(CC) $(OSSL_300_CFLAGS_REL) -c $< -o $@

$(OBJ_DIR)/$(TEST_COMMON_DIR)/%.o:$(TEST_COMMON_DIR)/%.c
	$(CC) $(CFLAGS_DBG) $(TEST_COMMON_CFLAGS) -c $< -o $@

$(OBJ_DIR)/$(TEST_OPENSSL_DIR)/%$(OSSL_111_SUFFIX).o:$(TEST_OPENSSL_DIR)/%.c \
								   $(OSSL_111_LIBS_DBG)
	$(CC) $(OSSL_111_CFLAGS_DBG) $(TEST_OSSL_111_CFLAGS) -c $< -o $@

$(OBJ_DIR)/$(TEST_OPENSSL_DIR)/%$(OSSL_300_SUFFIX).o:$(TEST_OPENSSL_DIR)/%.c \
								   $(OSSL_300_LIBS_DBG)
	$(CC) $(OSSL_300_CFLAGS_DBG) $(TEST_OSSL_300_CFLAGS) -c $< -o $@

$(OBJ_DIR)/$(UTILS_SRC)/%.o:$(UTILS_SRC)/%.c $(OSSL_111_LIBS_DBG)
	$(CC) $(OSSL_111_CFLAGS_DBG) -c $< -o $@

# Sample Binaries
$(SAMPLE_BIN_DIR)/$(OPENSSL_SAMPLE_NB_CLNT):$(OPENSSL_SAMPLE_NB_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_SAMPLE_NB_SERV):$(OPENSSL_SAMPLE_NB_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_CLNT):$(OPENSSL_D12_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_NB_SERV):$(OPENSSL_D12_NB_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_NB_CLNT):$(OPENSSL_D12_NB_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_SERV):$(OPENSSL_D12_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_D12_CUSTOM_BIO_CLNT):$(OPENSSL_D12_CUSTOM_BIO_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13RESUMPTION_SERV):$(OPENSSL_T13RESUMPTION_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13RESUMPTION_CLNT):$(OPENSSL_T13RESUMPTION_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_PSK_SERV):$(OPENSSL_T13_PSK_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_PSK_CLNT):$(OPENSSL_T13_PSK_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_0_RTT_SERV):$(OPENSSL_T13_0_RTT_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_0_RTT_CLNT):$(OPENSSL_T13_0_RTT_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_SERV_DHE):$(OPENSSL_T13_SERV_DHE_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_CLNT_DHE):$(OPENSSL_T13_CLNT_DHE_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_CLNT):$(OPENSSL_T13_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_SERV):$(OPENSSL_T13_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_CLNT_BOTH_AUTH):$(OPENSSL_T13_CLNT_BOTH_AUTH_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T13_SERV_BOTH_AUTH):$(OPENSSL_T13_SERV_BOTH_AUTH_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_CLNT):$(OPENSSL_T12_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_SERV):$(OPENSSL_T12_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T_SERV_MULTI_CLNT):$(OPENSSL_T_SERV_MULTI_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_VERF_CB_CLNT):$(OPENSSL_T12_VERF_CB_CLNT_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(OPENSSL_T12_VERF_CB_SERV):$(OPENSSL_T12_VERF_CB_SERV_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(BSSL_T13_PSK_SERV):$(BSSL_T13_PSK_SERV_OBJ)
	$(CC) $^ $(BSSL_MASTER_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(BSSL_T13_PSK_CLNT):$(BSSL_T13_PSK_CLNT_OBJ)
	$(CC) $^ $(BSSL_MASTER_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(BSSL_T13_RESUMPTION_SERV):$(BSSL_T13_RESUMPTION_SERV_OBJ)
	$(CC) $^ $(BSSL_MASTER_LDFLAGS_DBG) -o $@
	@echo ""

$(SAMPLE_BIN_DIR)/$(BSSL_T13_RESUMPTION_CLNT):$(BSSL_T13_RESUMPTION_CLNT_OBJ)
	$(CC) $^ $(BSSL_MASTER_LDFLAGS_DBG) -o $@
	@echo ""

# Perf Binaries
$(SPEED_OSSL_111_DBG):$(SPEED_OSSL_111_OBJ_DBG) $(OSSL_111_LIBS_DBG)
	$(CC) $(SPEED_OSSL_111_OBJ_DBG) $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(SPEED_OSSL_300_DBG):$(SPEED_OSSL_300_OBJ_DBG) $(OSSL_300_LIBS_DBG)
	$(CC) $(SPEED_OSSL_300_OBJ_DBG) $(OSSL_300_LDFLAGS_DBG) -o $@
	@echo ""

$(S_SERVER_OSSL_111_DBG):$(S_SERVER_OSSL_111_OBJ_DBG) $(OSSL_111_LIBS_DBG)
	$(CC) $(S_SERVER_OSSL_111_OBJ_DBG) $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(S_TIME_OSSL_111_DBG):$(S_TIME_OSSL_111_OBJ_DBG) $(OSSL_111_LIBS_DBG)
	$(CC) $(S_TIME_OSSL_111_OBJ_DBG) $(OSSL_111_LDFLAGS_DBG) -o $@
	@echo ""

$(S_SERVER_OSSL_300_DBG):$(S_SERVER_OSSL_300_OBJ_DBG) $(OSSL_300_LIBS_DBG)
	$(CC) $(S_SERVER_OSSL_300_OBJ_DBG) $(OSSL_300_LDFLAGS_DBG) -o $@
	@echo ""

$(S_TIME_OSSL_300_DBG):$(S_TIME_OSSL_300_OBJ_DBG) $(OSSL_300_LIBS_DBG)
	$(CC) $(S_TIME_OSSL_300_OBJ_DBG) $(OSSL_300_LDFLAGS_DBG) -o $@
	@echo ""

$(SPEED_OSSL_111_REL):$(SPEED_OSSL_111_OBJ_REL) $(OSSL_111_LIBS_DBG)
	$(CC) $(SPEED_OSSL_111_OBJ_REL) $(OSSL_111_LDFLAGS_REL) -o $@
	@echo ""

$(SPEED_OSSL_300_REL):$(SPEED_OSSL_300_OBJ_REL) $(OSSL_300_LIBS_DBG)
	$(CC) $(SPEED_OSSL_300_OBJ_REL) $(OSSL_300_LDFLAGS_REL) -o $@
	@echo ""

$(S_SERVER_OSSL_111_REL):$(S_SERVER_OSSL_111_OBJ_REL) $(OSSL_111_LIBS_DBG)
	$(CC) $(S_SERVER_OSSL_111_OBJ_REL) $(OSSL_111_LDFLAGS_REL) -o $@
	@echo ""

$(S_TIME_OSSL_111_REL):$(S_TIME_OSSL_111_OBJ_REL) $(OSSL_111_LIBS_DBG)
	$(CC) $(S_TIME_OSSL_111_OBJ_REL) $(OSSL_111_LDFLAGS_REL) -o $@
	@echo ""

$(S_SERVER_OSSL_300_REL):$(S_SERVER_OSSL_300_OBJ_REL) $(OSSL_300_LIBS_DBG)
	$(CC) $(S_SERVER_OSSL_300_OBJ_REL) $(OSSL_300_LDFLAGS_REL) -o $@
	@echo ""

$(S_TIME_OSSL_300_REL):$(S_TIME_OSSL_300_OBJ_REL) $(OSSL_300_LIBS_DBG)
	$(CC) $(S_TIME_OSSL_300_OBJ_REL) $(OSSL_300_LDFLAGS_REL) -o $@
	@echo ""

# Test Binaries
$(TEST_COMMON_LIB):$(TEST_COMMON_OBJ)
	$(AR) r $@ $^

$(TEST_OSSL_111_BIN):$(TEST_OSSL_111_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) $(TEST_OSSL_111_LDFLAGS) -o $@

$(TEST_OSSL_300_BIN):$(TEST_OSSL_300_OBJ)
	$(CC) $^ $(OSSL_300_LDFLAGS_DBG) $(TEST_OSSL_300_LDFLAGS) -o $@

# Utils Binaries
$(UTILS_BIN_DIR)/$(DTLS_PROXY):$(DTLS_PROXY_OBJ)
	$(CC) $^ $(OSSL_111_LDFLAGS_DBG) -o $@

clean:
	@$(RM) -rf *.o *.a
	@$(RM) -rf $(TARGET)
	@$(RM) -rf $(OBJ_DIR) $(BIN_DIR)

clobber: clean
	@echo "Cleaning $(OSSL_1_1_1_DIR)..."
	@if [ -f $(OSSL_1_1_1_DIR)/Makefile ]; then \
		cd $(OSSL_1_1_1_DIR) && $(MAKE) clean > /dev/null; fi
	@echo "Cleaning $(OSSL_1_1_1_DIR_REL)..."
	@if [ -f $(OSSL_1_1_1_DIR_REL)/Makefile ]; then \
		cd $(OSSL_1_1_1_DIR_REL) && $(MAKE) clean > /dev/null; fi
	@echo "Cleaning $(OSSL_300_DIR)..."
	@if [ -f $(OSSL_300_DIR)/Makefile ]; then \
		cd $(OSSL_300_DIR) && $(MAKE) clean > /dev/null; fi
	@echo "Cleaning $(OSSL_300_DIR_REL)..."
	@if [ -f $(OSSL_300_DIR_REL)/Makefile ]; then \
		cd $(OSSL_300_DIR_REL) && $(MAKE) clean > /dev/null; fi
	@echo "Cleaning $(BSSL_MASTER_DIR)..."
	@if [ -d $(BSSL_MASTER_DIR)/build_* ]; then \
		rm -rf $(BSSL_MASTER_DIR)/build_* > /dev/null; fi
