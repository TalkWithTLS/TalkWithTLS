# TalkWithTLS
Sample Code for TLS usage and a lot more than that.
- It has sample code to use OpenSSL and wolfSSL.
- And it has a python based automated test framework using Pytest to test OpenSSL
- Finally a perf script to test various TLS implementations.

## 1. Installing Dependencies
```
sudo apt install make gcc python python-pip
pip install --user pytest pytest-html
```

## 2. Building
```
make
```

### 2.1 Building only specific binaries
- `make sample_bin` To build only Sample binaries
- `make test_bin` To build only Test binaries
- `make perf_bin` To build only Performance script binaries

## 3. Running
All binaries needs to run with current working directory as root directory of this repo. As all
code accesses `certs` folder present on root directory.

### 3.1 Running Sample Binaries
```
./bin/sample/openssl_tls13_server
./bin/sample/openssl_tls13_client
```

### 3.2 Running Test
```
./run_test.sh
```

### 3.3 Running Perf Binaries
```
./bin/perf/s_server_openssl_master_rel
./bin/perf/s_time_openssl_master_rel
./bin/perf/speed_openssl_master_rel
```
