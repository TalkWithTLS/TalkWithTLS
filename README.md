# TalkWithTLS
Sample Code for [D]TLS usage and a lot more than that.
- It has sample code to use TLS and DTLS from OpenSSL and wolfSSL.
- And it has a python based automated test framework using Pytest to test OpenSSL.
- Finally a perf script to test various TLS implementations.

## 1. Installing Dependencies
```
sudo apt install make gcc python python-pip
pip install --user pytest pytest-html
```

## 2. Building
```
./get_submodules.sh
make
```

- Here `get_submodules.sh` executes
[git-submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules) commands to fetch latest code
of OpenSSL and wolfSSL master for its github repositories.
- This fails if you are behind HTTPS proxy. In that case `get_submodules.sh` execution can
be ignored so that `make` uses the pre archived master branch of OpenSSL and wolfSSL in `dependency`
directory.

### 2.1 Building only specific binaries
- `make sample_bin` To build only Sample binaries
- `make test_bin` To build only Test binaries
- `make perf_bin` To build only Performance script binaries

## 3. Running
**All binaries needs to run with current working directory as root directory of this repo**.
Because binary accesses `certs` folder present on root directory.

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
- Perf binaries available are
```
./bin/perf/s_server_openssl_master_rel
./bin/perf/s_time_openssl_master_rel
./bin/perf/speed_openssl_master_rel
```
- `s_server_xxx` and `s_time_xxx` can be executed on virtual interface of type `veth` in a
network namespace using the script `scripts/create_netns.sh`
