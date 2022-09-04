# TalkWithTLS
[![CircleCI](https://circleci.com/gh/TalkWithTLS/TalkWithTLS.svg?style=shield)](https://circleci.com/gh/TalkWithTLS/TalkWithTLS)

Sample Code for [D]TLS usage and a lot more than that.
- It has sample code to use TLS and DTLS from OpenSSL.
- And it has a python based automated test framework using Pytest to test OpenSSL.
- Finally a perf script to test various TLS implementations.

## 1. Installing Dependencies
### 1.1 On ubuntu
```
sudo apt install make cmake gcc g++ python3 python3-pip
sudo apt install libunwind-dev
pip3 install --user pytest pytest-html
```
Install latest golang by downloading it from `https://golang.org/doc/install`
and extract and copy to `/usr/local/go`. And then update env as below.
```
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export PATH=$GOROOT/bin:$PATH' >> ~/.bashrc
. ~/.bashrc
```

## 2. Binaries & Building Procedure
### 2.1 Binaries
Binaries generated are
- **./bin/test_openssl_xxx**
  - Test binaries for openssl which are generated from the code `src/test`.
  - Currently two binaries `test_openssl_111` and `test_openssl_300` are
  generated using `1.1.1` and `3.0.0` versions of OpenSSL.
  - These binaries are similar to `s_server` and `s_client` binaries in
  OpenSSL. One program itself can run as server or client.
- **./bin/sample/xxx**
  - Sample code binaries which are generated from the code `src/sample`.
- **./bin/perf/xxx**
  - Binaries which are generated from the code `src/perf` and used to calculate
  performance.

### 2.2 Building
```
./get_submodules.sh
make
```

- Here `get_submodules.sh` executes
[git-submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
commands to fetch latest code of OpenSSL and BoringSSL master from its git
repositories.
- This fails if you are behind HTTPS proxy. In that case `get_submodules.sh`
execution can be ignored so that `make` uses the pre archived master branch of
OpenSSL and BoringSSL in `dependency` directory.

#### 2.2.1 Building only specific binaries
- `make test_bin`: To build only Test binaries `./bin/test_openssl_xxx`.
- `make sample_bin`: To build only Sample binaries `./bin/sample/xxx`.
- `make perf_bin`: To build only Performance script binaries `./bin/perf/xxx`.

## 3. Running
**All binaries needs to run with root directory of this repo as current
working directory**. Because binary accesses `certs` folder present on root
directory.

### 3.1 Running Test
#### 3.1.1 Running Test Automation
Test automation is achieved using `pytest` which can be triggered by the
script `run_test.sh`.
```
./run_test.sh
```

#### 3.1.2 Running Test
Test binary can be executed separately similar to OpenSSL's `s_server` and
`s_client`.
```
./bin/test_openssl_111 -serv -ver 13
./bin/test_openssl_111 -ver 13
```

### 3.2 Running Sample Binaries
```
./bin/sample/openssl_tls13_server
./bin/sample/openssl_tls13_client
```

### 3.3 Running Perf Binaries
Perf binaries available are
```
./bin/perf/s_server_openssl_master_rel
./bin/perf/s_time_openssl_master_rel
./bin/perf/speed_openssl_master_rel
```
`s_server_xxx` and `s_time_xxx` can be executed on virtual interface of type
`veth` in a network namespace using the script `scripts/create_netns.sh`
