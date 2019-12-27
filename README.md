# TalkWithTLS
Sample Code for TLS usage and a lot more than that.
- It has sample code to use OpenSSL and wolfSSL.
- And it has a python based automated test framework using Pytest to test OpenSSL
- Finally a perf script to test various TLS implementations.

# 1. Dependencies
Testframe depends on python2.7. Installing dependency packages from `apt` on Ubuntu are given
below.
```
sudo apt install make gcc python python-pip
```

## 1.1 Python Dependencies
Python module dependencies are `pytest` and `pytest-html`. Command to install python dependencies
are given below.
```
pip install --user pytest pytest-html
```
